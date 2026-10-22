import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TRUST_PATH = ROOT / "trust.json"
FORMAT = "flatpak"
CHANNELS = ("stable", "testing")
MAX_JSON_BYTES = 1024 * 1024
MAX_KEY_BYTES = 256 * 1024
GPG_TIMEOUT = 30
FINGERPRINT = re.compile(r"[A-F0-9]{40}\Z")


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(raw):
    if len(raw) > MAX_JSON_BYTES:
        raise ValueError("trust manifest exceeds size limit")
    try:
        return json.loads(raw, object_pairs_hook=_reject_duplicates)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("trust manifest is invalid JSON") from error


def load_manifest(path=TRUST_PATH):
    with Path(path).open("rb") as stream:
        raw = stream.read(MAX_JSON_BYTES + 1)
    return validate_manifest(parse_json(raw))


def _valid_fingerprint(value):
    return isinstance(value, str) and FINGERPRINT.fullmatch(value) is not None


def _key_path(value):
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise ValueError("public key path is invalid")
    path = Path(value)
    if path.is_absolute() or any(part in ("", ".", "..") for part in value.split("/")):
        raise ValueError("public key path must stay under trust/")
    if not value.startswith("trust/"):
        raise ValueError("public key path must stay under trust/")
    return path


def validate_manifest(doc):
    fields = {"schema_version", "format", "status", "max_validity_days", "channels"}
    if not isinstance(doc, dict) or set(doc) != fields:
        raise ValueError("trust manifest fields do not match the closed schema")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1:
        raise ValueError("unsupported trust schema version")
    if doc["format"] != FORMAT:
        raise ValueError("trust manifest format does not match this repository")
    if doc["status"] not in ("unprovisioned", "provisioned"):
        raise ValueError("trust status is invalid")
    if type(doc["max_validity_days"]) is not int or not 1 <= doc["max_validity_days"] <= 400:
        raise ValueError("max_validity_days must be an integer from 1 through 400")
    channels = doc["channels"]
    if not isinstance(channels, dict) or set(channels) != set(CHANNELS):
        raise ValueError("trust channels must be exactly stable and testing")
    if doc["status"] == "unprovisioned":
        if channels != {"stable": None, "testing": None}:
            raise ValueError("unprovisioned trust requires null channels")
        return doc
    roots = set()
    subkeys = set()
    for channel in CHANNELS:
        identity = channels[channel]
        expected = {"primary_fingerprint", "signing_subkey_fingerprint", "public_key"}
        if not isinstance(identity, dict) or set(identity) != expected:
            raise ValueError("provisioned channel fields do not match the closed schema")
        primary = identity["primary_fingerprint"]
        subkey = identity["signing_subkey_fingerprint"]
        if not _valid_fingerprint(primary) or not _valid_fingerprint(subkey) or primary == subkey:
            raise ValueError("channel fingerprints must be distinct full uppercase fingerprints")
        if primary in roots or subkey in subkeys or primary in subkeys or subkey in roots:
            raise ValueError("stable and testing trust roots must be distinct")
        roots.add(primary)
        subkeys.add(subkey)
        _key_path(identity["public_key"])
    return doc


def resolve_key_path(root, relative):
    relative_path = _key_path(relative)
    root = Path(root).resolve()
    path = root.joinpath(*relative_path.parts)
    current = root
    for part in relative_path.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError("public key path cannot contain symlinks")
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as error:
        raise ValueError("public key path escapes repository") from error
    if not path.is_file():
        raise ValueError("public key file is missing or not regular")
    if path.stat().st_size > MAX_KEY_BYTES:
        raise ValueError("public key file exceeds size limit")
    return path


def _environment():
    env = {key: value for key, value in os.environ.items()
           if key != "GNUPGHOME" and not key.startswith("GPG_")}
    env["LC_ALL"] = "C"
    return env


def _gpg(home, arguments, *, input_data=None, check=True):
    command = ["gpg", "--homedir", str(home), "--no-options", "--no-auto-key-retrieve",
               *arguments]
    try:
        result = subprocess.run(command, input=input_data, capture_output=True,
                                timeout=GPG_TIMEOUT, env=_environment(), check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("GnuPG verification failed or timed out") from error
    if check and result.returncode:
        raise RuntimeError("GnuPG rejected the key material")
    return result


def _kill_agent(home):
    try:
        subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                       capture_output=True, timeout=5, env=_environment(), check=False)
    except (OSError, subprocess.TimeoutExpired):
        pass


def read_fingerprints(home):
    output = _gpg(home, ["--with-colons", "--fingerprint", "--fingerprint", "--list-keys"]).stdout
    records = []
    current = None
    want_fingerprint = False
    try:
        lines = output.decode("utf-8", "strict").splitlines()
        for line in lines:
            columns = line.split(":")
            kind = columns[0]
            if kind in ("pub", "sub"):
                if current is not None and current.get("fingerprint") is None:
                    raise ValueError("malformed GnuPG colon output")
                if len(columns) <= 11:
                    raise ValueError("malformed GnuPG key record")
                current = {"type": kind, "validity": columns[1], "length": columns[2],
                           "algorithm": columns[3], "created": columns[5],
                           "expires": columns[6], "capabilities": columns[11],
                           "fingerprint": None}
                records.append(current)
                want_fingerprint = True
            elif kind == "fpr" and want_fingerprint:
                if len(columns) <= 9 or not _valid_fingerprint(columns[9]):
                    raise ValueError("malformed GnuPG fingerprint record")
                current["fingerprint"] = columns[9]
                want_fingerprint = False
            elif kind in ("uid", "uat"):
                records.append({"type": kind, "validity": columns[1] if len(columns) > 1 else "",
                                "value": columns[9] if len(columns) > 9 else ""})
            elif kind in ("sec", "ssb"):
                raise ValueError("unexpected record in public key listing")
            elif kind not in ("", "tru", "cfg"):
                raise ValueError("unrecognized GnuPG colon record")
        if current is not None and current.get("fingerprint") is None:
            raise ValueError("missing GnuPG fingerprint record")
    except (UnicodeError, IndexError) as error:
        raise ValueError("malformed GnuPG colon output") from error
    return records


def _single_public_block(path):
    path = Path(path)
    flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0) |
             getattr(os, "O_NONBLOCK", 0))
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError("public key path must be a regular file without symlinks") from error
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ValueError("public key path must be a regular file without symlinks")
        data = os.read(descriptor, MAX_KEY_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(data) > MAX_KEY_BYTES:
        raise ValueError("public key file exceeds size limit")
    marker = b"-----BEGIN PGP PUBLIC KEY BLOCK-----"
    if marker in data:
        if data.count(marker) != 1 or data.count(b"-----END PGP PUBLIC KEY BLOCK-----") != 1:
            raise ValueError("key file must contain one public key block")
        before, rest = data.split(marker, 1)
        body, after = rest.split(b"-----END PGP PUBLIC KEY BLOCK-----", 1)
        if before.strip() or after.strip() or b"-----BEGIN PGP " in body:
            raise ValueError("key file must contain one public key block")
    return data


def _expiry(record, now, max_validity_days):
    try:
        created = int(record["created"])
        expires = int(record["expires"])
    except (TypeError, ValueError) as error:
        raise ValueError("key creation and expiry dates are required") from error
    if expires <= now:
        raise ValueError("key is expired")
    if created > now or expires <= created or expires - created > max_validity_days * 86400:
        raise ValueError("key validity exceeds the configured limit")


def verify_key(path, primary_fingerprint, signing_subkey_fingerprint,
               max_validity_days, *, now=None):
    if type(max_validity_days) is not int or not 1 <= max_validity_days <= 400:
        raise ValueError("max_validity_days must be an integer from 1 through 400")
    if not _valid_fingerprint(primary_fingerprint) or not _valid_fingerprint(signing_subkey_fingerprint):
        raise ValueError("full uppercase fingerprints are required")
    if primary_fingerprint == signing_subkey_fingerprint:
        raise ValueError("primary and signing fingerprints must differ")
    path = Path(path)
    data = _single_public_block(path)
    now = int(time.time()) if now is None else int(now)
    if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
        raise RuntimeError("GnuPG and gpgconf are required")
    with tempfile.TemporaryDirectory(prefix="luminus-trust-gpg-") as home:
        os.chmod(home, 0o700)
        try:
            packets = _gpg(home, ["--list-packets"], input_data=data).stdout.decode("utf-8", "strict")
            packet_lines = packets.splitlines()
            if any(":secret key packet:" in line or ":secret sub key packet:" in line
                   for line in packet_lines):
                raise ValueError("secret key material is forbidden")
            if (packet_lines.count(":public key packet:") != 1 or
                    packet_lines.count(":public sub key packet:") != 1):
                raise ValueError("key file must contain exactly one primary and signing subkey")
            result = _gpg(home, ["--status-fd", "1", "--import"], input_data=data)
            import_results = []
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) > 1 and fields[1] == b"IMPORT_RES":
                    import_results.append(fields)
            if len(import_results) != 1 or len(import_results[0]) < 12:
                raise ValueError("GnuPG import result is malformed")
            try:
                secret_counts = [int(import_results[0][index]) for index in (9, 10, 11)]
            except ValueError as error:
                raise ValueError("GnuPG import result is malformed") from error
            if any(secret_counts):
                raise ValueError("secret key material is forbidden")
            secrets = _gpg(home, ["--with-colons", "--list-secret-keys"]).stdout
            if any(line.startswith((b"sec:", b"sec#:", b"ssb:", b"ssb#:"))
                   for line in secrets.splitlines()):
                raise ValueError("secret key material is forbidden")
            records = read_fingerprints(home)
            keys = [record for record in records if record["type"] in ("pub", "sub")]
            primaries = [record for record in keys if record["type"] == "pub"]
            subs = [record for record in keys if record["type"] == "sub"]
            if len(primaries) != 1 or len(subs) != 1:
                raise ValueError("key must have exactly one primary and one subkey")
            primary, subkey = primaries[0], subs[0]
            if primary["fingerprint"] != primary_fingerprint or subkey["fingerprint"] != signing_subkey_fingerprint:
                raise ValueError("declared fingerprints do not match the key")
            if primary["fingerprint"] == subkey["fingerprint"]:
                raise ValueError("primary and signing fingerprints must differ")
            if primary["validity"] in ("r", "e", "d") or subkey["validity"] in ("r", "e", "d"):
                raise ValueError("revoked, expired, or disabled keys are forbidden")
            primary_usable = {flag for flag in primary["capabilities"] if flag.islower()}
            if primary_usable != {"c"}:
                raise ValueError("primary key must be certification-only")
            if set(subkey["capabilities"]) != {"s"}:
                raise ValueError("the only subkey must be signing-only")
            for key in keys:
                if key["algorithm"] != "1" or not key["length"].isdigit() or int(key["length"]) < 3072:
                    raise ValueError("all keys must use RSA of at least 3072 bits")
                _expiry(key, now, max_validity_days)
            if not any(record["type"] == "uid" and record["value"].strip()
                       and record["validity"] != "r" for record in records):
                raise ValueError("a non-revoked non-empty user ID is required")
        finally:
            _kill_agent(home)
    return {"status": "valid", "primary_fingerprint": primary_fingerprint,
            "signing_subkey_fingerprint": signing_subkey_fingerprint,
            "algorithm": "RSA", "minimum_bits": 3072}


def key_expiration_epoch(path):
    data = _single_public_block(path)
    with tempfile.TemporaryDirectory(prefix="luminus-trust-inspect-") as home:
        os.chmod(home, 0o700)
        try:
            _gpg(home, ["--import"], input_data=data)
            keys = [item for item in read_fingerprints(home) if item["type"] in ("pub", "sub")]
            return min(int(item["expires"]) for item in keys if item["expires"])
        finally:
            _kill_agent(home)


def key_creation_epoch(path):
    data = _single_public_block(path)
    with tempfile.TemporaryDirectory(prefix="luminus-trust-inspect-") as home:
        os.chmod(home, 0o700)
        try:
            _gpg(home, ["--import"], input_data=data)
            keys = [item for item in read_fingerprints(home) if item["type"] in ("pub", "sub")]
            return max(int(item["created"]) for item in keys)
        finally:
            _kill_agent(home)


def verify_signature(public_key, signature, content, primary_fingerprint, signing_subkey_fingerprint):
    data = _single_public_block(public_key)
    with tempfile.TemporaryDirectory(prefix="luminus-trust-signature-") as home:
        os.chmod(home, 0o700)
        try:
            _gpg(home, ["--import"], input_data=data)
            command = ["gpg", "--homedir", home, "--no-options", "--no-auto-key-retrieve",
                       "--status-fd", "1", "--verify", str(signature), str(content)]
            result = subprocess.run(command, capture_output=True, timeout=GPG_TIMEOUT,
                                    env=_environment(), check=False)
            valid = False
            for line in result.stdout.splitlines():
                fields = line.split()
                if len(fields) >= 12 and fields[1] == b"VALIDSIG":
                    valid = (fields[2].decode("ascii") == signing_subkey_fingerprint and
                             fields[11].decode("ascii") == primary_fingerprint)
            return result.returncode == 0 and valid
        finally:
            _kill_agent(home)


def compare_fingerprints(manifest, other_fingerprints):
    validate_manifest(manifest)
    if manifest["status"] != "provisioned":
        return True
    local = {value for identity in manifest["channels"].values()
             for value in (identity["primary_fingerprint"], identity["signing_subkey_fingerprint"])}
    for value in other_fingerprints:
        if not _valid_fingerprint(value):
            raise ValueError("other fingerprints must be full uppercase fingerprints")
        if value in local:
            raise ValueError("fingerprint collides with another repository")
    return True


def validate_installed(manifest, root=ROOT, other_fingerprints=()):
    validate_manifest(manifest)
    compare_fingerprints(manifest, other_fingerprints)
    if manifest["status"] == "provisioned":
        for identity in manifest["channels"].values():
            path = resolve_key_path(root, identity["public_key"])
            verify_key(path, identity["primary_fingerprint"],
                       identity["signing_subkey_fingerprint"], manifest["max_validity_days"])
    return {"status": "valid_" + manifest["status"], "format": FORMAT,
            "channels": list(CHANNELS)}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="trust.py")
    commands = parser.add_subparsers(dest="command", required=True)
    validate = commands.add_parser("validate")
    validate.add_argument("--other-fingerprints", default="")
    verify = commands.add_parser("verify-key")
    verify.add_argument("--channel", choices=CHANNELS, required=True)
    verify.add_argument("--file", required=True)
    verify.add_argument("--primary", required=True)
    verify.add_argument("--subkey", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            others = [item for item in args.other_fingerprints.split(",") if item]
            report = validate_installed(load_manifest(), other_fingerprints=others)
        else:
            manifest = load_manifest()
            report = verify_key(args.file, args.primary, args.subkey,
                                manifest["max_validity_days"])
            report["channel"] = args.channel
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, ValueError, RuntimeError, RecursionError):
        print(json.dumps({"status": "error", "message": "trust verification failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "signing-policy.json"
MAX_POLICY_BYTES = 1024 * 1024
GPG_TIMEOUT = 90
TEMP_ROOT = Path("/tmp/opencode")
FORMAT = "flatpak"
CHANNELS = ("stable", "testing")
TEAM = "luminusOS/flatpak"
HASH_ALGORITHM_IDS = {"SHA256": b"8"}


def validate_policy(policy):
    fields = {"schema_version", "format", "channels", "reviewer_team", "status", "gpg_algorithm"}
    if not isinstance(policy, dict) or set(policy) != fields:
        raise ValueError("policy fields do not match the closed schema")
    if policy["schema_version"] != 1 or type(policy["schema_version"]) is not int:
        raise ValueError("unsupported policy schema version")
    if policy["format"] != FORMAT or policy["reviewer_team"] != TEAM:
        raise ValueError("policy does not belong to this repository")
    if policy["channels"] != list(CHANNELS):
        raise ValueError("policy channels must be stable and testing")
    if policy["status"] != "unprovisioned":
        raise ValueError("production signing trust must remain unprovisioned")
    if policy["gpg_algorithm"] != "RSA3072-SHA256":
        raise ValueError("unsupported signing algorithm policy")
    return policy


def validate_claim(policy, artifact_format, channel):
    if artifact_format != policy["format"] or channel not in policy["channels"]:
        raise ValueError("format or channel is outside this repository policy")
    return True


def _reject_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate policy field")
        result[key] = value
    return result


def load_policy():
    with POLICY_PATH.open("rb") as stream:
        raw = stream.read(MAX_POLICY_BYTES + 1)
    if len(raw) > MAX_POLICY_BYTES:
        raise ValueError("policy exceeds size limit")
    return validate_policy(json.loads(raw, object_pairs_hook=_reject_duplicates))


def _environment():
    env = {key: value for key, value in os.environ.items()
           if not key.startswith("GPG_") and key != "GNUPGHOME"}
    env["LC_ALL"] = "C"
    return env


def _run(home, arguments, *, input_data=None, timeout=GPG_TIMEOUT):
    command = ["gpg", "--homedir", str(home), "--no-options", "--no-auto-key-retrieve", *arguments]
    try:
        result = subprocess.run(
            command, input=input_data, capture_output=True, check=False,
            timeout=timeout, env=_environment(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("GnuPG command failed or timed out") from error
    if result.returncode:
        raise RuntimeError("GnuPG operation failed")
    return result.stdout


def _kill_agent(home):
    try:
        subprocess.run(
            ["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
            capture_output=True, check=False, timeout=5, env=_environment(),
        )
    except (OSError, subprocess.TimeoutExpired):
        pass


def _fingerprints(home, secret=False):
    option = "--list-secret-keys" if secret else "--list-keys"
    output = _run(home, ["--with-colons", "--fingerprint", "--fingerprint", option])
    primary = None
    subkeys = []
    secret_records = []
    want_fingerprint = False
    for line in output.decode("utf-8", "strict").splitlines():
        columns = line.split(":")
        kind = columns[0]
        secret_marker = columns[14] if len(columns) > 14 else ""
        if kind in ("pub", "sec", "sec#"):
            want_fingerprint = True
            secret_records.append((kind, secret_marker))
        elif kind in ("sub", "ssb", "ssb#"):
            want_fingerprint = True
            secret_records.append((kind, secret_marker))
        elif kind == "fpr" and want_fingerprint:
            fingerprint = columns[9]
            if primary is None:
                primary = fingerprint
            else:
                subkeys.append(fingerprint)
            want_fingerprint = False
    return primary, subkeys, secret_records


def _signature_status(home, signature, content):
    command = ["gpg", "--homedir", str(home), "--no-options", "--no-auto-key-retrieve",
               "--status-fd", "1",
               "--verify", str(signature), str(content)]
    try:
        result = subprocess.run(command, capture_output=True, check=False,
                                 timeout=GPG_TIMEOUT, env=_environment())
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeError("signature verification failed or timed out") from error
    status = [line.split() for line in result.stdout.splitlines()
              if line.startswith(b"[GNUPG:]")]
    return result.returncode, status


def _verified_signature(home, signature, content, primary_fpr, signing_fpr, digest):
    code, statuses = _signature_status(home, signature, content)
    rejected = {b"BADSIG", b"ERRSIG", b"EXPSIG", b"EXPKEYSIG", b"KEYEXPIRED",
                b"KEYREVOKED", b"REVKEYSIG", b"SIGEXPIRED"}
    if code or any(row[1] in rejected for row in statuses):
        return False, None
    for fields in statuses:
        if fields[1] == b"VALIDSIG" and len(fields) >= 12:
            signer = fields[2].decode("ascii")
            hash_id = fields[9]
            primary = fields[11].decode("ascii")
            observed_hash_id = int(hash_id) if hash_id.isdigit() else None
            valid = (signer == signing_fpr and primary == primary_fpr
                     and hash_id == HASH_ALGORITHM_IDS.get(digest))
            return valid, observed_hash_id
    return False, None


def _valid_signature(home, signature, content, primary_fpr, signing_fpr, digest):
    return _verified_signature(home, signature, content, primary_fpr, signing_fpr, digest)[0]


def _secret_export_is_ci_safe(home):
    primary, subkeys, records = _fingerprints(home, secret=True)
    primary_records = [marker for kind, marker in records if kind in ("sec", "sec#")]
    signing_records = [marker for kind, marker in records if kind in ("ssb", "ssb#")]
    return bool(primary and primary_records == ["#"] and len(subkeys) == 1
                and signing_records == ["+"])


def _require(condition, message):
    if not condition:
        raise RuntimeError(message)


def _identity_fixture(root, artifact_format, channel, homes):
    identity = f"LuminusOS disposable {artifact_format} {channel} fixture"
    uid = f"{identity} <fixture@example.invalid>"
    home = root / f"source-{artifact_format}-{channel}"
    verifier = root / f"verify-{artifact_format}-{channel}"
    ci_home = root / f"ci-{artifact_format}-{channel}"
    for path in (home, verifier, ci_home):
        path.mkdir(mode=0o700)
        homes.append(path)
    _run(home, ["--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-generate-key", uid, "rsa3072", "cert", "1d"])
    primary, _, _ = _fingerprints(home)
    _require(bool(primary), "fixture primary fingerprint missing")
    _run(home, ["--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                "--quick-add-key", primary, "rsa3072", "sign", "1d"])
    primary, subkeys, _ = _fingerprints(home)
    _require(len(subkeys) == 1, "fixture signing subkey missing")
    signing = subkeys[0]
    public_path = root / f"{artifact_format}-{channel}.public"
    subkey_path = root / f"{artifact_format}-{channel}.subkey-export"
    full_secret_path = root / f"{artifact_format}-{channel}.full-secret-export"
    _run(home, ["--output", str(public_path), "--export", primary])
    _run(home, ["--output", str(subkey_path), "--export-secret-subkeys",
                f"{signing}!"])
    _run(home, ["--output", str(full_secret_path), "--export-secret-keys", primary])
    _run(verifier, ["--import", str(public_path)])
    _run(ci_home, ["--import", str(subkey_path)])
    _require(_secret_export_is_ci_safe(ci_home), "CI export contains primary private material")

    full_home = root / f"reject-full-secret-{artifact_format}-{channel}"
    full_home.mkdir(mode=0o700)
    homes.append(full_home)
    _run(full_home, ["--import", str(full_secret_path)])
    _require(not _secret_export_is_ci_safe(full_home), "full private key export was accepted as CI-safe")

    content = root / f"{artifact_format}-{channel}.payload"
    signature = root / f"{artifact_format}-{channel}.sig"
    content.write_text(f"disposable synthetic {artifact_format} {channel} signing fixture\n",
                       encoding="ascii")
    policy = load_policy()
    digest = policy["gpg_algorithm"].split("-")[-1]
    _run(ci_home, ["--digest-algo", digest, "--local-user", f"{signing}!", "--detach-sign", "--output",
                   str(signature), str(content)])

    tampered = root / f"{artifact_format}-{channel}.tampered"
    tampered.write_bytes(content.read_bytes() + b"tampered\n")
    code, statuses = _signature_status(verifier, signature, tampered)
    _require(code != 0 and not any(row[1] in (b"GOODSIG", b"VALIDSIG") for row in statuses),
             "tampered content was accepted")

    revocation = home / "openpgp-revocs.d" / f"{primary}.rev"
    _require(revocation.is_file(), "fixture revocation certificate missing")
    revocation_bytes = revocation.read_bytes().splitlines(keepends=True)
    for index, line in enumerate(revocation_bytes):
        if line.startswith(b":-----BEGIN PGP PUBLIC KEY BLOCK-----"):
            revocation_bytes[index] = line[1:]
            break
    else:
        raise RuntimeError("fixture revocation certificate is malformed")
    revocation_path = root / f"{artifact_format}-{channel}.revocation"
    revocation_path.write_bytes(b"".join(revocation_bytes))
    try:
        validate_claim(policy, artifact_format, channel)
        accepted = True
    except ValueError:
        accepted = False
    return {
        "format": artifact_format,
        "channel": channel,
        "primary_fingerprint": primary,
        "signing_fingerprint": signing,
        "signature": signature,
        "content": content,
        "verifier_home": verifier,
        "revocation_path": revocation_path,
        "digest": digest,
        "policy_accepts_this_claim": accepted,
        "checks": {
            "isolated_public_verification": False,
            "wrong_trust_roots_rejected": False,
            "exact_signing_subkey": True,
            "ci_has_subkey_only": True,
            "full_private_export_rejected": True,
            "tampering_rejected": True,
            "revocation_rejected": False,
        },
    }


def _check_trust_matrix(fixtures):
    matrix = []
    for signer in fixtures:
        accepted_by = []
        observed_hash_id = None
        for verifier in fixtures:
            accepted, hash_id = _verified_signature(
                verifier["verifier_home"], signer["signature"], signer["content"],
                signer["primary_fingerprint"], signer["signing_fingerprint"], signer["digest"],
            )
            expected = signer["primary_fingerprint"] == verifier["primary_fingerprint"]
            _require(accepted is expected, "isolated trust-root matrix mismatch")
            if accepted:
                accepted_by.append(verifier["primary_fingerprint"])
                observed_hash_id = hash_id
            matrix.append({
                "signer_primary_fingerprint": signer["primary_fingerprint"],
                "verifier_primary_fingerprint": verifier["primary_fingerprint"],
                "accepted": accepted,
            })
        signer["checks"]["isolated_public_verification"] = accepted_by == [signer["primary_fingerprint"]]
        signer["checks"]["wrong_trust_roots_rejected"] = len(accepted_by) == 1
        _require(signer["checks"]["isolated_public_verification"]
                 and signer["checks"]["wrong_trust_roots_rejected"],
                 "signature was accepted by an unexpected trust root")
        signer["signature_hash_algorithm_id"] = observed_hash_id
        signer["signature_hash_algorithm"] = next(
            (name for name, algorithm_id in HASH_ALGORITHM_IDS.items()
             if algorithm_id == str(observed_hash_id).encode("ascii")), None,
        )
        _require(signer["signature_hash_algorithm"] == signer["digest"]
                 and observed_hash_id is not None, "signature used an unexpected digest")
    return matrix


def _check_revocation(fixture):
    _run(fixture["verifier_home"], ["--import", str(fixture["revocation_path"])])
    _, statuses = _signature_status(
        fixture["verifier_home"], fixture["signature"], fixture["content"],
    )
    revoked = any(row[1] in (b"REVKEYSIG", b"KEYREVOKED") for row in statuses)
    valid = _valid_signature(
        fixture["verifier_home"], fixture["signature"], fixture["content"],
        fixture["primary_fingerprint"], fixture["signing_fingerprint"], fixture["digest"],
    )
    fixture["checks"]["revocation_rejected"] = revoked and not valid
    _require(fixture["checks"]["revocation_rejected"],
             "revoked fixture signature was not rejected as revoked")


def rehearse():
    if shutil.which("gpg") is None or shutil.which("gpgconf") is None:
        raise RuntimeError("GnuPG and gpgconf are required for rehearsal")
    if not TEMP_ROOT.is_dir():
        raise RuntimeError("approved temporary root is unavailable")
    fixtures = []
    homes = []
    with tempfile.TemporaryDirectory(prefix="luminus-signing-", dir=TEMP_ROOT) as work:
        os.chmod(work, 0o700)
        root = Path(work)
        try:
            for artifact_format in (FORMAT, "rpm" if FORMAT == "flatpak" else "flatpak"):
                for channel in CHANNELS:
                    fixture = _identity_fixture(root, artifact_format, channel, homes)
                    fixtures.append(fixture)
            if len({item["primary_fingerprint"] for item in fixtures}) != 4:
                raise RuntimeError("disposable identities were not distinct")
            trust_matrix = _check_trust_matrix(fixtures)
            for fixture in fixtures:
                _check_revocation(fixture)
        finally:
            for home in homes:
                _kill_agent(home)
    public_fixtures = [{key: fixture[key] for key in (
        "format", "channel", "primary_fingerprint", "signature_hash_algorithm",
        "signature_hash_algorithm_id", "policy_accepts_this_claim", "checks",
    )} for fixture in fixtures]
    return {"status": "rehearsal_passed", "format": FORMAT, "fixtures": public_fixtures,
            "trust_matrix": trust_matrix,
            "temporary_fixtures_removed": True}


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    try:
        policy = load_policy()
        if args == ["validate"]:
            report = {"status": "valid_unprovisioned_policy", "format": policy["format"],
                      "channels": policy["channels"], "reviewer_team": policy["reviewer_team"]}
        elif args == ["rehearse"]:
            report = rehearse()
        else:
            raise ValueError("expected validate or rehearse")
        print(json.dumps(report, sort_keys=True))
        return 0
    except (OSError, UnicodeError, ValueError, RuntimeError, RecursionError):
        print(json.dumps({"status": "error", "message": "signing check failed"}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

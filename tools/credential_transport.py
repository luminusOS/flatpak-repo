#!/usr/bin/env python3
"""Transport short-lived synthetic proof data between isolated CI jobs."""

import argparse
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass


CHANNELS = ("stable", "testing")
EXPECTED_REPOSITORY = "luminusOS/flatpak-repo"
EXPECTED_REF = "refs/heads/main"
TTL_SECONDS = 300
CLOCK_SKEW_SECONDS = 30
MAX_CIPHERTEXT_BYTES = 64 * 1024
MAX_PLAINTEXT_BYTES = 8 * 1024
GPG_TIMEOUT_SECONDS = 15
GPG_BINARY = "/usr/bin/gpg"
SECRET_ENV = "T02_TRANSPORT_KEY"
PARENT_ENV = "T02_PARENT_CANARY"
_HEX_64 = re.compile(r"[0-9a-fA-F]{64}\Z")
_HEX_SHA = re.compile(r"[0-9a-fA-F]{40,64}\Z")
_NONCE = re.compile(r"[A-Za-z0-9_-]{32}\Z")


class TransportError(Exception):
    """A sanitized input, validation, or cryptographic operation failure."""


@dataclass(frozen=True)
class Binding:
    repository: str
    run_id: str
    run_attempt: str
    sha: str
    ref: str
    channel: str

    def __post_init__(self):
        if self.repository != EXPECTED_REPOSITORY or self.ref != EXPECTED_REF:
            raise TransportError("GitHub context is not authorized")
        if not self.run_id.isdecimal() or not self.run_attempt.isdecimal():
            raise TransportError("GitHub context is invalid")
        if not _HEX_SHA.fullmatch(self.sha):
            raise TransportError("GitHub context is invalid")
        if self.channel not in CHANNELS:
            raise TransportError("Channel is not allowed")

    def as_dict(self):
        return {
            "repository": self.repository,
            "run_id": self.run_id,
            "run_attempt": self.run_attempt,
            "sha": self.sha.lower(),
            "ref": self.ref,
            "channel": self.channel,
        }


def binding_from_environment(channel, environ=None):
    environ = os.environ if environ is None else environ
    try:
        return Binding(
            repository=environ["GITHUB_REPOSITORY"],
            run_id=environ["GITHUB_RUN_ID"],
            run_attempt=environ["GITHUB_RUN_ATTEMPT"],
            sha=environ["GITHUB_SHA"],
            ref=environ["GITHUB_REF"],
            channel=channel,
        )
    except KeyError:
        raise TransportError("Required GitHub context is missing") from None


def parent_commitment(parent_canary):
    _require_hex_secret(parent_canary, PARENT_ENV)
    return hashlib.sha256(bytes.fromhex(parent_canary)).hexdigest()


def derive_temporary_secret(parent_canary, binding, nonce):
    _require_hex_secret(parent_canary, PARENT_ENV)
    if not _NONCE.fullmatch(nonce):
        raise TransportError("Envelope is invalid")
    message = json.dumps(
        {"binding": binding.as_dict(), "nonce": nonce},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hmac.new(bytes.fromhex(parent_canary), message, hashlib.sha256).hexdigest()


def build_envelope(binding, parent_canary, now=None):
    _require_hex_secret(parent_canary, PARENT_ENV)
    issued_at = int(time.time() if now is None else now)
    nonce = secrets.token_urlsafe(24)
    return {
        "version": 1,
        "kind": "transport-proof",
        "synthetic": True,
        "binding": binding.as_dict(),
        "iat": issued_at,
        "exp": issued_at + TTL_SECONDS,
        "nonce": nonce,
        "parent_commitment": parent_commitment(parent_canary),
        "temporary_secret": derive_temporary_secret(parent_canary, binding, nonce),
    }


def validate_envelope(envelope, binding, now=None):
    expected_keys = {
        "version", "kind", "synthetic", "binding", "iat", "exp", "nonce",
        "parent_commitment", "temporary_secret",
    }
    if not isinstance(envelope, dict) or set(envelope) != expected_keys:
        raise TransportError("Envelope shape is invalid")
    if (envelope["version"] != 1 or type(envelope["version"]) is not int
            or envelope["kind"] != "transport-proof" or envelope["synthetic"] is not True
            or envelope["binding"] != binding.as_dict()):
        raise TransportError("Envelope binding is invalid")
    issued_at, expires_at = envelope["iat"], envelope["exp"]
    current = int(time.time() if now is None else now)
    if (type(issued_at) is not int or type(expires_at) is not int
            or expires_at != issued_at + TTL_SECONDS
            or issued_at > current + CLOCK_SKEW_SECONDS
            or expires_at <= current):
        raise TransportError("Envelope is expired or not yet valid")
    if not isinstance(envelope["nonce"], str) or not _NONCE.fullmatch(envelope["nonce"]):
        raise TransportError("Envelope is invalid")
    for field in ("parent_commitment", "temporary_secret"):
        if not isinstance(envelope[field], str) or not _HEX_64.fullmatch(envelope[field]):
            raise TransportError("Envelope is invalid")
    return envelope


def ensure_publisher_has_no_parent_canary(environ=None):
    environ = os.environ if environ is None else environ
    if PARENT_ENV in environ:
        raise TransportError("Publisher must not receive the parent canary")


def _require_hex_secret(value, name):
    if not isinstance(value, str) or not _HEX_64.fullmatch(value):
        raise TransportError(f"{name} must be a 64-character hexadecimal secret")


def _transport_key(value):
    _require_hex_secret(value, SECRET_ENV)
    return value


def _strict_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise TransportError("Envelope contains duplicate fields")
        result[key] = value
    return result


def _gpg(data, passphrase, operation):
    _transport_key(passphrase)
    if not isinstance(data, bytes) or len(data) > MAX_CIPHERTEXT_BYTES:
        raise TransportError("Capsule size is invalid")
    if operation not in ("encrypt", "decrypt"):
        raise TransportError("Cryptographic operation is invalid")
    try:
        with tempfile.TemporaryDirectory(prefix="t02-gpg-") as home:
            os.chmod(home, 0o700)
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, passphrase.encode("ascii") + b"\n")
            finally:
                os.close(write_fd)
            args = [
                GPG_BINARY, "--homedir", home, "--batch", "--no-tty",
                "--pinentry-mode", "loopback", "--passphrase-fd", str(read_fd),
                "--no-symkey-cache", "--max-output", str(MAX_PLAINTEXT_BYTES),
            ]
            if operation == "encrypt":
                args.extend(("--symmetric", "--cipher-algo", "AES256", "--s2k-mode", "3",
                             "--compress-algo", "none", "--output", "-"))
            else:
                args.extend(("--decrypt",))
            try:
                result = subprocess.run(
                    args,
                    input=data,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=GPG_TIMEOUT_SECONDS,
                    pass_fds=(read_fd,),
                    check=False,
                    env={"PATH": "/usr/bin:/bin", "GNUPGHOME": home, "LC_ALL": "C"},
                )
            finally:
                os.close(read_fd)
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        raise TransportError("GnuPG operation failed") from None
    if result.returncode != 0:
        raise TransportError("GnuPG operation failed")
    limit = MAX_CIPHERTEXT_BYTES if operation == "encrypt" else MAX_PLAINTEXT_BYTES
    if len(result.stdout) > limit:
        raise TransportError("GnuPG output exceeds the size limit")
    return result.stdout


def encrypt_envelope(envelope, passphrase):
    try:
        plaintext = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise TransportError("Envelope cannot be encoded") from None
    if len(plaintext) > MAX_PLAINTEXT_BYTES:
        raise TransportError("Envelope exceeds the size limit")
    return _gpg(plaintext, passphrase, "encrypt")


def decrypt_envelope(ciphertext, passphrase):
    plaintext = _gpg(ciphertext, passphrase, "decrypt")
    try:
        envelope = json.loads(plaintext.decode("utf-8"), object_pairs_hook=_strict_json_object)
    except (UnicodeError, json.JSONDecodeError, TransportError):
        raise TransportError("Decrypted envelope is invalid") from None
    return envelope


def write_capsule(path, ciphertext):
    path = os.fspath(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as capsule:
            descriptor = None
            capsule.write(ciphertext)
            capsule.flush()
            os.fsync(capsule.fileno())
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise TransportError("Capsule could not be created") from None


def read_capsule_bytes(data):
    if not data or len(data) > MAX_CIPHERTEXT_BYTES:
        raise TransportError("Capsule size is invalid")
    return data


def read_capsule(path):
    path = os.fspath(path)
    try:
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > MAX_CIPHERTEXT_BYTES:
            raise TransportError("Capsule file is invalid")
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as capsule:
            data = capsule.read(MAX_CIPHERTEXT_BYTES + 1)
    except OSError:
        raise TransportError("Capsule file is unavailable") from None
    return read_capsule_bytes(data)


def _required_secret(name, environ):
    value = environ.get(name)
    _require_hex_secret(value, name)
    return value


def run_cli(argv=None, environ=None):
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    issue = subparsers.add_parser("issue")
    issue.add_argument("--channel", required=True, choices=CHANNELS)
    issue.add_argument("--output", required=True)
    consume = subparsers.add_parser("consume")
    consume.add_argument("--channel", required=True, choices=CHANNELS)
    consume.add_argument("--input", required=True)
    args = parser.parse_args(argv)
    binding = binding_from_environment(args.channel, environ)
    if args.command == "issue":
        parent = _required_secret(PARENT_ENV, environ)
        key = _required_secret(SECRET_ENV, environ)
        capsule = encrypt_envelope(build_envelope(binding, parent), key)
        write_capsule(args.output, capsule)
        summary = {"stage": "issuer", "channel": args.channel,
                   "synthetic": True, "encrypted": True, "capsule_bytes": len(capsule)}
    else:
        ensure_publisher_has_no_parent_canary(environ)
        key = _required_secret(SECRET_ENV, environ)
        envelope = decrypt_envelope(read_capsule(args.input), key)
        validate_envelope(envelope, binding)
        summary = {"stage": "publisher", "channel": args.channel,
                   "synthetic": True, "encrypted": True, "binding_verified": True}
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


def main():
    try:
        return run_cli()
    except TransportError:
        print("credential transport failed; details suppressed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

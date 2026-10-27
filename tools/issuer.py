#!/usr/bin/env python3
"""Issue and consume short-lived, channel-scoped R2 credentials."""

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

import credential_transport as transport

Binding = transport.Binding

FORMAT = "flatpak"
BUCKET = "luminus-flatpak"
REPOSITORY = "luminusOS/flatpak-repo"
CHANNELS = ("stable", "testing")
PARENT_ID_ENV = "R2_PARENT_ACCESS_KEY_ID"
PARENT_SECRET_ENV = "R2_PARENT_SECRET_ACCESS_KEY"
TRANSPORT_KEY_ENV = "TRANSPORT_KEY"
DEFAULT_TTL_SECONDS = 600
MAX_TTL_SECONDS = 900
MAX_ENVELOPE_TTL_SECONDS = 600
MAX_PLAINTEXT_BYTES = transport.MAX_PLAINTEXT_BYTES
_ACCESS_ID = re.compile(r"[0-9a-fA-F]{32}\Z")
_PARENT_SECRET = re.compile(r"[0-9a-fA-F]{64}\Z")
_SHA = re.compile(r"[0-9a-fA-F]{40,64}\Z")
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}\Z")
_TAG = re.compile(r"^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.?([1-9][0-9]*))?\Z")
_VERSION_CONTRACT = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-rc\.([1-9][0-9]*))?\Z")
SOURCE_RELEASES = {
    "dev.luminusos.ZapTide": ("luminusOS/zaptide", ".github/workflows/release.yml",
                               ".github/workflows/release.yml", "flatpak"),
    "org.luminusos.Aetheris": ("luminusOS/aetheris", ".github/workflows/release.yml",
                                ".github/workflows/release-flatpak.yml", "flatpak"),
    "sirius-installer": ("luminusOS/sirius", ".github/workflows/ci.yml",
                          ".github/workflows/ci.yml", "rpm"),
}
ALLOWED_SOURCE_EVENTS = ("push",)
GITHUB_API_HOST = "api.github.com"
GITHUB_API_VERSION = "2022-11-28"
GITHUB_TIMEOUT_SECONDS = 15
MAX_GITHUB_RESPONSE_BYTES = 1024 * 1024


class IssuerError(Exception):
    pass


def prefix_for(channel):
    if channel not in CHANNELS:
        raise IssuerError("Channel is not allowed")
    return f"{channel}/"


def validate_descriptor(descriptor, package_format=FORMAT, channel=None):
    expected = {"format", "channel", "package_id", "version", "git_sha", "source_run_id",
                "source_run_attempt"}
    if not isinstance(descriptor, dict) or set(descriptor) != expected:
        raise IssuerError("Release descriptor is invalid")
    if descriptor["format"] != package_format or descriptor["channel"] != channel:
        raise IssuerError("Release descriptor scope is invalid")
    if channel not in CHANNELS:
        raise IssuerError("Channel is not allowed")
    package_id = descriptor["package_id"]
    source = SOURCE_RELEASES.get(package_id) if isinstance(package_id, str) else None
    if source is None or source[3] != package_format:
        raise IssuerError("Release descriptor is invalid")
    if not isinstance(descriptor["version"], str) or not _VERSION_CONTRACT.fullmatch(descriptor["version"]):
        raise IssuerError("Release descriptor is invalid")
    if "-rc." in descriptor["version"] and channel == "stable":
        raise IssuerError("Pre-release versions are testing-only")
    if not isinstance(descriptor["git_sha"], str) or not _SHA.fullmatch(descriptor["git_sha"]):
        raise IssuerError("Release descriptor is invalid")
    if not isinstance(descriptor["source_run_id"], str) or not _RUN_ID.fullmatch(descriptor["source_run_id"]):
        raise IssuerError("Release descriptor is invalid")
    attempt = descriptor["source_run_attempt"]
    if type(attempt) is not int or attempt < 1:
        raise IssuerError("Release descriptor is invalid")
    return {**descriptor, "git_sha": descriptor["git_sha"].lower()}


def validate_envelope_descriptor(descriptor, package_format, channel):
    return validate_descriptor(descriptor, package_format, channel)


def temporary_request(parent_access_key_id, channel, ttl=DEFAULT_TTL_SECONDS):
    if not isinstance(parent_access_key_id, str) or not _ACCESS_ID.fullmatch(parent_access_key_id):
        raise IssuerError("Parent access key id is invalid")
    if type(ttl) is not int or not 1 <= ttl <= MAX_TTL_SECONDS:
        raise IssuerError("TTL is outside the allowed range")
    return {
        "parentAccessKeyId": parent_access_key_id,
        "bucket": BUCKET,
        "permission": "object-read-write",
        "prefixes": [prefix_for(channel)],
        "ttlSeconds": ttl,
    }


def _b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def derive_credentials(parent_access_key_id, parent_secret_access_key, package_format,
                       channel, ttl=DEFAULT_TTL_SECONDS, now=None):
    if package_format != FORMAT:
        raise IssuerError("Format is not allowed")
    request = temporary_request(parent_access_key_id, channel, ttl)
    if not isinstance(parent_secret_access_key, str) or not _PARENT_SECRET.fullmatch(parent_secret_access_key):
        raise IssuerError("Parent secret is invalid")
    issued_at = int(time.time() if now is None else now)
    if type(now) is not int and now is not None:
        raise IssuerError("Timestamp is invalid")
    expires_at = issued_at + request["ttlSeconds"]
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "bucket": request["bucket"],
        "scope": request["permission"],
        "paths": {"prefixPaths": request["prefixes"], "objectPaths": []},
        "sub": "89e6fc75aed6d04cd84a0c7d11a5594e",
        "iss": parent_access_key_id,
        "aud": "89e6fc75aed6d04cd84a0c7d11a5594e.r2.cloudflarestorage.com",
        "iat": issued_at,
        "exp": expires_at,
    }
    encoded_header = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    encoded_payload = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{encoded_header}.{encoded_payload}"
    signature = hmac.new(parent_secret_access_key.encode("utf-8"),
                         signing_input.encode("ascii"), hashlib.sha256).digest()
    jwt = f"{signing_input}.{_b64url(signature)}"
    jwt_bytes = jwt.encode("ascii")
    return {
        "bucket": BUCKET,
        "prefix": prefix_for(channel),
        "permission": "object-read-write",
        "expires_at": expires_at,
        "access_key_id": parent_access_key_id,
        "secret_access_key": hashlib.sha256(jwt_bytes).hexdigest(),
        "session_token": base64.b64encode(b"jwt/" + jwt_bytes).decode("ascii"),
    }


def _strict_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise IssuerError("JSON contains duplicate fields")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise IssuerError("Source run response is invalid")


class _NoRedirect(urllib_request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def fetch_github_json(path, token=None, opener=None):
    allowed_repositories = {entry[0] for entry in SOURCE_RELEASES.values()}
    allowed_path = False
    if isinstance(path, str):
        for repository in allowed_repositories:
            prefix = f"/repos/{repository}/"
            endpoint = path.removeprefix(prefix) if path.startswith(prefix) else None
            if endpoint is None:
                continue
            if endpoint.startswith("actions/runs/"):
                run_part = endpoint.removeprefix("actions/runs/")
                allowed_path = bool(_RUN_ID.fullmatch(run_part.removesuffix("/artifacts")))
            elif endpoint.startswith("git/ref/tags/"):
                allowed_path = bool(_TAG.fullmatch(endpoint.removeprefix("git/ref/tags/")))
            elif endpoint.startswith("git/tags/"):
                allowed_path = bool(_SHA.fullmatch(endpoint.removeprefix("git/tags/")))
            break
    if not allowed_path:
        raise IssuerError("Source run request is invalid")
    url = f"https://{GITHUB_API_HOST}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": GITHUB_API_VERSION,
    }
    if token:
        if not isinstance(token, str):
            raise IssuerError("Source run request is invalid")
        headers["Authorization"] = f"Bearer {token}"
    try:
        request = urllib_request.Request(url, headers=headers, method="GET")
        client = opener if opener is not None else urllib_request.build_opener(_NoRedirect())
        response = client.open(request, timeout=GITHUB_TIMEOUT_SECONDS)
        try:
            if getattr(response, "status", 200) != 200:
                raise IssuerError("Source run lookup failed")
            body = response.read(MAX_GITHUB_RESPONSE_BYTES + 1)
        finally:
            response.close()
        if not isinstance(body, bytes):
            raise IssuerError("Source run response is invalid")
        if len(body) > MAX_GITHUB_RESPONSE_BYTES:
            raise IssuerError("Source run response exceeds the size limit")
        result = json.loads(body.decode("utf-8"), object_pairs_hook=_strict_object,
                            parse_constant=_reject_json_constant)
    except IssuerError:
        raise
    except HTTPError as error:
        if error.fp is not None:
            error.close()
        raise IssuerError("Source run lookup failed") from None
    except (URLError, TimeoutError, OSError, UnicodeError, ValueError):
        raise IssuerError("Source run lookup failed") from None
    if not isinstance(result, dict):
        raise IssuerError("Source run response is invalid")
    return result


def fetch_source_run(repository, run_id, token=None, opener=None):
    return fetch_github_json(f"/repos/{repository}/actions/runs/{run_id}", token, opener)


def _version_from_tag(tag):
    if not isinstance(tag, str):
        raise IssuerError("Source run provenance is invalid")
    match = _TAG.fullmatch(tag)
    if not match:
        raise IssuerError("Source run provenance is invalid")
    version = ".".join(match.group(index) for index in (1, 2, 3))
    if match.group(4):
        version += f"-rc.{match.group(4)}"
    return version


def verify_source_run(descriptor, package_format=FORMAT, channel=None, fetcher=None, token=None):
    validated = validate_descriptor(descriptor, package_format, channel)
    repository, caller_workflow, contract_workflow, _ = SOURCE_RELEASES[validated["package_id"]]
    def get_json(path):
        try:
            result = fetcher(path, token) if fetcher is not None else fetch_github_json(path, token)
        except IssuerError:
            raise
        except Exception:
            raise IssuerError("Source run lookup failed") from None
        if not isinstance(result, dict):
            raise IssuerError("Source run response is invalid")
        return result

    try:
        run = get_json(f"/repos/{repository}/actions/runs/{validated['source_run_id']}")
    except IssuerError:
        raise
    repository_info = run.get("repository")
    if (not isinstance(repository_info, dict) or repository_info.get("full_name") != repository
            or type(run.get("id")) is not int or run["id"] != int(validated["source_run_id"])
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or not isinstance(run.get("head_sha"), str)
            or not _SHA.fullmatch(run["head_sha"])
            or run["head_sha"].lower() != validated["git_sha"]
            or run.get("event") not in ALLOWED_SOURCE_EVENTS):
        raise IssuerError("Source run provenance is invalid")
    head_branch = run.get("head_branch")
    version = _version_from_tag(head_branch)
    tag_ref = f"refs/tags/{head_branch}"
    if version != validated["version"] or run.get("path") != caller_workflow:
        raise IssuerError("Source run version is invalid")
    attempt = run.get("run_attempt")
    if type(attempt) is not int or attempt < 1 or attempt != validated["source_run_attempt"]:
        raise IssuerError("Source run attempt is invalid")
    if caller_workflow != contract_workflow:
        referenced = run.get("referenced_workflows")
        expected_reusable_path = f"{repository}/{contract_workflow}"
        matches = (isinstance(referenced, list) and any(
            isinstance(item, dict)
            and isinstance(item.get("path"), str)
            and item["path"] == f"{expected_reusable_path}@{validated['git_sha']}"
            and isinstance(item.get("sha"), str)
            and _SHA.fullmatch(item["sha"])
            and item["sha"].lower() == validated["git_sha"]
            and item.get("ref") == tag_ref
            for item in referenced
        ))
        if not matches:
            raise IssuerError("Source reusable workflow provenance is invalid")

    tag_path = f"/repos/{repository}/git/ref/tags/{head_branch}"
    ref = get_json(tag_path)
    tag_object = ref.get("object")
    if ref.get("ref") != tag_ref or not isinstance(tag_object, dict):
        raise IssuerError("Source tag provenance is invalid")
    object_type, object_sha = tag_object.get("type"), tag_object.get("sha")
    if not isinstance(object_sha, str) or not _SHA.fullmatch(object_sha):
        raise IssuerError("Source tag provenance is invalid")
    if object_type == "tag":
        tag_object = get_json(f"/repos/{repository}/git/tags/{object_sha}").get("object")
        if not isinstance(tag_object, dict) or tag_object.get("type") != "commit":
            raise IssuerError("Source tag provenance is invalid")
        object_sha = tag_object.get("sha")
    elif object_type != "commit":
        raise IssuerError("Source tag provenance is invalid")
    if (not isinstance(object_sha, str) or not _SHA.fullmatch(object_sha)
            or object_sha.lower() != validated["git_sha"]):
        raise IssuerError("Source tag provenance is invalid")
    return validated


def build_envelope(binding, descriptor, credentials, now=None):
    validated = validate_envelope_descriptor(descriptor, FORMAT, binding.channel)
    issued_at = int(time.time() if now is None else now)
    payload = validate_credentials(credentials, binding.channel, now=issued_at)
    return {
        "version": 1,
        "kind": "r2-temporary-credentials",
        "binding": binding.as_dict(),
        "descriptor": validated,
        "iat": issued_at,
        "exp": issued_at + MAX_ENVELOPE_TTL_SECONDS,
        "nonce": secrets.token_urlsafe(24),
        "payload": payload,
    }


def validate_credentials(credentials, channel, now=None):
    keys = {"bucket", "prefix", "permission", "expires_at", "access_key_id",
            "secret_access_key", "session_token"}
    if not isinstance(credentials, dict) or set(credentials) != keys:
        raise IssuerError("Credential payload is invalid")
    if credentials["bucket"] != BUCKET or credentials["prefix"] != prefix_for(channel):
        raise IssuerError("Credential scope is invalid")
    if credentials["permission"] != "object-read-write":
        raise IssuerError("Credential permission is invalid")
    if (not isinstance(credentials["access_key_id"], str) or not _ACCESS_ID.fullmatch(credentials["access_key_id"])
            or not isinstance(credentials["secret_access_key"], str) or not _PARENT_SECRET.fullmatch(credentials["secret_access_key"])
            or not isinstance(credentials["session_token"], str) or not 1 <= len(credentials["session_token"]) <= 4096):
        raise IssuerError("Credential material is invalid")
    expires_at = credentials["expires_at"]
    current = int(time.time() if now is None else now)
    if type(expires_at) is not int or expires_at <= current or expires_at > current + MAX_TTL_SECONDS:
        raise IssuerError("Credential expiry is invalid")
    return credentials


def validate_envelope(envelope, binding, package_format=FORMAT, now=None):
    fields = {"version", "kind", "binding", "descriptor", "iat", "exp", "nonce", "payload"}
    if not isinstance(envelope, dict) or set(envelope) != fields:
        raise IssuerError("Envelope shape is invalid")
    if (type(envelope["version"]) is not int or envelope["version"] != 1
            or envelope["kind"] != "r2-temporary-credentials"
            or envelope["binding"] != binding.as_dict()):
        raise IssuerError("Envelope binding is invalid")
    issued_at, expires_at = envelope["iat"], envelope["exp"]
    current = int(time.time() if now is None else now)
    if (type(issued_at) is not int or type(expires_at) is not int
            or expires_at != issued_at + MAX_ENVELOPE_TTL_SECONDS
            or issued_at > current + transport.CLOCK_SKEW_SECONDS or expires_at <= current):
        raise IssuerError("Envelope is expired or not yet valid")
    if not isinstance(envelope["nonce"], str) or not re.fullmatch(r"[A-Za-z0-9_-]{32}", envelope["nonce"]):
        raise IssuerError("Envelope is invalid")
    validate_envelope_descriptor(envelope["descriptor"], package_format, binding.channel)
    validate_credentials(envelope["payload"], binding.channel, now=current)
    return envelope


def encode_envelope(envelope):
    try:
        data = json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    except (TypeError, ValueError):
        raise IssuerError("Envelope cannot be encoded") from None
    if len(data) > MAX_PLAINTEXT_BYTES:
        raise IssuerError("Envelope exceeds the size limit")
    return data


def decode_envelope(data):
    if not isinstance(data, bytes) or not data or len(data) > MAX_PLAINTEXT_BYTES:
        raise IssuerError("Envelope size is invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=_strict_object)
    except (UnicodeError, json.JSONDecodeError, IssuerError):
        raise IssuerError("Envelope is invalid") from None


def ensure_consumer_has_no_parent(environ=None):
    environ = os.environ if environ is None else environ
    if PARENT_ID_ENV in environ or PARENT_SECRET_ENV in environ:
        raise IssuerError("Consumer must not receive parent credentials")


def write_private_file(path, data):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(os.fspath(path), flags, 0o600)
        with os.fdopen(descriptor, "wb") as output:
            descriptor = None
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except OSError:
        if descriptor is not None:
            os.close(descriptor)
        raise IssuerError("Private file could not be created") from None


def read_private_file(path, max_bytes=MAX_PLAINTEXT_BYTES):
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > max_bytes:
            raise IssuerError("Private file is invalid")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as source:
            data = source.read(max_bytes + 1)
    except OSError:
        raise IssuerError("Private file is unavailable") from None
    if not data or len(data) > max_bytes:
        raise IssuerError("Private file size is invalid")
    return data


def sigv4_self_test(credentials, channel, now=None):
    validate_credentials(credentials, channel, now=now)
    stamp = datetime.fromtimestamp(int(time.time() if now is None else now), timezone.utc)
    amz_date = stamp.strftime("%Y%m%dT%H%M%SZ")
    date = stamp.strftime("%Y%m%d")
    region, service = "auto", "s3"
    host = "synthetic.r2.cloudflarestorage.com"
    path = f"/{BUCKET}/{prefix_for(channel)}self-test"
    body_hash = hashlib.sha256(b"t07 synthetic PUT shape").hexdigest()
    headers = {
        "host": host,
        "x-amz-content-sha256": body_hash,
        "x-amz-date": amz_date,
        "x-amz-security-token": credentials["session_token"],
    }
    signed_headers = ";".join(sorted(headers))
    canonical_headers = "".join(f"{name}:{headers[name]}\n" for name in sorted(headers))
    canonical_request = "\n".join(("PUT", path, "", canonical_headers, signed_headers, body_hash))
    scope = f"{date}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope,
                                 hashlib.sha256(canonical_request.encode()).hexdigest()))
    def sign(key, value):
        return hmac.new(key, value.encode(), hashlib.sha256).digest()
    key = sign(("AWS4" + credentials["secret_access_key"]).encode(), date)
    key = sign(key, region)
    key = sign(key, service)
    key = sign(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return {"method": "PUT", "path": path, "signed_headers": signed_headers,
            "authorization": f"AWS4-HMAC-SHA256 Credential={credentials['access_key_id']}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"}


def issue_credentials(channel, descriptor, environ=None, ttl=DEFAULT_TTL_SECONDS, now=None,
                     fetcher=None):
    environ = os.environ if environ is None else environ
    verified = verify_source_run(descriptor, FORMAT, channel, fetcher=fetcher,
                                 token=environ.get("GITHUB_TOKEN"))
    try:
        key_id = environ[PARENT_ID_ENV]
        parent_secret = environ[PARENT_SECRET_ENV]
    except KeyError:
        raise IssuerError("Parent credentials are unavailable") from None
    return derive_credentials(key_id, parent_secret, FORMAT, channel, ttl, now), verified


def run_cli(argv=None, environ=None, fetcher=None):
    environ = os.environ if environ is None else environ
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    issue = commands.add_parser("issue")
    issue.add_argument("--channel", required=True, choices=CHANNELS)
    issue.add_argument("--package-id", required=True)
    issue.add_argument("--version", required=True)
    issue.add_argument("--git-sha", required=True)
    issue.add_argument("--source-run-id", required=True)
    issue.add_argument("--source-run-attempt", required=True, type=int)
    issue.add_argument("--output", required=True)
    issue.add_argument("--ttl", type=int, default=DEFAULT_TTL_SECONDS)
    consume = commands.add_parser("consume")
    consume.add_argument("--channel", required=True, choices=CHANNELS)
    consume.add_argument("--input", required=True)
    consume.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        binding = transport.binding_from_environment(args.channel, environ)
        if binding.repository != REPOSITORY:
            raise IssuerError("Repository is not authorized")
        key = environ.get(TRANSPORT_KEY_ENV)
        transport._transport_key(key)
        if args.command == "issue":
            descriptor = {"format": FORMAT, "channel": args.channel, "package_id": args.package_id,
                          "version": args.version, "git_sha": args.git_sha,
                          "source_run_id": args.source_run_id,
                          "source_run_attempt": args.source_run_attempt}
            credentials, descriptor = issue_credentials(args.channel, descriptor, environ,
                                                        args.ttl, fetcher=fetcher)
            envelope = build_envelope(binding, descriptor, credentials)
            ciphertext = transport.encrypt_envelope(envelope, key)
            transport.write_capsule(args.output, ciphertext)
        else:
            ensure_consumer_has_no_parent(environ)
            envelope = transport.decrypt_envelope(transport.read_capsule(args.input), key)
            validate_envelope(envelope, binding, FORMAT)
            write_private_file(args.output, encode_envelope(envelope["payload"]))
            sigv4_self_test(envelope["payload"], args.channel)
        return 0
    except (IssuerError, transport.TransportError) as error:
        print(f"credential issuer failed; {error}", file=sys.stderr)
        return 1
    except (OSError, ValueError):
        print("credential issuer failed; details suppressed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(run_cli())

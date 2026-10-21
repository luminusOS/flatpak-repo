import hashlib
import json
from pathlib import Path
import re
import ssl
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "hosting.json"
MAX_CONFIG_BYTES = 1024 * 1024
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT = 10
FORMAT = "flatpak"
DOMAIN = "flatpak.luminusos.org"
EXPECTED_BUCKET = "luminus-flatpak"
EXPECTED_FIELDS = {
    "schema_version", "format", "bucket", "domain", "storage_class",
    "public_dev_url", "min_tls", "channels", "cache", "state",
}
EXPECTED_CACHE_FIELDS = {
    "immutable_ttl_seconds", "mutable_cache_control", "negative_cache_ttl",
}
CAPTURE_HEADERS = ("cache-control", "cf-cache-status", "etag", "cf-ray", "content-type")
NONCE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")


def validate_config(document):
    if not isinstance(document, dict) or set(document) != EXPECTED_FIELDS:
        raise ValueError("hosting config fields do not match")
    if type(document["schema_version"]) is not int or document["schema_version"] != 1:
        raise ValueError("unsupported schema version")
    if document["format"] != FORMAT or document["bucket"] != EXPECTED_BUCKET:
        raise ValueError("hosting format or bucket does not match this repository")
    if document["domain"] != DOMAIN or document["storage_class"] != "Standard":
        raise ValueError("hosting domain or storage class does not match")
    if document["public_dev_url"] is not False or document["min_tls"] != "1.2":
        raise ValueError("hosting public access or TLS policy does not match")
    if document["channels"] != ["stable", "testing"]:
        raise ValueError("hosting channels do not match")
    cache = document["cache"]
    if not isinstance(cache, dict) or set(cache) != EXPECTED_CACHE_FIELDS:
        raise ValueError("hosting cache fields do not match")
    if type(cache["immutable_ttl_seconds"]) is not int or cache["immutable_ttl_seconds"] != 31536000:
        raise ValueError("immutable cache TTL does not match")
    if cache["mutable_cache_control"] != "no-store":
        raise ValueError("mutable cache policy does not match")
    if type(cache["negative_cache_ttl"]) is not int or cache["negative_cache_ttl"] != -1:
        raise ValueError("negative cache TTL does not match")
    if document["state"] != "planned":
        raise ValueError("hosting config must describe planned resources")
    return document


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def load_config(path=CONFIG_PATH):
    with open(path, "rb") as config_file:
        content = config_file.read(MAX_CONFIG_BYTES + 1)
    if len(content) > MAX_CONFIG_BYTES:
        raise ValueError("hosting config exceeds the size limit")
    document = json.loads(content.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
    return validate_config(document)


def validate_probe_url(url):
    if not isinstance(url, str) or len(url) > 2048 or any(char.isspace() for char in url):
        raise ValueError("probe URL is invalid")
    if any(char in url for char in ("%", "\\", "\r", "\n", "\0")):
        raise ValueError("probe URL is invalid")
    try:
        parsed = urlsplit(url)
        if parsed.scheme != "https" or parsed.netloc != DOMAIN or parsed.hostname != DOMAIN:
            raise ValueError("probe URL must use this repository's HTTPS host")
        if parsed.username is not None or parsed.password is not None or parsed.port is not None:
            raise ValueError("probe URL must not include credentials or a port")
    except ValueError as error:
        raise ValueError("probe URL is invalid") from error
    if "?" in url or "#" in url or parsed.query or parsed.fragment or not parsed.path.startswith("/") or "//" in parsed.path:
        raise ValueError("probe URL must not include query, fragment, or ambiguous paths")
    parts = parsed.path.split("/")[1:]
    if any(part in ("", ".", "..") for part in parts):
        raise ValueError("probe path is invalid")
    channel = parts[0] if parts else ""
    if channel not in ("stable", "testing"):
        raise ValueError("probe path is outside the test namespace")
    if FORMAT == "flatpak":
        valid = (
            len(parts) == 5 and parts[1:3] == ["objects", "_t05"]
            and NONCE.fullmatch(parts[3])
            and parts[4] in ("immutable.bin", "detached.commitmeta")
        ) or (
            len(parts) == 4 and parts[1] == "_t05"
            and NONCE.fullmatch(parts[2]) and parts[3] == "metadata.txt"
        )
    if not valid:
        raise ValueError("probe path is outside the owned test namespace")
    return url


def classify_path(path):
    parts = path.split("/")
    if (
        len(parts) >= 4 and parts[0] == "" and parts[1] in ("stable", "testing")
        and parts[2] == "objects" and parts[-1] and not path.endswith(".commitmeta")
    ):
        return {"classification": "immutable", "cache_control": "public, max-age=31536000, immutable"}
    return {"classification": "mutable", "cache_control": "no-store"}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


def _response_record(response, read_body):
    body = bytearray()
    if read_body:
        while len(body) <= MAX_RESPONSE_BYTES:
            chunk = response.read(min(8192, MAX_RESPONSE_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        if len(body) > MAX_RESPONSE_BYTES:
            raise ValueError("probe response exceeds the 64 KiB limit")
    headers = {name: response.headers.get(name) for name in CAPTURE_HEADERS if response.headers.get(name) is not None}
    record = {"status": response.status, "headers": headers}
    if read_body:
        record["bytes_read"] = len(body)
        record["sha256"] = hashlib.sha256(body).hexdigest()
    return record


def _request(opener, url, method):
    request = Request(url, method=method, headers={"User-Agent": "LuminusOS-T05-probe/1"})
    try:
        response = opener.open(request, timeout=REQUEST_TIMEOUT)
    except HTTPError as error:
        response = error
    with response:
        return _response_record(response, method == "GET")


def probe(url, opener=None):
    validate_probe_url(url)
    if opener is None:
        opener = build_opener(_NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
    return {
        "requests": 2,
        "url": url,
        "expected_policy": classify_path(urlsplit(url).path),
        "head": _request(opener, url, "HEAD"),
        "get": _request(opener, url, "GET"),
    }


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(description="Validate hosting policy or inspect an owned HTTPS probe")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    probe_parser = subparsers.add_parser("probe")
    probe_parser.add_argument("url")
    args = parser.parse_args(argv)
    try:
        load_config()
        if args.command == "validate":
            print("hosting config valid")
        else:
            print(json.dumps(probe(args.url), sort_keys=True))
    except Exception as error:
        if args.command == "validate":
            print("hosting config invalid", file=sys.stderr)
        else:
            print(f"hosting probe failed: {type(error).__name__}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

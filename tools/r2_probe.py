#!/usr/bin/env python3
"""Bounded live proof of the publisher's R2 temporary credential scope."""

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import time
from urllib.parse import quote, urlencode
import xml.etree.ElementTree as ET

ACCOUNT_ID = "89e6fc75aed6d04cd84a0c7d11a5594e"
FORMAT = "flatpak"
BUCKET = "luminus-flatpak"
OTHER_BUCKET = "luminus-rpm"
CHANNELS = ("stable", "testing")
REGION = "auto"
SERVICE = "s3"
TIMEOUT_SECONDS = 12
MAX_RESPONSE_BYTES = 1024 * 1024
MARKER = b"luminus-t07-live-probe"
DENIED = "HTTP 403"

EXPECTATIONS = {
    "put_allowed": ("PUT", "success"), "get_allowed": ("GET", "success"),
    "head_allowed": ("HEAD", "success"), "list_own_prefix_allowed": ("GET", "success"),
    "multipart_create_allowed": ("POST", "success"), "multipart_upload_part_allowed": ("PUT", "success"),
    "multipart_complete_allowed": ("POST", "success"), "copy_within_prefix_allowed": ("PUT", "success"),
    "copy_integrity_allowed": ("GET", "success"),
    "copy_destination_reservation_allowed": ("PUT", "success"),
    "multipart_destination_reservation_allowed": ("PUT", "success"),
    "delete_allowed": ("DELETE", "success"), "put_collision_guard": ("PUT", "HTTP 412"),
    "put_other_channel_denied": ("PUT", DENIED),
    "put_root_denied": ("PUT", DENIED),
    "get_other_channel_denied": ("GET", DENIED), "head_other_channel_denied": ("HEAD", DENIED),
    "list_other_channel_denied": ("GET", DENIED), "list_root_denied": ("GET", DENIED),
    "list_multipart_uploads_denied": ("GET", DENIED), "copy_from_other_channel_denied": ("PUT", DENIED),
    "delete_other_channel_denied": ("DELETE", DENIED), "put_other_bucket_denied": ("PUT", DENIED),
    "list_buckets_denied": ("GET", DENIED), "list_bucket_level_denied": ("GET", DENIED),
    "cleanup_list_empty": ("GET", "empty"), "multipart_cleanup_list_empty": ("GET", "empty"),
    "expiry_put_denied": ("PUT", "HTTP 403"),
    "expiry_next_put_denied": ("PUT", "HTTP 403"), "expiry_precondition_cleanup": ("DELETE", "success"),
}


class ProbeError(Exception):
    pass


class S3Response:
    def __init__(self, status, body=b"", headers=None, code=None):
        self.status, self.body, self.headers = status, body, headers or {}
        self.code = code or _xml(self).get("Code") or ("AccessDenied" if status == 403 else None)


class SigV4Client:
    def __init__(self, credentials, connection_factory=None, region=REGION, service=SERVICE, host=None):
        self.credentials = credentials
        self.host = host or f"{ACCOUNT_ID}.r2.cloudflarestorage.com"
        self.region = region
        self.service = service
        self.connection_factory = connection_factory or self._connection

    @staticmethod
    def _connection(host, timeout):
        return http.client.HTTPSConnection(host, timeout=timeout)

    def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
        if bucket is not None and bucket not in (BUCKET, OTHER_BUCKET):
            raise ProbeError("bucket outside fixed allowlist")
        path = "/" + quote(bucket, safe="-_") if bucket else ""
        if key is not None:
            path += ("/" if path else "/") + quote(key, safe="/-_.~")
        elif not path:
            path = "/"
        query_string = urlencode(sorted((query or {}).items()), quote_via=quote, safe="-_.~")
        canonical_query = query_string
        target = path + ("?" + query_string if query_string else "")
        now = datetime.now(timezone.utc)
        amz_date, date = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
        payload_hash = hashlib.sha256(body).hexdigest()
        signed = {"host": self.host, "x-amz-content-sha256": payload_hash, "x-amz-date": amz_date}
        if self.credentials.get("session_token"):
            signed["x-amz-security-token"] = self.credentials["session_token"]
        for name, value in (headers or {}).items():
            signed[name.lower()] = " ".join(value.strip().split())
        names = ";".join(sorted(signed))
        canonical_headers = "".join(f"{name}:{signed[name]}\n" for name in sorted(signed))
        canonical_request = "\n".join((method, path, canonical_query, canonical_headers, names, payload_hash))
        scope = f"{date}/{self.region}/{self.service}/aws4_request"
        to_sign = "\n".join(("AWS4-HMAC-SHA256", amz_date, scope,
                              hashlib.sha256(canonical_request.encode()).hexdigest()))
        def sign(key_bytes, text):
            return hmac.new(key_bytes, text.encode(), hashlib.sha256).digest()
        signing_key = sign(("AWS4" + self.credentials["secret_access_key"]).encode(), date)
        for part in (self.region, self.service, "aws4_request"):
            signing_key = sign(signing_key, part)
        signature = hmac.new(signing_key, to_sign.encode(), hashlib.sha256).hexdigest()
        auth = (f"AWS4-HMAC-SHA256 Credential={self.credentials['access_key_id']}/{scope}, "
                f"SignedHeaders={names}, Signature={signature}")
        request_headers = {"Host": self.host, "x-amz-date": amz_date,
                           "x-amz-content-sha256": payload_hash,
                           "Authorization": auth, "Content-Length": str(len(body))}
        if self.credentials.get("session_token"):
            request_headers["x-amz-security-token"] = self.credentials["session_token"]
        request_headers.update(headers or {})
        connection = self.connection_factory(self.host, TIMEOUT_SECONDS)
        try:
            connection.request(method, target, body=body, headers=request_headers)
            response = connection.getresponse()
            data = response.read(MAX_RESPONSE_BYTES + 1)
            if len(data) > MAX_RESPONSE_BYTES:
                raise ProbeError("R2 response exceeds size limit")
            headers = dict(response.getheaders())
            result = S3Response(response.status, data, headers)
            if response.status >= 400:
                code = _xml(result).get("Code")
                result.code = "403" if method == "HEAD" and response.status == 403 and not data else code or "Unknown"
            return result
        finally:
            connection.close()


def _xml(response):
    if not response.body:
        return {}
    try:
        root = ET.fromstring(response.body)
        return {"_root": root.tag.rsplit("}", 1)[-1],
                **{child.tag.rsplit("}", 1)[-1]: child.text or "" for child in root}}
    except ET.ParseError:
        return {}


def _has_listed_contents(body):
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return False
    return any(element.tag.rsplit("}", 1)[-1] == "Contents" for element in root.iter())


def _is_empty_list(response):
    try:
        root = ET.fromstring(response.body)
    except ET.ParseError:
        return False
    return (root.tag.rsplit("}", 1)[-1] == "ListBucketResult"
            and not any(element.tag.rsplit("}", 1)[-1] == "Contents" for element in root.iter()))


def _is_empty_multipart_list(response, prefix):
    try:
        root = ET.fromstring(response.body)
    except ET.ParseError:
        return False
    if root.tag.rsplit("}", 1)[-1] != "ListMultipartUploadsResult":
        return False
    if any(element.tag.rsplit("}", 1)[-1] == "IsTruncated" and element.text == "true"
           for element in root.iter()):
        return False
    return not any(element.tag.rsplit("}", 1)[-1] == "Upload"
                   and any(child.tag.rsplit("}", 1)[-1] == "Key" and (child.text or "").startswith(prefix)
                           for child in element)
                   for element in root.iter())


EXPIRED_WRITE_CODES = ("403", "AccessDenied", "ExpiredToken", "SignatureDoesNotMatch")


def _key(prefix, suffix):
    return prefix + suffix


def _expect(report, name, response, success=False, empty=False, body_marker=None, root_name=None):
    expected = EXPECTATIONS[name][1]
    denied = response.status == 403 and response.code in ("AccessDenied", "403", "ExpiredToken")
    root = _xml(response)
    valid_xml = root_name is None or root.get("_root") == root_name
    passed = (response.status in (200, 201, 204) and response.code is None and valid_xml
              and root.get("_root") != "Error"
              and (body_marker is None or response.body == body_marker)) if success else (
        response.status == 200 and response.code is None and _is_empty_list(response) if empty else denied)
    report.append({"name": name, "expected": expected, "observed": response.status, "pass": passed})
    return passed


def _record(report, name, action, success=False, empty=False, body_marker=None, root_name=None):
    try:
        response = action()
    except Exception:
        report.append({"name": name, "expected": EXPECTATIONS[name][1], "observed": "error", "pass": False})
        return None
    _expect(report, name, response, success=success, empty=empty, body_marker=body_marker, root_name=root_name)
    return response


def probe(credentials, run_id, attempt, channel, expiry_check=False, client_factory=SigV4Client, sleep=time.sleep):
    if channel not in CHANNELS or not re.fullmatch(r"[0-9]+", str(run_id)) or not re.fullmatch(r"[0-9]+", str(attempt)):
        raise ProbeError("invalid workflow identity")
    if credentials.get("bucket") != BUCKET or credentials.get("prefix") != channel + "/":
        raise ProbeError("credential scope mismatch")
    if type(credentials.get("expires_at")) is not int:
        raise ProbeError("credential expiry missing")
    prefix = f"{channel}/_t07-probe/{run_id}-{attempt}/"
    other = "testing" if channel == "stable" else "stable"
    nonce = secrets.token_hex(16)
    own = _key(prefix, "object-" + nonce)
    copied, multipart = (_key(prefix, suffix) for suffix in ("copy", "multipart"))
    foreign = f"{other}/_t07-probe/{run_id}-{attempt}/absent-{nonce}"
    report = []
    created = set()
    upload_id = None
    expiry_phase_started = False
    expiry_residue = []
    if expiry_check:
        remaining = credentials["expires_at"] - int(time.time())
        if remaining < 120 or remaining > 300:
            return {"format": FORMAT, "bucket": BUCKET, "channel": channel, "run_id": str(run_id),
                    "attempt": str(attempt), "expiry_check": True,
                    "expiry_result": "expired or nearly expired before probe; retry",
                    "expiry_residue": [], "residue": [], "operations": [], "passed": False}
    client = client_factory(credentials)

    def negative_put(name, bucket, key):
        response = _record(report, name, lambda: client._request(
            "PUT", bucket, key, body=MARKER, headers={"If-None-Match": "*"}))
        if response and response.status in (200, 201, 204):
            created.add((bucket, key))
            report[-1]["pass"] = False
        return response

    def cleanup_objects():
        for name in ("object_cleanup", "object_cleanup_retry"):
            for bucket, key in sorted(created):
                try:
                    response = client._request("DELETE", bucket, key)
                    removed = response.status in (200, 204)
                    report.append({"name": name, "expected": "success", "observed": response.status, "pass": removed})
                    if removed:
                        created.discard((bucket, key))
                except Exception:
                    report.append({"name": name, "expected": "success", "observed": "error", "pass": False})

    def final_inventory():
        final = _record(report, "cleanup_list_empty", lambda: client._request("GET", BUCKET,
            query={"list-type": "2", "prefix": prefix, "max-keys": "1000"}), empty=True)
        if final and final.status == 200 and _has_listed_contents(final.body):
            report[-1]["pass"] = False
        multipart_final = _record(report, "multipart_cleanup_list_empty", lambda: client._request(
            "GET", BUCKET, query={"uploads": "", "prefix": prefix, "max-uploads": "1000"}))
        if multipart_final:
            report[-1]["pass"] = multipart_final.status == 200 and _is_empty_multipart_list(multipart_final, prefix)

    def expired_write(name, key):
        try:
            response = client._request("PUT", BUCKET, key, body=MARKER, headers={"If-None-Match": "*"})
            passed = response.status == 403 and response.code in EXPIRED_WRITE_CODES
            report.append({"name": name, "expected": EXPECTATIONS[name][1], "observed": response.status, "pass": passed})
            if 200 <= response.status < 300:
                expiry_residue.append({"bucket": BUCKET, "key": key})
                report[-1]["pass"] = False
        except Exception:
            report.append({"name": name, "expected": EXPECTATIONS[name][1], "observed": "error", "pass": False})

    def collision_guard():
        try:
            response = client._request("PUT", BUCKET, own, body=MARKER, headers={"If-None-Match": "*"})
            passed = response.status == 412
            report.append({"name": "put_collision_guard", "expected": EXPECTATIONS["put_collision_guard"][1],
                           "observed": response.status, "pass": passed})
            return passed
        except Exception:
            report.append({"name": "put_collision_guard", "expected": EXPECTATIONS["put_collision_guard"][1],
                           "observed": "error", "pass": False})
            return False

    try:
        if expiry_check:
            before = _record(report, "put_allowed", lambda: client._request("PUT", BUCKET, own, body=MARKER,
                headers={"If-None-Match": "*"}), success=True)
            if not before or before.status not in (200, 201, 204):
                report.append({"name": "expiry_precondition_cleanup", "expected": "success", "observed": "skipped", "pass": False})
                raise ProbeError("conditional write guard unavailable")
            created.add((BUCKET, own))
            if not collision_guard():
                raise ProbeError("conditional write guard failed")
            try:
                removed = client._request("DELETE", BUCKET, own)
                removed_ok = removed.status in (200, 204)
                report.append({"name": "expiry_precondition_cleanup", "expected": "success", "observed": removed.status, "pass": removed_ok})
                if removed_ok:
                    created.discard((BUCKET, own))
            except Exception:
                report.append({"name": "expiry_precondition_cleanup", "expected": "success", "observed": "error", "pass": False})
            cleanup_objects()
            final_inventory()
            expiry_phase_started = True
            sleep(max(0, credentials["expires_at"] + 2 - time.time()))
            expired_write("expiry_put_denied", _key(prefix, "expired-" + nonce))
            expired_write("expiry_next_put_denied", _key(prefix, "next-" + nonce))
        else:
            own_response = _record(report, "put_allowed", lambda: client._request("PUT", BUCKET, own, body=MARKER,
                headers={"If-None-Match": "*"}), success=True)
            if own_response and own_response.status in (200, 201, 204):
                created.add((BUCKET, own))
            if not own_response or own_response.status not in (200, 201, 204) or not collision_guard():
                raise ProbeError("conditional write guard failed")
            _record(report, "get_allowed", lambda: client._request("GET", BUCKET, own), success=True, body_marker=MARKER)
            _record(report, "head_allowed", lambda: client._request("HEAD", BUCKET, own), success=True)
            _record(report, "list_own_prefix_allowed", lambda: client._request("GET", BUCKET, query={"list-type": "2", "prefix": prefix}), success=True)
            copied_reservation = _record(report, "copy_destination_reservation_allowed", lambda: client._request("PUT", BUCKET, copied,
                body=b"reservation", headers={"If-None-Match": "*"}), success=True)
            if copied_reservation and copied_reservation.status in (200, 201, 204):
                created.add((BUCKET, copied))
            multipart_reservation = _record(report, "multipart_destination_reservation_allowed", lambda: client._request("PUT", BUCKET, multipart,
                body=b"reservation", headers={"If-None-Match": "*"}), success=True)
            if multipart_reservation and multipart_reservation.status in (200, 201, 204):
                created.add((BUCKET, multipart))
            started = (_record(report, "multipart_create_allowed", lambda: client._request("POST", BUCKET, multipart, query={"uploads": ""}), success=True)
                       if (BUCKET, multipart) in created else None)
            if (BUCKET, multipart) not in created:
                report.append({"name": "multipart_create_allowed", "expected": "success", "observed": "skipped", "pass": False})
            if started and started.status == 200:
                upload_id = _xml(started).get("UploadId")
                if not upload_id:
                    report[-1]["pass"] = False
            if upload_id:
                part = _record(report, "multipart_upload_part_allowed", lambda: client._request("PUT", BUCKET, multipart,
                    query={"partNumber": "1", "uploadId": upload_id}, body=MARKER), success=True)
                etag = next((v.strip('"') for k, v in (part.headers.items() if part else ()) if k.lower() == "etag"), "")
                if etag:
                    complete = ET.Element("CompleteMultipartUpload")
                    element = ET.SubElement(complete, "Part")
                    ET.SubElement(element, "PartNumber").text = "1"
                    ET.SubElement(element, "ETag").text = f'"{etag}"'
                    completed = _record(report, "multipart_complete_allowed", lambda: client._request("POST", BUCKET, multipart,
                        query={"uploadId": upload_id}, body=ET.tostring(complete)), success=True,
                        root_name="CompleteMultipartUploadResult")
                    if (completed and completed.status == 200 and completed.code is None
                            and _xml(completed).get("_root") == "CompleteMultipartUploadResult"):
                        upload_id = None
            copy_headers = {"x-amz-copy-source": f"/{BUCKET}/{quote(own, safe='/-_.~')}"}
            if (BUCKET, copied) in created and (BUCKET, own) in created:
                _record(report, "copy_within_prefix_allowed", lambda: client._request("PUT", BUCKET, copied, headers=copy_headers), success=True,
                        root_name="CopyObjectResult")
                _record(report, "copy_integrity_allowed", lambda: client._request("GET", BUCKET, copied), success=True, body_marker=MARKER)
            else:
                report.extend({"name": name, "expected": EXPECTATIONS[name][1], "observed": "skipped", "pass": False}
                              for name in ("copy_within_prefix_allowed", "copy_integrity_allowed"))
            cases = [
                ("put_other_channel_denied", lambda: negative_put("put_other_channel_denied", BUCKET, foreign)),
                ("put_root_denied", lambda: negative_put("put_root_denied", BUCKET,
                    f"_t07-probe/{run_id}-{attempt}/root-{nonce}")),
                ("get_other_channel_denied", lambda: client._request("GET", BUCKET, foreign)),
                ("head_other_channel_denied", lambda: client._request("HEAD", BUCKET, foreign)),
                ("list_other_channel_denied", lambda: client._request("GET", BUCKET, query={"list-type": "2", "prefix": other + "/"})),
                ("list_root_denied", lambda: client._request("GET", BUCKET, query={"list-type": "2"})),
                ("list_multipart_uploads_denied", lambda: client._request("GET", BUCKET, query={"uploads": ""})),
                ("copy_from_other_channel_denied", lambda: client._request("PUT", BUCKET, copied,
                    headers={"x-amz-copy-source": f"/{BUCKET}/{quote(foreign, safe='/-_.~')}"})),
                ("delete_other_channel_denied", lambda: client._request("DELETE", BUCKET, foreign)),
                ("put_other_bucket_denied", lambda: negative_put("put_other_bucket_denied", OTHER_BUCKET,
                    f"{channel}/_t07-probe/{run_id}-{attempt}/absent-{nonce}")),
                ("list_buckets_denied", lambda: client._request("GET")),
                ("list_bucket_level_denied", lambda: client._request("GET", BUCKET, query={"uploads": ""})),
            ]
            for name, action in cases:
                if name in ("put_other_channel_denied", "put_root_denied", "put_other_bucket_denied"):
                    action()
                else:
                    _record(report, name, action)
            if (BUCKET, own) in created:
                removed = _record(report, "delete_allowed", lambda: client._request("DELETE", BUCKET, own), success=True)
                if removed and removed.status in (200, 204):
                    created.discard((BUCKET, own))
            else:
                report.append({"name": "delete_allowed", "expected": "success", "observed": "skipped", "pass": False})
    except Exception:
        report.append({"name": "probe_internal", "expected": "success", "observed": "error", "pass": False})
    finally:
        if expiry_check and not expiry_phase_started:
            if time.time() < credentials["expires_at"]:
                cleanup_objects()
                final_inventory()
            else:
                report.append({"name": "cleanup_list_empty", "expected": "empty", "observed": "expired before listing", "pass": False})
                report.append({"name": "multipart_cleanup_list_empty", "expected": "empty", "observed": "expired before listing", "pass": False})
        if not expiry_check and upload_id:
            try:
                response = client._request("DELETE", BUCKET, multipart, query={"uploadId": upload_id})
                report.append({"name": "multipart_cleanup", "expected": "success", "observed": response.status, "pass": response.status == 204})
            except Exception:
                report.append({"name": "multipart_cleanup", "expected": "success", "observed": "error", "pass": False})
        if not expiry_check:
            cleanup_objects()
            final_inventory()
    expiry_confirmed = (not expiry_check or all(
        next((item["pass"] for item in report if item["name"] == name), False)
        for name in ("expiry_put_denied", "expiry_next_put_denied")))
    residue = [{"bucket": bucket, "key": key} for bucket, key in sorted(created)]
    return {"format": FORMAT, "bucket": BUCKET, "channel": channel, "run_id": str(run_id),
            "attempt": str(attempt), "expiry_check": expiry_check,
            "expiry_result": ("expired credential denied" if expiry_confirmed else "not confirmed")
            if expiry_check else "not requested",
            "expiry_residue": expiry_residue,
            "residue": residue,
            "operations": report,
            "passed": all(item["pass"] for item in report)}


def load_credentials(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or info.st_mode & 0o077 or info.st_size > 8192):
                raise ProbeError("credentials file invalid")
            value = json.loads(stream.read(8193))
    except Exception:
        raise ProbeError("credentials file unavailable") from None
    fields = {"bucket", "prefix", "permission", "expires_at", "access_key_id", "secret_access_key", "session_token"}
    if not isinstance(value, dict) or set(value) != fields or value["permission"] != "object-read-write":
        raise ProbeError("credential payload invalid")
    return value


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--credentials", required=True)
    parser.add_argument("--channel", required=True, choices=CHANNELS)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--expiry-check", action="store_true")
    args = parser.parse_args(argv)
    try:
        result = probe(load_credentials(args.credentials), args.run_id, args.attempt, args.channel, args.expiry_check)
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a", encoding="utf-8") as output:
                output.write("## T07 live R2 scope probe\n\n| Operation | Expected | Observed HTTP | Result |\n|---|---|---:|---|\n")
                for item in result["operations"]:
                    output.write(f"| {item['name']} | {item['expected']} | {item['observed']} | {'PASS' if item['pass'] else 'FAIL'} |\n")
        if result.get("expiry_result") == "expired or nearly expired before probe; retry":
            return 2
        return 0 if result["passed"] else 1
    except Exception:
        print(json.dumps({"format": FORMAT, "passed": False, "error": "sanitized probe failure"}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

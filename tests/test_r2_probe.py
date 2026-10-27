import importlib.util
import json
from pathlib import Path
import sys
import socket
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("r2_probe", ROOT / "tools" / "r2_probe.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


class FakeClient:
    def __init__(self, credentials, now=lambda: 1000):
        self.credentials = credentials
        self.now = now
        self.objects = {}
        self.uploads = {}
        self.calls = []

    def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
        query = query or {}
        self.calls.append((method, bucket, key, query.copy(), self.now()))
        if self.now() >= self.credentials["expires_at"]:
            return probe.S3Response(403)
        if bucket is None:
            return probe.S3Response(403)
        if bucket != probe.BUCKET or (key is not None and not key.startswith(self.credentials["prefix"])):
            return probe.S3Response(403)
        if key and "/../" in key:
            return probe.S3Response(403)
        if "uploads" in query and method == "GET":
            if "prefix" in query:
                uploads = b"".join(b"<Upload><Key>" + value["key"].encode() + b"</Key></Upload>"
                                    for value in self.uploads.values()
                                    if value["key"].startswith(query["prefix"]))
                return probe.S3Response(200, b"<ListMultipartUploadsResult>" + uploads + b"</ListMultipartUploadsResult>")
            return probe.S3Response(403)
        if "list-type" in query:
            if query.get("prefix", "") not in (self.credentials["prefix"] + "_scope-probe/100-1/",):
                return probe.S3Response(403)
            contents = b"<Contents/>" if any(k.startswith(query["prefix"]) for k in self.objects) else b""
            return probe.S3Response(200, b"<ListBucketResult>" + contents + b"</ListBucketResult>")
        if method == "PUT" and query.get("partNumber"):
            self.uploads.setdefault(query.get("uploadId"), {})[int(query["partNumber"])] = body
            return probe.S3Response(200, headers={"ETag": '"etag"'})
        if method == "POST" and "uploads" in query:
            self.uploads["u1"] = {"key": key}
            return probe.S3Response(200, b"<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>")
        if method == "POST" and "uploadId" in query:
            self.objects[key] = probe.MARKER
            self.uploads.pop(query["uploadId"], None)
            return probe.S3Response(200, b"<CompleteMultipartUploadResult/>")
        if method == "PUT" and headers and "x-amz-copy-source" in headers:
            source = headers["x-amz-copy-source"].split("/", 2)[-1]
            if source in self.objects:
                self.objects[key] = self.objects[source]
                return probe.S3Response(200, b"<CopyObjectResult/>")
            return probe.S3Response(403)
        if method == "PUT":
            if headers and headers.get("If-None-Match") == "*" and key in self.objects:
                return probe.S3Response(412)
            self.objects[key] = body
            return probe.S3Response(200)
        if method == "GET" and key:
            return probe.S3Response(200, self.objects[key]) if key in self.objects else probe.S3Response(404)
        if method == "HEAD":
            return probe.S3Response(200) if key in self.objects else probe.S3Response(404)
        if method == "DELETE":
            if query.get("uploadId"):
                self.uploads.pop(query["uploadId"], None)
                return probe.S3Response(204)
            self.objects.pop(key, None)
            return probe.S3Response(204)
        return probe.S3Response(403)


class R2ProbeTests(unittest.TestCase):
    def setUp(self):
        self.connection_guard = patch.object(
            probe.http.client, "HTTPSConnection", side_effect=AssertionError("network access in unit test"))
        self.socket_guard = patch.object(
            socket, "create_connection", side_effect=AssertionError("network access in unit test"))
        self.connection_guard.start()
        self.socket_guard.start()
        self.addCleanup(self.socket_guard.stop)
        self.addCleanup(self.connection_guard.stop)

    def credentials(self, bucket=probe.BUCKET, channel="stable", expires=999999):
        return {"bucket": bucket, "prefix": channel + "/", "permission": "object-read-write",
                "expires_at": expires, "access_key_id": "a" * 32,
                "secret_access_key": "b" * 64, "session_token": "synthetic-session"}

    def test_expectation_table_covers_all_allow_and_deny_cases_for_each_format(self):
        expected = {
            "put_allowed", "get_allowed", "head_allowed", "list_own_prefix_allowed",
            "multipart_create_allowed", "multipart_upload_part_allowed", "multipart_complete_allowed",
            "copy_within_prefix_allowed", "copy_integrity_allowed", "copy_destination_reservation_allowed",
            "multipart_destination_reservation_allowed", "delete_allowed", "put_other_channel_denied", "put_root_denied",
            "get_other_channel_denied", "head_other_channel_denied",
            "list_other_channel_denied", "list_root_denied", "list_multipart_uploads_denied",
            "copy_from_other_channel_denied", "delete_other_channel_denied", "put_other_bucket_denied",
            "list_buckets_denied", "list_bucket_level_denied", "cleanup_list_empty", "multipart_cleanup_list_empty",
        }
        expected.add("put_collision_guard")
        self.assertEqual(set(probe.EXPECTATIONS), expected | {"expiry_put_denied", "expiry_next_put_denied", "expiry_precondition_cleanup"})
        buckets = {"flatpak": ("luminus-flatpak", "luminus-rpm"),
                   "rpm": ("luminus-rpm", "luminus-flatpak")}
        self.assertEqual((probe.BUCKET, probe.OTHER_BUCKET), buckets[probe.FORMAT])
        self.assertEqual({name for name, (_, value) in probe.EXPECTATIONS.items() if value == "HTTP 403"} - {"expiry_put_denied", "expiry_next_put_denied"},
                          expected - {"put_allowed", "put_collision_guard", "get_allowed", "head_allowed", "list_own_prefix_allowed", "multipart_create_allowed", "multipart_upload_part_allowed", "multipart_complete_allowed", "copy_within_prefix_allowed", "copy_integrity_allowed", "copy_destination_reservation_allowed", "multipart_destination_reservation_allowed", "delete_allowed", "cleanup_list_empty", "multipart_cleanup_list_empty"})

    def test_full_probe_passes_and_cleans_owned_objects_and_uploads(self):
        clients = []
        def factory(credentials):
            client = FakeClient(credentials)
            clients.append(client)
            return client
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=factory)
        self.assertTrue(result["passed"], [item for item in result["operations"] if not item["pass"]])
        for item in result["operations"]:
            self.assertEqual(set(item), {"name", "expected", "observed", "pass"})
        public_report = str(result)
        for sensitive in ("a" * 32, "b" * 64, "synthetic-session", "Authorization", "Signature="):
            self.assertNotIn(sensitive, public_report)
        self.assertEqual(clients[0].objects, {})
        self.assertEqual(clients[0].uploads, {})
        self.assertEqual({item["name"] for item in result["operations"]} & set(probe.EXPECTATIONS), set(probe.EXPECTATIONS) - {"expiry_put_denied", "expiry_next_put_denied", "expiry_precondition_cleanup"})

    def test_expiry_uses_expires_at_and_denies_next_put_after_sequence(self):
        clock = [1000]
        client = FakeClient(self.credentials(expires=1300), lambda: clock[0])
        def sleep(duration):
            clock[0] += duration
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(self.credentials(expires=1300), "100", "1", "stable", True,
                                 client_factory=lambda credentials: client, sleep=sleep)
        self.assertTrue(result["passed"], [item for item in result["operations"] if not item["pass"]])
        self.assertEqual(client.objects, {})
        self.assertIn("expiry_next_put_denied", {item["name"] for item in result["operations"]})
        self.assertEqual(result["expiry_result"], "expired credential denied")
        for name in ("cleanup_list_empty", "multipart_cleanup_list_empty"):
            listing = next(item for item in result["operations"] if item["name"] == name)
            self.assertTrue(listing["pass"])
        after_expiry = [call for call in client.calls if call[4] >= 1300]
        self.assertEqual([call[0] for call in after_expiry], ["PUT", "PUT"])

    def test_unexpected_post_expiry_write_reports_exact_residue_without_cleanup(self):
        clock = [1000]
        class ExpiredPutSucceeds(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "PUT" and self.now() >= self.credentials["expires_at"]:
                    self.calls.append((method, bucket, key, (query or {}).copy(), self.now()))
                    self.objects[key] = body
                    return probe.S3Response(200)
                return super()._request(method, bucket, key, query, body, headers)
        credentials = self.credentials(expires=1300)
        client = ExpiredPutSucceeds(credentials, lambda: clock[0])
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(credentials, "100", "1", "stable", True,
                                 client_factory=lambda value: client,
                                 sleep=lambda duration: clock.__setitem__(0, clock[0] + duration))
        self.assertFalse(result["passed"])
        successful_keys = {(bucket, key) for method, bucket, key, _, when in client.calls
                           if method == "PUT" and when >= 1300}
        self.assertEqual({(entry["bucket"], entry["key"]) for entry in result["expiry_residue"]}, successful_keys)
        self.assertEqual(len(successful_keys), 2)
        self.assertTrue(all(method == "PUT" for method, _, _, _, when in client.calls if when >= 1300))

    def test_post_expiry_401_unauthorized_is_not_proof_of_expiry(self):
        clock = [1000]
        class Revoked(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "PUT" and self.now() >= self.credentials["expires_at"]:
                    self.calls.append((method, bucket, key, (query or {}).copy(), self.now()))
                    return probe.S3Response(401, b"<Error><Code>Unauthorized</Code></Error>")
                return super()._request(method, bucket, key, query, body, headers)
        credentials = self.credentials(expires=1300)
        client = Revoked(credentials, lambda: clock[0])
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(credentials, "100", "1", "stable", True,
                                 client_factory=lambda value: client,
                                 sleep=lambda duration: clock.__setitem__(0, clock[0] + duration))
        self.assertFalse(result["passed"])
        self.assertEqual(result["expiry_result"], "not confirmed")

    def test_precondition_guard_failure_aborts_all_negative_puts(self):
        class NoPrecondition(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "PUT" and headers and headers.get("If-None-Match") == "*" and key in self.objects:
                    self.calls.append((method, bucket, key, (query or {}).copy(), self.now()))
                    self.objects[key] = body
                    return probe.S3Response(200)
                return super()._request(method, bucket, key, query, body, headers)
        client = NoPrecondition(self.credentials())
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda value: client)
        guard = next(item for item in result["operations"] if item["name"] == "put_collision_guard")
        self.assertFalse(result["passed"])
        self.assertFalse(guard["pass"])
        self.assertEqual([key for method, _, key, _, _ in client.calls if method == "PUT"],
                         [next(key for method, _, key, _, _ in client.calls if method == "PUT")]
                         * 2)
        self.assertFalse(any("absent-" in key or "root-" in key
                             for method, _, key, _, _ in client.calls if method == "PUT"))

    def test_failed_cleanup_of_allowed_negative_put_reports_exact_residue(self):
        class LeakyBroadClient(FakeClient):
            def __init__(self, credentials):
                super().__init__(credentials)
                self.failed_deletes = []

            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "PUT" and headers and headers.get("If-None-Match") == "*":
                    if key in self.objects:
                        return probe.S3Response(412)
                    self.objects[key] = body
                    return probe.S3Response(200)
                if method == "DELETE" and ("absent-" in (key or "") or "root-" in (key or "")):
                    self.calls.append((method, bucket, key, (query or {}).copy(), self.now()))
                    self.failed_deletes.append((bucket, key))
                    return probe.S3Response(403)
                return super()._request(method, bucket, key, query, body, headers)
        client = LeakyBroadClient(self.credentials())
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda value: client)
        residue = {(entry["bucket"], entry["key"]) for entry in result["residue"]}
        self.assertFalse(result["passed"])
        self.assertEqual(residue, set(client.failed_deletes))
        self.assertTrue(any("absent-" in key or "root-" in key for _, key in residue))

    def test_expiry_accepts_the_signature_error_r2_returns_for_expired_credentials(self):
        class RealShapeClient(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                response = super()._request(method, bucket, key, query, body, headers)
                if self.now() >= self.credentials["expires_at"]:
                    return probe.S3Response(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>")
                return response
        clock = [1000]
        client = RealShapeClient(self.credentials(expires=1300), lambda: clock[0])
        def sleep(duration):
            clock[0] += duration
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(self.credentials(expires=1300), "100", "1", "stable", True,
                                 client_factory=lambda credentials: client, sleep=sleep)
        self.assertTrue(result["passed"], [item for item in result["operations"] if not item["pass"]])
        self.assertEqual(result["expiry_result"], "expired credential denied")

    def test_expiry_rejects_unrelated_error_codes_after_expiry(self):
        class OddClient(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                response = super()._request(method, bucket, key, query, body, headers)
                if self.now() >= self.credentials["expires_at"]:
                    return probe.S3Response(403, b"<Error><Code>NoSuchBucket</Code></Error>")
                return response
        clock = [1000]
        client = OddClient(self.credentials(expires=1300), lambda: clock[0])
        def sleep(duration):
            clock[0] += duration
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(self.credentials(expires=1300), "100", "1", "stable", True,
                                 client_factory=lambda credentials: client, sleep=sleep)
        self.assertFalse(result["passed"])

    def test_expiry_final_list_failure_before_expiry_fails_probe(self):
        clock = [1000]
        class ListingFails(FakeClient):
            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "GET" and query and ("list-type" in query or "uploads" in query):
                    self.calls.append((method, bucket, key, query.copy(), self.now()))
                    return probe.S3Response(403)
                return super()._request(method, bucket, key, query, body, headers)
        credentials = self.credentials(expires=1300)
        client = ListingFails(credentials, lambda: clock[0])
        with patch.object(probe.time, "time", side_effect=lambda: clock[0]):
            result = probe.probe(credentials, "100", "1", "stable", True,
                                 client_factory=lambda value: client,
                                 sleep=lambda duration: clock.__setitem__(0, clock[0] + duration))
        self.assertFalse(result["passed"])
        self.assertFalse(next(item for item in result["operations"] if item["name"] == "cleanup_list_empty")["pass"])
        self.assertFalse(next(item for item in result["operations"] if item["name"] == "multipart_cleanup_list_empty")["pass"])
        self.assertEqual([call[0] for call in client.calls if call[4] >= 1300], ["PUT", "PUT"])

    def test_expiry_preflight_returns_retry_outcome_before_client_creation(self):
        with patch.object(probe.time, "time", return_value=1000):
            result = probe.probe(self.credentials(expires=1119), "100", "1", "stable", True,
                                 client_factory=lambda credentials: self.fail("client created"))
        self.assertFalse(result["passed"])
        self.assertEqual(result["expiry_result"], "expired or nearly expired before probe; retry")
        self.assertEqual(result["operations"], [])

    def test_expiry_preflight_retry_uses_distinct_exit_code(self):
        with redirect_stdout(StringIO()), \
                patch.object(probe, "load_credentials", return_value=self.credentials(expires=1119)), \
                patch.object(probe.time, "time", return_value=1000):
            status = probe.main(["--credentials", "ignored", "--channel", "stable", "--run-id", "100",
                                 "--attempt", "1", "--expiry-check"])
        self.assertEqual(status, 2)

    def test_successful_negative_puts_are_nonce_scoped_and_cleaned(self):
        class BroadClient(FakeClient):
            def __init__(self, credentials):
                super().__init__(credentials)
                self.negative_puts = []
                self.deleted = []

            def _request(self, method, bucket=None, key=None, query=None, body=b"", headers=None):
                if method == "PUT" and headers and headers.get("If-None-Match") == "*":
                    if key in self.objects:
                        return probe.S3Response(412)
                    self.negative_puts.append((bucket, key, headers.copy()))
                    self.objects[key] = body
                    return probe.S3Response(200)
                if method == "DELETE" and key in self.objects:
                    self.deleted.append((bucket, key))
                    self.objects.pop(key)
                    return probe.S3Response(204)
                return super()._request(method, bucket, key, query, body, headers)
        client = BroadClient(self.credentials())
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda credentials: client)
        self.assertFalse(result["passed"])
        self.assertEqual(client.objects, {})
        negative_puts = [(bucket, key, headers) for bucket, key, headers in client.negative_puts
                         if "/absent-" in key or "/root-" in key]
        self.assertGreaterEqual(len(negative_puts), 3)
        self.assertTrue(all(headers.get("If-None-Match") == "*" for _, _, headers in negative_puts))
        self.assertTrue({(bucket, key) for bucket, key, _ in negative_puts} <= set(client.deleted))
        self.assertTrue(all(len(key.rsplit("-", 1)[-1]) == 32 for _, key, _ in negative_puts))
        negative_names = {"put_other_channel_denied", "put_root_denied", "put_other_bucket_denied"}
        self.assertTrue(negative_names <= {item["name"] for item in result["operations"]})

    def test_wrong_scope_rejected_and_error_reports_are_sanitized(self):
        with self.assertRaises(probe.ProbeError):
            probe.probe(self.credentials(channel="testing"), "100", "1", "stable")
        self.assertNotIn("Authorization", probe.main.__code__.co_names)

    def test_credentials_file_must_be_private_regular_and_not_a_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.json")
            path.write_text(json.dumps(self.credentials()))
            path.chmod(0o600)
            self.assertEqual(probe.load_credentials(path)["bucket"], probe.BUCKET)
            path.chmod(0o640)
            with self.assertRaises(probe.ProbeError):
                probe.load_credentials(path)
            path.chmod(0o600)
            link = Path(directory, "link.json")
            link.symlink_to(path)
            with self.assertRaises(probe.ProbeError):
                probe.load_credentials(link)

    def test_not_found_and_signature_errors_are_not_scope_denials(self):
        for response in (probe.S3Response(404), probe.S3Response(403, b"<Error><Code>SignatureDoesNotMatch</Code></Error>")):
            checks = []
            probe._expect(checks, "get_other_channel_denied", response)
            self.assertFalse(checks[0]["pass"])
        checks = []
        probe._expect(checks, "put_other_channel_denied", probe.S3Response(412))
        self.assertFalse(checks[0]["pass"])

    def test_head_403_without_body_is_classified_as_access_denied(self):
        class Response:
            status = 403
            def read(self, size): return b""
            def getheaders(self): return []
        class Connection:
            def __init__(self, host, timeout): pass
            def request(self, method, target, body, headers): self.method = method
            def getresponse(self): return Response()
            def close(self): pass
        client = probe.SigV4Client(self.credentials(), Connection)
        response = client._request("HEAD", probe.BUCKET, "testing/absent")
        self.assertEqual(response.code, "403")
        checks = []
        probe._expect(checks, "head_other_channel_denied", response)
        self.assertTrue(checks[0]["pass"])

    def test_network_guard_blocks_default_https_and_socket_creation(self):
        with self.assertRaises(AssertionError):
            probe.http.client.HTTPSConnection("example.invalid", timeout=1)
        with self.assertRaises(AssertionError):
            socket.create_connection(("127.0.0.1", 1), timeout=0.01)

    def test_copy_and_multipart_error_xml_in_http_200_are_failures(self):
        for name, body, root_name in (
            ("copy_within_prefix_allowed", b"<Error/>", "CopyObjectResult"),
            ("multipart_complete_allowed", b"<Error/>", "CompleteMultipartUploadResult"),
        ):
            checks = []
            probe._expect(checks, name, probe.S3Response(200, body), success=True, root_name=root_name)
            self.assertFalse(checks[0]["pass"])

    def test_cleanup_runs_after_request_transport_failure(self):
        client = FakeClient(self.credentials())
        original = client._request
        raised = [False]
        def fail_once(method, bucket=None, key=None, **kwargs):
            if method == "GET" and key and key.startswith("stable/_scope-probe/100-1/object-") and not raised[0]:
                raised[0] = True
                raise OSError("synthetic transport failure")
            return original(method, bucket, key, **kwargs)
        client._request = fail_once
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda credentials: client)
        self.assertFalse(result["passed"])
        self.assertEqual(client.objects, {})

    def test_owned_delete_failure_is_retried_during_cleanup(self):
        client = FakeClient(self.credentials())
        original = client._request
        failed = [False]
        def fail_first_delete(method, bucket=None, key=None, **kwargs):
            if method == "DELETE" and key and key.startswith("stable/_scope-probe/100-1/object-") and not failed[0]:
                failed[0] = True
                return probe.S3Response(403)
            return original(method, bucket, key, **kwargs)
        client._request = fail_first_delete
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda credentials: client)
        self.assertFalse(result["passed"])
        self.assertEqual(client.objects, {})
        self.assertTrue(any(item["name"] == "object_cleanup" and item["pass"] for item in result["operations"]))

    def test_complete_error_keeps_upload_tracked_and_aborts_it(self):
        client = FakeClient(self.credentials())
        original = client._request
        def fail_complete(method, bucket=None, key=None, query=None, **kwargs):
            if method == "POST" and query and query.get("uploadId"):
                return probe.S3Response(200, b"<Error><Code>InternalError</Code></Error>")
            return original(method, bucket, key, query, **kwargs)
        client._request = fail_complete
        result = probe.probe(self.credentials(), "100", "1", "stable", client_factory=lambda credentials: client)
        self.assertFalse(result["passed"])
        self.assertEqual(client.uploads, {})
        complete = next(item for item in result["operations"] if item["name"] == "multipart_complete_allowed")
        self.assertFalse(complete["pass"])
        self.assertTrue(next(item for item in result["operations"] if item["name"] == "multipart_cleanup_list_empty")["pass"])

    def test_sigv4_request_uses_fixed_host_timeout_and_never_logs_authorization(self):
        captured = {}
        class Response:
            status = 200
            def read(self, size): return b""
            def getheaders(self): return []
        class Connection:
            def __init__(self, host, timeout): captured.update(host=host, timeout=timeout)
            def request(self, method, target, body, headers): captured.update(method=method, target=target, headers=headers)
            def getresponse(self): return Response()
            def close(self): pass
        client = probe.SigV4Client(self.credentials(), Connection)
        client._request("PUT", probe.BUCKET, "stable/test", body=b"payload", headers={"If-None-Match": "*"})
        self.assertEqual(captured["host"], probe.ACCOUNT_ID + ".r2.cloudflarestorage.com")
        self.assertEqual(captured["timeout"], probe.TIMEOUT_SECONDS)
        self.assertIn("AWS4-HMAC-SHA256", captured["headers"]["Authorization"])
        signed_headers = captured["headers"]["Authorization"].split("SignedHeaders=")[1].split(",", 1)[0]
        self.assertIn("if-none-match", signed_headers)
        self.assertNotIn("Authorization", str({"name": "operation", "observed": 200}))

    def test_sigv4_fixed_get_and_put_payload_hash_vectors(self):
        from datetime import datetime, timezone
        captured = []
        class FixedDateTime:
            @staticmethod
            def now(_): return datetime(2015, 8, 30, 12, 36, tzinfo=timezone.utc)
        class Response:
            status = 200
            def read(self, size): return b""
            def getheaders(self): return []
        class Connection:
            def __init__(self, host, timeout): pass
            def request(self, method, target, body, headers): captured.append((method, headers))
            def getresponse(self): return Response()
            def close(self): pass
        credentials = {"access_key_id": "AKIDEXAMPLE",
                       "secret_access_key": "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                       "session_token": "example-token"}
        with patch.object(probe, "datetime", FixedDateTime):
            client = probe.SigV4Client(credentials, Connection)
            client._request("GET", probe.BUCKET, "stable/test")
            client._request("PUT", probe.BUCKET, "stable/test", body=b"Welcome to Amazon S3.")
        signatures = ("0b47cf7c8700bdc9fa92ad704f05fa2e04dea1cb43c3bc8adb21933a86017ae5",
                      "5ca84efd1c993770bb195a9e6dc310c9302b74899c327558d99b4a78c32f17fa")
        self.assertEqual(captured[0][1]["Authorization"].split("Signature=")[1], signatures[probe.FORMAT == "rpm"])
        self.assertEqual(captured[0][1]["x-amz-content-sha256"],
                         "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        signatures = ("61587baf9ca52e6761b6cf2cefe307f726f96c35a64b13343d0e81df16e3c9e9",
                      "012a17936cf1573b875944a3f955b614455f0c0a61bf3e1771b43ce87bb66567")
        self.assertEqual(captured[1][1]["Authorization"].split("Signature=")[1], signatures[probe.FORMAT == "rpm"])
        self.assertEqual(captured[1][1]["x-amz-content-sha256"],
                         "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072")

    def test_sigv4_matches_aws_documented_get_object_vector(self):
        from datetime import datetime, timezone
        captured = {}
        class FixedDateTime:
            @staticmethod
            def now(_): return datetime(2013, 5, 24, tzinfo=timezone.utc)
        class Response:
            status = 200
            def read(self, size): return b""
            def getheaders(self): return []
        class Connection:
            def __init__(self, host, timeout): pass
            def request(self, method, target, body, headers): captured.update(method=method, target=target, headers=headers)
            def getresponse(self): return Response()
            def close(self): pass
        credentials = {"access_key_id": "AKIAIOSFODNN7EXAMPLE",
                       "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
        with patch.object(probe, "datetime", FixedDateTime):
            client = probe.SigV4Client(credentials, Connection, region="us-east-1", host="examplebucket.s3.amazonaws.com")
            client._request("GET", key="test.txt", headers={"Range": "bytes=0-9"})
        self.assertEqual(captured["target"], "/test.txt")
        self.assertEqual(captured["headers"]["Authorization"].split("Signature=")[1],
                         "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")

    def test_sigv4_canonical_query_is_sorted_independent_of_input_order(self):
        captured = []
        class Response:
            status = 200
            def read(self, size): return b""
            def getheaders(self): return []
        class Connection:
            def __init__(self, host, timeout): pass
            def request(self, method, target, body, headers): captured.append((target, headers["Authorization"]))
            def getresponse(self): return Response()
            def close(self): pass
        client = probe.SigV4Client(self.credentials(), Connection)
        client._request("GET", probe.BUCKET, "stable/test", query={"uploads": "", "partNumber": "1"})
        client._request("GET", probe.BUCKET, "stable/test", query={"partNumber": "1", "uploads": ""})
        self.assertEqual(captured[0], captured[1])
        self.assertIn("partNumber=1&uploads=", captured[0][0])


if __name__ == "__main__":
    unittest.main()

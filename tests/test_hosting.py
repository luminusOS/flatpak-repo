import copy
from email.message import Message
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from urllib.error import HTTPError
from urllib.request import Request
from unittest import mock

from tools import hosting


ROOT = Path(__file__).resolve().parents[1]


class HostingTests(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((ROOT / "hosting.json").read_text(encoding="utf-8"))

    def test_current_config_is_valid_and_cli_reports_success(self):
        self.assertEqual(hosting.validate_config(self.config), self.config)
        result = subprocess.run(
            [sys.executable, "-B", "tools/hosting.py", "validate"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual((result.returncode, result.stdout.strip()), (0, "hosting config valid"))
        self.assertEqual(result.stderr, "")

    def test_rejects_unknown_or_missing_fields_and_policy_drift(self):
        for mutate in (
            lambda value: value.pop("domain"),
            lambda value: value.update(extra=True),
            lambda value: value.update(public_dev_url=True),
            lambda value: value["cache"].update(immutable_ttl_seconds=True),
            lambda value: value["cache"].update(negative_cache_ttl=0),
            lambda value: value.update(state="provisioned"),
        ):
            candidate = copy.deepcopy(self.config)
            mutate(candidate)
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                hosting.validate_config(candidate)

    def test_flatpak_detached_commit_metadata_is_mutable_and_no_store(self):
        self.assertEqual(
            hosting.classify_path("/stable/objects/ab/cd.commitmeta"),
            {"classification": "mutable", "cache_control": "no-store"},
        )

    def test_commitmeta_probe_is_owned_and_reports_mutable_no_store(self):
        class Response:
            status = 200
            headers = Message()
            headers["Cache-Control"] = "no-store"

            def __init__(self, body=b"synthetic detached metadata"):
                self.body = io.BytesIO(body)

            def read(self, size=-1):
                return self.body.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.body.close()

        opener = mock.Mock()
        opener.open.side_effect = [Response(b""), Response()]
        url = "https://flatpak.luminusos.org/stable/objects/_hosting-check/run/detached.commitmeta"
        result = hosting.probe(url, opener=opener)
        self.assertEqual([result[method]["status"] for method in ("head", "get")], [200, 200])
        self.assertEqual(result["requests"], 2)
        self.assertEqual(
            result["expected_policy"],
            {"classification": "mutable", "cache_control": "no-store"},
        )
        self.assertEqual(result["get"]["headers"]["cache-control"], "no-store")
        self.assertEqual(
            [call.args[0].get_method() for call in opener.open.call_args_list], ["HEAD", "GET"],
        )

    def test_commitmeta_probe_rejects_paths_outside_exact_owned_key(self):
        for path in (
            "/stable/objects/ab/detached.commitmeta",
            "/stable/objects/_hosting-check/bad.nonce/detached.commitmeta",
            "/stable/objects/_hosting-check/run/extra/detached.commitmeta",
            "/stable/objects/_hosting-check/run/other.commitmeta",
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                hosting.validate_probe_url(f"https://flatpak.luminusos.org{path}")

    def test_probe_accepts_only_owned_https_test_paths(self):
        nonce = "run_2026-10"
        valid = f"https://flatpak.luminusos.org/stable/objects/_hosting-check/{nonce}/immutable.bin"
        for url in (
            "http://flatpak.luminusos.org/stable/objects/_hosting-check/run/immutable.bin",
            "https://evil.example/stable/objects/_hosting-check/run/immutable.bin",
            "https://flatpak.luminusos.org:443/stable/objects/_hosting-check/run/immutable.bin",
            "https://user@flatpak.luminusos.org/stable/objects/_hosting-check/run/immutable.bin",
            "https://flatpak.luminusos.org/stable/objects/_hosting-check/run/a%2fb",
            "https://flatpak.luminusos.org/stable/objects/_hosting-check/run/../summary",
            "https://flatpak.luminusos.org/stable/objects/_hosting-check/run/immutable.bin?x=1",
            "https://flatpak.luminusos.org/stable/objects/real-package.flatpak",
            "https://rpm.luminusos.org/stable/45/x86_64/_hosting-check/run/immutable.rpm",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                hosting.validate_probe_url(url)
        self.assertEqual(hosting.validate_probe_url(valid), valid)

    def test_probe_makes_bounded_head_and_get_and_returns_hash_not_body(self):
        class Response:
            status = 200
            headers = {"Cache-Control": "public, max-age=31536000", "ETag": '"abc"', "X-Secret": "hidden"}

            def __init__(self, body=b"synthetic flatpak bytes"):
                self.body = io.BytesIO(body)

            def read(self, size=-1):
                return self.body.read(size)

            def __enter__(self):
                return self

            def __exit__(self, *args):
                self.body.close()

        opener = mock.Mock()
        opener.open.side_effect = [Response(b""), Response()]
        url = "https://flatpak.luminusos.org/stable/objects/_hosting-check/run/immutable.bin"
        result = hosting.probe(url, opener=opener)
        self.assertEqual(result["requests"], 2)
        self.assertEqual(result["expected_policy"]["classification"], "immutable")
        self.assertEqual(result["get"]["bytes_read"], len(b"synthetic flatpak bytes"))
        self.assertNotIn("body", result["get"])
        self.assertNotIn("hidden", json.dumps(result))
        requests = [call.args[0] for call in opener.open.call_args_list]
        self.assertEqual([request.get_method() for request in requests], ["HEAD", "GET"])
        self.assertTrue(all(isinstance(request, Request) for request in requests))
        self.assertTrue(all(call.kwargs["timeout"] <= 15 for call in opener.open.call_args_list))

    def test_redirect_handler_does_not_follow(self):
        self.assertIsNone(hosting._NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://other.example/"))

    def test_probe_accepts_404_as_observed_status(self):
        def missing(request, timeout):
            raise HTTPError(request.full_url, 404, "missing", {"Cache-Control": "no-store"}, io.BytesIO(b""))

        opener = mock.Mock()
        opener.open.side_effect = missing
        result = hosting.probe(
            "https://flatpak.luminusos.org/stable/_hosting-check/run/metadata.txt", opener=opener,
        )
        self.assertEqual([result[method]["status"] for method in ("head", "get")], [404, 404])
        self.assertEqual(result["requests"], 2)

    def test_probe_rejects_oversized_get_body(self):
        class Response:
            status = 200
            headers = {}

            def __init__(self):
                self.remaining = b"x" * (hosting.MAX_RESPONSE_BYTES + 50)

            def read(self, size=-1):
                chunk, self.remaining = self.remaining[:3], self.remaining[3:]
                return chunk

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

        opener = mock.Mock()
        opener.open.side_effect = [Response(), Response()]
        with self.assertRaisesRegex(ValueError, "response exceeds"):
            hosting.probe(
                "https://flatpak.luminusos.org/stable/_hosting-check/run/metadata.txt", opener=opener,
            )


if __name__ == "__main__":
    unittest.main()

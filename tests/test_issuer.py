import ast
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import BytesIO, StringIO
from urllib.error import HTTPError, URLError
import yaml
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
SPEC = importlib.util.spec_from_file_location("issuer", ROOT / "tools" / "issuer.py")
issuer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(issuer)


SOURCE_FIXTURES = {
    "dev.luminusos.ZapTide": ("luminusOS/zaptide", ".github/workflows/release.yml",
                               ".github/workflows/release.yml", "flatpak"),
    "org.luminusos.Aetheris": ("luminusOS/aetheris", ".github/workflows/release.yml",
                                ".github/workflows/release-flatpak.yml", "flatpak"),
    "sirius-installer": ("luminusOS/sirius", ".github/workflows/ci.yml",
                          ".github/workflows/ci.yml", "rpm"),
}
REAL_SOURCE_RUNS = {
    "dev.luminusos.ZapTide": {
        "id": 40045135138, "event": "push", "head_branch": "v0.7.3",
        "head_sha": "8f1ac14f366f52b86389961ce82ceb7898ee75b7",
        "path": ".github/workflows/release.yml", "run_attempt": 1,
        "status": "completed", "conclusion": "success",
        "repository": {"full_name": "luminusOS/zaptide"},
        "referenced_workflows": [
            {"path": "luminusOS/zaptide/.github/workflows/release-appimage.yml@8f1ac14f366f52b86389961ce82ceb7898ee75b7",
             "ref": "refs/tags/v0.7.3", "sha": "8f1ac14f366f52b86389961ce82ceb7898ee75b7"},
            {"path": "luminusOS/zaptide/.github/workflows/ci.yml@8f1ac14f366f52b86389961ce82ceb7898ee75b7",
             "ref": "refs/tags/v0.7.3", "sha": "8f1ac14f366f52b86389961ce82ceb7898ee75b7"},
        ],
    },
    "org.luminusos.Aetheris": {
        "id": 32636733386, "event": "push", "head_branch": "v1.5.0",
        "head_sha": "b3ac2820bdf2bb11dbf4a4639d9a962f96630c33",
        "path": ".github/workflows/release.yml", "run_attempt": 1,
        "status": "completed", "conclusion": "success",
        "repository": {"full_name": "luminusOS/aetheris"},
        "referenced_workflows": [
            {"path": "luminusOS/aetheris/.github/workflows/release-flatpak.yml@b3ac2820bdf2bb11dbf4a4639d9a962f96630c33",
             "ref": "refs/tags/v1.5.0", "sha": "b3ac2820bdf2bb11dbf4a4639d9a962f96630c33"},
        ],
    },
    "sirius-installer": {
        "id": 35161979157, "event": "push", "head_branch": "v1.0.4",
        "head_sha": "a" * 40, "path": ".github/workflows/ci.yml",
        "run_attempt": 1, "status": "completed", "conclusion": "success",
        "repository": {"full_name": "luminusOS/sirius"},
        "referenced_workflows": [],
    },
}


def source_run(descriptor, **changes):
    repository, caller_workflow, contract_workflow, _ = SOURCE_FIXTURES[descriptor["package_id"]]
    head_branch = "v" + descriptor["version"]
    data = {
        "repository": {"full_name": repository},
        "id": int(descriptor["source_run_id"]),
        "path": caller_workflow,
        "status": "completed",
        "conclusion": "success",
        "head_sha": descriptor["git_sha"].lower(),
        "event": "push",
        "head_branch": head_branch,
        "run_attempt": descriptor["source_run_attempt"],
    }
    if caller_workflow != contract_workflow:
        data["referenced_workflows"] = [{
            "path": f"{repository}/{contract_workflow}@{descriptor['git_sha'].lower()}",
            "sha": descriptor["git_sha"].lower(),
            "ref": f"refs/tags/{head_branch}",
        }]
    data.update(changes)
    return data


class FakeResponse:
    def __init__(self, body, status=200):
        self.body = body
        self.status = status
        self.closed = False

    def read(self, size=-1):
        return self.body[:size]

    def close(self):
        self.closed = True


class IssuerTests(unittest.TestCase):
    def setUp(self):
        self.binding = issuer.Binding(
            "luminusOS/flatpak-repo", "12345", "2", "a" * 40,
            "refs/heads/main", "stable",
        )
        self.descriptor = {
            "format": issuer.FORMAT, "channel": "stable",
            "package_id": "dev.luminusos.ZapTide" if issuer.FORMAT == "flatpak" else "sirius-installer",
            "version": "1.2.3", "git_sha": "b" * 40, "source_run_id": "321",
            "source_run_attempt": 4,
        }

    def fake_fetcher(self, run=None, tag_ref=None, tag_object=None):
        response = source_run(self.descriptor) if run is None else run
        calls = []

        def fetcher(path, token=None):
            calls.append((path, token))
            if "/actions/runs/" in path:
                return response
            if "/git/ref/tags/" in path:
                if isinstance(tag_ref, BaseException):
                    if isinstance(tag_ref, HTTPError):
                        tag_ref.close()
                    raise tag_ref
                return tag_ref if tag_ref is not None else {
                    "ref": f"refs/tags/{response['head_branch']}", "object": {
                        "type": "commit", "sha": response["head_sha"]}}
            if "/git/tags/" in path:
                return tag_object if tag_object is not None else {"object": {
                    "type": "commit", "sha": response["head_sha"]}}
            raise AssertionError(path)

        return fetcher, calls

    def test_source_run_accepts_only_contract_sources_and_records_attempt(self):
        allowed = [(app, details) for app, details in SOURCE_FIXTURES.items()
                   if details[3] == issuer.FORMAT]
        for app, (repository, caller_workflow, contract_workflow, _) in allowed:
            run = copy.deepcopy(REAL_SOURCE_RUNS[app])
            descriptor = {**self.descriptor, "package_id": app,
                          "source_run_id": str(run["id"]),
                          "source_run_attempt": run.get("run_attempt", 1),
                          "git_sha": run["head_sha"],
                          "version": run["head_branch"].removeprefix("v")}
            fetcher, calls = self.fake_fetcher(run)
            verified = issuer.verify_source_run(descriptor, issuer.FORMAT, "stable", fetcher)
            self.assertEqual(verified["source_run_attempt"], descriptor["source_run_attempt"])
            self.assertEqual(calls[0], (f"/repos/{repository}/actions/runs/{descriptor['source_run_id']}", None))
            self.assertEqual(calls[1][0], f"/repos/{repository}/git/ref/tags/{run['head_branch']}")
            self.assertEqual(run["path"], caller_workflow)
            if caller_workflow != contract_workflow:
                self.assertEqual(run["referenced_workflows"][0]["path"],
                                 f"{repository}/{contract_workflow}@{descriptor['git_sha']}")
            credentials = issuer.derive_credentials("a" * 32, "b" * 64,
                                                    issuer.FORMAT, "stable", now=1700000000)
            envelope = issuer.build_envelope(self.binding, verified, credentials, now=1700000000)
            self.assertEqual(envelope["descriptor"]["source_run_attempt"], descriptor["source_run_attempt"])

    def test_reusable_workflow_requires_same_repository_reference_and_matching_sha(self):
        descriptor = {**self.descriptor, "package_id": "org.luminusos.Aetheris"}
        valid_run = source_run(descriptor)
        fetcher, _ = self.fake_fetcher(valid_run)
        self.assertEqual(issuer.verify_source_run(descriptor, "flatpak", "stable", fetcher), descriptor)
        invalid_references = (
            [],
            [{"path": "luminusOS/other/.github/workflows/release-flatpak.yml@refs/tags/v1.2.3",
              "sha": descriptor["git_sha"], "ref": "refs/tags/v1.2.3"}],
            [{"path": "luminusOS/aetheris/.github/workflows/release-flatpak.yml@refs/tags/v1.2.3",
              "sha": "c" * 40, "ref": "refs/tags/v1.2.3"}],
            [{"path": f"luminusOS/aetheris/.github/workflows/release-flatpak.yml@{descriptor['git_sha']}",
              "sha": descriptor["git_sha"], "ref": "refs/tags/v9.9.9"}],
        )
        for references in invalid_references:
            fetcher, _ = self.fake_fetcher({**valid_run, "referenced_workflows": references})
            with self.subTest(references=references), self.assertRaises(issuer.IssuerError):
                issuer.verify_source_run(descriptor, "flatpak", "stable", fetcher)

    def test_real_run_path_uses_caller_workflow_and_tag_ref_proves_tag(self):
        run = source_run(self.descriptor)
        fetcher, _ = self.fake_fetcher(run)
        self.assertEqual(issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher),
                         self.descriptor)
        branch_named_tag = {**run, "head_branch": "v1.2.3"}
        fetcher, _ = self.fake_fetcher(branch_named_tag, tag_ref={})
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_tag_ref_requires_matching_commit_and_accepts_one_level_annotated_tag(self):
        fetcher, calls = self.fake_fetcher(tag_ref={"ref": "refs/tags/v1.2.3", "object": {
            "type": "tag", "sha": "d" * 40}}, tag_object={"object": {
                "type": "commit", "sha": self.descriptor["git_sha"]}})
        issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher, token="fake-token")
        self.assertEqual(calls[2][0], f"/repos/{SOURCE_FIXTURES[self.descriptor['package_id']][0]}/git/tags/" + "d" * 40)
        self.assertEqual([token for _, token in calls], ["fake-token"] * 3)

    def test_tag_ref_rejects_other_commit_nested_tag_and_wrong_annotated_commit(self):
        cases = (
            ({"ref": "refs/tags/v1.2.3", "object": {"type": "commit", "sha": "c" * 40}}, None),
            ({"ref": "refs/tags/v1.2.3", "object": {"type": "tag", "sha": "d" * 40}},
             {"object": {"type": "tag", "sha": "e" * 40}}),
            ({"ref": "refs/tags/v1.2.3", "object": {"type": "tag", "sha": "d" * 40}},
             {"object": {"type": "commit", "sha": "c" * 40}}),
        )
        for ref, tag in cases:
            fetcher, _ = self.fake_fetcher(tag_ref=ref, tag_object=tag)
            with self.subTest(ref=ref, tag=tag), self.assertRaises(issuer.IssuerError):
                issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_caller_workflow_path_must_not_include_tag_suffix(self):
        run = source_run(self.descriptor, path=SOURCE_FIXTURES[self.descriptor["package_id"]][1]
                         + "@refs/tags/v1.2.3")
        fetcher, _ = self.fake_fetcher(run)
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_missing_tag_ref_http_404_is_a_lookup_failure(self):
        missing = HTTPError("https://api.github.com/private", 404, "not found", {}, BytesIO())
        fetcher, _ = self.fake_fetcher(tag_ref=missing)
        with self.assertRaises(issuer.IssuerError) as caught:
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)
        self.assertEqual(str(caught.exception), "Source run lookup failed")

    def test_source_run_rejects_wrong_repository_workflow_state_conclusion_sha_event_and_id(self):
        invalid_runs = (
            {"repository": {"full_name": "luminusOS/other"}},
            {"path": ".github/workflows/other.yml"},
            {"status": "in_progress"},
            {"conclusion": "failure"},
            {"conclusion": "cancelled"},
            {"head_sha": "c" * 40},
            {"event": "pull_request"},
            {"id": 322},
        )
        for changes in invalid_runs:
            run = source_run(self.descriptor, **changes)
            fetcher, _ = self.fake_fetcher(run)
            with self.subTest(changes=changes), self.assertRaises(issuer.IssuerError):
                issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_source_run_accepts_case_insensitive_sha_and_normalizes_rc_tag_spelling(self):
        descriptor = {**self.descriptor, "git_sha": self.descriptor["git_sha"].upper()}
        run = source_run(descriptor, head_sha=descriptor["git_sha"].lower())
        fetcher, _ = self.fake_fetcher(run)
        self.assertEqual(issuer.verify_source_run(descriptor, issuer.FORMAT, "stable", fetcher)["git_sha"],
                         descriptor["git_sha"].lower())
        descriptor.update(version="1.2.3-rc.2", channel="testing")
        run = source_run(descriptor, head_branch="v1.2.3-rc2",
            path=SOURCE_FIXTURES[descriptor["package_id"]][1])
        fetcher, _ = self.fake_fetcher(run)
        verified = issuer.verify_source_run(descriptor, issuer.FORMAT, "testing", fetcher)
        self.assertEqual(verified["version"], "1.2.3-rc.2")

    def test_source_run_rejects_version_tag_mismatch_and_rc_in_stable(self):
        run = source_run(self.descriptor, head_branch="v1.2.4")
        fetcher, _ = self.fake_fetcher(run)
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)
        rc_descriptor = {**self.descriptor, "version": "1.2.3-rc.1"}
        run = source_run(rc_descriptor, head_branch="v1.2.3-rc1",
                          path=SOURCE_FIXTURES[rc_descriptor["package_id"]][1])
        fetcher, _ = self.fake_fetcher(run)
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(rc_descriptor, issuer.FORMAT, "stable", fetcher)

    def test_source_descriptor_rejects_unknown_and_other_format_packages(self):
        for app in ("unknown-app", "sirius-installer" if issuer.FORMAT == "flatpak" else "dev.luminusos.ZapTide"):
            descriptor = {**self.descriptor, "package_id": app}
            with self.subTest(app=app), self.assertRaises(issuer.IssuerError):
                issuer.validate_descriptor(descriptor, issuer.FORMAT, "stable")

    def test_source_run_rejects_invalid_run_attempt(self):
        for attempt in (0, -1, True, "4", None):
            fetcher, _ = self.fake_fetcher(source_run(self.descriptor, run_attempt=attempt))
            with self.subTest(attempt=attempt), self.assertRaises(issuer.IssuerError):
                issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_source_attempt_is_required_positive_integer_and_must_match_api(self):
        for attempt in (0, -1, True, "4", None):
            descriptor = {**self.descriptor, "source_run_attempt": attempt}
            with self.subTest(attempt=attempt), self.assertRaises(issuer.IssuerError):
                issuer.validate_descriptor(descriptor, issuer.FORMAT, "stable")
        descriptor = {key: value for key, value in self.descriptor.items()
                      if key != "source_run_attempt"}
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_descriptor(descriptor, issuer.FORMAT, "stable")
        fetcher, _ = self.fake_fetcher(source_run(self.descriptor, run_attempt=5))
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)
        fetcher, _ = self.fake_fetcher(source_run(self.descriptor, run_attempt=None))
        with self.assertRaises(issuer.IssuerError):
            issuer.verify_source_run(self.descriptor, issuer.FORMAT, "stable", fetcher)

    def test_source_failure_precedes_parent_secret_reads_and_credential_derivation(self):
        class ParentSpy(dict):
            def get(self, key, default=None):
                if key in (issuer.PARENT_ID_ENV, issuer.PARENT_SECRET_ENV):
                    raise AssertionError("parent secrets accessed")
                return default

            def __getitem__(self, key):
                if key in (issuer.PARENT_ID_ENV, issuer.PARENT_SECRET_ENV):
                    raise AssertionError("parent secrets accessed")
                return super().__getitem__(key)

        fetcher, _ = self.fake_fetcher(source_run(self.descriptor, conclusion="failure"))
        with patch.object(issuer, "derive_credentials") as derive:
            with self.assertRaises(issuer.IssuerError):
                issuer.issue_credentials("stable", self.descriptor, ParentSpy(), fetcher=fetcher)
        derive.assert_not_called()

    def test_github_fetcher_uses_fixed_endpoint_headers_and_timeout(self):
        body = json.dumps(source_run(self.descriptor)).encode()

        class Opener:
            def open(self, request, timeout):
                self.request, self.timeout = request, timeout
                return FakeResponse(body)

        opener = Opener()
        result = issuer.fetch_source_run("luminusOS/zaptide", "321", token="fake-token", opener=opener)
        self.assertEqual(result["id"], 321)
        self.assertEqual(opener.request.full_url, "https://api.github.com/repos/luminusOS/zaptide/actions/runs/321")
        self.assertEqual(opener.timeout, issuer.GITHUB_TIMEOUT_SECONDS)
        self.assertEqual(opener.request.get_header("Accept"), "application/vnd.github+json")
        self.assertEqual(opener.request.get_header("X-github-api-version"), "2022-11-28")
        self.assertEqual(opener.request.get_header("Authorization"), "Bearer fake-token")

    def test_generic_github_fetcher_allows_only_release_read_paths(self):
        body = json.dumps({"ref": "refs/tags/v1.2.3", "object": {
            "type": "commit", "sha": "b" * 40}}).encode()

        class Opener:
            def open(self, request, timeout):
                self.request = request
                return FakeResponse(body)

        opener = Opener()
        result = issuer.fetch_github_json("/repos/luminusOS/zaptide/git/ref/tags/v1.2.3",
                                          token="fake-token", opener=opener)
        self.assertEqual(result["ref"], "refs/tags/v1.2.3")
        self.assertEqual(opener.request.full_url,
                         "https://api.github.com/repos/luminusOS/zaptide/git/ref/tags/v1.2.3")
        for path in ("/repos/luminusOS/other/git/ref/tags/v1.2.3",
                     "/repos/luminusOS/zaptide/git/ref/tags/../bad",
                     "/repos/luminusOS/zaptide/actions/runs/0"):
            with self.subTest(path=path), self.assertRaises(issuer.IssuerError):
                issuer.fetch_github_json(path, opener=opener)
        class MissingTagOpener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 404, "missing", {}, BytesIO())

        with self.assertRaises(issuer.IssuerError):
            issuer.fetch_github_json("/repos/luminusOS/zaptide/git/ref/tags/v1.2.3",
                                     opener=MissingTagOpener())

    def test_github_fetcher_refuses_redirects_and_does_not_follow_them(self):
        handler = issuer._NoRedirect()
        request = issuer.urllib_request.Request("https://api.github.com/one")
        self.assertIsNone(handler.redirect_request(request, None, 302, "Found", {}, "https://example.com"))

        class RedirectingOpener:
            def open(self, request, timeout):
                raise HTTPError(request.full_url, 302, "redirect", {}, BytesIO())

        with self.assertRaises(issuer.IssuerError):
            issuer.fetch_source_run("luminusOS/zaptide", "321", opener=RedirectingOpener())

    def test_github_fetcher_rejects_oversize_malformed_duplicate_http_and_timeout(self):
        class Opener:
            def __init__(self, result):
                self.result = result

            def open(self, request, timeout):
                if isinstance(self.result, BaseException):
                    raise self.result
                return FakeResponse(self.result)

        bodies = (b"x" * (issuer.MAX_GITHUB_RESPONSE_BYTES + 1), b"not-json",
                 b'{"id":321,"id":321}', b'{"id":NaN}')
        for body in bodies:
            with self.subTest(size=len(body)), self.assertRaises(issuer.IssuerError):
                issuer.fetch_source_run("luminusOS/zaptide", "321", opener=Opener(body))
        for error in (HTTPError("https://api.github.com/private?q=secret", 500, "bad", {}, BytesIO()),
                      URLError("timeout"), TimeoutError("timeout")):
            with self.subTest(error=type(error).__name__), self.assertRaises(issuer.IssuerError) as caught:
                issuer.fetch_source_run("luminusOS/zaptide", "321", opener=Opener(error))
            self.assertNotIn("private", str(caught.exception))
            self.assertNotIn("secret", str(caught.exception))

    def test_hmac_jwt_derivation_matches_fixed_vector(self):
        credentials = issuer.derive_credentials(
            "0123456789abcdef0123456789abcdef", "a" * 64, "flatpak", "stable", 600,
            now=1_700_000_000,
        )
        self.assertEqual(credentials["access_key_id"], "0123456789abcdef0123456789abcdef")
        self.assertEqual(credentials["expires_at"], 1_700_000_600)
        self.assertEqual(credentials["secret_access_key"], "8570185910b216910ee5f93f835aa7e0203c798401d102ac54c6b8c85d606493")
        self.assertEqual(hashlib.sha256(credentials["session_token"].encode()).hexdigest(), "10b35785738d7fa4b01b94805cf48b0e1ce8e96177192f439711d2c576bb4b6e")

    def test_request_shape_is_minimal_and_scope_is_channel_derived(self):
        request = issuer.temporary_request("0123456789abcdef0123456789abcdef", "stable", 600)
        self.assertEqual(request, {
            "parentAccessKeyId": "0123456789abcdef0123456789abcdef",
            "bucket": "luminus-flatpak", "permission": "object-read-write",
            "prefixes": ["stable/"], "ttlSeconds": 600,
        })
        self.assertNotIn("objects", request)
        self.assertNotIn("prefix", request)
        self.assertEqual(issuer.temporary_request(
            "0123456789abcdef0123456789abcdef", "testing", 600
        )["prefixes"], ["testing/"])

    def test_descriptor_rejects_scope_overrides_and_malformed_identity(self):
        for key, value in (("bucket", "other"), ("prefix", "testing/"),
                           ("prefixes", ["testing/"]), ("channel", "testing"),
                           ("format", "other-format"), ("package_id", "../bad"),
                           ("git_sha", "../sha")):
            candidate = {**self.descriptor, key: value}
            with self.subTest(key=key), self.assertRaises(issuer.IssuerError):
                issuer.validate_descriptor(candidate, "flatpak", "stable")

    def test_ttl_is_bounded_and_defaults_to_six_hundred(self):
        self.assertEqual(issuer.DEFAULT_TTL_SECONDS, 600)
        for ttl in (0, -1, 901, True, "600"):
            with self.subTest(ttl=ttl), self.assertRaises(issuer.IssuerError):
                issuer.temporary_request("a" * 32, "stable", ttl)

    def test_envelope_binds_payload_to_every_run_field_and_rejects_expiry(self):
        envelope = issuer.build_envelope(self.binding, self.descriptor,
                                         {"bucket": "luminus-flatpak", "prefix": "stable/",
                                          "permission": "object-read-write", "expires_at": 1700000600,
                                          "access_key_id": "a" * 32, "secret_access_key": "b" * 64,
                                          "session_token": "c" * 80}, now=1700000000)
        issuer.validate_envelope(envelope, self.binding, "flatpak", now=1700000001)
        for field, value in (("run_id", "12346"), ("run_attempt", "3"),
                             ("sha", "d" * 40), ("channel", "testing")):
            changed = issuer.Binding(
                self.binding.repository, value if field == "run_id" else self.binding.run_id,
                value if field == "run_attempt" else self.binding.run_attempt,
                value if field == "sha" else self.binding.sha,
                value if field == "ref" else self.binding.ref,
                value if field == "channel" else self.binding.channel,
            )
            with self.subTest(field=field), self.assertRaises(issuer.IssuerError):
                issuer.validate_envelope(envelope, changed, "flatpak", now=1700000001)
        changed = copy.deepcopy(envelope)
        changed["binding"]["ref"] = "refs/heads/other"
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_envelope(changed, self.binding, "flatpak", now=1700000001)
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_envelope(envelope, self.binding, "flatpak", now=1700000600)

    def test_envelope_rejects_tamper_wrong_type_duplicates_and_oversize(self):
        envelope = issuer.build_envelope(self.binding, self.descriptor,
                                         {"bucket": "luminus-flatpak", "prefix": "stable/",
                                          "permission": "object-read-write", "expires_at": 1700000600,
                                          "access_key_id": "a" * 32, "secret_access_key": "b" * 64,
                                          "session_token": "c" * 80}, now=1700000000)
        changed = copy.deepcopy(envelope)
        changed["payload"]["prefix"] = "testing/"
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_envelope(changed, self.binding, "flatpak", now=1700000001)
        with self.assertRaises(issuer.IssuerError):
            issuer.decode_envelope(b'{"kind":"x","kind":"y"}')
        with self.assertRaises(issuer.IssuerError):
            issuer.decode_envelope(b"x" * (issuer.MAX_PLAINTEXT_BYTES + 1))
        changed = copy.deepcopy(envelope)
        changed["iat"] = True
        with self.assertRaises(issuer.IssuerError):
            issuer.validate_envelope(changed, self.binding, "flatpak", now=1700000001)

    def test_publisher_refuses_parent_variables_even_when_empty(self):
        for name in (issuer.PARENT_ID_ENV, issuer.PARENT_SECRET_ENV):
            with self.subTest(name=name), self.assertRaises(issuer.IssuerError):
                issuer.ensure_consumer_has_no_parent({name: ""})

    def test_secrets_do_not_appear_in_errors_or_cli_streams(self):
        canaries = ("canary-parent-id-123456789012", "canary-parent-secret-" + "x" * 44)
        fetcher, _ = self.fake_fetcher()
        with self.assertRaises(issuer.IssuerError) as caught:
            issuer.issue_credentials("stable", self.descriptor,
                                     {issuer.PARENT_ID_ENV: canaries[0], issuer.PARENT_SECRET_ENV: canaries[1]},
                                     fetcher=fetcher)
        text = str(caught.exception)
        for canary in canaries:
            self.assertNotIn(canary, text)

    def test_capsule_file_is_exclusive_private_and_symlink_safe(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory, "credentials.gpg")
            issuer.write_private_file(path, b"ciphertext")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            with self.assertRaises(issuer.IssuerError):
                issuer.write_private_file(path, b"replacement")
            target = Path(directory, "target")
            link = Path(directory, "link")
            target.write_bytes(b"safe")
            link.symlink_to(target)
            with self.assertRaises(issuer.IssuerError):
                issuer.write_private_file(link, b"no")

    def test_synthetic_sigv4_self_test_builds_scoped_put_without_network(self):
        credentials = {
            "bucket": "luminus-flatpak", "prefix": "stable/",
            "permission": "object-read-write", "expires_at": 1700000600,
            "access_key_id": "a" * 32, "secret_access_key": "b" * 64,
            "session_token": "c" * 80,
        }
        result = issuer.sigv4_self_test(credentials, "stable", now=1700000000)
        self.assertEqual(result["method"], "PUT")
        self.assertEqual(result["path"], "/luminus-flatpak/stable/self-test")
        self.assertIn("x-amz-security-token", result["signed_headers"])
        self.assertNotIn("http", json.dumps(result))

    def test_confidential_capsule_round_trip_validates_and_rejects_ciphertext_tampering(self):
        credentials = {
            "bucket": "luminus-flatpak", "prefix": "stable/",
            "permission": "object-read-write", "expires_at": 1700000600,
            "access_key_id": "a" * 32, "secret_access_key": "b" * 64,
            "session_token": "c" * 80,
        }
        envelope = issuer.build_envelope(self.binding, self.descriptor, credentials, now=1700000000)
        key = "d" * 64
        ciphertext = issuer.transport.encrypt_envelope(envelope, key)
        decoded = issuer.transport.decrypt_envelope(ciphertext, key)
        issuer.validate_envelope(decoded, self.binding, "flatpak", now=1700000001)
        self.assertEqual(decoded["payload"], credentials)
        damaged = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])
        with self.assertRaises(issuer.transport.TransportError):
            issuer.transport.decrypt_envelope(damaged, key)

    def test_cli_suppresses_parent_secret_from_both_streams(self):
        parent_id = "a" * 32
        parent_secret = "canary-secret-" + "x" * 50
        environment = {
            "GITHUB_REPOSITORY": "luminusOS/flatpak-repo", "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/main", "TRANSPORT_KEY": "c" * 64,
            issuer.PARENT_ID_ENV: parent_id, issuer.PARENT_SECRET_ENV: parent_secret,
        }
        fetcher, _ = self.fake_fetcher()
        stdout, stderr = StringIO(), StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stdout(stdout), redirect_stderr(stderr):
            result = issuer.run_cli([
                "issue", "--channel", "stable", "--package-id", self.descriptor["package_id"],
                "--version", "1.2.3", "--git-sha", "b" * 40,
                "--source-run-id", "321", "--source-run-attempt", "4",
                "--output", str(Path(directory, "capsule")),
            ], environment, fetcher=fetcher)
        self.assertEqual(result, 1)
        for canary in (parent_id, parent_secret):
            self.assertNotIn(canary, stdout.getvalue())
            self.assertNotIn(canary, stderr.getvalue())
        self.assertIn("credential issuer failed; Parent secret is invalid", stderr.getvalue())

    def test_error_raise_sites_use_static_messages(self):
        for filename in ("issuer.py", "credential_transport.py"):
            tree = ast.parse((ROOT / "tools" / filename).read_text())
            for node in ast.walk(tree):
                if not isinstance(node, ast.Raise) or not isinstance(node.exc, ast.Call):
                    continue
                func = node.exc.func
                if not isinstance(func, ast.Name) or func.id not in ("IssuerError", "TransportError"):
                    continue
                with self.subTest(filename=filename, line=node.lineno):
                    self.assertTrue(node.exc.args)
                    message = node.exc.args[0]
                    self.assertIsInstance(message, ast.Constant)
                    self.assertIsInstance(message.value, str)

    def test_cli_prints_static_transport_error_text(self):
        environment = {
            "GITHUB_REPOSITORY": "luminusOS/flatpak-repo", "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "2", "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/main", "TRANSPORT_KEY": "canary-invalid-key",
        }
        stderr = StringIO()
        with tempfile.TemporaryDirectory() as directory, redirect_stderr(stderr):
            result = issuer.run_cli([
                "consume", "--channel", "stable", "--input", str(Path(directory, "in")),
                "--output", str(Path(directory, "out")),
            ], environment)
        self.assertEqual(result, 1)
        self.assertIn("credential issuer failed; Secret must be a 64-character hexadecimal value",
                      stderr.getvalue())
        self.assertNotIn("canary-invalid-key", stderr.getvalue())

    def test_workflow_is_dispatch_only_and_secrets_are_role_scoped(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/r2-credential-check.yml").read_text())
        self.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
        serialized = json.dumps(workflow)
        for forbidden in ("pull_request", "pull_request_target", "workflow_run", "secrets: inherit", "set -x"):
            self.assertNotIn(forbidden, serialized)
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertIn("${{ inputs.channel }}", workflow["concurrency"]["group"])
        self.assertEqual(set(workflow["on"]["workflow_dispatch"]["inputs"]),
                         {"channel", "package_id", "version", "git_sha", "source_run_id",
                          "source_run_attempt", "live_probe", "ttl_seconds", "expiry_check"})
        self.assertEqual(workflow["on"]["workflow_dispatch"]["inputs"]["source_run_attempt"],
                         {"description": "Source workflow run attempt", "required": True,
                          "type": "string"})
        allowed_actions = {
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
            "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
        }
        for job_name, job in workflow["jobs"].items():
            if job_name != "checks":
                self.assertIn("refs/heads/main", job["if"])
                self.assertIn("github.ref_protected", job["if"])
            for step in job["steps"]:
                if "uses" in step:
                    self.assertIn(step["uses"], allowed_actions)
                    self.assertNotIn("repository", step.get("with", {}))
                self.assertNotIn("GITHUB_OUTPUT", step.get("run", ""))
                self.assertNotIn("set -x", step.get("run", ""))
                self.assertNotIn("${{ inputs.", step.get("run", ""))
            self.assertNotIn("outputs", job)
        uploads = [step for job in workflow["jobs"].values() for step in job["steps"]
                   if step.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(uploads), 2)
        self.assertTrue(all(step["with"]["retention-days"] == 1 for step in uploads))
        parent_references = [name for name, job in workflow["jobs"].items()
                             if "secrets.R2_PARENT_" in json.dumps(job)]
        self.assertEqual(set(parent_references), {"issuer-stable", "issuer-testing"})
        token_references = [name for name, job in workflow["jobs"].items()
                            if "secrets.GITHUB_TOKEN" in json.dumps(job)]
        self.assertEqual(set(token_references), {"issuer-stable", "issuer-testing"})
        for name, job in workflow["jobs"].items():
            if "TRANSPORT_KEY" in json.dumps(job):
                self.assertTrue(name.startswith(("issuer-", "publisher-")))
        for channel in ("stable", "testing"):
            self.assertEqual(workflow["jobs"][f"issuer-{channel}"]["environment"], f"issuer-{channel}")
            self.assertEqual(workflow["jobs"][f"publisher-{channel}"]["environment"], f"publisher-{channel}")
            for role in ("issuer", "publisher"):
                job = workflow["jobs"][f"{role}-{channel}"]
                self.assertTrue(any("secrets.TRANSPORT_KEY" in json.dumps(step)
                                    for step in job["steps"]))
                if role == "publisher":
                    self.assertNotIn("GITHUB_TOKEN", json.dumps(job))
        self.assertEqual(workflow["on"]["workflow_dispatch"]["inputs"]["channel"]["type"], "choice")
        inputs = workflow["on"]["workflow_dispatch"]["inputs"]
        self.assertEqual(inputs["live_probe"]["type"], "boolean")
        self.assertFalse(inputs["live_probe"]["default"])
        self.assertEqual(inputs["ttl_seconds"]["options"], ["300", "600"])
        self.assertEqual(inputs["expiry_check"]["type"], "boolean")
        for channel in ("stable", "testing"):
            issuer_steps = workflow["jobs"][f"issuer-{channel}"]["steps"]
            issue = next(step for step in issuer_steps if step.get("name", "").startswith("Issue and encrypt"))
            self.assertIn("${{ inputs.ttl_seconds }}", json.dumps(issue))
            self.assertIn("inputs.expiry_check", json.dumps(issue))
            self.assertIn('!= "300"', issue["run"])
            publisher = workflow["jobs"][f"publisher-{channel}"]
            probe_steps = [step for step in publisher["steps"] if step.get("name") == "Run live R2 scope probe"]
            self.assertEqual(len(probe_steps), 1)
            self.assertEqual(probe_steps[0]["if"], "${{ inputs.live_probe }}")
            serialized_probe = json.dumps(probe_steps[0])
            self.assertIn("$RUNNER_TEMP/check-credentials.json", serialized_probe)
            self.assertNotIn("secrets.", serialized_probe)
            self.assertIn("inputs.expiry_check", serialized_probe)
            self.assertEqual(probe_steps[0]["env"]["RELEASE_EXPIRY_CHECK"], "${{ inputs.expiry_check }}")
            self.assertIn('= "true"', probe_steps[0]["run"])
            self.assertIn("always()", json.dumps(publisher["steps"]))


if __name__ == "__main__":
    unittest.main()

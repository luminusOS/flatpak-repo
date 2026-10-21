import contextlib
import io
import os
import re
import subprocess
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import signing_environment


ROOT = Path(__file__).resolve().parents[1]
CANARY = "disposable-canary-value"
REPOSITORY = "luminusOS/flatpak-repo"


def valid_environment(**overrides):
    values = {
        "T06_GITHUB_REPOSITORY": "luminusOS/flatpak-repo",
        "T06_GITHUB_REF": "refs/heads/main",
        "T06_GITHUB_REF_PROTECTED": "true",
        "T06_GITHUB_EVENT_NAME": "workflow_dispatch",
        "T06_ENVIRONMENT": "issuer-stable",
        "T06_CANARY": CANARY,
        "T06_CANARY_SHA256": "2b8fe48f2f758de7a9f3f43239da7c316784e6db55e1a5999758b70abdcd8e74",
    }
    values.update(overrides)
    return values


def workflow_job(workflow, job_id):
    match = re.search(
        rf"(?ms)^  {re.escape(job_id)}:\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", workflow,
    )
    if match is None:
        raise AssertionError(f"workflow job missing: {job_id}")
    return match.group(1)


def assert_dispatch_job_gate(job_id, block):
    match = re.search(r"(?m)^    if:\s*>-\s*\n((?:^      .*\n)+)", block)
    if match is None:
        raise AssertionError(f"dispatch gate missing: {job_id}")
    actual = " ".join(line.strip() for line in match.group(1).splitlines())
    expected = "github.event_name == 'workflow_dispatch' && " \
        f"github.repository == '{REPOSITORY}' && " \
        "github.ref == 'refs/heads/main' && github.ref_protected"
    if job_id == "verify-disposable-canary":
        expected = "needs.authorize-dispatch.result == 'success' && " + expected
    if actual != expected:
        raise AssertionError(f"dispatch gate differs from policy: {job_id}")


class SigningEnvironmentTests(unittest.TestCase):
    def test_validates_only_this_repo_main_dispatch_and_exact_environment(self):
        self.assertTrue(signing_environment.validate_context(
            valid_environment(), "issuer", "stable"))

    def test_rejects_untrusted_repository_ref_event_environment_and_channel(self):
        for overrides, role, channel in (
            ({"T06_GITHUB_REPOSITORY": "attacker/fork"}, "issuer", "stable"),
            ({"T06_GITHUB_REF": "refs/pull/1/merge"}, "issuer", "stable"),
            ({"T06_GITHUB_REF_PROTECTED": "false"}, "issuer", "stable"),
            ({"T06_GITHUB_EVENT_NAME": "pull_request"}, "issuer", "stable"),
            ({"T06_ENVIRONMENT": "issuer-testing"}, "issuer", "stable"),
            ({}, "publisher", "stable"),
            ({}, "issuer", "preview"),
        ):
            with self.subTest(overrides=overrides, role=role, channel=channel), \
                    self.assertRaises(ValueError):
                signing_environment.validate_context(
                    valid_environment(**overrides), role, channel)

    def test_rejects_missing_malformed_or_mismatched_canary_without_disclosing_it(self):
        for overrides in (
            {"T06_CANARY": ""},
            {"T06_CANARY_SHA256": "not-a-digest"},
            {"T06_CANARY_SHA256": "0" * 64},
        ):
            with self.subTest(overrides=overrides), self.assertRaises(ValueError):
                signing_environment.validate_canary(valid_environment(**overrides))

        with patch.dict(os.environ, valid_environment(), clear=True):
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                result = subprocess.run(
                    [sys.executable, "-B", "tools/signing_environment.py",
                     "check", "--role", "issuer", "--channel", "stable"],
                    cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
                )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(CANARY, result.stdout)
        self.assertNotIn(CANARY, result.stderr)

    def test_workflow_keeps_pull_request_jobs_secretless_and_dispatch_restricted(self):
        workflow = (ROOT / ".github/workflows/t06-signing-gates.yml").read_text()
        pr_job = workflow_job(workflow, "pull-request-denial")
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("environment:", pr_job)
        self.assertNotIn("secrets.", pr_job)
        self.assertNotIn("actions/checkout", pr_job)
        self.assertNotIn("${{ inputs.", pr_job)

        for job_id in ("authorize-dispatch", "verify-disposable-canary"):
            assert_dispatch_job_gate(job_id, workflow_job(workflow, job_id))
        self.assertIn("T06_CANARY", workflow)
        self.assertIn("install -d -m 700 /tmp/opencode", workflow)
        self.assertLess(workflow.index("install -d -m 700 /tmp/opencode"),
                        workflow.index("Run repository tests"))

    def test_each_dispatch_job_rejects_a_weakened_main_ref_guard(self):
        workflow = (ROOT / ".github/workflows/t06-signing-gates.yml").read_text()
        for job_id in ("authorize-dispatch", "verify-disposable-canary"):
            with self.subTest(job_id=job_id):
                block = workflow_job(workflow, job_id)
                weakened = block.replace(
                    "github.ref == 'refs/heads/main'",
                    "startsWith(github.ref, 'refs/heads/')",
                    1,
                )
                self.assertNotEqual(block, weakened)
                with self.assertRaisesRegex(AssertionError, "differs from policy"):
                    assert_dispatch_job_gate(job_id, weakened)


if __name__ == "__main__":
    unittest.main()

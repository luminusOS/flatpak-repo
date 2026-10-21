import json
import subprocess
import sys
import unittest
from pathlib import Path

from tools import signing


ROOT = Path(__file__).resolve().parents[1]


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.policy = json.loads((ROOT / "signing-policy.json").read_text(encoding="utf-8"))

    def test_policy_is_closed_and_matches_this_repository(self):
        self.assertEqual(signing.validate_policy(self.policy), self.policy)
        for mutate in (
            lambda value: value.pop("status"),
            lambda value: value.update(unreviewed=True),
            lambda value: value.update(format="rpm"),
            lambda value: value.update(reviewer_team="luminusOS/other"),
            lambda value: value.update(channels=["stable"]),
            lambda value: value.update(status="provisioned"),
            lambda value: value.update(gpg_algorithm="RSA4096"),
        ):
            changed = json.loads(json.dumps(self.policy))
            mutate(changed)
            with self.subTest(policy=changed), self.assertRaises(ValueError):
                signing.validate_policy(changed)

    def test_claims_reject_other_formats_and_unknown_channels(self):
        for artifact_format, channel in (("rpm", "stable"), ("flatpak", "preview")):
            with self.subTest(format=artifact_format, channel=channel), self.assertRaises(ValueError):
                signing.validate_claim(self.policy, artifact_format, channel)

    def test_validate_cli_emits_only_public_policy_status(self):
        result = subprocess.run(
            [sys.executable, "-B", "tools/signing.py", "validate"],
            cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "valid_unprovisioned_policy")
        self.assertEqual(report["format"], "flatpak")
        self.assertEqual(result.stderr, "")

    def test_rehearsal_uses_four_isolated_disposable_identities(self):
        result = subprocess.run(
            [sys.executable, "-B", "tools/signing.py", "rehearse"],
            cwd=ROOT, capture_output=True, text=True, check=False, timeout=300,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, "")
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "rehearsal_passed")
        self.assertEqual(len(report["fixtures"]), 4)
        self.assertEqual(len({item["primary_fingerprint"] for item in report["fixtures"]}), 4)
        expected_checks = {
            "isolated_public_verification", "wrong_trust_roots_rejected", "exact_signing_subkey",
            "ci_has_subkey_only", "full_private_export_rejected", "tampering_rejected",
            "revocation_rejected",
        }
        for item in report["fixtures"]:
            self.assertEqual(set(item["checks"]), expected_checks)
            self.assertTrue(all(value is True for value in item["checks"].values()))
            self.assertEqual(item["signature_hash_algorithm"], "SHA256")
            self.assertEqual(item["signature_hash_algorithm_id"], 8)
        accepted = {(item["format"], item["channel"])
                    for item in report["fixtures"] if item["policy_accepts_this_claim"] is True}
        self.assertEqual(accepted, {("flatpak", "stable"), ("flatpak", "testing")})
        matrix = report["trust_matrix"]
        self.assertEqual(len(matrix), 16)
        self.assertTrue(all(cell["accepted"] is
                            (cell["signer_primary_fingerprint"] == cell["verifier_primary_fingerprint"])
                            for cell in matrix))
        output = result.stdout.lower()
        for forbidden in ("private key", "private-key", "passphrase", "secret material"):
            self.assertNotIn(forbidden, output)


if __name__ == "__main__":
    unittest.main()

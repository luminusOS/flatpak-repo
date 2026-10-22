import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

from tools import trust


ROOT = Path(__file__).resolve().parents[1]
PYTHON = "/tmp/opencode/luminus-t06-venv/bin/python"


def run_gpg(home, *arguments):
    env = {key: value for key, value in os.environ.items()
           if key != "GNUPGHOME" and not key.startswith("GPG_")}
    env["LC_ALL"] = "C"
    result = subprocess.run(
        ["gpg", "--homedir", str(home), "--no-options", "--no-auto-key-retrieve",
         "--batch", "--pinentry-mode", "loopback", "--passphrase", "", *arguments],
        capture_output=True, timeout=90, env=env,
    )
    if result.returncode:
        raise AssertionError("disposable GnuPG fixture operation failed")
    return result.stdout


def fixture(root, name, primary_usage="cert", subkeys=("sign",), algorithm="rsa3072",
            revoke_primary=False, revoke_subkey=False, validity="1y"):
    home = root / f"home-{name}"
    home.mkdir(mode=0o700)
    uid = f"Disposable {name} <{name}@example.invalid>"
    run_gpg(home, "--quick-generate-key", uid, algorithm, primary_usage, validity)
    primary = trust.read_fingerprints(home)[0]["fingerprint"]
    for usage in subkeys:
        run_gpg(home, "--quick-add-key", primary, algorithm, usage, validity)
    if revoke_primary:
        revocation = home / "openpgp-revocs.d" / f"{primary}.rev"
        content = revocation.read_bytes().replace(
            b":-----BEGIN PGP PUBLIC KEY BLOCK-----", b"-----BEGIN PGP PUBLIC KEY BLOCK-----", 1)
        revocation_file = root / f"{name}-revocation.asc"
        revocation_file.write_bytes(content)
        run_gpg(home, "--import", str(revocation_file))
    if revoke_subkey:
        result = subprocess.run(
            ["gpg", "--homedir", str(home), "--no-options", "--batch", "--yes",
             "--pinentry-mode", "loopback", "--passphrase", "", "--command-fd", "0",
             "--edit-key", primary], input="key 1\nrevkey\ny\n1\ncompromised\n\ny\nsave\n",
            capture_output=True, text=True, timeout=90,
            env={key: value for key, value in os.environ.items()
                 if key != "GNUPGHOME" and not key.startswith("GPG_")},
        )
        if result.returncode:
            raise AssertionError("disposable subkey revocation fixture failed")
    keys = root / f"{name}.gpg"
    run_gpg(home, "--output", str(keys), "--export", primary)
    records = trust.read_fingerprints(home)
    signing = next((item["fingerprint"] for item in records if item["type"] == "sub"), None)
    return {"home": home, "path": keys, "primary": primary, "signing": signing}


class TrustTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="luminus-trust-tests-", dir="/tmp/opencode")
        os.chmod(cls.temp.name, 0o700)
        cls.root = Path(cls.temp.name)
        cls.homes = []
        cls.good = fixture(cls.root, "good")
        cls.other = fixture(cls.root, "other")
        cls.primary_signer = fixture(cls.root, "primary-signer", "sign")
        cls.no_subkey = fixture(cls.root, "no-subkey", subkeys=())
        cls.two_signers = fixture(cls.root, "two-signers", subkeys=("sign", "sign"))
        cls.extra_encrypt = fixture(cls.root, "extra-encrypt", subkeys=("sign", "encrypt"))
        cls.weak = fixture(cls.root, "weak", algorithm="rsa2048")
        cls.revoked = fixture(cls.root, "revoked", revoke_primary=True)
        cls.revoked_subkey = fixture(cls.root, "revoked-subkey", revoke_subkey=True)
        cls.homes.extend(item["home"] for item in (
            cls.good, cls.other, cls.primary_signer, cls.no_subkey, cls.two_signers,
            cls.extra_encrypt, cls.weak, cls.revoked, cls.revoked_subkey,
        ))

    @classmethod
    def tearDownClass(cls):
        for home in cls.homes:
            subprocess.run(["gpgconf", "--homedir", str(home), "--kill", "gpg-agent"],
                           capture_output=True, timeout=5)
        cls.temp.cleanup()

    def setUp(self):
        self.doc = {
            "schema_version": 1,
            "format": trust.FORMAT,
            "status": "provisioned",
            "max_validity_days": 400,
            "channels": {
                "stable": {"primary_fingerprint": self.good["primary"],
                           "signing_subkey_fingerprint": self.good["signing"],
                           "public_key": "trust/stable.gpg"},
                "testing": {"primary_fingerprint": self.other["primary"],
                            "signing_subkey_fingerprint": self.other["signing"],
                            "public_key": "trust/testing.gpg"},
            },
        }

    def unprovisioned_manifest(self):
        return {"schema_version": 1, "format": trust.FORMAT, "status": "unprovisioned",
                "max_validity_days": 400, "channels": {"stable": None, "testing": None}}

    def test_unprovisioned_manifest_is_valid(self):
        doc = self.unprovisioned_manifest()
        self.assertEqual(trust.validate_manifest(doc)["format"], trust.FORMAT)

    def test_committed_manifest_validates_through_the_cli_with_public_output_only(self):
        result = subprocess.run([PYTHON, "-B", "tools/trust.py", "validate"], cwd=ROOT,
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn(report["status"], ("valid_unprovisioned", "valid_provisioned"))
        self.assertEqual(report["format"], trust.FORMAT)
        self.assertEqual(result.stderr, "")
        self.assertNotIn("BEGIN PGP", result.stdout)

    def test_committed_provisioned_manifest_declares_two_distinct_one_year_identities(self):
        doc = json.loads((ROOT / "trust.json").read_text())
        if doc["status"] == "unprovisioned":
            self.skipTest("trust.json is still unprovisioned")
        self.assertEqual(doc["max_validity_days"], 400)
        stable, testing = doc["channels"]["stable"], doc["channels"]["testing"]
        values = [stable["primary_fingerprint"], stable["signing_subkey_fingerprint"],
                  testing["primary_fingerprint"], testing["signing_subkey_fingerprint"]]
        self.assertEqual(len(set(values)), 4)
        self.assertEqual(stable["public_key"], "trust/stable.asc")
        self.assertEqual(testing["public_key"], "trust/testing.asc")

    def test_closed_schema_rejects_wrong_types_and_duplicates(self):
        for mutate in (
            lambda d: d.update(unknown=True),
            lambda d: d.update(max_validity_days=True),
            lambda d: d.update(max_validity_days=401),
            lambda d: d.update(max_validity_days=0),
            lambda d: d.update(schema_version=True),
            lambda d: d["channels"].update(extra=None),
        ):
            changed = json.loads(json.dumps(self.doc))
            mutate(changed)
            with self.assertRaises(ValueError):
                trust.validate_manifest(changed)
        with self.assertRaises(ValueError):
            trust.parse_json(b'{"schema_version":1,"schema_version":1}')
        accepted = json.loads(json.dumps(self.doc))
        accepted["max_validity_days"] = 400
        self.assertEqual(trust.validate_manifest(accepted), accepted)

    def test_unprovisioned_requires_null_channels(self):
        doc = self.unprovisioned_manifest()
        doc["channels"]["stable"] = self.doc["channels"]["stable"]
        with self.assertRaises(ValueError):
            trust.validate_manifest(doc)

    def test_provisioned_channel_set_and_fingerprints_are_exact(self):
        self.assertEqual(trust.validate_manifest(self.doc), self.doc)
        for field, value in (("primary_fingerprint", self.good["primary"].lower()),
                             ("signing_subkey_fingerprint", "1234")):
            changed = json.loads(json.dumps(self.doc))
            changed["channels"]["stable"][field] = value
            with self.assertRaises(ValueError):
                trust.validate_manifest(changed)

    def test_provisioned_manifest_rejects_missing_channel(self):
        changed = json.loads(json.dumps(self.doc))
        changed["channels"].pop("testing")
        with self.assertRaises(ValueError):
            trust.validate_manifest(changed)

    def test_key_paths_reject_traversal_absolute_symlink_and_non_regular_files(self):
        for path in ("../stable.gpg", "/tmp/stable.gpg", "trust/../x.gpg"):
            changed = json.loads(json.dumps(self.doc))
            changed["channels"]["stable"]["public_key"] = path
            with self.assertRaises(ValueError):
                trust.validate_manifest(changed)
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            base = Path(temp)
            (base / "trust").mkdir()
            (base / "real.gpg").write_bytes(b"x")
            (base / "trust" / "stable.gpg").symlink_to(base / "real.gpg")
            with self.assertRaises(ValueError):
                trust.resolve_key_path(base, "trust/stable.gpg")

    def test_channels_must_not_share_any_root_or_subkey(self):
        changed = json.loads(json.dumps(self.doc))
        changed["channels"]["testing"]["primary_fingerprint"] = self.good["primary"]
        with self.assertRaises(ValueError):
            trust.validate_manifest(changed)
        changed = json.loads(json.dumps(self.doc))
        changed["channels"]["testing"]["signing_subkey_fingerprint"] = self.good["signing"]
        with self.assertRaises(ValueError):
            trust.validate_manifest(changed)

    def test_other_repository_fingerprints_cannot_collide(self):
        with self.assertRaises(ValueError):
            trust.compare_fingerprints(self.doc, [self.good["signing"]])

    def test_public_key_verification_and_public_only_signature_proof(self):
        report = trust.verify_key(self.good["path"], self.good["primary"], self.good["signing"],
                                  400, now=int(time.time()))
        self.assertEqual(report["primary_fingerprint"], self.good["primary"])
        payload = self.root / "payload"
        signature = self.root / "payload.sig"
        payload.write_bytes(b"synthetic verifier fixture\n")
        run_gpg(self.good["home"], "--local-user", self.good["signing"] + "!",
                "--detach-sign", "--output", str(signature), str(payload))
        self.assertTrue(trust.verify_signature(self.good["path"], signature, payload,
                                               self.good["primary"], self.good["signing"]))

    def test_verify_key_cli_reports_only_public_metadata(self):
        result = subprocess.run(
            [PYTHON, "-B", "tools/trust.py", "verify-key", "--channel", "stable",
             "--file", str(self.good["path"]), "--primary", self.good["primary"],
             "--subkey", self.good["signing"]],
            cwd=ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "valid")
        self.assertEqual(report["primary_fingerprint"], self.good["primary"])
        self.assertEqual(report["channel"], "stable")
        self.assertEqual(result.stderr, "")

    def test_swapped_fingerprints_secret_and_non_key_inputs_are_rejected(self):
        with self.assertRaises((ValueError, RuntimeError)):
            trust.verify_key(self.good["path"], self.other["primary"], self.good["signing"], 400)
        secret = self.root / "secret.gpg"
        run_gpg(self.good["home"], "--output", str(secret), "--export-secret-keys", self.good["primary"])
        with self.assertRaisesRegex(ValueError, "secret key material is forbidden"):
            trust.verify_key(secret, self.good["primary"], self.good["signing"], 400)
        garbage = self.root / "garbage.gpg"
        garbage.write_bytes(b"not an OpenPGP key")
        with self.assertRaises((ValueError, RuntimeError)):
            trust.verify_key(garbage, self.good["primary"], self.good["signing"], 400)

    def test_declared_fingerprints_must_match_the_imported_key(self):
        with self.assertRaises((ValueError, RuntimeError)):
            trust.verify_key(self.good["path"], self.other["primary"], self.good["signing"], 400)

    def test_secret_key_material_is_rejected(self):
        secret = self.root / "secret-only-test.gpg"
        run_gpg(self.good["home"], "--output", str(secret), "--export-secret-keys", self.good["primary"])
        with self.assertRaisesRegex(ValueError, "secret key material is forbidden"):
            trust.verify_key(secret, self.good["primary"], self.good["signing"], 400)

    def test_multiple_public_key_blocks_are_rejected(self):
        combined = self.root / "multiple-keys.gpg"
        combined.write_bytes(self.good["path"].read_bytes() + self.other["path"].read_bytes())
        with self.assertRaises(ValueError):
            trust.verify_key(combined, self.good["primary"], self.good["signing"], 400)

    def test_primary_signing_capability_and_missing_signing_subkey_are_rejected(self):
        with self.assertRaises(ValueError):
            trust.verify_key(self.primary_signer["path"], self.primary_signer["primary"],
                             self.primary_signer["signing"], 400)
        with self.assertRaises(ValueError):
            trust.verify_key(self.no_subkey["path"], self.no_subkey["primary"],
                             self.no_subkey["primary"], 400)

    def test_extra_signing_or_encryption_subkeys_are_rejected(self):
        for candidate in (self.two_signers, self.extra_encrypt):
            with self.subTest(key=candidate["primary"]), self.assertRaises(ValueError):
                trust.verify_key(candidate["path"], candidate["primary"], candidate["signing"], 400)

    def test_weak_rsa_primary_and_subkey_are_rejected(self):
        with self.assertRaises(ValueError):
            trust.verify_key(self.weak["path"], self.weak["primary"], self.weak["signing"], 400)

    def test_oversized_manifest_and_key_are_rejected(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            path = Path(temp) / "large.gpg"
            path.write_bytes(b"x" * (256 * 1024 + 1))
            with self.assertRaises(ValueError):
                trust.verify_key(path, self.good["primary"], self.good["signing"], 400)
        with self.assertRaises(ValueError):
            trust.parse_json(b" " * (1024 * 1024 + 1))

    def test_declared_expiry_bound_is_enforced_with_injected_time(self):
        report = trust.verify_key(self.good["path"], self.good["primary"], self.good["signing"],
                                  400, now=trust.key_creation_epoch(self.good["path"]) + 1)
        self.assertEqual(report["status"], "valid")

    def test_expired_keys_are_rejected_at_an_injected_time(self):
        with self.assertRaises(ValueError):
            trust.verify_key(self.good["path"], self.good["primary"], self.good["signing"],
                             400, now=trust.key_expiration_epoch(self.good["path"]) + 1)

    def test_revoked_primary_is_rejected(self):
        with self.assertRaises(ValueError):
            trust.verify_key(self.revoked["path"], self.revoked["primary"],
                             self.revoked["signing"], 400)

    def test_revoked_signing_subkey_is_rejected(self):
        with self.assertRaises(ValueError):
            trust.verify_key(self.revoked_subkey["path"], self.revoked_subkey["primary"],
                             self.revoked_subkey["signing"], 400)

    def test_one_year_key_passes_and_401_day_key_fails(self):
        report = trust.verify_key(self.good["path"], self.good["primary"], self.good["signing"],
                                  400, now=int(time.time()))
        self.assertEqual(report["status"], "valid")
        for maximum in (0, 401):
            with self.assertRaises(ValueError):
                trust.verify_key(self.good["path"], self.good["primary"],
                                 self.good["signing"], maximum)
        long_key = fixture(self.root, "long-validity", validity="2y")
        self.homes.append(long_key["home"])
        with self.assertRaisesRegex(ValueError, "validity exceeds"):
            trust.verify_key(long_key["path"], long_key["primary"], long_key["signing"],
                             400, now=int(time.time()))

    def test_key_read_is_bounded_and_rejects_symlinks_and_non_regular_files(self):
        with tempfile.TemporaryDirectory(dir="/tmp/opencode") as temp:
            root = Path(temp)
            large = root / "large.gpg"
            with large.open("wb") as stream:
                stream.truncate(64 * 1024 * 1024)
            real_read = trust.os.read
            requested = []

            def bounded_read(fd, size):
                requested.append(size)
                return real_read(fd, size)

            with mock.patch.object(trust.os, "read", side_effect=bounded_read):
                with self.assertRaises(ValueError):
                    trust._single_public_block(large)
            self.assertEqual(requested, [trust.MAX_KEY_BYTES + 1])

            requested.clear()
            with mock.patch.object(trust.os, "read", side_effect=bounded_read):
                with self.assertRaises(ValueError):
                    trust.verify_key(large, self.good["primary"], self.good["signing"], 400)
            self.assertEqual(requested, [trust.MAX_KEY_BYTES + 1])

            link = root / "key-link.gpg"
            link.symlink_to(self.good["path"])
            with self.assertRaises(ValueError):
                trust._single_public_block(link)

            fifo = root / "key.fifo"
            os.mkfifo(fifo)
            check_fifo = subprocess.run(
                [PYTHON, "-B", "-c",
                 "import sys\nfrom tools import trust\ntry:\n"
                 "    trust._single_public_block(sys.argv[1])\n"
                 "except ValueError:\n    sys.exit(0)\nsys.exit(1)\n",
                 str(fifo)], cwd=ROOT, capture_output=True, timeout=5,
            )
            self.assertEqual(check_fifo.returncode, 0, check_fifo.stderr)


if __name__ == "__main__":
    unittest.main()

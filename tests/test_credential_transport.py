import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import credential_transport as transport


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.binding = transport.Binding(
            repository="luminusOS/flatpak-repo",
            run_id="12345",
            run_attempt="2",
            sha="a" * 40,
            ref="refs/heads/main",
            channel="stable",
        )

    def test_round_trip_envelope_contains_only_synthetic_derived_value(self):
        envelope = transport.build_envelope(self.binding, "b" * 64, now=1000)
        validated = transport.validate_envelope(envelope, self.binding, now=1100)

        self.assertEqual(validated["temporary_secret"], transport.derive_temporary_secret(
            "b" * 64, self.binding, envelope["nonce"]
        ))
        self.assertEqual(envelope["parent_commitment"], transport.parent_commitment("b" * 64))
        self.assertNotIn("b" * 64, json.dumps(envelope))
        self.assertTrue(envelope["synthetic"])

    def test_rejects_parent_secret_in_publisher_environment_even_when_empty(self):
        with mock.patch.dict(os.environ, {"T02_PARENT_CANARY": ""}, clear=False):
            with self.assertRaises(transport.TransportError):
                transport.ensure_publisher_has_no_parent_canary()

    def test_rejects_unknown_fields_and_invalid_channel(self):
        envelope = transport.build_envelope(self.binding, "b" * 64, now=1000)
        with self.assertRaises(transport.TransportError):
            transport.validate_envelope({**envelope, "extra": True}, self.binding, now=1001)
        with self.assertRaises(transport.TransportError):
            transport.Binding(**{**self.binding.__dict__, "channel": "preview"})

    def test_rejects_expired_future_and_binding_mismatch(self):
        envelope = transport.build_envelope(self.binding, "b" * 64, now=1000)
        with self.assertRaises(transport.TransportError):
            transport.validate_envelope(envelope, self.binding, now=1301)
        with self.assertRaises(transport.TransportError):
            transport.validate_envelope(envelope, self.binding, now=900)
        other = transport.Binding(**{**self.binding.__dict__, "run_attempt": "3"})
        with self.assertRaises(transport.TransportError):
            transport.validate_envelope(envelope, other, now=1001)
        for field, value in (("sha", "b" * 40), ("channel", "testing")):
            other = transport.Binding(**{**self.binding.__dict__, field: value})
            with self.subTest(binding=field), self.assertRaises(transport.TransportError):
                transport.validate_envelope(envelope, other, now=1001)
        changed_ref = {**envelope, "binding": {**envelope["binding"], "ref": "refs/heads/elsewhere"}}
        with self.assertRaises(transport.TransportError):
            transport.validate_envelope(changed_ref, self.binding, now=1001)

    def test_rejects_malformed_envelope_values(self):
        envelope = transport.build_envelope(self.binding, "b" * 64, now=1000)
        for field, value in (("nonce", "bad"), ("nonce", []),
                             ("temporary_secret", ""), ("temporary_secret", {}),
                             ("exp", 1001)):
            candidate = {**envelope, field: value}
            with self.subTest(field=field), self.assertRaises(transport.TransportError):
                transport.validate_envelope(candidate, self.binding, now=1001)


class GpgTransportTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(Path(transport.GPG_BINARY).is_file(), "GnuPG must be installed to verify transport")
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.binding = transport.Binding(
            "luminusOS/flatpak-repo", "12345", "1", "c" * 40,
            "refs/heads/main", "testing",
        )
        self.key = "d" * 64
        self.envelope = transport.build_envelope(self.binding, "e" * 64)

    def tearDown(self):
        self.temp.cleanup()

    def test_encrypt_decrypt_round_trip_uses_gpg(self):
        ciphertext = transport.encrypt_envelope(self.envelope, self.key)
        plaintext = transport.decrypt_envelope(ciphertext, self.key)
        self.assertEqual(plaintext, self.envelope)
        self.assertNotIn("e" * 64, ciphertext.decode("latin1"))

    def test_wrong_key_and_tampering_fail_without_details(self):
        ciphertext = transport.encrypt_envelope(self.envelope, self.key)
        with self.assertRaises(transport.TransportError):
            transport.decrypt_envelope(ciphertext, "f" * 64)
        damaged = ciphertext[:-8] + bytes([ciphertext[-8] ^ 1]) + ciphertext[-7:]
        with self.assertRaises(transport.TransportError):
            transport.decrypt_envelope(damaged, self.key)

    def test_capsule_file_is_private_and_never_overwritten(self):
        ciphertext = transport.encrypt_envelope(self.envelope, self.key)
        path = self.root / "capsule.gpg"
        transport.write_capsule(path, ciphertext)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        with self.assertRaises(transport.TransportError):
            transport.write_capsule(path, ciphertext)

    def test_rejects_symlink_and_oversize_input(self):
        path = self.root / "target"
        path.write_bytes(b"not a capsule")
        link = self.root / "link"
        link.symlink_to(path)
        with self.assertRaises(transport.TransportError):
            transport.read_capsule(link)
        with self.assertRaises(transport.TransportError):
            transport.read_capsule_bytes(b"x" * (transport.MAX_CIPHERTEXT_BYTES + 1))

    def test_cli_issuer_and_publisher_exchange_only_synthetic_capsule(self):
        context = {
            "GITHUB_REPOSITORY": "luminusOS/flatpak-repo",
            "GITHUB_RUN_ID": "12345",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "c" * 40,
            "GITHUB_REF": "refs/heads/main",
            "T02_PARENT_CANARY": "e" * 64,
            "T02_TRANSPORT_KEY": self.key,
        }
        capsule_path = self.root / "exchange.gpg"
        output = StringIO()
        with redirect_stdout(output):
            transport.run_cli(
                ["issue", "--channel", "testing", "--output", str(capsule_path)], context
            )
        self.assertNotIn("e" * 64, output.getvalue())
        self.assertNotIn(self.key, output.getvalue())
        publisher_context = {key: value for key, value in context.items()
                             if key != "T02_PARENT_CANARY"}
        with redirect_stdout(output):
            transport.run_cli(
                ["consume", "--channel", "testing", "--input", str(capsule_path)],
                publisher_context,
            )
        self.assertNotIn("temporary_secret", output.getvalue())


class EnvironmentTests(unittest.TestCase):
    def test_binding_requires_expected_repository_and_main_ref(self):
        values = {
            "GITHUB_REPOSITORY": "luminusOS/flatpak-repo",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
            "GITHUB_REF": "refs/heads/main",
        }
        self.assertEqual(transport.binding_from_environment("stable", values).channel, "stable")
        for name, value in (("GITHUB_REPOSITORY", "attacker/repo"),
                            ("GITHUB_REF", "refs/heads/other"),
                            ("GITHUB_RUN_ID", "../1")):
            candidate = {**values, name: value}
            with self.subTest(name=name), self.assertRaises(transport.TransportError):
                transport.binding_from_environment("stable", candidate)


if __name__ == "__main__":
    unittest.main()

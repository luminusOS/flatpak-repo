import configparser
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from tools import descriptors, trust

ROOT = Path(__file__).resolve().parents[1]


def _gpg_listing(data):
    with tempfile.TemporaryDirectory(prefix="descriptor-gpg-") as home:
        os.chmod(home, 0o700)
        key = Path(home) / "key.gpg"
        key.write_bytes(data)
        try:
            result = subprocess.run(
                ["gpg", "--homedir", home, "--batch", "--no-options", "--with-colons",
                 "--show-keys", "--fingerprint", "--fingerprint", str(key)],
                capture_output=True, text=True, check=True, timeout=60)
        finally:
            subprocess.run(["gpgconf", "--homedir", home, "--kill", "gpg-agent"], capture_output=True)
    return [line.split(":")[9] for line in result.stdout.splitlines() if line.startswith("fpr:")]


class DescriptorTests(unittest.TestCase):
    def test_committed_descriptors_match_their_sources(self):
        self.assertTrue(descriptors.check())

    def test_every_catalog_application_and_channel_has_a_ref(self):
        files = descriptors.render_all()
        catalog = json.loads((ROOT / "catalog.json").read_text())
        expected = {f"{channel}/luminus-{channel}.flatpakrepo" for channel in descriptors.CHANNELS}
        expected |= {f"{channel}/{item['id']}.flatpakref"
                     for channel in descriptors.CHANNELS for item in catalog["applications"]}
        self.assertEqual(set(files), expected)

    def test_repo_descriptor_points_at_the_channel_and_branch(self):
        for channel in descriptors.CHANNELS:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(descriptors.flatpakrepo(channel))
            section = parser["Flatpak Repo"]
            self.assertEqual(section["url"], f"https://flatpak.luminusos.org/{channel}/")
            self.assertEqual(section["defaultbranch"], channel)
            self.assertNotRegex(section["gpgkey"], r"\s")

    def test_ref_descriptor_names_the_application_branch_and_runtime_repo(self):
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(descriptors.flatpakref("dev.luminusos.ZapTide", "testing"))
        section = parser["Flatpak Ref"]
        self.assertEqual(section["name"], "dev.luminusos.ZapTide")
        self.assertEqual(section["branch"], "testing")
        self.assertEqual(section["isruntime"], "false")
        self.assertEqual(section["url"], "https://flatpak.luminusos.org/testing/")
        self.assertEqual(section["runtimerepo"], "https://dl.flathub.org/repo/flathub.flatpakrepo")

    def test_embedded_key_carries_exactly_the_pinned_identity(self):
        manifest = trust.load_manifest(ROOT / "trust.json")
        for channel in descriptors.CHANNELS:
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(descriptors.flatpakrepo(channel))
            import base64
            fingerprints = _gpg_listing(base64.b64decode(parser["Flatpak Repo"]["gpgkey"], validate=True))
            identity = manifest["channels"][channel]
            self.assertEqual(fingerprints, [identity["primary_fingerprint"], identity["signing_subkey_fingerprint"]])

    def test_channels_never_share_a_key(self):
        self.assertNotEqual(descriptors.channel_key("stable"), descriptors.channel_key("testing"))

    def test_unknown_channel_and_application_are_rejected(self):
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.flatpakrepo("nightly")
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.flatpakref("dev.luminusos.ZapTide", "nightly")
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.flatpakref("org.example.Other", "stable")
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.flatpakref("../evil", "stable")

    def test_armor_checksum_and_shape_are_enforced(self):
        text = (ROOT / "trust" / "testing.asc").read_text()
        self.assertTrue(descriptors.armor_to_binary(text))
        lines = text.splitlines()
        tampered = [line for line in lines]
        index = next(i for i, line in enumerate(tampered) if line and not line.startswith(("-", "=")) and ":" not in line)
        tampered[index] = ("A" if tampered[index][0] != "A" else "B") + tampered[index][1:]
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.armor_to_binary("\n".join(tampered))
        with self.assertRaises(descriptors.DescriptorError):
            descriptors.armor_to_binary("not a key")

    def test_drift_in_a_descriptor_file_is_detected(self):
        with tempfile.TemporaryDirectory(prefix="descriptor-drift-") as directory:
            target = Path(directory) / "descriptors"
            shutil.copytree(ROOT / "descriptors", target)
            self.assertTrue(descriptors.check(directory=target))
            victim = target / "stable" / "dev.luminusos.ZapTide.flatpakref"
            victim.write_text(victim.read_text().replace("Branch=stable", "Branch=testing"))
            with self.assertRaises(descriptors.DescriptorError):
                descriptors.check(directory=target)
            victim.unlink()
            with self.assertRaises(descriptors.DescriptorError):
                descriptors.check(directory=target)

    @unittest.skipUnless(shutil.which("flatpak") and shutil.which("ostree"), "flatpak and ostree are required")
    def test_real_flatpak_accepts_the_remote_and_stores_the_pinned_key(self):
        manifest = trust.load_manifest(ROOT / "trust.json")
        for channel in descriptors.CHANNELS:
            with tempfile.TemporaryDirectory(prefix="descriptor-flatpak-") as directory:
                env = {**os.environ, "FLATPAK_USER_DIR": directory}
                name = descriptors.remote_name(channel)
                added = subprocess.run(
                    ["flatpak", "remote-add", "--user", name, str(ROOT / "descriptors" / channel / f"luminus-{channel}.flatpakrepo")],
                    env=env, capture_output=True, text=True, timeout=120)
                self.assertEqual(added.returncode, 0, added.stderr)
                listed = subprocess.run(["flatpak", "remotes", "--user", "--columns=name,url"], env=env,
                                        capture_output=True, text=True, timeout=60).stdout
                self.assertIn(f"https://flatpak.luminusos.org/{channel}/", listed)
                keys = subprocess.run(["ostree", f"--repo={directory}/repo", "remote", "gpg-list-keys", name],
                                      capture_output=True, text=True, timeout=60).stdout
                identity = manifest["channels"][channel]
                self.assertIn(identity["primary_fingerprint"], keys)
                self.assertIn(identity["signing_subkey_fingerprint"], keys)


if __name__ == "__main__":
    unittest.main()

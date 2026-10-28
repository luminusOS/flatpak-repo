import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parent.parent
CATALOG = json.loads((ROOT / "catalog.json").read_text())
APPLICATIONS = [item["id"] for item in CATALOG["applications"]]
ARCHITECTURES = CATALOG["architectures"]
FIXTURE_ROOT = "/tmp/opencode" if os.path.isdir("/tmp/opencode") else None


@unittest.skipUnless(all(shutil.which(tool) for tool in ("ostree", "flatpak", "gpg")),
                     "local Flatpak, OSTree and GnuPG tools are required")
class ClientProfileTests(unittest.TestCase):
    """Runs the Flatpak operations from docs/CLIENTS.md against a disposable profile and a local repository."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="client-", dir=FIXTURE_ROOT)
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.stop_gpg_agent)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.gnupg = self.root / "g"
        self.home.mkdir()
        self.gnupg.mkdir(mode=0o700)
        self.env = {
            **os.environ, "HOME": str(self.home), "FLATPAK_USER_DIR": str(self.root / "fp"),
            "GNUPGHOME": str(self.gnupg), "XDG_DATA_HOME": str(self.home / ".local/share"),
            "XDG_CONFIG_HOME": str(self.home / ".config"), "XDG_CACHE_HOME": str(self.home / ".cache"),
        }
        self.host_arch = self.run_tool("flatpak", "--default-arch").stdout.strip()
        self.assertIn(self.host_arch, ARCHITECTURES)
        self.keys = {}

    def stop_gpg_agent(self):
        subprocess.run(["gpgconf", "--homedir", str(self.gnupg), "--kill", "gpg-agent"],
                       env=self.env, capture_output=True, timeout=30)

    def run_tool(self, *command, check=True):
        result = subprocess.run(command, env=self.env, text=True, capture_output=True, timeout=120)
        if check and result.returncode:
            self.fail(f"{' '.join(command)} failed: {result.stdout}{result.stderr}")
        return result

    def flatpak(self, *arguments, check=True):
        return self.run_tool("flatpak", "--user", *arguments, check=check)

    def make_key(self, name):
        self.run_tool("gpg", "--batch", "--pinentry-mode", "loopback", "--passphrase", "",
                      "--quick-generate-key", f"{name} <{name}@example.invalid>", "ed25519", "sign", "never")
        listing = self.run_tool("gpg", "--list-keys", "--with-colons", f"{name}@example.invalid").stdout
        fingerprint = next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr"))
        public = self.root / f"{name}.gpg"
        public.write_bytes(subprocess.run(["gpg", "--export", fingerprint], env=self.env,
                                          capture_output=True, check=True).stdout)
        self.keys[name] = (fingerprint, public)

    def publish(self, repo, key, application, branch, marker):
        fingerprint, _ = self.keys[key]
        for arch in ARCHITECTURES:
            build = self.root / f"build-{application}-{arch}-{branch}-{marker}"
            (build / "files/bin").mkdir(parents=True)
            (build / "export/share").mkdir(parents=True)
            (build / "metadata").write_text(
                f"[Application]\nname={application}\nruntime=org.example.Platform/{arch}/1\n"
                f"sdk=org.example.Sdk/{arch}/1\ncommand=run\n")
            (build / "files/bin/run").write_text(f"{marker}\n")
            self.run_tool("flatpak", "build-export", f"--arch={arch}", "--disable-sandbox",
                          f"--gpg-sign={fingerprint}", f"--gpg-homedir={self.gnupg}",
                          str(repo), str(build), branch)
        self.run_tool("flatpak", "build-update-repo", f"--gpg-sign={fingerprint}",
                      f"--gpg-homedir={self.gnupg}", str(repo))

    def channel(self, key, branch, marker="1"):
        repo = self.root / f"repo-{branch}"
        self.make_key(key)
        for application in APPLICATIONS:
            self.publish(repo, key, application, branch, marker)
        return repo

    def add_remote(self, name, repo, key):
        self.flatpak("remote-add", f"--gpg-import={self.keys[key][1]}", name, f"file://{repo}")

    def install(self, remote, branch, *extra):
        self.flatpak("install", "-y", "--noninteractive", "--no-deps", *extra, remote,
                     *[f"{application}//{branch}" for application in APPLICATIONS])

    def installed_marker(self, application, branch):
        path = Path(self.env["FLATPAK_USER_DIR"]) / "app" / application / self.host_arch / branch
        return (path / "active/files/bin/run").read_text().strip()

    def installed_commit(self, application, branch):
        listing = self.flatpak("list", "--app", "--columns=application,branch,active").stdout
        for line in listing.splitlines():
            fields = line.split("\t")
            if fields[:2] == [application, branch]:
                return fields[2]
        self.fail(f"{application}//{branch} is not installed")

    def origin(self, application, branch):
        return self.flatpak("info", f"{application}//{branch}", "--show-origin").stdout.strip()

    def test_every_catalog_application_is_offered_for_every_architecture(self):
        repo = self.channel("testing", "testing")
        self.add_remote("luminus-testing", repo, "testing")
        offered = set(self.flatpak("remote-ls", "luminus-testing", "--arch=*", "--app",
                                   "--columns=ref").stdout.split())
        self.assertEqual(offered, {f"app/{application}/{arch}/testing"
                                   for application in APPLICATIONS for arch in ARCHITECTURES})

    def test_updating_one_application_leaves_the_other_untouched(self):
        repo = self.channel("testing", "testing")
        self.add_remote("luminus-testing", repo, "testing")
        self.install("luminus-testing", "testing")
        first, second = APPLICATIONS[:2]
        untouched = self.installed_commit(second, "testing")
        self.publish(repo, "testing", first, "testing", "2")
        self.flatpak("update", "-y", "--noninteractive", "--no-deps")
        self.assertEqual(self.installed_marker(first, "testing"), "2")
        self.assertEqual(self.installed_marker(second, "testing"), "1")
        self.assertEqual(self.installed_commit(second, "testing"), untouched)
        self.assertEqual(self.flatpak("list", "--app", "--columns=application").stdout.split(),
                         sorted(APPLICATIONS))

    def test_a_bundle_moves_to_the_remote_without_losing_user_data(self):
        repo = self.channel("testing", "testing")
        self.add_remote("luminus-testing", repo, "testing")
        application = APPLICATIONS[0]
        bundle = self.root / "app.flatpak"
        self.run_tool("flatpak", "build-bundle", f"--arch={self.host_arch}", str(repo), str(bundle),
                      application, "testing")
        self.flatpak("install", "-y", "--noninteractive", "--no-deps", "--bundle", str(bundle))
        data = self.home / ".var/app" / application / "config/settings.ini"
        data.parent.mkdir(parents=True)
        data.write_text("keep=me\n")
        self.assertTrue(self.origin(application, "testing").endswith("-origin"))

        refused = self.flatpak("install", "-y", "--noninteractive", "--no-deps", "luminus-testing",
                               f"{application}//testing", check=False)
        self.assertNotEqual(refused.returncode, 0)
        self.assertIn("already installed", refused.stderr)

        self.flatpak("install", "-y", "--noninteractive", "--no-deps", "--reinstall", "luminus-testing",
                     f"{application}//testing")
        self.assertEqual(self.origin(application, "testing"), "luminus-testing")
        self.assertEqual(data.read_text(), "keep=me\n")
        remotes = self.flatpak("remotes", "--columns=name").stdout.split()
        self.assertEqual(remotes, ["luminus-testing"])

    def test_channels_are_separate_branches_with_separate_keys_and_shared_data(self):
        testing = self.channel("testing", "testing", marker="rc")
        stable = self.channel("stable", "stable", marker="final")
        self.add_remote("luminus-testing", testing, "testing")
        self.add_remote("luminus", stable, "stable")
        application = APPLICATIONS[0]
        data = self.home / ".var/app" / application / "config/settings.ini"
        data.parent.mkdir(parents=True)
        data.write_text("keep=me\n")

        self.install("luminus-testing", "testing")
        self.install("luminus", "stable")
        self.assertEqual(self.installed_marker(application, "testing"), "rc")
        self.assertEqual(self.installed_marker(application, "stable"), "final")
        self.assertEqual(self.origin(application, "stable"), "luminus")

        self.flatpak("uninstall", "-y", "--noninteractive", *[f"{item}//testing" for item in APPLICATIONS])
        self.assertEqual(self.installed_marker(application, "stable"), "final")
        self.assertEqual(data.read_text(), "keep=me\n")

        self.flatpak("uninstall", "-y", "--noninteractive", *[f"{item}//stable" for item in APPLICATIONS])
        mismatch = self.flatpak("remote-add", f"--gpg-import={self.keys['testing'][1]}", "mismatch",
                                f"file://{stable}", check=False)
        self.assertNotEqual(mismatch.returncode, 0)
        self.assertIn("public key not found", mismatch.stderr)
        self.assertEqual(self.flatpak("list", "--app", "--columns=application").stdout.strip(), "")
        self.assertEqual(data.read_text(), "keep=me\n")


if __name__ == "__main__":
    unittest.main()

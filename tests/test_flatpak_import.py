import hashlib
import json
from email.message import Message
from io import BytesIO
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from urllib.error import HTTPError
from unittest.mock import patch

from tools.flatpak_import import (
    ImporterError, _validate_tree_paths, catalog_update_document, download_asset, fetch_plan,
    inspect_bundle, merge_bundles, validate_manifest, parse_release_json, verify_artifact,
    validate_rc_channel, verify_tmpfs, verify_mirrored_repo, sign_staged_repo,
    BASE_AUTH_DIR, snapshot_base_auth, verify_stage, _version_rules, changed_files,
)


def descriptor(channel="testing", version="1.2.3-rc.1"):
    return {
        "format": "flatpak", "channel": channel, "package_id": "dev.luminusos.ZapTide",
        "version": version, "tag": "v1.2.3-rc.1", "git_sha": "a" * 40,
        "source_run_id": "12345", "source_run_attempt": 2,
    }


def manifest(arch_files=None):
    arch_files = arch_files or {
        "x86_64": ("zaptide-v1.2.3-rc.1-x86_64.flatpak", b"x86"),
        "aarch64": ("zaptide-v1.2.3-rc.1-aarch64.flatpak", b"arm"),
    }
    return {
        "schema_version": 1, "kind": "release", "format": "flatpak",
        "application": "dev.luminusos.ZapTide", "version": "1.2.3-rc.1",
        "source": {"repository": "luminusOS/zaptide", "workflow": ".github/workflows/release.yml",
                   "tag": "v1.2.3-rc.1", "revision": "a" * 40,
                   "run_id": 12345, "run_attempt": 2},
        "artifacts": {
            arch: {"artifact_id": index, "filename": filename,
                   "sha256": hashlib.sha256(data).hexdigest(), "size_bytes": len(data)}
            for index, (arch, (filename, data)) in enumerate(arch_files.items(), start=1)
        },
    }


class ImporterContractTests(unittest.TestCase):
    def test_fetch_plan_is_fixed_to_allowlisted_release_assets(self):
        plan = fetch_plan(descriptor())
        self.assertEqual(plan.repository, "luminusOS/zaptide")
        self.assertEqual(plan.manifest_url,
                         "https://github.com/luminusOS/zaptide/releases/download/v1.2.3-rc.1/luminus-release-manifest.json")
        self.assertTrue(any("zaptide-v1.2.3-rc.1-aarch64.flatpak" in url
                            for url in plan.asset_urls.values()))
        with self.assertRaises(ImporterError):
            fetch_plan({**descriptor(), "package_id": "org.example.Unknown"})

    def test_manifest_matches_release_descriptor_and_two_architectures(self):
        self.assertEqual(validate_manifest(manifest(), descriptor())["version"], "1.2.3-rc.1")

    def test_manifest_rejects_source_run_or_revision_mismatch(self):
        for field, value in (("run_id", 555), ("revision", "b" * 40), ("tag", "v1.2.3")):
            changed = manifest()
            changed["source"][field] = value
            with self.subTest(field=field), self.assertRaises(ImporterError):
                validate_manifest(changed, descriptor())

    def test_manifest_rejects_missing_or_misnamed_architecture(self):
        missing = manifest()
        del missing["artifacts"]["aarch64"]
        with self.assertRaises(ImporterError):
            validate_manifest(missing, descriptor())
        changed = manifest()
        changed["artifacts"]["aarch64"]["filename"] = "zaptide-v1.2.3-rc.1-x86_64.flatpak"
        with self.assertRaises(ImporterError):
            validate_manifest(changed, descriptor())

    def test_rc_cannot_target_stable_and_final_channel_is_explicit(self):
        with self.assertRaises(ImporterError):
            validate_manifest(manifest(), descriptor(channel="stable"))
        final_descriptor = {**descriptor(channel="stable", version="1.2.3"),
                            "tag": "v1.2.3"}
        final_manifest = manifest({
            "x86_64": ("zaptide-v1.2.3-x86_64.flatpak", b"x86"),
            "aarch64": ("zaptide-v1.2.3-aarch64.flatpak", b"arm"),
        })
        final_manifest["version"] = "1.2.3"
        final_manifest["source"]["tag"] = "v1.2.3"
        self.assertEqual(validate_manifest(final_manifest, final_descriptor)["version"], "1.2.3")

    def test_importer_rc_guard_rejects_stable_without_manifest_validation(self):
        with self.assertRaises(ImporterError):
            validate_rc_channel({"channel": "stable", "version": "1.2.3-rc.1"})

    def test_merge_rejects_rc_descriptor_for_stable_directly(self):
        rc = {"format": "flatpak", "channel": "stable", "package_id": "org.luminusos.TestOne",
              "version": "1.2.3-rc.1", "tag": "v1.2.3-rc.1", "git_sha": "a" * 40,
              "source_run_id": "123", "source_run_attempt": 1}
        with self.assertRaisesRegex(ImporterError, "testing-only"):
            merge_bundles("unused", {}, rc, sign=False)

    def test_gpg_home_requires_verified_tmpfs(self):
        with tempfile.TemporaryDirectory(prefix="t09-gpg-home-", dir="/dev/shm") as tmpfs_home:
            self.assertEqual(verify_tmpfs(tmpfs_home), Path(tmpfs_home))
        with self.assertRaisesRegex(ImporterError, "tmpfs"):
            verify_tmpfs(Path(__file__).resolve().parents[1])

    def test_artifact_hash_and_size_are_verified(self):
        artifact = manifest()["artifacts"]["x86_64"]
        self.assertEqual(verify_artifact(b"x86", artifact), b"x86")
        with self.assertRaises(ImporterError):
            verify_artifact(b"BAD", artifact)

    def test_release_json_rejects_duplicate_fields_and_non_finite_numbers(self):
        for content in (b'{"version":"1.0.0","version":"2.0.0"}', b'{"size":NaN}'):
            with self.subTest(content=content), self.assertRaises(ImporterError):
                parse_release_json(content)

    def test_bundle_tree_path_guard_rejects_traversal_entries(self):
        with patch("tools.flatpak_import._run", return_value=b"/\0/../../outside\0"):
            with self.assertRaises(ImporterError):
                _validate_tree_paths("repo", "a" * 64)

    def test_catalog_update_is_channel_scoped_and_records_both_refs(self):
        checked = descriptor()
        records = [{"architecture": arch,
                    "ref": f"app/{checked['package_id']}/{arch}/{checked['channel']}",
                    "commit": str(index) * 64}
                   for index, arch in enumerate(("x86_64", "aarch64"), start=1)]
        update = catalog_update_document(checked, records, [])
        self.assertEqual(update["channel"], "testing")
        self.assertEqual({item["ref"].split("/")[2] for item in update["refs"]},
                         {"x86_64", "aarch64"})
        with self.assertRaises(ImporterError):
            catalog_update_document({**checked, "channel": "stable"}, records, [])

    def test_release_asset_redirect_allows_only_one_github_objects_hop(self):
        class Response:
            status = 200
            headers = {"Content-Length": "4"}

            def __init__(self, url):
                self.url = url

            def geturl(self):
                return self.url

            def read(self, size):
                return b"data"

            def close(self):
                pass

        class Opener:
            def __init__(self, location):
                self.location = location
                self.calls = []

            def open(self, request, timeout):
                self.calls.append(request.full_url)
                if len(self.calls) == 1:
                    headers = Message()
                    headers["Location"] = self.location
                    raise HTTPError(request.full_url, 302, "redirect", headers, BytesIO())
                return Response(request.full_url)

        allowed = "https://objects.githubusercontent.com/release/asset?token=fixture"
        opener = Opener(allowed)
        self.assertEqual(download_asset("https://github.com/luminusOS/zaptide/a", limit=10,
                                        opener=opener), b"data")
        self.assertEqual(len(opener.calls), 2)
        denied = Opener("https://attacker.example/asset")
        with self.assertRaises(ImporterError):
            download_asset("https://github.com/luminusOS/zaptide/a", limit=10, opener=denied)
        self.assertEqual(len(denied.calls), 1)


@unittest.skipUnless(all(shutil.which(tool) for tool in ("ostree", "flatpak", "gpg")),
                     "local Flatpak, OSTree and GnuPG tools are required")
class RealFlatpakImportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="t09-flatpak-tools-", dir="/tmp/opencode")
        cls.root = Path(cls.temp.name)
        cls.gpg_home = cls.root / "gpg"
        cls.gpg_home.mkdir(mode=0o700)
        cls.env = {**os.environ, "GNUPGHOME": str(cls.gpg_home), "LC_ALL": "C"}
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Luminus T09 fixture <t09@example.invalid>", "rsa1024", "sign", "1d"],
                       env=cls.env, check=True, capture_output=True)
        listing = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint", "--list-keys"],
                                env=cls.env, check=True, capture_output=True, text=True)
        cls.fingerprint = next(line.split(":")[9] for line in listing.stdout.splitlines()
                               if line.startswith("fpr:"))
        cls.trust_path = cls.root / "trust" / "testing.asc"
        cls.trust_path.parent.mkdir()
        cls.trust_path.write_bytes(subprocess.run(["gpg", "--batch", "--armor", "--export",
                                                   cls.fingerprint], env=cls.env, check=True,
                                                  capture_output=True).stdout)
        cls.auth_home = cls.root / "auth-gpg"
        cls.auth_home.mkdir(mode=0o700)
        cls.auth_env = {**os.environ, "GNUPGHOME": str(cls.auth_home), "LC_ALL": "C"}
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Luminus auth fixture <auth@example.invalid>", "rsa1024", "cert", "1d"],
                       env=cls.auth_env, check=True, capture_output=True)
        auth_listing = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint",
                                       "--list-keys"], env=cls.auth_env, check=True,
                                      capture_output=True, text=True).stdout
        cls.auth_primary = next(line.split(":")[9] for line in auth_listing.splitlines()
                                if line.startswith("fpr:"))
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-add-key",
                        cls.auth_primary, "rsa1024", "sign", "1d"], env=cls.auth_env,
                       check=True, capture_output=True)
        auth_listing = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint",
                                       "--fingerprint", "--list-keys"], env=cls.auth_env,
                                      check=True, capture_output=True, text=True).stdout
        cls.auth_signing = [line.split(":")[9] for line in auth_listing.splitlines()
                            if line.startswith("fpr:")][1]
        cls.auth_trust = cls.root / "auth-root"
        (cls.auth_trust / "trust").mkdir(parents=True)
        cls.auth_key_path = cls.auth_trust / "trust" / "testing.asc"
        cls.auth_key_path.write_bytes(subprocess.run(
            ["gpg", "--batch", "--armor", "--export", cls.auth_primary], env=cls.auth_env,
            check=True, capture_output=True).stdout)
        (cls.auth_trust / "trust.json").write_text(json.dumps({
            "schema_version": 1, "format": "flatpak", "status": "provisioned",
            "max_validity_days": 400,
            "channels": {"stable": {"primary_fingerprint": "A" * 40,
                                      "signing_subkey_fingerprint": "B" * 40,
                                      "public_key": "trust/stable.asc"},
                         "testing": {"primary_fingerprint": cls.auth_primary,
                                     "signing_subkey_fingerprint": cls.auth_signing,
                                     "public_key": "trust/testing.asc"}},
        }), encoding="utf-8")

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def setUp(self):
        self.work = tempfile.TemporaryDirectory(prefix="t09-case-", dir=self.root)
        self.root_case = Path(self.work.name)
        self.repo = self.root_case / "shared-repo"
        subprocess.run(["ostree", "init", "--repo", str(self.repo), "--mode=archive-z2"], check=True,
                       capture_output=True)

    def tearDown(self):
        self.work.cleanup()

    def make_bundle(self, app, arch, *, version="1.2.3", branch="testing", marker="initial",
                    runtime_arch=None, custom_version=True, subject=None):
        root = self.root_case / f"bundle-{app}-{arch}-{branch}-{version}-{marker}-{runtime_arch or arch}"
        source = root / "repo"
        tree = root / "tree"
        tree.mkdir(parents=True)
        (tree / "files").mkdir()
        (tree / "metadata").write_text(
            f"[Application]\nname={app}\nruntime=org.freedesktop.Platform/{runtime_arch or arch}/24.08\n"
            f"sdk=org.freedesktop.Sdk/{arch}/24.08\ncommand=test\n"
            + (f"version={version}\n" if custom_version else ""),
            encoding="utf-8")
        (tree / "files" / "payload.txt").write_text(marker, encoding="utf-8")
        subprocess.run(["ostree", "init", "--repo", str(source), "--mode=archive-z2"], check=True,
                       capture_output=True)
        ref = f"app/{app}/{arch}/{branch}"
        subprocess.run(["ostree", "commit", "--repo", str(source), "--branch=" + ref,
                        "--tree=dir=" + str(tree), "--subject=" + (subject or version)],
                       check=True, capture_output=True)
        bundle = root / "app.flatpak"
        subprocess.run(["flatpak", "build-bundle", "--arch=" + arch, str(source), str(bundle),
                        app, branch], check=True, capture_output=True)
        return bundle

    def bundles(self, app, **kwargs):
        return {arch: self.make_bundle(app, arch, **kwargs) for arch in ("x86_64", "aarch64")}

    def merge(self, app, bundles, version="1.2.3"):
        return merge_bundles(self.repo, bundles, {
            "format": "flatpak", "channel": "testing", "package_id": app, "version": version,
            "tag": "v" + version, "git_sha": "a" * 40, "source_run_id": "12345",
            "source_run_attempt": 1,
        }, gpg_home=self.gpg_home, signing_fingerprint=self.fingerprint)

    def refs(self):
        output = subprocess.run(["ostree", "refs", "--repo", str(self.repo), "--list"], check=True,
                                capture_output=True, text=True)
        return set(output.stdout.splitlines())

    def sign_file(self, path, *, primary=None, signing=None, output=None):
        signer = signing or self.auth_signing
        subprocess.run(["gpg", "--batch", "--yes", "--local-user", signer + "!",
                        "--detach-sign", "--output", str(output or (str(path) + ".sig")), str(path)],
                       env=self.auth_env, check=True, capture_output=True)

    def signed_repo(self, *, ledger=True):
        repo = self.root_case / "signed-origin"
        subprocess.run(["ostree", "init", "--repo", str(repo), "--mode=archive-z2"],
                       check=True, capture_output=True)
        summary = repo / "summary"
        subprocess.run(["ostree", "summary", "--repo", str(repo), "--update", "--gpg-sign",
                        self.auth_signing + "!", "--gpg-homedir", str(self.auth_home)],
                       check=True, capture_output=True)
        self.sign_file(summary, output=repo / "summary.detached.sig")
        if ledger:
            ledger_path = repo / "luminus-imports.json"
            ledger_path.write_text('{"schema_version":1,"refs":{}}\n', encoding="utf-8")
            self.sign_file(ledger_path)
        trust = self.auth_trust
        return repo, trust

    def test_mirrored_summary_and_ledger_signatures_are_accepted(self):
        repo, trust = self.signed_repo()
        self.assertTrue(verify_mirrored_repo(repo, "testing", trust_root=trust))

    def test_tampered_summary_is_rejected(self):
        repo, trust = self.signed_repo()
        (repo / "summary").write_bytes(b"tampered\n")
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_missing_summary_signature_is_rejected(self):
        repo, trust = self.signed_repo()
        (repo / "summary.sig").unlink()
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_summary_signed_by_unpinned_key_is_rejected(self):
        repo, trust = self.signed_repo()
        other_home = self.root_case / "other-gpg"
        other_home.mkdir(mode=0o700)
        env = {**os.environ, "GNUPGHOME": str(other_home), "LC_ALL": "C"}
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-generate-key",
                        "Other signer <other@example.invalid>", "rsa1024", "sign", "1d"],
                       env=env, check=True, capture_output=True)
        subprocess.run(["gpg", "--batch", "--yes", "--detach-sign", "--output",
                        str(repo / "summary.detached.sig"), str(repo / "summary")], env=env,
                       check=True, capture_output=True)
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_summary_signed_by_unregistered_subkey_of_pinned_primary_is_rejected(self):
        repo, trust = self.signed_repo()
        subprocess.run(["gpg", "--batch", "--passphrase", "", "--quick-add-key",
                        self.auth_primary, "rsa1024", "sign", "1d"], env=self.auth_env,
                       check=True, capture_output=True)
        listing = subprocess.run(["gpg", "--batch", "--with-colons", "--fingerprint",
                                 "--fingerprint", "--list-keys"], env=self.auth_env, check=True,
                                capture_output=True, text=True).stdout
        unregistered = [line.split(":")[9] for line in listing.splitlines()
                        if line.startswith("fpr:")][-1]
        subprocess.run(["gpg", "--batch", "--yes", "--local-user", unregistered + "!",
                        "--detach-sign", "--output", str(repo / "summary.detached.sig"),
                        str(repo / "summary")], env=self.auth_env, check=True, capture_output=True)
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_tampered_ledger_is_rejected(self):
        repo, trust = self.signed_repo()
        (repo / "luminus-imports.json").write_text('{"schema_version":1,"refs":{"bad":{}}}\n')
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_ledger_without_signature_is_rejected(self):
        repo, trust = self.signed_repo()
        (repo / "luminus-imports.json.sig").unlink()
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_explicit_empty_repository_bootstrap_is_allowed(self):
        repo, trust = self.signed_repo()
        shutil.rmtree(repo)
        subprocess.run(["ostree", "init", "--repo", str(repo), "--mode=archive-z2"],
                       check=True, capture_output=True)
        self.assertTrue(verify_mirrored_repo(repo, "testing", trust_root=trust,
                                             allow_empty=True))

    def test_summary_signature_failure_prevents_import_signing_and_upload(self):
        repo, trust = self.signed_repo()
        (repo / "summary.sig").unlink()
        with patch("tools.flatpak_import.merge_bundles") as merge, \
                patch("tools.flatpak_import.sign_staged_repo") as sign, \
                patch("tools.flatpak_import.publish_repo") as upload:
            with self.assertRaises(ImporterError):
                verify_mirrored_repo(repo, "testing", trust_root=trust)
            merge.assert_not_called()
            sign.assert_not_called()
            upload.assert_not_called()

    def test_signing_publisher_generates_authenticated_ledger_signature(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app))
        sign_staged_repo(self.repo, self.auth_home, self.auth_signing)
        self.assertTrue((self.repo / "luminus-imports.json.sig").is_file())
        checked = subprocess.run(["gpg", "--homedir", str(self.auth_home), "--status-fd", "1",
                                  "--verify", str(self.repo / "summary.detached.sig"),
                                  str(self.repo / "summary")], capture_output=True)
        self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)
        self.assertTrue(verify_mirrored_repo(self.repo, "testing", trust_root=self.auth_trust))

    def test_mirror_ref_checksums_must_match_verified_summary(self):
        app = "org.luminusos.TestOne"
        bundles = self.bundles(app)
        self.merge(app, bundles)
        subprocess.run(["ostree", "summary", "--repo", str(self.repo), "--update", "--gpg-sign",
                        self.auth_signing + "!", "--gpg-homedir", str(self.auth_home)],
                       check=True, capture_output=True)
        self.sign_file(self.repo / "summary", output=self.repo / "summary.detached.sig")
        summary_refs = subprocess.run(["ostree", "summary", "--repo", str(self.repo), "--view"],
                                      check=True, capture_output=True, text=True).stdout
        self.assertIn("app/" + app, summary_refs)
        (self.repo / "luminus-imports.json").unlink()
        (self.repo / "luminus-imports.json.sig").unlink(missing_ok=True)
        tree = self.root_case / "changed-tree"
        tree.mkdir()
        subprocess.run(["ostree", "commit", "--repo", str(self.repo),
                        "--branch=app/" + app + "/x86_64/testing", "--tree=dir=" + str(tree),
                        "--subject=mismatched mirror"], check=True, capture_output=True)
        with self.assertRaisesRegex(ImporterError, "verified summary"):
            verify_mirrored_repo(self.repo, "testing", trust_root=self.auth_trust)

    FIRST_APP = "org.luminusos.TestOne"
    SECOND_APP = "org.luminusos.TestTwo"

    def release(self, app, version="1.2.3"):
        return {"format": "flatpak", "channel": "testing", "package_id": app, "version": version,
                "tag": "v" + version, "git_sha": "a" * 40, "source_run_id": "12345",
                "source_run_attempt": 1, "manifest_sha256": "b" * 64}

    def staged_case(self):
        merge_bundles(self.repo, self.bundles(self.FIRST_APP), self.release(self.FIRST_APP), sign=False)
        sign_staged_repo(self.repo, self.auth_home, self.auth_signing)
        work = self.root_case / "work"
        snapshot_base_auth(self.repo, work / BASE_AUTH_DIR)
        second = self.bundles(self.SECOND_APP)
        release = self.release(self.SECOND_APP)
        merge_bundles(self.repo, second, release, sign=False)
        return work, release, second

    def commit_on(self, ref, label):
        tree = self.root_case / ("tree-" + label)
        tree.mkdir()
        (tree / "marker").write_text(label)
        subprocess.run(["ostree", "commit", "--repo", str(self.repo), "--branch=" + ref,
                        "--tree=dir=" + str(tree), "--subject=" + label],
                       check=True, capture_output=True)

    def test_stage_matching_authenticated_base_and_verified_bundles_is_accepted(self):
        work, release, bundles = self.staged_case()
        inspected = verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)
        self.assertEqual({item["architecture"] for item in inspected}, {"x86_64", "aarch64"})
        self.assertTrue(all(not item["no_op"] for item in inspected))

    def test_stage_with_an_extra_ref_is_rejected(self):
        work, release, bundles = self.staged_case()
        self.commit_on("app/org.luminusos.Injected/x86_64/testing", "extra")
        with self.assertRaisesRegex(ImporterError, "refs differ"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_stage_that_repoints_an_existing_app_is_rejected(self):
        work, release, bundles = self.staged_case()
        self.commit_on("app/" + self.FIRST_APP + "/x86_64/testing", "repointed")
        with self.assertRaisesRegex(ImporterError, "refs differ"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_stage_whose_new_commit_is_not_the_verified_bundle_is_rejected(self):
        work, release, bundles = self.staged_case()
        self.commit_on("app/" + self.SECOND_APP + "/aarch64/testing", "swapped")
        with self.assertRaisesRegex(ImporterError, "refs differ"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_stage_with_a_forged_ledger_is_rejected(self):
        work, release, bundles = self.staged_case()
        ledger = json.loads((self.repo / "luminus-imports.json").read_text())
        ledger["refs"]["app/forged/x86_64/testing"] = {
            "commit": "c" * 64, "version": "9.9.9", "source_run_id": "1", "manifest_sha256": "d" * 64}
        (self.repo / "luminus-imports.json").write_text(json.dumps(ledger))
        with self.assertRaisesRegex(ImporterError, "ledger differs"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_tampered_base_record_is_rejected(self):
        work, release, bundles = self.staged_case()
        (work / BASE_AUTH_DIR / "summary").write_bytes(b"forged summary")
        with self.assertRaises(ImporterError):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_missing_base_record_is_rejected(self):
        work, release, bundles = self.staged_case()
        shutil.rmtree(work / BASE_AUTH_DIR)
        with self.assertRaises(ImporterError):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_empty_base_claim_needs_the_public_repository_to_be_empty(self):
        work, release, bundles = self.staged_case()
        shutil.rmtree(work / BASE_AUTH_DIR)
        (work / BASE_AUTH_DIR).mkdir()
        (work / BASE_AUTH_DIR / "EMPTY").write_bytes(b"")
        with self.assertRaisesRegex(ImporterError, "empty base"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust,
                         public_empty=lambda channel: False)

    def test_empty_base_marker_with_other_files_is_rejected(self):
        work, release, bundles = self.staged_case()
        (work / BASE_AUTH_DIR / "EMPTY").write_bytes(b"")
        with self.assertRaisesRegex(ImporterError, "empty base"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust,
                         public_empty=lambda channel: True)

    def test_stage_with_unexpected_top_level_file_is_rejected(self):
        work, release, bundles = self.staged_case()
        (self.repo / "evil.txt").write_text("x")
        with self.assertRaisesRegex(ImporterError, "unexpected top-level"):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_stage_with_a_corrupted_object_is_rejected_by_fsck(self):
        work, release, bundles = self.staged_case()
        victim = next((self.repo / "objects").rglob("*.filez"))
        victim.chmod(0o600)
        victim.write_bytes(b"corrupt")
        with self.assertRaises(ImporterError):
            verify_stage(self.repo, work, release, bundles, trust_root=self.auth_trust)

    def test_upload_set_skips_lock_and_tmp_files(self):
        (self.repo / "tmp").mkdir(exist_ok=True)
        (self.repo / "tmp" / "leftover").write_text("x")
        (self.repo / ".lock").write_text("")
        (self.repo / "config.extra-check").write_text("kept")
        names = set(changed_files(self.repo, {}))
        self.assertNotIn(".lock", names)
        self.assertNotIn("tmp/leftover", names)
        self.assertIn("config.extra-check", names)

    def test_orphan_ledger_signature_is_rejected(self):
        repo, trust = self.signed_repo(ledger=False)
        (repo / "luminus-imports.json.sig").write_bytes(b"stale")
        with self.assertRaises(ImporterError):
            verify_mirrored_repo(repo, "testing", trust_root=trust)

    def test_signing_removes_a_stale_ledger_signature_without_a_ledger(self):
        merge_bundles(self.repo, self.bundles(self.FIRST_APP), self.release(self.FIRST_APP), sign=False)
        (self.repo / "luminus-imports.json").unlink()
        (self.repo / "luminus-imports.json.sig").write_bytes(b"stale")
        sign_staged_repo(self.repo, self.auth_home, self.auth_signing)
        self.assertFalse((self.repo / "luminus-imports.json.sig").exists())

    def test_version_rules_use_the_authenticated_ledger(self):
        ref = "app/x/x86_64/testing"
        entry = {"commit": "a" * 64, "version": "1.2.3", "source_run_id": "1", "manifest_sha256": "b" * 64}
        item = {"ref": ref, "no_op": False}
        _version_rules({ref: "a" * 64}, {ref: entry}, [item], {"version": "1.2.4"})
        _version_rules({}, {}, [item], {"version": "0.0.1"})
        _version_rules({ref: "a" * 64}, {}, [{"ref": ref, "no_op": True}], {"version": "1.0.0"})
        for version in ("1.2.3", "1.2.2", "1.2.3-rc.1"):
            with self.assertRaises(ImporterError):
                _version_rules({ref: "a" * 64}, {ref: entry}, [item], {"version": version})
        with self.assertRaises(ImporterError):
            _version_rules({ref: "a" * 64}, {}, [item], {"version": "9.9.9"})

    def test_two_apps_and_architectures_merge_and_repeat_without_ref_changes(self):
        first = "org.luminusos.TestOne"
        second = "org.luminusos.TestTwo"
        first_bundles = self.bundles(first)
        self.merge(first, first_bundles)
        first_refs = self.refs()
        self.merge(first, first_bundles)
        self.assertEqual(first_refs, self.refs())
        self.merge(second, self.bundles(second))
        app_refs = {ref for ref in self.refs() if ref.startswith("app/")}
        self.assertEqual(len(app_refs), 4)
        self.assertTrue(any("TestOne" in ref for ref in self.refs()))
        self.assertTrue(any("TestTwo" in ref for ref in self.refs()))

    def test_one_architecture_failure_does_not_import_the_other_architecture(self):
        app = "org.luminusos.TestOne"
        original = self.bundles(app)
        self.merge(app, original)
        before = {ref: subprocess.run(["ostree", "rev-parse", "--repo", str(self.repo), ref],
                                      check=True, capture_output=True, text=True).stdout.strip()
                  for ref in self.refs()}
        invalid = self.root_case / "invalid-aarch64.flatpak"
        invalid.write_bytes(b"not a bundle")
        with self.assertRaises(ImporterError):
            self.merge(app, {"x86_64": original["x86_64"],
                             "aarch64": invalid})
        after = {ref: subprocess.run(["ostree", "rev-parse", "--repo", str(self.repo), ref],
                                     check=True, capture_output=True, text=True).stdout.strip()
                 for ref in self.refs()}
        self.assertEqual(before, after)

    def test_same_version_with_different_commit_is_rejected(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app))
        before = {ref: subprocess.run(["ostree", "rev-parse", "--repo", str(self.repo), ref],
                                      check=True, capture_output=True, text=True).stdout.strip()
                  for ref in self.refs()}
        with self.assertRaises(ImporterError):
            self.merge(app, self.bundles(app, marker="different"))
        after = {ref: subprocess.run(["ostree", "rev-parse", "--repo", str(self.repo), ref],
                                     check=True, capture_output=True, text=True).stdout.strip()
                 for ref in self.refs()}
        self.assertEqual(before, after)

    def test_ledger_allows_higher_version_without_custom_bundle_metadata(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app, version="0.7.3", custom_version=False,
                                     subject="maintenance build"), "0.7.3")
        self.merge(app, self.bundles(app, version="0.7.4", custom_version=False,
                                     subject="maintenance build"), "0.7.4")

    def test_ledger_rejects_same_version_different_commit_without_custom_metadata(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app, version="0.7.3", marker="first", custom_version=False),
                   "0.7.3")
        with self.assertRaises(ImporterError):
            self.merge(app, self.bundles(app, version="0.7.3", marker="different", custom_version=False),
                       "0.7.3")

    def test_ledger_rejects_downgrade_without_custom_metadata(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app, version="0.7.4", custom_version=False), "0.7.4")
        with self.assertRaises(ImporterError):
            self.merge(app, self.bundles(app, version="0.7.3", custom_version=False), "0.7.3")

    def test_ledger_uses_semver_rc_ordering(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app, version="0.7.4-rc.2", custom_version=False),
                   "0.7.4-rc.2")
        self.merge(app, self.bundles(app, version="0.7.4", custom_version=False), "0.7.4")
        with self.assertRaises(ImporterError):
            self.merge(app, self.bundles(app, version="0.7.4-rc.3", marker="older",
                                         custom_version=False), "0.7.4-rc.3")

    def test_existing_ref_without_ledger_fails_closed_on_different_commit(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app))
        (self.repo / "luminus-imports.json").unlink(missing_ok=True)
        with self.assertRaises(ImporterError):
            self.merge(app, self.bundles(app, marker="different"))

    def test_wrong_bundle_branch_is_rejected(self):
        bundle = self.make_bundle("org.luminusos.TestOne", "x86_64", branch="stable")
        with self.assertRaises(ImporterError):
            inspect_bundle(bundle, app_id="org.luminusos.TestOne", architecture="x86_64",
                           channel="testing", version="1.2.3", work_dir=self.root_case / "inspect")

    def test_summary_signature_is_accepted_by_a_flatpak_client(self):
        app = "org.luminusos.TestOne"
        self.merge(app, self.bundles(app))
        home = self.root_case / "flatpak-home"
        env = {**self.env, "XDG_DATA_HOME": str(home / "data"), "XDG_CONFIG_HOME": str(home / "config")}
        subprocess.run(["flatpak", "remote-add", "--user", "--gpg-import", str(self.trust_path),
                        "t09-fixture", "file://" + str(self.repo)], env=env, check=True, capture_output=True)
        result = subprocess.run(["flatpak", "remote-ls", "--user", "--app", "--show-details",
                                 "--arch=*",
                                 "t09-fixture"], env=env, check=True, capture_output=True, text=True)
        self.assertIn(app, result.stdout)
        self.assertIn("x86_64", result.stdout)
        self.assertIn("aarch64", result.stdout)

    def test_runtime_architecture_must_match_bundle_ref(self):
        bundle = self.make_bundle("org.luminusos.TestOne", "aarch64", runtime_arch="x86_64")
        with self.assertRaises(ImporterError):
            inspect_bundle(bundle, app_id="org.luminusos.TestOne", architecture="aarch64",
                           channel="testing", version="1.2.3", work_dir=self.root_case / "inspect-arch")


if __name__ == "__main__":
    unittest.main()

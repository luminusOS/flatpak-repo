from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class UniqueKeyLoader(yaml.SafeLoader):
    pass


def _unique_mapping(loader, node, deep=False):
    result = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in result:
            raise ValueError(f"duplicate workflow key: {key}")
        result[key] = loader.construct_object(value_node, deep=deep)
    return result


UniqueKeyLoader.add_constructor(yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _unique_mapping)


class PublishWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = (ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")
        cls.workflow = yaml.load(cls.raw, Loader=UniqueKeyLoader)

    def test_only_dispatch_runs_on_protected_main_with_read_permissions(self):
        self.assertEqual(set(self.workflow["on"]), {"workflow_dispatch"})
        self.assertEqual(self.workflow["permissions"], {"contents": "read"})
        for job in self.workflow["jobs"].values():
            self.assertIn("github.ref_protected", job["if"])
            self.assertIn("refs/heads/main", job["if"])

    def test_jobs_are_gated_in_checks_issuer_publisher_order(self):
        self.assertEqual(list(self.workflow["jobs"]), ["checks", "prepare", "issuer", "publisher"])
        self.assertEqual(set(self.workflow["jobs"]), {"checks", "prepare", "issuer", "publisher"})
        self.assertEqual(self.workflow["jobs"]["prepare"]["needs"], "checks")
        self.assertEqual(self.workflow["jobs"]["issuer"]["needs"], "prepare")
        self.assertEqual(self.workflow["jobs"]["publisher"]["needs"], "issuer")
        self.assertNotIn("environment", self.workflow["jobs"]["prepare"])
        self.assertNotIn("environment", self.workflow["jobs"]["prepare"])
        self.assertEqual(self.workflow["jobs"]["prepare"]["permissions"], {"contents": "read"})
        self.assertIn("issuer-${{ inputs.channel }}", self.workflow["jobs"]["issuer"]["environment"])
        self.assertIn("publisher-${{ inputs.channel }}", self.workflow["jobs"]["publisher"]["environment"])

    def test_prepare_is_credential_free_and_capsule_consumption_is_first_run_step(self):
        prepare = self.workflow["jobs"]["prepare"]
        serialized = str(prepare)
        self.assertNotIn("secrets.", serialized)
        self.assertNotIn("R2_PARENT", serialized)
        publisher = self.workflow["jobs"]["publisher"]["steps"]
        consume = next(i for i, step in enumerate(publisher)
                       if step.get("name") == "Consume capsule and verify publisher context")
        run_steps = [i for i, step in enumerate(publisher) if "run" in step]
        self.assertEqual(consume, run_steps[0])

    def test_existing_mirror_is_pinned_and_authenticated_before_import(self):
        prepare = self.workflow["jobs"]["prepare"]
        mirror = next(step["run"] for step in prepare["steps"]
                      if step.get("name") == "Mirror public channel repository without credentials")
        self.assertIn("$URL/summary", mirror)
        self.assertIn("$URL/refs/", mirror)
        self.assertIn('test "$REFS_STATUS" = 404', mirror)
        self.assertIn("--gpg-import=\"trust/$CHANNEL.asc\"", mirror)
        self.assertIn("--set=gpg-verify=false", mirror)
        self.assertIn("--set=gpg-verify-summary=true", mirror)
        self.assertIn("ostree pull --repo=\"$REPO\" --mirror luminus-public", mirror)
        import_step = next(step["run"] for step in prepare["steps"]
                           if step.get("name") == "Verify release, import unsigned commits, and stage repository")
        self.assertIn("--allow-empty-repo", import_step)
        self.assertIn('if [ -e /tmp/opencode/luminus-t09/first-publish ]', import_step)
        self.assertEqual(import_step.count("--allow-empty-repo"), 1)
        self.assertIn("summary.detached.sig", mirror)
        self.assertIn("luminus-imports.json.sig", mirror)
        self.assertLess(mirror.index("first-publish"), mirror.rindex("*) exit 1"))
        first_publish_branch = mirror[mirror.rindex("404)"):mirror.rindex("*) exit 1")]
        self.assertIn('test "$REFS_STATUS" = 404', first_publish_branch)

    def test_publisher_requires_prepare_authentication_record_before_signing(self):
        publisher = self.workflow["jobs"]["publisher"]
        names = [step.get("name", "") for step in publisher["steps"]]
        sign_index = next(i for i, name in enumerate(names) if name.startswith("Re-verify the staged repository"))
        descriptor_index = next(i for i, name in enumerate(names) if name.startswith("Write trusted release descriptor"))
        download_index = next(i for i, step in enumerate(publisher["steps"])
                              if str(step.get("with", {}).get("name", "")).startswith("flatpak-stage-"))
        self.assertLess(download_index, descriptor_index)
        self.assertLess(descriptor_index, sign_index)
        sign_upload = publisher["steps"][sign_index]["run"]
        for forbidden in ("--verification", "--inspected", "repository-verification.json"):
            self.assertNotIn(forbidden, sign_upload)
        descriptor_step = publisher["steps"][descriptor_index]
        self.assertIn("inputs.channel", str(descriptor_step["env"]))
        self.assertNotIn("${{", descriptor_step["run"])

    def test_issuer_uses_maximum_supported_credential_ttl(self):
        issuer = self.workflow["jobs"]["issuer"]
        issue = next(step for step in issuer["steps"]
                     if step.get("name", "").startswith("Issue channel-scoped"))
        self.assertIn("--ttl 900", issue["run"])

    def test_credential_material_never_enters_runner_environment_or_later_steps(self):
        self.assertNotIn("GITHUB_ENV", self.raw)
        self.assertNotIn("GITHUB_OUTPUT", self.raw)
        steps = self.workflow["jobs"]["publisher"]["steps"]
        upload = next(i for i, step in enumerate(steps)
                      if step.get("name", "").startswith("Re-verify"))
        for step in steps[upload + 1:]:
            self.assertNotIn("AWS_ACCESS_KEY_ID", str(step))
            self.assertNotIn("AWS_SECRET_ACCESS_KEY", str(step))
            self.assertNotIn("AWS_SESSION_TOKEN", str(step))

    def test_signing_home_is_verified_tmpfs(self):
        self.assertIn("/dev/shm/luminus-t09-gnupg", self.raw)
        self.assertIn('stat -f -c %T "$GNUPGHOME"', self.raw)

    def test_concurrency_is_per_channel_and_not_cancelled(self):
        self.assertIn("${{ inputs.channel }}", self.workflow["concurrency"]["group"])
        self.assertIs(self.workflow["concurrency"]["cancel-in-progress"], False)

    def test_actions_are_pinned_and_run_scripts_do_not_interpolate_inputs(self):
        uses = re.findall(r"uses:\s*([^\s]+)", self.raw)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"@([0-9a-f]{40})$")
        for job in self.workflow["jobs"].values():
            for step in job.get("steps", []):
                if "run" in step:
                    self.assertNotIn("${{ inputs.", step["run"])

    def test_mirror_and_publish_never_use_delete_sync(self):
        self.assertIn("ostree pull", self.raw)
        self.assertIn("404)", self.raw)
        self.assertIn('*) exit 1', self.raw)
        self.assertNotIn("sync --delete", self.raw)
        self.assertNotRegex(self.raw, r"aws\s+s3\s+rm\b")

    def test_signing_key_comes_from_selected_environment_and_cleanup_precedes_artifact(self):
        publisher = self.workflow["jobs"]["publisher"]
        steps = publisher["steps"]
        key_step = next(step for step in steps
                        if step.get("name") == "Import signing subkey to verified tmpfs GnuPG home")
        self.assertIn("${{ secrets.SIGNING_SUBKEY }}", key_step["env"]["SIGNING_SUBKEY"])
        self.assertIn("${{ vars.SIGNING_SUBKEY_FINGERPRINT }}",
                      key_step["env"]["SIGNING_SUBKEY_FINGERPRINT"])
        cleanup_index = next(index for index, step in enumerate(steps)
                             if step.get("name") == "Remove temporary credentials and key material")
        artifact_index = next(index for index, step in enumerate(steps)
                              if step.get("uses", "").startswith("actions/upload-artifact@"))
        self.assertLess(cleanup_index, artifact_index)


if __name__ == "__main__":
    unittest.main()

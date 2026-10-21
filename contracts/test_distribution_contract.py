import copy
import unittest

from jsonschema import Draft202012Validator

from distribution_contract import (
    SCHEMA, channel_for, merge_release, release_digest, select_testing,
    validate_pins, validate_release,
)


def release_fixture(version="1.2.3", application="dev.luminusos.ZapTide"):
    repository, workflow, package_format = {
        "dev.luminusos.ZapTide": ("zaptide", "release.yml", "flatpak"),
        "org.luminusos.Aetheris": ("aetheris", "release-flatpak.yml", "flatpak"),
        "sirius-installer": ("sirius", "ci.yml", "rpm"),
    }[application]
    return {
        "schema_version": 1, "kind": "release", "format": package_format,
        "application": application, "version": version,
        "source": {
            "repository": f"luminusOS/{repository}",
            "tag": "v" + version.replace("-rc.", "-rc"),
            "revision": "a" * 40, "workflow": f".github/workflows/{workflow}",
            "run_id": 123, "run_attempt": 1,
        },
        "artifacts": {
            arch: {"artifact_id": index, "filename": f"{repository}-{arch}.tar",
                   "sha256": str(index) * 64, "size_bytes": 1024}
            for index, arch in enumerate(("x86_64", "aarch64"), 1)
        },
    }


def pins_fixture(package_format="rpm", channel="stable", architecture="x86_64"):
    application = "sirius-installer" if package_format == "rpm" else "dev.luminusos.ZapTide"
    version = "1.2.3" if channel == "stable" else "1.2.3-rc.1"
    pin = {
        "format": package_format, "application": application, "channel": channel,
        "version": version, "sha256": "b" * 64, "fallback": "none",
    }
    if package_format == "rpm":
        pin.update(
            url=f"https://rpm.luminusos.org/{channel}/45/{architecture}/Packages/sirius.rpm",
            rpm={"name": application, "epoch": 0, "version": version.replace("-rc.", "~rc."), "release": "1.fc45", "fedora": 45},
        )
    else:
        pin.update(
            url=f"https://flatpak.luminusos.org/{channel}/objects/cc/{'c' * 62}.commit",
            flatpak={"ref": f"app/{application}/{architecture}/{channel}", "commit": "c" * 64},
        )
    return {
        "schema_version": 1, "kind": "image-pins",
        "image": {"reference": "ghcr.io/luminusos/workstation", "digest": "sha256:" + "d" * 64,
                  "channel": channel, "architecture": architecture},
        "pins": [pin],
    }


class ReleaseTests(unittest.TestCase):
    def test_schema_is_valid(self):
        Draft202012Validator.check_schema(SCHEMA)

    def test_accepts_three_applications_and_both_tag_spellings(self):
        for app in ("dev.luminusos.ZapTide", "org.luminusos.Aetheris", "sirius-installer"):
            for version in ("1.2.3", "1.2.3-rc.1"):
                release = release_fixture(version, app)
                validate_release(release)
                release["source"]["tag"] = "v" + version
                validate_release(release)

    def test_all_fields_are_required(self):
        for path in ((), ("source",), ("artifacts", "x86_64"), ("artifacts", "aarch64")):
            original = release_fixture()
            target = original
            for key in path:
                target = target[key]
            for field in target:
                candidate = copy.deepcopy(original)
                mapping = candidate
                for key in path:
                    mapping = mapping[key]
                del mapping[field]
                with self.subTest(path=path, field=field), self.assertRaises(ValueError):
                    validate_release(candidate)

    def test_rejects_unknown_fields_at_every_level(self):
        for path in ((), ("source",), ("artifacts",), ("artifacts", "x86_64")):
            candidate = release_fixture()
            mapping = candidate
            for key in path:
                mapping = mapping[key]
            mapping["channel"] = "stable"
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_release(candidate)

    def test_rejects_wrong_source_workflow_and_format_for_each_app(self):
        for app in ("dev.luminusos.ZapTide", "org.luminusos.Aetheris", "sirius-installer"):
            for field, value in (("repository", "attacker/app"), ("workflow", ".github/workflows/evil.yml"),
                                 ("format", "flatpak" if app == "sirius-installer" else "rpm")):
                release = release_fixture(application=app)
                (release if field == "format" else release["source"])[field] = value
                with self.subTest(app=app, field=field), self.assertRaises(ValueError):
                    validate_release(release)

    def test_rejects_invalid_tag_version_and_nonobjects(self):
        for candidate in (None, [], 1, {"source": []}, {"version": None}):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                validate_release(candidate)
        for tag in ("main", "v1.2.4", "v1.2.3-rc1", "v1.2.3\n", "v1.2.3;echo bad"):
            release = release_fixture()
            release["source"]["tag"] = tag
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                validate_release(release)

    def test_rejects_invalid_paths_digests_and_architectures(self):
        for filename in ("../x.tar", "/x.tar", "a/b.tar", "a\\b.tar", "a%2fb.tar", "a.tar\n"):
            release = release_fixture()
            release["artifacts"]["aarch64"]["filename"] = filename
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                validate_release(release)
        for sha in ("", "b" * 63, "B" * 64, "b" * 64 + "\n"):
            release = release_fixture()
            release["artifacts"]["x86_64"]["sha256"] = sha
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                validate_release(release)
        release = release_fixture()
        release["artifacts"]["arm64"] = release["artifacts"].pop("aarch64")
        with self.assertRaises(ValueError):
            validate_release(release)

    def test_rejects_boolean_ids_and_duplicate_artifacts(self):
        for field in ("run_id", "run_attempt"):
            release = release_fixture()
            release["source"][field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_release(release)
        release = release_fixture()
        release["artifacts"]["aarch64"]["artifact_id"] = 1
        with self.assertRaises(ValueError):
            validate_release(release)


class SelectionTests(unittest.TestCase):
    def test_channels_and_invalid_versions(self):
        self.assertEqual(channel_for("1.2.3"), "stable")
        self.assertEqual(channel_for("1.2.3-rc.1"), "testing")
        for version in (None, 1, "latest", "01.2.3", "1.2.3-rc.0", "1.2.3\n"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                channel_for(version)

    def test_latest_rc_is_selected_numerically(self):
        selected = select_testing([release_fixture("1.2.3-rc.2"), release_fixture("1.2.3-rc.10")])
        self.assertEqual(selected["release"]["version"], "1.2.3-rc.10")
        self.assertEqual(selected["fallback"], "none")

    def test_final_supersedes_old_rc_with_explicit_approval(self):
        final = release_fixture("1.3.0")
        selected = select_testing([release_fixture("1.2.3-rc.2"), final], approved_stable=[final])
        self.assertEqual(selected["release"], final)
        self.assertEqual(selected["channel"], "testing")
        self.assertEqual(selected["fallback"], "stable-approved")

    def test_final_candidates_never_self_approve(self):
        for candidates in ([release_fixture()], [release_fixture("1.2.3-rc.1"), release_fixture()]):
            with self.subTest(candidates=candidates), self.assertRaises(ValueError):
                select_testing(candidates)

    def test_newer_rc_wins_and_latest_approved_final_is_fallback(self):
        final = release_fixture("1.2.3")
        rc = release_fixture("1.3.0-rc.1")
        self.assertEqual(select_testing([rc], approved_stable=[final])["release"], rc)
        self.assertEqual(select_testing([], approved_stable=[release_fixture("1.2.2"), final])["release"], final)
        with self.assertRaises(ValueError):
            select_testing([])

    def test_selection_rejects_mixed_apps_invalid_and_conflicting_inputs(self):
        for candidates, approved in (
            ([release_fixture("1.2.3-rc.1")], [release_fixture(application="org.luminusos.Aetheris")]),
            ([{"version": "1.2.3-rc.1"}], []),
            ([], [release_fixture("1.2.3-rc.1")]),
        ):
            with self.subTest(candidates=candidates), self.assertRaises(ValueError):
                select_testing(candidates, approved_stable=approved)
        final = release_fixture()
        altered = copy.deepcopy(final)
        altered["artifacts"]["x86_64"]["sha256"] = "f" * 64
        with self.assertRaises(ValueError):
            select_testing([final], approved_stable=[altered])

    def test_merge_replays_are_noops_and_do_not_mutate_inputs(self):
        release = release_fixture()
        original = copy.deepcopy(release)
        catalog = merge_release({}, release, approved_stable=[release])
        self.assertEqual(merge_release(catalog, release, approved_stable=[release]), catalog)
        self.assertEqual(release, original)
        other = release_fixture(application="org.luminusos.Aetheris")
        merged = merge_release(catalog, other, approved_stable=[other])
        self.assertEqual(merged["releases"][release["application"]], catalog["releases"][release["application"]])
        self.assertNotIn(other["application"], catalog["releases"])

    def test_merge_rejects_conflicts_and_bad_catalogs_without_mutation(self):
        release = release_fixture()
        catalog = merge_release({}, release, approved_stable=[release])
        before = copy.deepcopy(catalog)
        for field in ("sha256", "size_bytes"):
            altered = copy.deepcopy(release)
            altered["artifacts"]["aarch64"][field] = "c" * 64 if field == "sha256" else 2048
            with self.subTest(field=field), self.assertRaises(ValueError):
                merge_release(catalog, altered, approved_stable=[altered])
            self.assertEqual(catalog, before)
        for invalid in ([], {"unexpected": []}, {"releases": {"wrong": {}}}):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                merge_release(invalid, release)

    def test_merge_testing_fallback_requires_exact_approved_release(self):
        final = release_fixture()
        with self.assertRaises(ValueError):
            merge_release({}, final, channel="testing")
        catalog = merge_release({}, final, channel="testing", approved_stable=[final])
        self.assertIn("flatpak:testing:1.2.3", catalog["releases"][final["application"]])
        with self.assertRaises(ValueError):
            merge_release({}, release_fixture("1.2.3-rc.1"), channel="stable")

    def test_stable_merge_requires_exact_protected_approval(self):
        final = release_fixture()
        altered = copy.deepcopy(final)
        altered["source"]["revision"] = "f" * 40
        for approved in ([], [altered], [release_fixture(application="org.luminusos.Aetheris")]):
            with self.subTest(approved=approved), self.assertRaises(ValueError):
                merge_release({}, final, approved_stable=approved)
        catalog = merge_release({}, final, approved_stable=[final])
        self.assertIn("flatpak:stable:1.2.3", catalog["releases"][final["application"]])

    def test_digest_is_canonical_and_changes_with_provenance(self):
        release = release_fixture()
        self.assertEqual(release_digest(release), release_digest(dict(reversed(list(release.items())))))
        changed = copy.deepcopy(release)
        changed["source"]["run_attempt"] += 1
        self.assertNotEqual(release_digest(release), release_digest(changed))


class PinTests(unittest.TestCase):
    def test_accepts_both_formats_architectures_and_channels(self):
        for package_format in ("rpm", "flatpak"):
            for architecture in ("x86_64", "aarch64"):
                for channel in ("stable", "testing"):
                    validate_pins(pins_fixture(package_format, channel, architecture))

    def test_all_pin_and_image_fields_are_required(self):
        for package_format in ("rpm", "flatpak"):
            for path in ((), ("image",), ("pins", 0), ("pins", 0, package_format)):
                original = pins_fixture(package_format)
                target = original
                for key in path:
                    target = target[key]
                for field in target:
                    candidate = copy.deepcopy(original)
                    mapping = candidate
                    for key in path:
                        mapping = mapping[key]
                    del mapping[field]
                    with self.subTest(format=package_format, path=path, field=field), self.assertRaises(ValueError):
                        validate_pins(candidate)

    def test_rejects_duplicate_pins_unknown_fields_and_empty_pins(self):
        for pins in ([], [pins_fixture()["pins"][0]] * 2):
            candidate = pins_fixture()
            candidate["pins"] = pins
            with self.assertRaises(ValueError):
                validate_pins(candidate)
        candidate = pins_fixture()
        candidate["pins"][0]["approved"] = True
        with self.assertRaises(ValueError):
            validate_pins(candidate)

    def test_rejects_wrong_hosts_paths_queries_ports_and_channels(self):
        for url in (
            "http://rpm.luminusos.org/stable/45/x86_64/a.rpm",
            "https://rpm.luminusos.org.evil/stable/45/x86_64/a.rpm",
            "https://user@rpm.luminusos.org/stable/45/x86_64/a.rpm",
            "https://rpm.luminusos.org:443/stable/45/x86_64/a.rpm",
            "https://rpm.luminusos.org/testing/45/x86_64/a.rpm",
            "https://rpm.luminusos.org/stable/45/aarch64/a.rpm",
            "https://rpm.luminusos.org/stable/44/x86_64/a.rpm",
            "https://rpm.luminusos.org/stable/45/x86_64/../a.rpm",
            "https://rpm.luminusos.org/stable/45/x86_64/%2e%2e/a.rpm",
            "https://rpm.luminusos.org/stable/45/x86_64/a.rpm?token=x",
            "https://rpm.luminusos.org/stable/45/x86_64/a.rpm#x",
        ):
            candidate = pins_fixture()
            candidate["pins"][0]["url"] = url
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_pins(candidate)

    def test_rejects_channel_fallback_mismatches_and_rc_in_stable(self):
        for image_channel, pin_channel, version, fallback in (
            ("stable", "testing", "1.2.3", "none"),
            ("stable", "stable", "1.2.3-rc.1", "none"),
            ("testing", "stable", "1.2.3", "none"),
            ("stable", "stable", "1.2.3", "stable-approved"),
        ):
            candidate = pins_fixture(channel=pin_channel)
            candidate["image"]["channel"] = image_channel
            candidate["pins"][0].update(version=version, fallback=fallback)
            with self.subTest(case=(image_channel, pin_channel, version, fallback)), self.assertRaises(ValueError):
                validate_pins(candidate)
        candidate = pins_fixture()
        candidate["image"]["channel"] = "testing"
        candidate["pins"][0]["fallback"] = "stable-approved"
        validate_pins(candidate)

    def test_final_reexported_in_testing_still_records_fallback(self):
        candidate = pins_fixture(channel="testing")
        candidate["pins"][0].update(version="1.2.3", fallback="none")
        candidate["pins"][0]["rpm"]["version"] = "1.2.3"
        with self.assertRaises(ValueError):
            validate_pins(candidate)
        candidate["pins"][0]["fallback"] = "stable-approved"
        validate_pins(candidate)

    def test_rejects_rpm_metadata_mismatches(self):
        for field, value in (("name", "other"), ("fedora", 44), ("epoch", True),
                             ("version", "1.2.4"), ("release", "%{dist}")):
            candidate = pins_fixture()
            candidate["pins"][0]["rpm"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_pins(candidate)
        candidate = pins_fixture(channel="testing")
        candidate["pins"][0]["version"] = "1.2.3-rc.1"
        candidate["pins"][0]["rpm"]["version"] = "1.2.3~rc.1"
        validate_pins(candidate)

    def test_rejects_flatpak_ref_commit_and_variant_mismatches(self):
        for ref in ("app/dev.luminusos.ZapTide/aarch64/stable", "app/dev.luminusos.ZapTide/x86_64/testing",
                    "app/org.luminusos.Aetheris/x86_64/stable", "runtime/dev.luminusos.ZapTide/x86_64/stable"):
            candidate = pins_fixture("flatpak")
            candidate["pins"][0]["flatpak"]["ref"] = ref
            with self.subTest(ref=ref), self.assertRaises(ValueError):
                validate_pins(candidate)
        candidate = pins_fixture("flatpak")
        candidate["pins"][0]["flatpak"]["commit"] = "f" * 64
        with self.assertRaises(ValueError):
            validate_pins(candidate)
        candidate = pins_fixture()
        candidate["pins"][0]["flatpak"] = pins_fixture("flatpak")["pins"][0]["flatpak"]
        with self.assertRaises(ValueError):
            validate_pins(candidate)

    def test_rejects_mixed_document_kinds_and_unfixed_oci(self):
        candidate = pins_fixture()
        candidate.update(release_fixture())
        with self.assertRaises(ValueError):
            validate_pins(candidate)
        for digest in ("latest", "sha256:" + "D" * 64, "sha256:" + "d" * 63):
            candidate = pins_fixture()
            candidate["image"]["digest"] = digest
            with self.subTest(digest=digest), self.assertRaises(ValueError):
                validate_pins(candidate)


if __name__ == "__main__":
    unittest.main()

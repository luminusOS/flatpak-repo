import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from jsonschema import Draft202012Validator

from tools.catalog import CATALOG_SCHEMA, validate_catalog


ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "catalog.json"
LOCK_EXPECTED = {
    "schema_version": 1,
    "source": {"path": "docs/specs/luminus-distribution", "approved": "2026-10-18"},
    "files": {
        "distribution.schema.json": "a17635d45c5a0f0c2c51a075133f31884ce14cd1393daa20600255836732fe8a",
        "distribution_contract.py": "c5675fa4feeb69eca43bd4c7274645a5851a417d9f01acca908535a7dfac59ab",
        "test_distribution_contract.py": "056048dd5faf28604f88e004a7b94516a6730abba53ee0d58a5c7208212a90ff",
    },
}


def catalog_fixture():
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


def expected_application_sources(catalog):
    if catalog["format"] == "flatpak":
        return {
            "dev.luminusos.ZapTide": {
                "repository": "luminusOS/zaptide",
                "workflow": ".github/workflows/release.yml",
            },
            "org.luminusos.Aetheris": {
                "repository": "luminusOS/aetheris",
                "workflow": ".github/workflows/release-flatpak.yml",
            },
        }
    return {
        "sirius-installer": {
            "repository": "luminusOS/sirius",
            "workflow": ".github/workflows/ci.yml",
        }
    }


def known_application_sources(catalog):
    actual = {item["id"]: item["source"] for item in catalog["applications"]}
    expected = expected_application_sources(catalog)
    return {identifier: actual.get(identifier) for identifier in expected}


def future_application(catalog):
    identifiers = {item["id"] for item in catalog["applications"]}
    if catalog["format"] == "flatpak":
        base_identifier = "org.luminusos.FutureApp"
    else:
        base_identifier = "future-app"
    suffix = 1
    identifier = base_identifier
    while identifier in identifiers:
        suffix += 1
        identifier = f"{base_identifier}{suffix}"
    return {
        "id": identifier,
        "source": {
            "repository": "luminusOS/future-app",
            "workflow": ".github/workflows/release.yml",
        },
    }


class CatalogTests(unittest.TestCase):
    def test_schema_is_valid_and_current_catalog_is_valid(self):
        Draft202012Validator.check_schema(CATALOG_SCHEMA)
        self.assertEqual(validate_catalog(catalog_fixture()), catalog_fixture())

    def test_current_application_sources_are_registered(self):
        catalog = catalog_fixture()
        self.assertEqual(known_application_sources(catalog), expected_application_sources(catalog))

    def test_rejects_missing_required_fields(self):
        for path in (
            ("schema_version",), ("format",), ("architectures",), ("channels",),
            ("applications",), ("applications", 0, "id"),
            ("applications", 0, "source"), ("applications", 0, "source", "repository"),
            ("applications", 0, "source", "workflow"),
        ):
            candidate = catalog_fixture()
            target = candidate
            for key in path[:-1]:
                target = target[key]
            target.pop(path[-1])
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_catalog(candidate)

    def test_rejects_unknown_fields_at_every_level(self):
        for path in ((), ("applications", 0), ("applications", 0, "source")):
            candidate = catalog_fixture()
            target = candidate
            for key in path:
                target = target[key]
            target["unexpected"] = "value"
            with self.subTest(path=path), self.assertRaises(ValueError):
                validate_catalog(candidate)

    def test_rejects_wrong_format_and_missing_architecture_or_channel(self):
        candidate = catalog_fixture()
        candidate["format"] = "rpm" if candidate["format"] == "flatpak" else "flatpak"
        with self.assertRaises(ValueError):
            validate_catalog(candidate)
        for field in ("architectures", "channels"):
            candidate = catalog_fixture()
            candidate[field].pop()
            with self.subTest(field=field), self.assertRaises(ValueError):
                validate_catalog(candidate)

    def test_rejects_duplicate_application_ids(self):
        candidate = catalog_fixture()
        candidate["applications"].append(copy.deepcopy(candidate["applications"][0]))
        with self.assertRaises(ValueError):
            validate_catalog(candidate)

    def test_rejects_unsafe_application_ids_repositories_and_workflows(self):
        for field, values in (
            ("id", ("../app", "org.luminusos.Bad/Path", "sirius;touch", "org.luminusos.Bad\n")),
            ("repository", ("luminusOS/../repo", "luminusOS/app%2fother", "attacker/repo", "luminusOS/app\n")),
            ("workflow", (".github/workflows/../../bad.yml", ".github/workflows/a%2fb.yml",
                          ".github/workflows/evil;run.yml", ".github/workflows/a\nb.yml",
                          ".github/workflows/safe.yml\n")),
        ):
            for value in values:
                candidate = catalog_fixture()
                target = candidate["applications"][0]
                if field != "id":
                    target = target["source"]
                target[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    validate_catalog(candidate)

    def test_accepts_future_application_with_configuration_only(self):
        candidate = catalog_fixture()
        expected_known_sources = known_application_sources(candidate)
        candidate["applications"].append(future_application(candidate))
        self.assertEqual(known_application_sources(candidate), expected_known_sources)
        self.assertEqual(validate_catalog(candidate), candidate)

    def test_future_application_fixture_avoids_an_already_registered_id(self):
        candidate = catalog_fixture()
        expected_known_sources = known_application_sources(candidate)
        candidate["applications"].append(future_application(candidate))
        candidate["applications"].append(future_application(candidate))
        self.assertEqual(known_application_sources(candidate), expected_known_sources)
        self.assertEqual(validate_catalog(candidate), candidate)

    def test_rpm_requires_fedora_45_and_flatpak_forbids_fedora(self):
        candidate = catalog_fixture()
        if candidate["format"] == "rpm":
            self.assertEqual(candidate["fedora"], 45)
            del candidate["fedora"]
        else:
            candidate["fedora"] = 45
        with self.assertRaises(ValueError):
            validate_catalog(candidate)

    def test_contract_lock_pins_only_known_snapshot_files(self):
        lock = json.loads((ROOT / "contracts.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(lock, LOCK_EXPECTED)
        self.assertEqual(set(lock["files"]), set(LOCK_EXPECTED["files"]))
        for name, expected in LOCK_EXPECTED["files"].items():
            actual = hashlib.sha256((ROOT / "contracts" / name).read_bytes()).hexdigest()
            self.assertEqual(actual, expected, name)

    def test_validation_does_not_make_network_requests(self):
        with mock.patch("socket.create_connection", side_effect=AssertionError("network access")), \
                mock.patch("urllib.request.urlopen", side_effect=AssertionError("network access")):
            self.assertEqual(validate_catalog(catalog_fixture()), catalog_fixture())

    def test_cli_accepts_valid_catalog(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "tools" / "catalog.py"), str(CATALOG_PATH)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_cli_rejects_invalid_and_malformed_catalogs(self):
        invalid_inputs = (
            '{"schema_version":1,"format":"wrong"}',
            '{"schema_version":1,"schema_version":1}',
            '{"schema_version":NaN}',
            "{",
        )
        for content in invalid_inputs:
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
                file.write(content)
                path = file.name
            try:
                result = subprocess.run(
                    [sys.executable, str(ROOT / "tools" / "catalog.py"), path],
                    capture_output=True, text=True, check=False,
                )
                with self.subTest(content=content):
                    self.assertNotEqual(result.returncode, 0)
                    self.assertLess(len(result.stderr), 1000)
            finally:
                os.unlink(path)

    def test_cli_rejects_oversized_input(self):
        with tempfile.NamedTemporaryFile("wb", delete=False) as file:
            file.write(b" " * (1024 * 1024 + 1))
            path = file.name
        try:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "catalog.py"), path],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
        finally:
            os.unlink(path)

    def test_cli_rejects_deep_json_without_traceback(self):
        content = "[" * 100000 + "0" + "]" * 100000
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as file:
            file.write(content)
            path = file.name
        try:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "catalog.py"), path],
                capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertEqual(result.stderr, "catalog validation failed\n")
        finally:
            os.unlink(path)

    def test_cli_finds_its_schema_outside_the_checkout_working_directory(self):
        with tempfile.TemporaryDirectory() as cwd:
            result = subprocess.run(
                [sys.executable, str(ROOT / "tools" / "catalog.py"), str(CATALOG_PATH)],
                cwd=cwd, capture_output=True, text=True, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()

import unittest

from tools.publish_plan import ImportError, build_upload_plan, publish_uploads


class RecordingStorage:
    def __init__(self, fail_key=None):
        self.uploaded = []
        self.fail_key = fail_key

    def put(self, key, content):
        if key == self.fail_key:
            raise OSError("injected upload failure")
        self.uploaded.append(key)


class PublishPlanTests(unittest.TestCase):
    def test_objects_and_deltas_precede_mutable_metadata(self):
        plan = build_upload_plan("testing", {
            "testing/summary": b"s",
            "testing/refs/heads/app/org.example.App/x86_64/testing": b"r",
            "testing/objects/ab/c.commit": b"o",
            "testing/deltas/ab/c-delta": b"d",
        })
        self.assertEqual([item.key for item in plan], [
            "testing/deltas/ab/c-delta", "testing/objects/ab/c.commit",
            "testing/refs/heads/app/org.example.App/x86_64/testing", "testing/summary",
        ])

    def test_ledger_and_detached_signature_are_mutable_metadata(self):
        plan = build_upload_plan("testing", {
            "testing/luminus-imports.json": b"ledger",
            "testing/luminus-imports.json.sig": b"signature",
            "testing/objects/ab/c.commit": b"object",
        })
        self.assertEqual([item.key for item in plan], [
            "testing/objects/ab/c.commit", "testing/luminus-imports.json",
            "testing/luminus-imports.json.sig",
        ])
        self.assertTrue(all(item.mutable for item in plan[1:]))

    def test_mutable_upload_waits_for_public_verification(self):
        storage = RecordingStorage()
        observed = []
        publish_uploads("stable", {"stable/summary": b"s", "stable/objects/a": b"o"},
                        storage, lambda key, data: observed.append((key, data)) or True)
        self.assertEqual(storage.uploaded, ["stable/objects/a", "stable/summary"])
        self.assertEqual([key for key, _ in observed], ["stable/objects/a"])

    def test_verification_failure_leaves_mutable_metadata_untouched(self):
        storage = RecordingStorage()
        with self.assertRaises(ImportError):
            publish_uploads("stable", {"stable/summary": b"s", "stable/objects/a": b"o"},
                            storage, lambda key, data: False)
        self.assertEqual(storage.uploaded, ["stable/objects/a"])

    def test_upload_failure_leaves_mutable_metadata_untouched(self):
        storage = RecordingStorage(fail_key="stable/objects/b")
        with self.assertRaises(OSError):
            publish_uploads("stable", {"stable/summary": b"s", "stable/objects/a": b"a",
                                        "stable/objects/b": b"b"}, storage,
                            lambda key, data: True)
        self.assertNotIn("stable/summary", storage.uploaded)

    def test_insufficient_expiry_budget_prevents_all_mutable_uploads(self):
        storage = RecordingStorage()
        with self.assertRaises(ImportError):
            publish_uploads("stable", {"stable/objects/a": b"o", "stable/summary": b"s"},
                            storage, lambda key, data: True, expires_at=110,
                            minimum_mutable_budget=20, clock=lambda: 100)
        self.assertEqual(storage.uploaded, ["stable/objects/a"])

    def test_rejects_other_channel_and_unscoped_keys(self):
        for key in ("testing/objects/a", "stableish/objects/a", "objects/a"):
            with self.subTest(key=key), self.assertRaises(ImportError):
                build_upload_plan("stable", {key: b"x"})

    def test_rejects_path_traversal(self):
        for key in ("stable/../testing/summary", "stable/objects/../../summary",
                    "stable//summary", "stable/./summary", "stable/objects\\..\\summary"):
            with self.subTest(key=key), self.assertRaises(ImportError):
                build_upload_plan("stable", {key: b"x"})

    def test_never_deletes(self):
        plan = build_upload_plan("stable", {"stable/objects/a": b"x"})
        self.assertTrue(all(item.method == "PUT" for item in plan))


if __name__ == "__main__":
    unittest.main()

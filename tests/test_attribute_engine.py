import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from attribute_engine import (
    AttributeChangeEngine,
    AttributeChangeError,
    AttributeChangeRequest,
    UnknownDirectoryServiceError,
)


class _RecordingService:
    def __init__(self, name, records):
        self.name = name
        self._records = records

    def update_attribute(self, user_id, attribute, value):
        self._records.append((self.name, user_id, attribute, value))


class AttributeChangeEngineTests(unittest.TestCase):
    def setUp(self):
        self.records = []
        self.engine = AttributeChangeEngine()
        self.engine.register_service(_RecordingService("ldap", self.records))
        self.engine.register_service(_RecordingService("okta", self.records))

    def test_apply_change_updates_all_services_by_default(self):
        request = AttributeChangeRequest("user-1", "email", "user@example.com")
        result = self.engine.apply_change(request)

        self.assertTrue(result.success)
        self.assertEqual(len(self.records), 2)
        self.assertEqual(
            self.records,
            [
                ("ldap", "user-1", "email", "user@example.com"),
                ("okta", "user-1", "email", "user@example.com"),
            ],
        )

    def test_apply_change_with_specific_services(self):
        request = AttributeChangeRequest("user-2", "department", "Engineering", services=("okta",))
        result = self.engine.apply_change(request)

        self.assertTrue(result.success)
        self.assertEqual(result.successful, ["okta"])
        self.assertEqual(self.records, [("okta", "user-2", "department", "Engineering")])

    def test_unknown_service_reports_failure(self):
        request = AttributeChangeRequest("user-3", "title", "Manager", services=("unknown",))
        result = self.engine.apply_change(request)

        self.assertFalse(result.success)
        self.assertIsInstance(result.failures["unknown"], UnknownDirectoryServiceError)

    def test_apply_changes_batches_multiple_requests(self):
        requests = [
            AttributeChangeRequest("user-a", "email", "a@example.com"),
            AttributeChangeRequest("user-b", "email", "b@example.com", services=("ldap",)),
        ]

        results = self.engine.apply_changes(requests)

        self.assertEqual(len(results), 2)
        self.assertTrue(all(result.success for result in results))
        self.assertEqual(len(self.records), 3)

    def test_registering_duplicate_service_requires_replace(self):
        with self.assertRaises(ValueError):
            self.engine.register_service(_RecordingService("ldap", self.records))

        # ensure replace=True overwrites
        self.engine.register_service(_RecordingService("ldap", self.records), replace=True)
        request = AttributeChangeRequest("user-c", "email", "c@example.com", services=("ldap",))
        result = self.engine.apply_change(request)
        self.assertTrue(result.success)

    def test_callable_registration_requires_name(self):
        updates = []

        def handler(user_id, attribute, value):
            updates.append((user_id, attribute, value))

        self.engine.register_service(handler, name="custom")
        request = AttributeChangeRequest("user-d", "phone", "+1")
        result = self.engine.apply_change(request)

        self.assertTrue(result.success)
        self.assertIn(("user-d", "phone", "+1"), updates)

    def test_raise_if_failed(self):
        request = AttributeChangeRequest("user-e", "role", "admin", services=("missing",))
        result = self.engine.apply_change(request)

        with self.assertRaises(AttributeChangeError):
            result.raise_if_failed()


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

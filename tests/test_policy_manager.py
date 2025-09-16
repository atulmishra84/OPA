import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Provide light-weight stubs for third-party dependencies that are not
# available in the execution environment during tests.
flask_stub = types.ModuleType("flask")
flask_stub.Flask = lambda name: mock.Mock(name="FlaskApp")
flask_stub.jsonify = lambda *args, **kwargs: {"args": args, "kwargs": kwargs}
flask_stub.request = mock.Mock(name="request")
sys.modules.setdefault("flask", flask_stub)

requests_stub = types.ModuleType("requests")


class _StubSession:
    def __init__(self):
        self.put = mock.Mock(name="requests.put")
        self.delete = mock.Mock(name="requests.delete")


class RequestException(Exception):
    pass


requests_stub.Session = _StubSession
requests_stub.RequestException = RequestException
requests_stub.post = mock.Mock(
    name="requests.post",
    return_value=mock.Mock(
        status_code=200,
        raise_for_status=mock.Mock(),
        json=lambda: {},
    ),
)
sys.modules.setdefault("requests", requests_stub)

# Ensure the global policy manager does not auto start when importing the app module in tests.
os.environ.setdefault("AUTO_START_POLICY_MANAGER", "false")

from app import PolicyManager, _extract_log_payload  # noqa: E402


class PolicyManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        base_dir = Path(self._tmp.name) / "base"
        dynamic_dir = Path(self._tmp.name) / "dynamic"
        base_dir.mkdir()
        dynamic_dir.mkdir()

        (base_dir / "policy.rego").write_text("package test\nallow = true\n")

        self.manager = PolicyManager(
            opa_url="http://localhost:8181",
            base_dir=base_dir,
            dynamic_dir=dynamic_dir,
            poll_interval=0,
        )

    def tearDown(self) -> None:
        self._tmp.cleanup()

    @staticmethod
    def _mock_response(status_code=200):
        response = mock.Mock()
        response.status_code = status_code
        response.raise_for_status = mock.Mock()
        return response

    def test_force_reload_publishes_base_policy(self) -> None:
        with mock.patch.object(self.manager.session, "put", return_value=self._mock_response()):
            self.manager.force_reload()

        self.assertIn("base:policy", self.manager._loaded)
        self.assertEqual(self.manager.status["policy_count"], 1)
        self.assertEqual(self.manager.status["dynamic_policy_count"], 0)

    def test_dynamic_policy_sync_detects_new_files(self) -> None:
        dynamic_policy_path = Path(self.manager.dynamic_dir) / "cms.rego"
        dynamic_policy_path.write_text("package gatekeeper\nallow = true\n")

        with mock.patch.object(self.manager.session, "put", return_value=self._mock_response()):
            self.manager._sync_directory(self.manager.dynamic_dir, prefix="dynamic")

        self.assertIn("dynamic:cms", self.manager._loaded)
        self.assertEqual(self.manager.status.get("last_error"), None)

    def test_extract_log_payload_helper(self) -> None:
        wrapped = {"log": {"message": "hello"}}
        plain = {"message": "hello"}
        self.assertEqual(_extract_log_payload(wrapped), wrapped["log"])
        self.assertEqual(_extract_log_payload(plain), plain)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()

import atexit
import hashlib
import logging
import os
import threading
import time
from pathlib import Path
from typing import Dict, Optional

import requests
from flask import Flask, jsonify, request

logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger(__name__)

OPA_URL = os.getenv("OPA_URL", "http://opa:8181").rstrip("/")
BASE_POLICY_DIR = Path(os.getenv("BASE_POLICY_DIR", "policies/base"))
DYNAMIC_POLICY_DIR = Path(os.getenv("DYNAMIC_POLICY_DIR", "policy_feed"))
POLICY_POLL_INTERVAL = int(os.getenv("POLICY_POLL_INTERVAL", "30"))
AUTO_START_POLICY_MANAGER = os.getenv("AUTO_START_POLICY_MANAGER", "true").lower() not in {
    "false",
    "0",
    "no",
}

LOG_POLICY_PATH = "logsecurity/deny"
GATEKEEPER_POLICY_PATH = "gatekeeper/violations"


def opa_query(path: str, payload: Dict) -> Dict:
    """Send a data query to OPA and return the parsed result."""
    url = f"{OPA_URL}/v1/data/{path}"
    logger.debug("Querying OPA at %s", url)

    try:
        response = requests.post(url, json={"input": payload}, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as exc:
        logger.exception("OPA query failed: %s", exc)
        raise


class PolicyManager:
    """Synchronises local Rego policies with a running OPA instance."""

    def __init__(
        self,
        opa_url: str,
        base_dir: Path,
        dynamic_dir: Optional[Path] = None,
        poll_interval: int = 30,
    ) -> None:
        self.opa_url = opa_url.rstrip("/")
        self.base_dir = base_dir
        self.dynamic_dir = dynamic_dir
        self.poll_interval = poll_interval
        self.session = requests.Session()
        self._loaded: Dict[str, Dict] = {}
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self.status: Dict[str, Optional[str]] = {
            "last_full_sync": None,
            "policy_count": 0,
            "dynamic_policy_count": 0,
            "last_dynamic_sync": None,
        }

    def start(self) -> None:
        """Load policies immediately and start background polling."""
        logger.info("Initialising policy manager")
        self.force_reload()

        if self.dynamic_dir and self.poll_interval > 0:
            self._thread = threading.Thread(target=self._watch_loop, daemon=True)
            self._thread.start()
            logger.info(
                "Started background policy watcher for %s (interval=%ss)",
                self.dynamic_dir,
                self.poll_interval,
            )

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def force_reload(self) -> None:
        """Reload all policies, ignoring cached hashes."""
        with self._lock:
            self._loaded.clear()
            self._sync_directory(self.base_dir, prefix="base")
            if self.dynamic_dir:
                self._sync_directory(self.dynamic_dir, prefix="dynamic")
            self.status.update(
                {
                    "last_full_sync": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "policy_count": sum(1 for k in self._loaded if k.startswith("base:")),
                    "dynamic_policy_count": sum(1 for k in self._loaded if k.startswith("dynamic:")),
                }
            )

    def _watch_loop(self) -> None:
        logger.debug("Entering policy watch loop")
        while not self._stop_event.wait(self.poll_interval):
            with self._lock:
                self._sync_directory(self.dynamic_dir, prefix="dynamic")
                dynamic_count = sum(1 for key in self._loaded if key.startswith("dynamic:"))
                self.status["dynamic_policy_count"] = dynamic_count
                self.status["last_dynamic_sync"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _sync_directory(self, directory: Optional[Path], prefix: str) -> int:
        if not directory or not directory.exists():
            logger.debug("Policy directory %s does not exist", directory)
            return 0

        logger.info("Synchronising %s policies from %s", prefix, directory)
        seen_ids = set()
        count = 0

        for file_path in sorted(directory.rglob("*.rego")):
            policy_id = self._policy_id(prefix, directory, file_path)
            seen_ids.add(policy_id)
            count += 1
            self._publish_policy(policy_id, file_path)

        # Remove policies that no longer exist on disk
        existing_ids = {key for key in self._loaded if key.startswith(f"{prefix}:")}
        for stale_id in existing_ids - seen_ids:
            self._delete_policy(stale_id)

        return count

    def _policy_id(self, prefix: str, root: Path, file_path: Path) -> str:
        relative = file_path.relative_to(root).with_suffix("")
        normalized = str(relative).replace(os.sep, "_")
        return f"{prefix}:{normalized}"

    def _publish_policy(self, policy_id: str, file_path: Path) -> None:
        content = file_path.read_text()
        policy_hash = hashlib.sha256(content.encode("utf-8")).hexdigest()
        cached = self._loaded.get(policy_id)

        if cached and cached["hash"] == policy_hash:
            logger.debug("Policy %s unchanged", policy_id)
            return

        opa_endpoint = f"{self.opa_url}/v1/policies/{policy_id}"
        logger.info("Publishing policy %s to %s", policy_id, opa_endpoint)
        try:
            response = self.session.put(
                opa_endpoint,
                data=content,
                headers={"Content-Type": "text/plain"},
                timeout=10,
            )
            response.raise_for_status()
            self._loaded[policy_id] = {"hash": policy_hash, "path": str(file_path)}
        except requests.RequestException as exc:
            logger.error("Failed to publish policy %s: %s", policy_id, exc)
            self.status["last_error"] = str(exc)

    def _delete_policy(self, policy_id: str) -> None:
        opa_endpoint = f"{self.opa_url}/v1/policies/{policy_id}"
        logger.info("Deleting policy %s", policy_id)
        try:
            response = self.session.delete(opa_endpoint, timeout=10)
            if response.status_code in (200, 204, 404):
                self._loaded.pop(policy_id, None)
            else:
                response.raise_for_status()
        except requests.RequestException as exc:
            logger.error("Failed to delete policy %s: %s", policy_id, exc)
            self.status["last_error"] = str(exc)


app = Flask(__name__)
policy_manager = PolicyManager(
    opa_url=OPA_URL,
    base_dir=BASE_POLICY_DIR,
    dynamic_dir=DYNAMIC_POLICY_DIR,
    poll_interval=POLICY_POLL_INTERVAL,
)
if AUTO_START_POLICY_MANAGER:
    policy_manager.start()
    atexit.register(policy_manager.stop)


@app.route("/")
def home():
    return "OPA Governance API is running."


def _extract_log_payload(data: Dict) -> Dict:
    if "log" in data:
        return data["log"]
    return data


@app.route("/check-log", methods=["POST"])
@app.route("/logs/check", methods=["POST"])
def check_log():
    payload = request.get_json(force=True)
    log_entry = _extract_log_payload(payload)

    try:
        opa_result = opa_query(LOG_POLICY_PATH, {"log": log_entry})
    except requests.RequestException:
        return jsonify({"allowed": False, "error": "OPA backend unavailable"}), 503
    deny_reasons = opa_result.get("result", [])

    if deny_reasons:
        return jsonify({"allowed": False, "reasons": deny_reasons}), 403

    return jsonify({"allowed": True, "message": "Log entry is compliant"})


@app.route("/gatekeeper/validate", methods=["POST"])
def gatekeeper_validate():
    payload = request.get_json(force=True)
    artifacts = payload.get("artifacts", [])

    try:
        opa_result = opa_query(GATEKEEPER_POLICY_PATH, {"artifacts": artifacts})
    except requests.RequestException:
        return jsonify({"allowed": False, "error": "OPA backend unavailable"}), 503
    violations = opa_result.get("result", [])

    return jsonify({
        "allowed": len(violations) == 0,
        "violations": violations,
    }), (200 if not violations else 422)


@app.route("/policies/reload", methods=["POST"])
def reload_policies():
    policy_manager.force_reload()
    return jsonify({"status": "reloaded", "metadata": policy_manager.status})


@app.route("/policies/status", methods=["GET"])
def policies_status():
    return jsonify(policy_manager.status)


if __name__ == "__main__":
<<<<<<< HEAD
    try:
        app.run(host="0.0.0.0", port=5000)
    finally:
        policy_manager.stop()
=======
    app.run(port=5001)
>>>>>>> a6bf77b (Your descriptive commit message)

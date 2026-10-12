"""Actual loopback HTTP seams; all model paths are disabled or mocked."""

import copy
from http.client import HTTPConnection
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("local_server", ROOT / "scripts/serve.py")
local_server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(local_server)


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.records = Path(self.directory.name) / "reports"
        self.server = local_server.make_server(port=0, reports_dir=self.records)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.payload = json.loads((ROOT / "examples/offline-request.json").read_text())

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.directory.cleanup()

    def call(self, path="/api/verify", body=None, headers=None, method=None):
        method = method or ("POST" if body is not None else "GET")
        sent = {"Origin": self.origin, "Content-Type": "application/json"}
        sent.update(headers or {})
        if sent.get("Origin") is None:
            del sent["Origin"]
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.request(method, path, body=body, headers=sent)
        response = connection.getresponse()
        raw = response.read()
        result = json.loads(raw) if response.getheader("Content-Type", "").startswith("application/json") else raw
        output = response.status, dict(response.getheaders()), result
        connection.close()
        return output

    def test_get_config_and_matched_demo_never_invoke_core(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), patch.object(local_server, "verify") as verify:
            status, headers, config = self.call("/api/config")
            self.assertEqual(status, 200)
            self.assertFalse(config["model_configured"])
            self.assertNotIn("Access-Control-Allow-Origin", headers)
            self.assertEqual(headers["Cache-Control"], "no-store")
            status, _, demo = self.call("/api/demo")
            self.assertEqual(status, 200)
            self.assertIn(demo["mode"], {"synthetic_replay", "offline_fixture"})
            self.assertFalse(demo["report"]["formal_closed"])
            verify.assert_not_called()
        self.assertFalse(self.records.exists())

    def test_offline_round_uses_real_core_and_saves_private_append_only_records(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            first = self.call(body=json.dumps({"request": self.payload}).encode())
            second = self.call(body=json.dumps({"request": self.payload}).encode())
        self.assertEqual(first[0], 201)
        self.assertEqual(second[0], 201)
        self.assertEqual(first[2]["mode"], "offline")
        self.assertFalse(first[2]["report"]["model"]["invoked"])
        self.assertFalse(first[2]["report"]["formal_closed"])
        self.assertNotEqual(first[2]["record"]["id"], second[2]["record"]["id"])
        files = list(self.records.glob("*.json"))
        self.assertEqual(len(files), 2)
        saved = json.loads(files[0].read_text())
        self.assertEqual(saved["record"]["input_sha256"], local_server.sha256(local_server.encoded(self.payload)))
        self.assertEqual(saved["record"]["report_sha256"], local_server.sha256(local_server.encoded(saved["report"])))
        self.assertEqual(files[0].stat().st_mode & 0o777, 0o600)

    def test_model_requires_explicit_mode_and_process_configuration(self):
        payload = copy.deepcopy(self.payload)
        payload.pop("mode")
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-not-a-key"}), patch.object(local_server, "verify") as verify:
            result = self.call(body=json.dumps({"request": payload}).encode())
            self.assertEqual(result[0], 422)
            self.assertEqual(result[2]["error"]["code"], "explicit_mode_required")
            verify.assert_not_called()
        payload["mode"] = "model"
        payload.pop("candidate", None)
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), patch.object(local_server, "verify") as verify:
            result = self.call(body=json.dumps({"request": payload}).encode())
            self.assertEqual(result[0], 503)
            verify.assert_not_called()
        self.assertFalse(self.records.exists())

    def test_full_config_and_demo_are_offline_and_model_submission_is_explicit(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), \
             patch("urllib.request.urlopen", side_effect=AssertionError("no network")), \
             patch("formsy_sop_verification.full_audit.catalog_summary", return_value={
                 "condition_count": 144, "max_sop_calls": 64, "max_total_calls": 80}):
            config = self.call("/api/full-audit-config")
            self.assertEqual(config[0], 200)
            self.assertEqual(config[2]["condition_count"], 144)
            self.assertEqual(config[2]["max_total_calls"], 80)
            self.assertFalse(config[2]["model_configured"])
            demo = self.call("/api/full-audit-demo")[2]
            self.assertIn("trace", demo)
            for body in ({"request": demo}, {"request": demo, "mode": "offline"}):
                self.assertEqual(self.call("/api/full-audits", json.dumps(body).encode())[0], 422)
            self.assertEqual(self.call("/api/full-audits", json.dumps({"request": demo, "mode": "model"}).encode())[0], 503)
        self.assertFalse(self.records.exists())

    def test_full_job_submit_poll_and_busy_do_not_dispatch_the_quick_engine(self):
        # A fake queue exercises the wire contract without starting a model worker.
        jobs = Mock()
        queued = {"id": "123", "status": "queued", "progress": "queued"}
        jobs.submit.return_value = queued
        jobs.get.return_value = queued
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server = local_server.make_server(port=0, reports_dir=self.records, full_jobs=jobs)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        demo = local_server.full_demo()
        body = json.dumps({"request": demo, "mode": "model"}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-not-a-key"}), \
             patch.object(local_server, "verify") as verify:
            submitted = self.call("/api/full-audits", body)
            self.assertEqual((submitted[0], submitted[2]), (202, queued))
            jobs.submit.assert_called_once_with(demo)
            self.assertEqual(self.call("/api/full-audits/123")[2], queued)
            jobs.get.return_value = None
            self.assertEqual(self.call("/api/full-audits/missing")[0], 404)
            jobs.submit.side_effect = RuntimeError("busy")
            self.assertEqual(self.call("/api/full-audits", body)[0], 429)
            self.assertEqual(self.call("/api/full-audits", body, headers={"Origin": "https://other.invalid"})[0], 403)
            verify.assert_not_called()
        self.assertFalse(self.records.exists())

    def test_sop_upload_is_offline_private_and_round_trips_with_a_fixed_identity(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": ""}), \
             patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
            template = self.call("/api/sop-template")[2]
            result = self.call("/api/sop-uploads", json.dumps(template).encode())
            self.assertEqual(result[0], 201)
            uploaded = result[2]
            self.assertFalse(uploaded["model_invoked"])
            self.assertEqual(uploaded["summary"]["source"]["kind"], "uploaded_rules")
            self.assertEqual(uploaded["summary"]["rule_count"], 1)
            self.assertEqual(self.call("/api/sop-uploads/" + uploaded["id"])[2], uploaded)
            self.assertEqual(self.call("/api/sop-uploads/missing")[0], 404)
            bad = {**template, "path": "/private/not-allowed"}
            self.assertEqual(self.call("/api/sop-uploads", json.dumps(bad).encode())[0], 422)
            self.assertEqual(self.call("/api/sop-uploads", json.dumps(template).encode(),
                                       headers={"Origin": "https://other.invalid"})[0], 403)
        saved = list((self.records / "sop-uploads").glob("*.json"))
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(saved[0].read_text())["original"], template)

    def test_configured_model_dispatch_is_only_explicit_post_and_mocked(self):
        payload = copy.deepcopy(self.payload)
        payload["mode"] = "model"
        payload.pop("candidate", None)
        report = local_server.verify(self.payload)
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-not-a-key"}), patch.object(local_server, "verify", return_value=report) as verify:
            result = self.call(body=json.dumps({"request": payload}).encode())
            self.assertEqual(result[0], 201)
            verify.assert_called_once_with(payload)

    def test_host_origin_and_cross_site_requests_are_rejected(self):
        body = json.dumps({"request": self.payload}).encode()
        for headers in ({"Host": "attacker.invalid"}, {"Origin": "https://attacker.invalid"},
                        {"Origin": None}, {"Sec-Fetch-Site": "cross-site"}):
            with self.subTest(headers=headers):
                self.assertEqual(self.call(body=body, headers=headers)[0], 403)
        self.assertEqual(self.call("/api/demo", headers={"Host": "attacker.invalid"})[0], 403)
        self.assertFalse(self.records.exists())

    def test_invalid_or_oversized_json_is_not_echoed_or_saved(self):
        secret_marker = "do-not-echo-this-source"
        invalid = [b'{"request":{},"request":{}}', b"{broken:" + secret_marker.encode(),
                   json.dumps({"request": self.payload, "extra": secret_marker}).encode()]
        broken = copy.deepcopy(self.payload)
        broken["sources"][0]["kind"] = []
        invalid.append(json.dumps({"request": broken}).encode())
        for raw in invalid:
            with self.subTest(raw=raw[:30]):
                status, _, response = self.call(body=raw)
                self.assertEqual(status, 422)
                self.assertNotIn(secret_marker, json.dumps(response))
        result = self.call(body=b"", headers={"Content-Length": str(local_server.MAX_INPUT_BYTES + 1)})
        self.assertEqual(result[0], 413)
        self.assertEqual(self.call(body=b"{}", headers={"Content-Type": "text/plain"})[0], 415)
        self.assertFalse(self.records.exists())

    def test_static_paths_cannot_escape_web_root(self):
        for path in ("/../AGENTS.md", "/%2e%2e/AGENTS.md", "/scripts/serve.py", "/api/unknown"):
            self.assertEqual(self.call(path)[0], 404)

    def test_malformed_wire_headers_and_paths_return_fixed_json(self):
        for length, status in (("²", 400), ("9" * 5000, 413)):
            with self.subTest(length=length[:20]):
                result = self.call(body=b"", headers={"Content-Length": length})
                self.assertEqual(result[0], status)
                self.assertIn("error", result[2])
        connection = HTTPConnection("127.0.0.1", self.server.server_port, timeout=10)
        connection.putrequest("GET", "http://[", skip_host=True)
        connection.putheader("Host", self.origin.removeprefix("http://"))
        connection.endheaders()
        response = connection.getresponse()
        self.assertEqual(response.status, 400)
        self.assertEqual(json.loads(response.read())["error"]["code"], "invalid_path")
        connection.close()

    def test_fallback_demo_is_paired_offline_and_mismatched_replay_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "examples").mkdir()
            for name in ("offline-request.json", "offline-report.json", "model-request.json"):
                (root / "examples" / name).write_bytes((ROOT / "examples" / name).read_bytes())
            self.assertEqual(local_server.load_demo(root)["mode"], "offline_fixture")
            report = json.loads((ROOT / "examples/offline-report.json").read_text())
            report["context"]["task_id"] = "wrong-task"
            path = root / "bad.json"
            path.write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                local_server.load_demo(root, path)


if __name__ == "__main__":
    unittest.main()

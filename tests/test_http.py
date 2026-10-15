"""Actual loopback HTTP seams; all model paths are disabled or mocked."""

import copy
from http.client import HTTPConnection
import importlib.util
import json
import hashlib
import shutil
import os
from pathlib import Path
import tempfile
import threading
import time
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

    def test_invalid_full_thinking_config_is_disabled_and_cannot_submit(self):
        with patch.dict(os.environ, {"DEEPSEEK_THINKING": "invalid"}, clear=True), \
             patch.object(local_server, "configuration", side_effect=AssertionError("no key configuration read")), \
             patch("formsy_sop_verification.full_audit.catalog_summary", side_effect=AssertionError("no catalog read")), \
             patch.object(local_server.FullAuditJobs, "submit", side_effect=AssertionError("no job submission")) as submit, \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no provider request")):
            status, _, config = self.call("/api/full-audit-config")
            self.assertEqual(status, 200)
            for field in ("available", "default_available", "model_configured"):
                self.assertFalse(config[field])
            self.assertEqual(config["configuration_error"], "provider_invalid_configuration")
            status, _, result = self.call("/api/full-audits", body=json.dumps({"request": {}, "mode": "model"}).encode())
            self.assertEqual(status, 503)
            self.assertEqual(result["error"]["code"], "provider_invalid_configuration")
            submit.assert_not_called()
        self.assertFalse(self.records.exists())

    def test_embedding_defaults_to_blocked_and_allows_only_an_explicit_local_origin(self):
        status, headers, _ = self.call("/")
        self.assertEqual(status, 200)
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        for value in ["https://example.com", "http://127.0.0.1", "http://127.0.0.1:4175/",
                      "http://127.0.0.1:4175\n", "http://localhost:4175?x=1", "http://user@localhost:4175"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                local_server.make_server(port=0, embed_origin=value)
        with patch.object(local_server, "ThreadingHTTPServer") as server:
            local_server.make_server(port=0, embed_origin="http://127.0.0.1:4175")
            handler = server.call_args.args[1]
            response = Mock()
            response.command = "HEAD"
            handler.reply(response, 200, b"")
            csp = next(call.args[1] for call in response.send_header.call_args_list
                       if call.args[0] == "Content-Security-Policy")
            self.assertIn("frame-ancestors http://127.0.0.1:4175;", csp)
            self.assertIn("connect-src 'self'", csp)

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

    def test_full_job_submit_poll_active_and_start_failure_do_not_dispatch_the_quick_engine(self):
        # A fake queue exercises the wire contract without starting a model worker.
        jobs = Mock()
        queued = {"id": "123", "status": "queued", "progress": "queued", "supersedes": ["old-id"], "input_sha256": "sha256:" + "a" * 64}
        jobs.submit.return_value = queued
        jobs.get.return_value = queued
        jobs.active.return_value = queued
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
            self.assertEqual(self.call("/api/full-audits/active")[2], {"job": queued})
            jobs.active.return_value = None
            self.assertEqual(self.call("/api/full-audits/active")[2], {"job": None})
            failed = {"id": "123", "status": "failed", "progress": "model:analysis-1.call-001", "error": {
                "code": "full_audit_failed", "message": "Fixed safe message", "provider_code": "provider_network_or_timeout",
                "error_category": "timeout", "failure_stage": "analysis-1.call-001", "exception_type": "TimeoutError",
                "phase": "read", "transport_retry": False,
                "recording_error": {"error_category": "storage", "failure_stage": "job_failure_write",
                                    "exception_type": "OSError", "phase": "store", "transport_retry": False},
            }}
            jobs.get.return_value = failed
            polled = self.call("/api/full-audits/123")
            self.assertEqual(polled[0], 200)
            self.assertEqual(polled[2], failed)
            jobs.get.return_value = None
            self.assertEqual(self.call("/api/full-audits/missing")[0], 404)
            for category, status in (("start", 503), ("storage", 500)):
                error = {"code": "full_audit_start_failed", "error_category": category, "failure_stage": "job_start"}
                jobs.submit.side_effect = local_server.FullAuditStartError(error)
                failed_start = self.call("/api/full-audits", body)
                self.assertEqual((failed_start[0], failed_start[2]), (status, {"error": error}))
            jobs.submit.side_effect = RuntimeError("private unexpected error")
            unknown_start = self.call("/api/full-audits", body)
            self.assertEqual(unknown_start[0], 500)
            self.assertNotIn("private unexpected", json.dumps(unknown_start))
            self.assertEqual(self.call("/api/full-audits", body, headers={"Origin": "https://other.invalid"})[0], 403)
            verify.assert_not_called()
        self.assertFalse(self.records.exists())

    def test_new_full_http_submission_waits_for_old_runner_and_latest_queue_wins(self):
        from formsy_sop_verification.cancellation import check_cancelled
        started, release = threading.Event(), threading.Event()
        calls = []

        def run(request, *, directory, cancellation_event, **_):
            calls.append(request["title"])
            if request["title"] == "first private title":
                directory.mkdir()
                (directory / "received-response.json").write_text('{"old":"kept"}')
                started.set()
                self.assertTrue(release.wait(5))
                check_cancelled(cancellation_event, "analysis-1.call-001")
            return {"candidate": True}

        jobs = local_server.FullAuditJobs(self.records / "full", runner=run, prepare=lambda _: None)
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server = local_server.make_server(port=0, reports_dir=self.records, full_jobs=jobs)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"

        def submit(title):
            response = self.call("/api/full-audits", json.dumps({"request": {"title": title}, "mode": "model"}).encode())
            self.assertEqual(response[0], 202)
            self.assertEqual(response[2]["status"], "queued")
            return response[2]

        def terminal(job):
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                polled = self.call("/api/full-audits/" + job["id"])[2]
                if polled["status"] in {"completed", "failed", "cancelled"}:
                    return polled
                time.sleep(0.01)
            self.fail("HTTP fake job did not finish")

        with patch.object(local_server, "full_configuration", return_value={"available": True, "model_configured": True}), \
             patch.object(local_server, "verify", side_effect=AssertionError("no quick engine")), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no provider")):
            try:
                first = submit("first private title")
                self.assertTrue(started.wait(5))
                second = submit("second")
                third = submit("third")
                self.assertEqual(third["supersedes"], [first["id"], second["id"]])
                self.assertEqual(calls, ["first private title"])
                self.assertEqual(self.call("/api/full-audits/" + first["id"])[2]["status"], "cancelling")
                active = self.call("/api/full-audits/active")[2]["job"]
                self.assertEqual(active["id"], third["id"])
                self.assertNotIn("private", json.dumps(active))
                self.assertNotIn("title", active)
                self.assertNotIn("request", active)
                release.set()
                self.assertEqual(terminal(first)["status"], "cancelled")
                self.assertEqual(terminal(second)["status"], "cancelled")
                self.assertEqual(terminal(third)["status"], "completed")
                self.assertEqual(calls, ["first private title", "third"])
                self.assertEqual(self.call("/api/full-audits/active")[2], {"job": None})
                self.assertTrue((self.records / "full" / first["id"] / "engine/received-response.json").is_file())
            finally:
                release.set()

    def test_public_demo_catalog_and_selection_are_hash_checked_offline_fixed_files(self):
        fixture_root = Path(self.directory.name) / "fixture-app"
        (fixture_root / "examples").mkdir(parents=True)
        for name in ("offline-request.json", "offline-report.json"):
            shutil.copyfile(ROOT / "examples" / name, fixture_root / "examples" / name)
        base = fixture_root / "examples/public-traces"
        demo_id = "Melevir__cognitive_complexity-15"
        (base / demo_id).mkdir(parents=True)
        request = local_server.full_demo()
        raw = json.dumps(request, ensure_ascii=False).encode()
        input_path = base / demo_id / "input.json"
        input_path.write_bytes(raw)
        license_path = base / demo_id / "LICENSE"
        license_path.write_text("Synthetic offline test fixture, not a claim about public source licensing.")
        entry = {"id": demo_id, "title": "Explicit synthetic fixture", "repository": "synthetic/demo",
                 "input_file": demo_id + "/input.json", "input_sha256": hashlib.sha256(raw).hexdigest(),
                 "source_url": "https://example.org/synthetic-fixture", "license_files": [demo_id + "/LICENSE"],
                 "message_count": 1, "material_count": 1, "commit_shas": ["a" * 40]}
        catalog_path = base / "catalog.json"
        catalog_path.write_text(json.dumps({"examples": [entry]}))
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.server = local_server.make_server(root=fixture_root, port=0, reports_dir=self.records)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        with patch.object(local_server, "verify", side_effect=AssertionError("no model")), \
             patch.object(local_server.FullAuditJobs, "submit", side_effect=AssertionError("no submit")), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no provider")):
            catalog = self.call("/api/full-demo-catalog")
            self.assertEqual(catalog[0], 200)
            metadata = catalog[2]["demos"][0]
            self.assertEqual(metadata["input_sha256"], entry["input_sha256"])
            self.assertNotIn("input_file", metadata)
            self.assertNotIn("request", metadata)
            selected = self.call("/api/full-demo/" + demo_id)
            self.assertEqual(selected[0], 200)
            self.assertEqual(selected[2], {"demo": metadata, "request": request})
            self.assertEqual(self.call("/api/full-demo")[2], self.call("/api/full-audit-demo")[2])
            for path in ("missing", "../reports/private.json", "%2e%2e/private", "akolar__ogn-lib-18"):
                self.assertEqual(self.call("/api/full-demo/" + path)[0], 404)
            input_path.write_bytes(raw + b" ")
            self.assertEqual(self.call("/api/full-demo-catalog")[0], 503)
            self.assertEqual(self.call("/api/full-demo/" + demo_id)[0], 503)
            input_path.unlink()
            outside = Path(self.directory.name) / "outside-private.json"
            outside.write_bytes(raw)
            input_path.symlink_to(outside)
            self.assertEqual(self.call("/api/full-demo/" + demo_id)[0], 503)
            input_path.unlink()
            input_path.write_bytes(raw)
            entry["input_file"] = "../outside-private.json"
            catalog_path.write_text(json.dumps({"examples": [entry]}))
            self.assertEqual(self.call("/api/full-demo-catalog")[0], 503)
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

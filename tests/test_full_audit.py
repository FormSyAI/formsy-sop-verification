"""Offline integration of the packaged engine, its adapter and explicit CLI."""
import copy
import http.client
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.full_audit import (_ClientAdapter, _EnvironmentFullClient, _NoRedirects,
    catalog_summary, prepare_full, run_full_audit)
from formsy_sop_verification.model_client import ProviderError
from formsy_sop_verification.trace_audit.tests.test_engine import scripted_result, synthetic_payload
from formsy_sop_verification.trace_audit.tests.test_requirement_isolation import support_for
from formsy_sop_verification.trace_audit.model_client import ModelOutputError
from formsy_sop_verification.trace_audit import sop_catalog


class OfflineClient:
    model = "synthetic-offline-model"

    def __init__(self):
        self.calls = 0

    def complete(self, system, payload):
        self.calls += 1
        if "candidate_tasks" in payload:
            return support_for(payload["candidate_tasks"])
        if "candidate_rules" in payload:
            return {"rules": [{"rule_id": row["id"], "selection": "uncertain",
                               "reason": "Synthetic fixture does not decide applicability.",
                               "evidence_refs": []} for row in payload["candidate_rules"]]}
        if "rules" not in payload:
            # Requirement extraction deliberately receives only user evidence.
            if "commits" in payload and "source_inventory" not in payload:
                return {"tasks": scripted_result({**payload, "rules": []})["tasks"]}
            return {}
        return scripted_result(payload)


class FullAuditTests(unittest.TestCase):
    def setUp(self):
        # Adapter tests freeze a public packaged fixture; rule_sources tests below
        # exercise the real external checkout and release validation separately.
        root = Path(__file__).resolve().parents[1] / "src/formsy_sop_verification/trace_audit"
        catalog = sop_catalog.resolve_catalog(root)
        rules = json.loads((root / "rules/default_rules.json").read_text())
        source = {"rules": rules, "catalog": catalog,
                  "summary": {"source": {"kind": "offline_packaged_test_fixture"}, "max_upload_rules": 8}}
        self.default_source = patch("formsy_sop_verification.full_audit.default_catalog", side_effect=lambda *_: copy.deepcopy(source))
        self.default_source.start()
        self.addCleanup(self.default_source.stop)

    def test_catalog_and_freeze_are_offline_and_preserve_complete_reference(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("no network")), \
             patch("formsy_sop_verification.trace_audit.run_evidence.verify_runs", side_effect=AssertionError("no private runner reads")):
            summary = catalog_summary()
            package = prepare_full(synthetic_payload())
        self.assertEqual((summary["rule_count"], summary["condition_count"], summary["atomic_item_count"]), (33, 144, 184))
        self.assertEqual(package["run_verification"], [])
        self.assertEqual(package["audit_context"]["profile"], "code_fix")
        self.assertEqual(len(package["sop_catalog"]["rules"]), 33)

    def test_r11_summary_causal_units_preserve_text_and_do_not_promote_code_literals(self):
        from formsy_sop_verification.trace_audit.requirement_review import summary_review_units
        for goal in ["服务应完成；因缓存过期而退出。", "Because the response is a string, output fails."]:
            units = summary_review_units([{"id": "T", "title": "目标", "goal": goal}])[1]["units"]
            self.assertEqual("".join(unit["text"] for unit in units), goal)
            self.assertTrue(any(unit["role"] == "causal_premise" for unit in units))
        literal = "应保留 `因配置而退出` 这段字面量。"
        units = summary_review_units([{"id": "T", "title": "目标", "goal": literal}])[1]["units"]
        self.assertFalse(any(unit["role"] == "causal_premise" for unit in units))

    def test_real_pipeline_with_fake_client_produces_144_rows_without_network_or_execution(self):
        payload = synthetic_payload()
        client, stages = OfflineClient(), []
        before = copy.deepcopy(payload)
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root) / "attempt"
            marker = Path(root) / "must-not-exist"
            payload["trace"]["messages"].append({"role": "tool", "content": "touch " + str(marker)})
            before = copy.deepcopy(payload)
            with patch("urllib.request.urlopen", side_effect=AssertionError("no network")), \
                 patch("formsy_sop_verification.trace_audit.audit_engine.AuditService", side_effect=AssertionError("no old history")), \
                 patch("formsy_sop_verification.trace_audit.run_evidence.verify_runs", side_effect=AssertionError("no private runner reads")):
                report = run_full_audit(payload, directory=directory, client=client,
                                        max_sop_calls=8, stage_callback=stages.append)
            self.assertEqual(report["schema_version"], "2.1")
            self.assertEqual(len(report["sop_condition_checks"]), 144)
            self.assertTrue(report["sop_coverage"]["matrix_complete"])
            self.assertFalse(report["formal_closed"])
            self.assertFalse(report["source_authenticated"])
            self.assertFalse(report["business_tests_executed"])
            self.assertFalse(report["model_snapshot"]["model_invoked"])
            self.assertEqual(report["model_snapshot"]["execution_mode"], "offline_fake")
            self.assertEqual(report["model_snapshot"]["api_request_count"], 0)
            self.assertEqual(report["model_snapshot"]["stage_call_count"], client.calls)
            self.assertFalse(marker.exists())
            self.assertTrue(any(stage.startswith("model:sop-") for stage in stages))
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertTrue((directory / "report.json").exists())
            self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in directory.iterdir() if item.is_file()))
            with self.assertRaisesRegex(ValueError, "output_not_empty"):
                run_full_audit(payload, directory=directory, client=OfflineClient())
        self.assertEqual(payload, before)

    def test_zero_sop_budget_keeps_unknown_matrix_and_failed_analysis(self):
        with tempfile.TemporaryDirectory() as directory:
            report = run_full_audit(synthetic_payload(), directory=directory,
                                    client=OfflineClient(), max_sop_calls=0)
        self.assertEqual(len(report["sop_condition_checks"]), 144)
        self.assertFalse(report["sop_coverage"]["analysis_complete"])
        self.assertEqual(report["sop_coverage"]["request_count"], 0)
        self.assertTrue(all(row["result"] == "未核查" for row in report["sop_condition_checks"]))

    def test_redacted_source_keeps_original_and_display_hashes_separate(self):
        from formsy_sop_verification.trace_audit.audit_engine import sha
        payload = synthetic_payload()
        payload["materials"][0]["content"] = "password = 'synthetic-password'\n"
        with tempfile.TemporaryDirectory() as root:
            report = run_full_audit(payload, directory=root, client=OfflineClient(), max_sop_calls=0)
            source = next(item for item in report["evidence"] if item["kind"] == "source")
            self.assertTrue(source["display_redacted"])
            self.assertEqual(source["original_sha256"], sha(payload["materials"][0]["content"]))
            self.assertEqual(source["display_sha256"], sha(source["content"]))
            self.assertNotEqual(source["original_sha256"], source["display_sha256"])
            self.assertNotIn("synthetic-password", (Path(root) / "report.json").read_text())

    def test_total_call_budget_is_hard_and_failure_keeps_private_attempt(self):
        client = OfflineClient()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "call_budget_exhausted"):
                run_full_audit(synthetic_payload(), directory=directory, client=client, max_total_calls=1)
            self.assertEqual(client.calls, 1)
            self.assertTrue((Path(directory) / "failure.json").exists())
            self.assertFalse((Path(directory) / "report.json").exists())

    def test_provider_auth_failure_is_not_automatically_retried(self):
        class Failing(OfflineClient):
            def complete(self, system, payload):
                self.calls += 1
                raise ProviderError("provider_authentication_failed")
        client = Failing()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "provider_authentication_failed"):
                run_full_audit(synthetic_payload(), directory=directory, client=client)
            self.assertEqual(client.calls, 1)
            self.assertFalse((Path(directory) / "report.json").exists())

    def test_fatal_provider_failure_in_sop_preserves_unknown_matrix_and_stops_calls(self):
        class FailingSop(OfflineClient):
            failed = False
            def complete(self, system, payload):
                if self.failed:
                    raise AssertionError("No calls after a fatal SOP provider failure")
                if "candidate_rules" in payload:
                    self.failed = True
                    self.calls += 1
                    raise ProviderError("provider_quota_exhausted")
                return super().complete(system, payload)
        client = FailingSop()
        with tempfile.TemporaryDirectory() as root:
            report = run_full_audit(synthetic_payload(), directory=root, client=client)
            self.assertTrue(client.failed)
            self.assertFalse(report["sop_coverage"]["analysis_complete"])
            self.assertEqual(len(report["sop_condition_checks"]), 144)
            self.assertTrue(any(item["kind"] == "provider_failure"
                                for item in report["sop_coverage"]["failures"]))
            self.assertTrue((Path(root) / "report.json").exists())
            self.assertTrue(any(Path(root).glob("*.error.json")))

    def test_http_read_interruption_in_sop_preserves_partial_report_and_stops_transport(self):
        scripted = OfflineClient()
        stopped = False

        class Response:
            def __init__(self, candidate=None, interrupted=False):
                self.candidate, self.interrupted = candidate, interrupted
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                if self.interrupted:
                    raise http.client.IncompleteRead(b'{"choices":[', 100)
                return json.dumps({"choices": [{"finish_reason": "stop", "message": {
                    "content": json.dumps(self.candidate)}}]}).encode()

        def transport(request, **kwargs):
            nonlocal stopped
            self.assertFalse(stopped, "No provider calls after an interrupted SOP response")
            body = json.loads(request.data)
            payload = json.loads(body["messages"][1]["content"])
            if "candidate_rules" in payload:
                stopped = True
                return Response(interrupted=True)
            return Response(scripted.complete(body["messages"][0]["content"], payload))

        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
             patch("urllib.request.OpenerDirector.open", side_effect=transport) as wire:
            report = run_full_audit(synthetic_payload(), directory=root)
            self.assertTrue(stopped)
            self.assertFalse(report["sop_coverage"]["analysis_complete"])
            self.assertEqual(len(report["sop_condition_checks"]), 144)
            self.assertTrue(any(item["kind"] == "provider_failure"
                                for item in report["sop_coverage"]["failures"]))
            self.assertEqual(report["model_snapshot"]["api_request_count"], wire.call_count)
            self.assertTrue((Path(root) / "report.json").exists())
            self.assertTrue(any(json.loads(path.read_text()).get("transport_incomplete")
                                for path in Path(root).glob("*.provider-response.json")))
            self.assertTrue(any(json.loads(path.read_text()).get("code") == "provider_network_or_timeout"
                                for path in Path(root).glob("*.error.json")))

    def test_invalid_request_missing_user_and_missing_config_fail_before_output(self):
        for mutate in [lambda payload: payload.update(mode="model"),
                       lambda payload: payload.update(audit_context={"profile": "other"}),
                       lambda payload: payload.update(rules=[]),
                       lambda payload: payload["materials"][0].update(content="x" * 320001)]:
            payload = synthetic_payload()
            mutate(payload)
            with self.assertRaises(ValueError):
                prepare_full(payload)
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "not-created"
            payload = synthetic_payload()
            payload["trace"]["messages"] = [{"role": "assistant", "content": "claimed user demand"}]
            with self.assertRaisesRegex(ValueError, "missing_user_requirement"):
                run_full_audit(payload, directory=output, client=OfflineClient())
            with patch.dict("os.environ", {"DEEPSEEK_API_KEY": ""}), \
                 patch("urllib.request.urlopen", side_effect=AssertionError("no network")):
                with self.assertRaisesRegex(ValueError, "provider_not_configured"):
                    run_full_audit(synthetic_payload(), directory=output)
            self.assertFalse(output.exists())

    def test_cli_prepare_default_does_not_make_provider_calls(self):
        script = Path(__file__).resolve().parents[1] / "scripts/audit_full.py"
        payload = synthetic_payload()
        payload["rules"] = [{"id": "CUSTOM", "title": "合成规则", "version": "fixture-1", "criterion": "保留显式零值"}]
        result = subprocess.run([sys.executable, "-I", str(script)], input=json.dumps(payload),
                                text=True, capture_output=True, check=True)
        output = json.loads(result.stdout)
        self.assertEqual(output["mode"], "prepare_only")
        self.assertFalse(output["model_invoked"])
        # CLI prepare output includes the selected source, without needing a
        # developer's default checkout or making any model request.
        self.assertEqual(output["catalog"]["condition_count"], 1)

    def test_bounded_raw_provider_envelope_survives_incomplete_and_invalid_output(self):
        class Response:
            def __init__(self, body): self.body = body
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return self.body[:size]
        bodies = [json.dumps({"choices": [{"finish_reason": "length", "message": {
                    "content": "{partial-fake-key-123"}}]}).encode(),
                  b'{bad-json-fake-key-123',
                  json.dumps({"choices": [None]}).encode(),
                  json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": "{bad-json"}}]}).encode()]
        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "fake-key-123"}), \
             patch("urllib.request.OpenerDirector.open", side_effect=[Response(body) for body in bodies]) as transport:
            adapter = _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)
            for number, body in enumerate(bodies, 1):
                with self.assertRaises(ModelOutputError):
                    adapter.complete("synthetic", {"source": "fixture"}, root, "same-stage")
                artifact = json.loads((Path(root) / f"same-stage.call-{number:03d}.provider-response.json").read_text())
                self.assertNotIn("fake-key-123", json.dumps(artifact))
                self.assertFalse(artifact["truncated"])
            first = json.loads((Path(root) / "same-stage.call-001.provider-response.json").read_text())
            self.assertEqual(first["envelope"]["choices"][0]["finish_reason"], "length")
            self.assertEqual(len(list(Path(root).glob("*.provider-response.json"))), 4)
            self.assertEqual(transport.call_count, 4)

    def test_oversized_provider_response_is_bounded_and_not_adopted(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b"x" * size
        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
             patch("urllib.request.OpenerDirector.open", return_value=Response()):
            adapter = _ClientAdapter(_EnvironmentFullClient(), 2, lambda stage: None)
            with self.assertRaisesRegex(ValueError, "provider_response_too_large"):
                adapter.complete("synthetic", {}, root, "oversized")
            artifact = json.loads((Path(root) / "oversized.call-001.provider-response.json").read_text())
            self.assertTrue(artifact["truncated"])
            self.assertEqual(artifact["captured_bytes"], 1024 * 1024)
            self.assertFalse((Path(root) / "oversized.call-001.response.json").exists())

    def test_interrupted_http_response_keeps_partial_evidence_and_never_retries(self):
        class Interrupted:
            def __init__(self, error): self.error = error
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): raise self.error
            def close(self): pass

        partials = [b'{"token":"synthetic-key",', b"x" * (_EnvironmentFullClient.MAX_RESPONSE_BYTES + 1)]
        for partial in partials:
            with self.subTest(size=len(partial)), tempfile.TemporaryDirectory() as root, \
                 patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
                 patch("urllib.request.OpenerDirector.open", return_value=Interrupted(
                     http.client.IncompleteRead(partial, 100))) as transport:
                adapter = _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)
                with self.assertRaisesRegex(ValueError, "provider_network_or_timeout"):
                    adapter.complete("synthetic", {}, root, "interrupted")
                artifact = json.loads((Path(root) / "interrupted.call-001.provider-response.json").read_text())
                self.assertTrue(artifact["transport_incomplete"])
                self.assertEqual(artifact["http_status"], 200)
                self.assertEqual(artifact["captured_bytes"], min(len(partial), _EnvironmentFullClient.MAX_RESPONSE_BYTES))
                self.assertEqual(artifact["truncated"], len(partial) > _EnvironmentFullClient.MAX_RESPONSE_BYTES)
                self.assertNotIn("envelope", artifact)
                self.assertNotIn("synthetic-key", json.dumps(artifact))
                self.assertEqual(json.loads((Path(root) / "interrupted.call-001.error.json").read_text()),
                                 {"code": "provider_network_or_timeout"})
                self.assertFalse((Path(root) / "interrupted.call-001.response.json").exists())
                self.assertEqual((adapter.calls, adapter.client.request_count, transport.call_count), (1, 1, 1))

        for opening in [True, False]:
            with self.subTest(opening=opening), tempfile.TemporaryDirectory() as root, \
                 patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
                 patch("urllib.request.OpenerDirector.open") as transport:
                if opening:
                    transport.side_effect = http.client.HTTPException("synthetic-key must never appear")
                else:
                    transport.return_value = Interrupted(http.client.HTTPException("synthetic-key must never appear"))
                adapter = _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)
                with self.assertRaisesRegex(ValueError, "provider_network_or_timeout"):
                    adapter.complete("synthetic", {}, root, "http-error")
                self.assertEqual(json.loads((Path(root) / "http-error.call-001.error.json").read_text()),
                                 {"code": "provider_network_or_timeout"})
                self.assertEqual(transport.call_count, 1)

        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
             patch("urllib.request.OpenerDirector.open", side_effect=urllib.error.HTTPError(
                 "https://api.deepseek.com/chat/completions", 402, "quota", {},
                 Interrupted(http.client.IncompleteRead(b'{"error":', 100)))) as transport:
            adapter = _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)
            with self.assertRaisesRegex(ValueError, "provider_quota_exhausted"):
                adapter.complete("synthetic", {}, root, "quota-interrupted")
            artifact = json.loads((Path(root) / "quota-interrupted.call-001.provider-response.json").read_text())
            self.assertEqual(artifact["http_status"], 402)
            self.assertTrue(artifact["transport_incomplete"])
            self.assertEqual(transport.call_count, 1)

    def test_actual_transport_budget_includes_all_recovery_calls_and_blocks_redirects(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size):
                return b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}'
        self.assertIsNone(_NoRedirects().redirect_request(None, None, 307, "redirect", {}, "https://other.invalid/"))
        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
             patch("urllib.request.OpenerDirector.open", return_value=Response()) as transport:
            client = _EnvironmentFullClient()
            adapter = _ClientAdapter(client, 80, lambda stage: None)
            for number in range(80):
                adapter.complete("synthetic", {}, root, "recovery")
            with self.assertRaisesRegex(ValueError, "call_budget_exhausted"):
                adapter.complete("synthetic", {}, root, "recovery")
            self.assertEqual((adapter.calls, client.request_count, transport.call_count), (80, 80, 80))
            self.assertTrue(all(call.args[0].full_url == "https://api.deepseek.com/chat/completions"
                                for call in transport.call_args_list))

    def test_http_error_artifact_storage_failure_is_not_mislabeled_as_network(self):
        with tempfile.TemporaryDirectory() as root, \
             patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
             patch("urllib.request.OpenerDirector.open", side_effect=urllib.error.HTTPError(
                 "https://api.deepseek.com/chat/completions", 402, "quota", {}, io.BytesIO(b"{}"))), \
             patch.object(_EnvironmentFullClient, "_response", side_effect=OSError("synthetic storage failure")):
            adapter = _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)
            with self.assertRaisesRegex(OSError, "synthetic storage failure"):
                adapter.complete("synthetic", {}, root, "storage")
            self.assertFalse((Path(root) / "storage.call-001.error.json").exists())

    def test_quota_network_and_redirect_errors_stop_without_whole_run_retry(self):
        for error, expected in [
            (urllib.error.HTTPError("https://api.deepseek.com/chat/completions", 402, "quota", {}, io.BytesIO(b'{"error":"quota"}')),
             "provider_quota_exhausted"),
            (urllib.error.URLError("synthetic offline"), "provider_network_or_timeout"),
            (urllib.error.HTTPError("https://api.deepseek.com/chat/completions", 307, "redirect", {}, io.BytesIO(b'{"error":"redirect"}')),
             "provider_http_error"),
        ]:
            with self.subTest(expected=expected), tempfile.TemporaryDirectory() as root, \
                 patch.dict("os.environ", {"DEEPSEEK_API_KEY": "synthetic-key"}), \
                 patch("urllib.request.OpenerDirector.open", side_effect=error) as transport:
                with self.assertRaisesRegex(ValueError, expected):
                    run_full_audit(synthetic_payload(), directory=root)
                self.assertEqual(transport.call_count, 1)
                self.assertTrue((Path(root) / "failure.json").exists())
                self.assertFalse((Path(root) / "report.json").exists())
                if isinstance(error, urllib.error.HTTPError):
                    artifact = json.loads(next(Path(root).glob("*.provider-response.json")).read_text())
                    self.assertEqual(artifact["http_status"], error.code)


if __name__ == "__main__":
    unittest.main()

import http.client
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.failure_reporting import AuditFailure, failure_details, safe_stage
from formsy_sop_verification.model_client import ProviderError
from formsy_sop_verification.full_audit import _ClientAdapter
from formsy_sop_verification.trace_audit.model_client import ModelOutputError


class FailureReportingTests(unittest.TestCase):
    def test_credential_review_keeps_exact_stage_and_adapter_failure_without_retry(self):
        base = 'sop-credential-review-395e90173540-SEC06-C02'
        for stage in (base, base + '-1', base + '-2.call-080', 'model:' + base + '-1.call-003'):
            self.assertEqual(safe_stage(stage), stage)
            for exc, phase in ((TimeoutError(), 'read'), (OSError(), 'store')):
                self.assertEqual(failure_details(exc, stage=stage, phase=phase)['failure_stage'], stage)
        class InvalidOutputClient:
            def complete(self, system, payload):
                raise ModelOutputError('provider_invalid_candidate')
        adapter = _ClientAdapter(InvalidOutputClient(), 80, lambda stage: None)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ModelOutputError):
                adapter.complete('strict JSON', {}, directory, base + '-1')
            record = json.loads((Path(directory) / (base + '-1.call-001.error.json')).read_text())
            self.assertEqual(record['failure_stage'], base + '-1.call-001')
            self.assertEqual(record['error_category'], 'output')
            self.assertFalse(record['transport_retry'])
            self.assertEqual(adapter.calls, 1)

    def test_credential_review_does_not_accept_sensitive_or_nonbuiltin_stages(self):
        base = 'sop-credential-review-395e90173540-SEC06-C02'
        for value in (base.replace('SEC06-C02', 'SEC06-C05'), base.replace('395e90173540', 'T1'),
                      base.replace('395e90173540', '395E90173540'), base + '-3', base + '-01',
                      base + '-1.call-0016', base + '-1.call-０１６', base + '\n',
                      base + '?password=synthetic-private', base + '/../../private'):
            self.assertEqual(safe_stage(value), 'unknown')
            self.assertNotIn('synthetic-private', json.dumps(failure_details(ValueError(), stage=value)))

    def test_source_review_stage_is_preserved_through_output_failure(self):
        base = "sop-source-review-395e90173540-TC14-C01"
        for stage in (base, base + "-1", base + "-2.call-017",
                      "model:" + base + "-1.call-016"):
            with self.subTest(stage=stage):
                self.assertEqual(safe_stage(stage), stage)
                exc = ProviderError("provider_invalid_candidate", failure_stage=stage,
                    exception_type="ModelOutputError", phase="parse", http_status=200,
                    response_saved=True, response_partial=False)
                details = failure_details(exc, stage="job_run", phase="job")
                self.assertEqual(details["failure_stage"], stage)
                self.assertEqual(details["error_category"], "output")
                self.assertEqual(details["phase"], "parse")
                self.assertEqual(details["provider_code"], "provider_invalid_candidate")
                self.assertFalse(details["transport_retry"])
                wrapped = AuditFailure("full_audit_failed", **details)
                self.assertEqual(failure_details(wrapped)["failure_stage"], stage)

    def test_source_review_adapter_records_exact_stage_without_retry(self):
        class InvalidOutputClient:
            calls = 0

            def complete(self, system, payload):
                self.calls += 1
                raise ModelOutputError("provider_invalid_candidate")

        client, progress = InvalidOutputClient(), []
        adapter = _ClientAdapter(client, 80, progress.append)
        stage = "sop-source-review-395e90173540-TC14-C01-1"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ModelOutputError) as raised:
                adapter.complete("strict JSON object", {}, directory, stage)
            self.assertEqual(client.calls, 1)
            self.assertEqual(adapter.calls, 1)
            self.assertEqual(progress, ["model:" + stage])
            recorded = json.loads((Path(directory) / (stage + ".call-001.error.json")).read_text())
            self.assertEqual(recorded["failure_stage"], stage + ".call-001")
            self.assertEqual(recorded["error_category"], "output")
            self.assertEqual(recorded["phase"], "parse")
            self.assertFalse(recorded["transport_retry"])
            self.assertEqual(raised.exception.failure_details["failure_stage"], recorded["failure_stage"])
            self.assertEqual(adapter.failure_diagnostics[0]["failure_stage"], recorded["failure_stage"])

    def test_source_review_whitelist_rejects_untrusted_lookalikes(self):
        base = "sop-source-review-395e90173540-TC14-C01"
        values = [None, {"stage": base}, base.replace("395e90173540", "T1"),
                  base.replace("395e90173540", "395E90173540"),
                  base.replace("395e90173540", "395e9017354"),
                  base.replace("395e90173540", "395e901735400"),
                  base.replace("TC14-C01", "TC14-C02"),
                  base + "-0", base + "-3", base + "-01", base + "-split-1",
                  base + "-1.call-16", base + "-1.call-0016", base + "-1.call-０１６",
                  base + "-1.call-016\n", base + "/../../private", "https://" + base,
                  base + "?password=synthetic-private", base + ":synthetic-private",
                  base + "x" * 201]
        for value in values:
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(safe_stage(value), "unknown")
                details = failure_details(ValueError("synthetic-private"), stage=value)
                self.assertEqual(details["failure_stage"], "unknown")
                self.assertNotIn("synthetic-private", json.dumps(details))

    def test_local_failure_stage_preserves_only_builtin_bounded_call_tokens(self):
        base = "sop-failure-review-local-e257d129e51b"
        for stage in (base, base + "-1-1-1", base + "-1-2-1.call-080",
                      "model:" + base + "-1-1-1.call-028"):
            with self.subTest(stage=stage):
                self.assertEqual(safe_stage(stage), stage)
                exc = ProviderError("provider_invalid_candidate", failure_stage=stage,
                    exception_type="ModelOutputError", phase="parse")
                details = failure_details(exc, stage="job_run")
                self.assertEqual(details["failure_stage"], stage)
                self.assertEqual(details["error_category"], "output")
                self.assertFalse(details["transport_retry"])

    def test_local_failure_stage_rejects_untrusted_or_nonbuiltin_variants(self):
        base = "sop-failure-review-local-e257d129e51b"
        values = [base.replace("e257d129e51b", "T1"), base.replace("e257d129e51b", "E257D129E51B"),
                  base.replace("e257d129e51b", "e257d129e51"), base.replace("e257d129e51b", "e257d129e51b0"),
                  base + "-0-1-1", base + "-2-1-1", base + "-1-0-1", base + "-1-3-1",
                  base + "-1-1-0", base + "-1-1-2", base + "-1-1", base + "-FIX03-1-1",
                  base + "-1-1-1.call-28", base + "-1-1-1.call-0028", base + "-1-1-1.call-０２８",
                  base + "-1-1-1\n", "https://" + base, base + "/../../private",
                  base + "?password=synthetic-private", base + ":synthetic-private"]
        for value in values:
            with self.subTest(value=value):
                self.assertEqual(safe_stage(value), "unknown")
                self.assertNotIn("synthetic-private", json.dumps(failure_details(ValueError("synthetic-private"), stage=value)))

    def test_stage_character_and_length_boundaries_stay_strict(self):
        stage = "analysis-" + "1" * 191
        self.assertEqual(len(stage), 200)
        self.assertEqual(safe_stage(stage), stage)
        for value in (stage + "1", "analysis-１", "", True, 17,
                      "sop-source-review-395e90173540-TC14-C01-1\x00"):
            with self.subTest(value_type=type(value).__name__):
                self.assertEqual(safe_stage(value), "unknown")

    def test_typed_failure_keeps_original_safe_stage_and_transport_context(self):
        exc = ProviderError("provider_network_or_timeout", error_category="timeout",
                            failure_stage="sop-condition-a225562fa243-7-rows-1-1.call-018",
                            exception_type="TimeoutError", phase="read", response_saved=False)
        details = failure_details(exc, stage="job_run", phase="job")
        self.assertEqual(str(exc), "provider_network_or_timeout")
        self.assertEqual(details["error_category"], "timeout")
        self.assertEqual(details["exception_type"], "TimeoutError")
        self.assertTrue(details["failure_stage"].endswith("call-018"))
        self.assertEqual(details["phase"], "read")
        self.assertFalse(details["transport_retry"])

    def test_dynamic_progress_and_exception_details_never_enter_diagnostics(self):
        secret = "synthetic private task and credential"
        exc = ValueError(secret)
        details = failure_details(exc, stage="逐项核查原SOP条件：" + secret)
        self.assertEqual(details["failure_stage"], "unknown")
        self.assertEqual(details["error_category"], "validation")
        self.assertNotIn(secret, json.dumps(details))
        self.assertEqual(safe_stage("model:sop-T1-rows-1.call-018"), "model:sop-T1-rows-1.call-018")
        self.assertEqual(safe_stage("execution-mapping-T1-1"), "execution-mapping-T1-1")
        recursive = "model:sop-condition-a225562fa243-7-split-1-split-2-rows-1-1.call-018"
        self.assertEqual(safe_stage(recursive), recursive)
        self.assertEqual(safe_stage("model:sop-secret/../../key"), "unknown")
        self.assertEqual(safe_stage("model:sop-sensitive-user-title"), "unknown")
        self.assertEqual(safe_stage("analysis-private-key"), "unknown")

    def test_unknown_exception_class_and_arbitrary_attributes_are_not_exposed(self):
        private_type = type("synthetic_key_must_not_be_saved", (Exception,), {})
        exc = private_type("private message")
        exc.failure_details = {"message": "private message", "traceback": "private trace", "key": "private key"}
        details = failure_details(exc, stage="job_run")
        self.assertEqual(details["exception_type"], "UnexpectedError")
        self.assertEqual(details["error_category"], "internal_unknown")
        self.assertNotIn("private", json.dumps(details))

    def test_malformed_metadata_cannot_break_the_failure_handler(self):
        exc = RuntimeError("private error")
        exc.code = {"bad": "private"}
        exc.failure_details = {field: ["private"] for field in (
            "phase", "error_category", "exception_type", "provider_code", "transport_issue", "failure_stage")}
        details = failure_details(exc, stage="job_run")
        self.assertEqual(details["failure_stage"], "job_run")
        self.assertEqual(details["phase"], "engine")
        self.assertEqual(details["exception_type"], "UnexpectedError")
        self.assertNotIn("private", json.dumps(details))

    def test_plain_network_and_storage_failures_are_separate(self):
        cases = [(TimeoutError("private"), "read", "timeout"),
                 (urllib.error.URLError(TimeoutError("private")), "connect", "timeout"),
                 (http.client.IncompleteRead(b"private body", 12), "read", "read_incomplete"),
                 (http.client.RemoteDisconnected("private"), "connect", "connection"),
                 (PermissionError("private path"), "store", "storage"),
                 (TimeoutError("private filesystem"), "store", "storage"),
                 (ConnectionResetError("private filesystem"), "store", "storage")]
        for exc, phase, category in cases:
            with self.subTest(category=category):
                details = failure_details(exc, stage="job_report_write", phase=phase)
                self.assertEqual(details["error_category"], category)
                self.assertNotIn("private", json.dumps(details))

    def test_http_status_has_precedence_over_body_transport_issue(self):
        exc = ProviderError("provider_quota_exhausted", error_category="quota", http_status=402,
                            transport_issue="read_incomplete", response_partial=True,
                            response_saved=True, captured_bytes=14, exception_type="IncompleteRead", phase="read")
        details = failure_details(exc, stage="analysis-1.call-001")
        self.assertEqual(details["error_category"], "quota")
        self.assertEqual(details["provider_code"], "provider_quota_exhausted")
        self.assertEqual(details["http_status"], 402)
        self.assertEqual(details["transport_issue"], "read_incomplete")
        overridden = ProviderError("provider_quota_exhausted", error_category="storage", phase="read")
        self.assertEqual(failure_details(overridden)["error_category"], "quota")
        raw = urllib.error.HTTPError("https://private.invalid", 401, "private body", {}, None)
        self.assertEqual(failure_details(raw)["error_category"], "authentication")
        self.assertNotIn("private", json.dumps(failure_details(raw)))

    def test_optional_fields_are_strict_and_bounded(self):
        exc = AuditFailure("full_audit_storage_failed", http_status=True, captured_bytes=2**40,
                           response_saved="yes", response_partial=None, transport_issue="private")
        details = failure_details(exc)
        self.assertEqual(details["error_category"], "storage")
        for field in ("http_status", "captured_bytes", "response_saved", "response_partial", "transport_issue"):
            self.assertNotIn(field, details)

    def test_unknown_codes_cannot_leak_via_exception_string(self):
        exc = AuditFailure("private credential and source")
        self.assertEqual(str(exc), "full_audit_internal_unknown")
        self.assertEqual(failure_details(exc)["error_category"], "internal_unknown")
        self.assertEqual(failure_details(ValueError("full_audit_call_budget_exhausted"))["error_category"], "budget")

    def test_secondary_recording_failure_keeps_the_primary_cause_and_is_sanitized(self):
        exc = ProviderError("provider_authentication_failed", failure_stage="analysis-1.call-001",
                            exception_type="HTTPError", http_status=401,
                            recording_error={"error_category": "quota", "message": "private key",
                                             "failure_stage": "job_failure_write", "exception_type": "PermissionError",
                                             "recording_error": {"message": "private nested"}})
        details = failure_details(exc)
        self.assertEqual(details["error_category"], "authentication")
        self.assertEqual(details["provider_code"], "provider_authentication_failed")
        self.assertEqual(details["recording_error"]["error_category"], "storage")
        self.assertEqual(details["recording_error"]["phase"], "store")
        self.assertEqual(details["recording_error"]["exception_type"], "PermissionError")
        self.assertNotIn("recording_error", details["recording_error"])
        self.assertNotIn("private", json.dumps(details))


if __name__ == "__main__":
    unittest.main()

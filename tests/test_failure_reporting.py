import http.client
import json
from pathlib import Path
import sys
import unittest
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.failure_reporting import AuditFailure, failure_details, safe_stage
from formsy_sop_verification.model_client import ProviderError


class FailureReportingTests(unittest.TestCase):
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

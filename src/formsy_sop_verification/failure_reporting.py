"""Safe diagnostics shared by the full-audit transport, engine and local jobs."""

import http.client
import re
import urllib.error


PROVIDER_TIMEOUT_SECONDS = 180
PROVIDER_CATEGORIES = {
    "provider_not_configured": "configuration",
    "provider_invalid_configuration": "configuration",
    "provider_authentication_failed": "authentication",
    "provider_quota_exhausted": "quota",
    "provider_rate_limited": "rate_limit",
    "provider_http_error": "http",
    "provider_network_or_timeout": "connection",
    "provider_request_too_large": "output",
    "provider_response_too_large": "output",
    "provider_invalid_json": "output",
    "provider_invalid_candidate": "output",
    "provider_incomplete_output": "output",
}
FIXED_CODES = set(PROVIDER_CATEGORIES) | {
    "full_audit_failed", "full_audit_storage_failed", "full_audit_internal_unknown",
    "full_audit_call_budget_exhausted", "full_audit_start_failed",
}
CATEGORIES = set(PROVIDER_CATEGORIES.values()) | {
    "timeout", "read_incomplete", "validation", "budget", "storage", "internal_unknown", "start",
}
PHASES = {"prepare", "connect", "read", "parse", "store", "engine", "job", "report"}
STAGES = {
    "unknown", "prepare", "analyze", "apply_policy", "audit_sop", "report_build", "report_write",
    "job_start", "job_run", "job_report_write", "job_report_validation", "job_failure_write",
}
EXCEPTION_TYPES = {
    "AuditFailure", "ProviderError", "ModelOutputError", "ValueError", "TypeError", "KeyError",
    "AttributeError", "RuntimeError", "AssertionError", "RecursionError", "UnicodeError",
    "UnicodeDecodeError", "JSONDecodeError", "OSError", "PermissionError", "FileNotFoundError",
    "FileExistsError", "IsADirectoryError", "NotADirectoryError", "TimeoutError", "URLError",
    "HTTPError", "HTTPException", "IncompleteRead", "RemoteDisconnected", "BadStatusLine",
    "ConnectionError", "ConnectionResetError", "ConnectionAbortedError", "ConnectionRefusedError",
    "BrokenPipeError", "SSLError", "SSLCertVerificationError", "UnexpectedError",
}
MODEL_STAGE = re.compile(
    r"(?:model:)?(?:"
    r"(?:task-extraction(?:-recheck)?|requirement-review(?:-recheck(?:-filtered)?)?|analysis|counter-review)-[0-9]+|"
    r"execution-mapping-(?:[0-9]+|T[0-9]+)-[0-9]+|"
    r"sop-source-review-[a-f0-9]{12}-TC14-C01(?:-[12])?|"
    r"sop-credential-review-[a-f0-9]{12}-SEC06-C02(?:-[12])?|"
    r"sop-failure-review-local-[a-f0-9]{12}(?:-1-[12]-1)?|"
    r"sop-(?:(?:condition(?:-scope)?|select|failure-review(?:-exclusions)?)-(?:[a-f0-9]{12}|T[0-9]+)|T[0-9]+)"
    r"(?:-(?:rows|extract|compare|retry|split|scope|user|design|resolution|exclusions|[0-9]+))*"
    r")(?:\.call-[0-9]{3})?\Z"
)


def safe_stage(value):
    # Human progress contains task titles; only program stage tokens are diagnostics.
    if isinstance(value, str) and len(value) <= 200 and (value in STAGES or MODEL_STAGE.fullmatch(value)):
        return value
    return "unknown"


def failure_details(exc, *, stage="unknown", phase="engine"):
    attributes = vars(exc)
    supplied = attributes.get("failure_details", {})
    supplied = supplied if isinstance(supplied, dict) else {}
    code = attributes.get("code")
    if not isinstance(code, str) or code not in FIXED_CODES:
        code = exc.args[0] if len(exc.args) == 1 and isinstance(exc.args[0], str) else None
        code = code if code in FIXED_CODES else None
    raw_http_status = None
    if isinstance(exc, urllib.error.HTTPError) and type(exc.code) is int and 100 <= exc.code <= 599:
        raw_http_status = exc.code
        if code is None:
            code = {401: "provider_authentication_failed", 402: "provider_quota_exhausted",
                    429: "provider_rate_limited"}.get(exc.code, "provider_http_error")
    selected_phase = supplied.get("phase", phase)
    selected_phase = selected_phase if isinstance(selected_phase, str) and selected_phase in PHASES else "engine"
    category = PROVIDER_CATEGORIES.get(code)
    if category is None:
        if code in {"full_audit_failed", "full_audit_internal_unknown"}:
            category = "internal_unknown"
        elif code == "full_audit_call_budget_exhausted":
            category = "budget"
        elif code == "full_audit_start_failed":
            category = "start"
        elif code == "full_audit_storage_failed":
            category = "storage"
        elif selected_phase == "store":
            category = "storage"
        elif isinstance(exc, http.client.IncompleteRead):
            category = "read_incomplete"
        elif isinstance(exc, TimeoutError):
            category = "timeout"
        elif isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError):
            category = "timeout"
        elif isinstance(exc, (urllib.error.URLError, http.client.HTTPException, ConnectionError)):
            category = "connection"
        elif isinstance(exc, OSError):
            category = "connection" if selected_phase in {"connect", "read"} else "storage"
        elif isinstance(exc, ValueError) and code != "full_audit_internal_unknown":
            category = "validation"
        else:
            category = "internal_unknown"
    requested_category = supplied.get("error_category")
    if isinstance(requested_category, str) and requested_category in CATEGORIES:
        if code == "provider_network_or_timeout" and requested_category in {"timeout", "connection", "read_incomplete"}:
            category = requested_category
        elif code in {None, "full_audit_failed", "full_audit_internal_unknown"}:
            category = "storage" if selected_phase == "store" else requested_category
    selected_stage = safe_stage(supplied.get("failure_stage"))
    if selected_stage == "unknown":
        selected_stage = safe_stage(stage)
    name = supplied.get("exception_type", type(exc).__name__)
    name = name if isinstance(name, str) and name in EXCEPTION_TYPES else "UnexpectedError"
    result = {"error_category": category, "failure_stage": selected_stage,
              "exception_type": name, "phase": selected_phase, "transport_retry": False}
    provider = code if code in PROVIDER_CATEGORIES else supplied.get("provider_code")
    if isinstance(provider, str) and provider in PROVIDER_CATEGORIES:
        result["provider_code"] = provider
    status = supplied.get("http_status", raw_http_status)
    if type(status) is int and 100 <= status <= 599:
        result["http_status"] = status
    for field in ("response_saved", "response_partial"):
        if type(supplied.get(field)) is bool:
            result[field] = supplied[field]
    count = supplied.get("captured_bytes")
    if type(count) is int and 0 <= count <= 1024 * 1024:
        result["captured_bytes"] = count
    if isinstance(supplied.get("transport_issue"), str) and supplied["transport_issue"] in {"timeout", "connection", "read_incomplete"}:
        result["transport_issue"] = supplied["transport_issue"]
    recording = supplied.get("recording_error")
    if isinstance(recording, dict):
        # A secondary diagnostic write failure must never replace the original cause.
        result["recording_error"] = failure_details(AuditFailure(
            "full_audit_storage_failed", phase="store",
            failure_stage=safe_stage(recording.get("failure_stage")),
            exception_type=recording.get("exception_type", "UnexpectedError")),
            stage=selected_stage, phase="store")
    return result


class AuditFailure(ValueError):
    def __init__(self, code, **details):
        self.code = code if isinstance(code, str) and code in FIXED_CODES else "full_audit_internal_unknown"
        super().__init__(self.code)
        self.failure_details = details
        self.failure_details = failure_details(self)

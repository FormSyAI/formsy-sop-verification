"""Callable frozen 144-condition engine, separate from the four-condition worker."""

from collections import Counter
import copy
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import urllib.error
import urllib.request
import uuid

from .core import MAX_INPUT_BYTES, decode_json
from .failure_reporting import AuditFailure, PROVIDER_TIMEOUT_SECONDS, failure_details
from .model_client import ProviderError
from .rule_sources import default_catalog, validate_upload
from .trace_audit import audit_engine, audit_policy, sop_audit, sop_catalog
from .trace_audit.model_client import ModelOutputError, redact, redact_value, save_json


ENGINE_ID = "traceaudit-r11"
ROOT = Path(__file__).resolve().parent / "trace_audit"
KNOWN_LIMITATIONS = [
    "r11 TC14: some whole-file claims remain uncertain; attribute/path scope errors are unresolved.",
    "r11 SEC06: a valid citation does not establish every fact in the accompanying reason.",
    "r11 FIX03/FIX04 and TC04/TC05: bounded citation/contract recovery can still fail.",
    "r11 TC13: an overly broad description can omit existing True test assertions.",
    "This adapter authenticates neither uploaded sources nor runner receipts; human closure stays false.",
    "Upstream 1018 regressions and 109 public programs describe r11 evidence, not this adapter's test count.",
]


def catalog_summary():
    source = default_catalog()
    catalog = source["catalog"]
    rules = catalog["rules"]
    return {
        "engine": ENGINE_ID,
        "contract_version": catalog["contract_version"],
        "rule_count": len(rules),
        "condition_count": sum(len(rule["conditions"]) for rule in rules),
        "atomic_item_count": sum(len(condition["contract"]["items"])
                                 for rule in rules for condition in rule["conditions"]),
        "documents": sop_catalog.public_summary(catalog)["documents"],
        "max_input_bytes": MAX_INPUT_BYTES,
        "max_material_chars": audit_engine.MAX_CHARS,
        "max_sop_calls": 64,
        "max_total_calls": 80,
        "known_limitations": list(KNOWN_LIMITATIONS),
        "source": source["summary"]["source"],
        "max_upload_rules": source["summary"]["max_upload_rules"],
    }


def prepare_full(payload):
    """Validate and freeze only explicit input and the packaged reference library."""
    if not isinstance(payload, dict) or set(payload) - {
        "title", "trace", "commits", "materials", "audit_context", "sop_selection", "rules"
    }:
        raise ValueError("invalid_full_audit_request")
    try:
        raw = json.dumps(payload, ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise ValueError("invalid_full_audit_json") from None
    if len(raw) > MAX_INPUT_BYTES:
        raise ValueError("full_audit_request_too_large")
    selection = payload.get("sop_selection")
    if "rules" in payload:
        if selection is not None and (not isinstance(selection, dict) or selection.get("mode", "auto") != "auto"):
            raise ValueError("uploaded_rules_and_pinned_catalog_are_mutually_exclusive")
        source = validate_upload({"rules": payload["rules"]})
    else:
        source = default_catalog(selection)
    package = audit_engine.normalize(copy.deepcopy(payload), source["rules"])
    # Upstream normalizes/redacts before assigning evidence IDs. Keep upload hashes
    # separately, including distinct originals that normalize to one evidence item.
    raw_trace = payload["trace"]
    if isinstance(raw_trace, str):
        raw_trace = decode_json(raw_trace.encode("utf-8"))
    originals = {}
    pairs = [(raw.get("content", ""), normalized["evidence_id"])
             for raw, normalized in zip(raw_trace["messages"], package["trace"]["messages"])]
    pairs += [(raw.get("diff", ""), normalized["evidence_id"])
              for raw, normalized in zip(payload["commits"], package["commits"])]
    pairs += [(raw.get("content", ""), normalized["evidence_id"])
              for raw, normalized in zip(payload.get("materials", []), package["materials"])]
    for content, evidence_id in pairs:
        originals.setdefault(evidence_id, set()).add(audit_engine.sha(content))
    for item in package["evidence"]:
        item["original_sha256s"] = sorted(originals[item["id"]])
        item["normalization_redacted"] = any(value != item["sha256"] for value in item["original_sha256s"])
    catalog = source["catalog"]
    catalog["sha256"] = audit_engine.sha(json.dumps(catalog, sort_keys=True, ensure_ascii=False))
    package["sop_catalog"] = catalog
    package["sop_selection"] = copy.deepcopy(catalog["selection"])
    package["rule_source"] = copy.deepcopy(source["summary"]["source"])
    # Never call verify_runs: that legacy entry point reads private signing config.
    package["run_verification"] = []
    package["integration_input_sha256"] = "sha256:" + hashlib.sha256(raw).hexdigest()
    return package


def _store(path, value, stage, **details):
    try:
        save_json(path, value)
    except OSError as exc:
        raise AuditFailure("full_audit_storage_failed", failure_stage=stage, phase="store",
                           exception_type=type(exc).__name__, **details) from None


class _ClientAdapter:
    """Apply one shared call budget and unique artifacts to every upstream stage."""

    def __init__(self, client, max_total_calls, stage_callback):
        self.client = client
        self.model = getattr(client, "model", "injected-offline-client")
        self.calls = 0
        self.limit = max_total_calls
        self.stage_callback = stage_callback
        self.failure_diagnostics = []
        self.current_stage = "prepare"

    def _record_failure(self, exc, directory, stage):
        details = failure_details(exc, stage=stage)
        self.failure_diagnostics.append(details)
        path = Path(directory) / (stage + ".error.json")
        # Call numbers and the new empty attempt directory make these unique.
        # Preserve an existing diagnostic if an external caller reuses a path.
        if not path.exists():
            try:
                code = exc.code if isinstance(exc, AuditFailure) else details.get("provider_code", "full_audit_failed")
                _store(path, {"code": code, **details}, stage)
            except AuditFailure as storage:
                recording = failure_details(storage, stage=stage)
                details["recording_error"] = recording
                exc.failure_details = details
                self.failure_diagnostics.append(recording)
        return details

    def complete(self, system, payload, directory, stage):
        if self.calls >= self.limit:
            raise AuditFailure("full_audit_call_budget_exhausted", failure_stage=stage, phase="prepare")
        self.calls += 1
        artifact_stage = f"{stage}.call-{self.calls:03d}"
        self.current_stage = artifact_stage
        phase = "prepare"
        try:
            self.stage_callback("model:" + stage)
            phase = "store"
            _store(Path(directory) / (artifact_stage + ".request.json"),
                   {"provider": "DeepSeek", "model": self.model, "system": system, "payload": payload},
                   artifact_stage)
            phase = "connect"
            result = (self.client.complete(system, payload, directory, artifact_stage)
                      if isinstance(self.client, _EnvironmentFullClient)
                      else self.client.complete(system, payload))
            phase = "store"
            result = redact_value(result, (getattr(self.client, "key", ""),))
            _store(Path(directory) / (artifact_stage + ".response.json"), result, artifact_stage)
            return result
        except ModelOutputError as exc:
            if not hasattr(exc, "failure_details"):
                exc.failure_details = failure_details(ProviderError("provider_invalid_candidate",
                    failure_stage=artifact_stage, phase="parse", exception_type="ModelOutputError"))
            details = self._record_failure(exc, directory, artifact_stage)
            output = ModelOutputError(details.get("provider_code", "provider_invalid_candidate"),
                                      truncated=exc.truncated)
            output.failure_details = details
            raise output from None
        except AuditFailure as exc:
            details = self._record_failure(exc, directory, artifact_stage)
            if exc.code in {"provider_invalid_json", "provider_invalid_candidate", "provider_incomplete_output"}:
                output = ModelOutputError(exc.code, truncated=exc.code == "provider_incomplete_output")
                output.failure_details = details
                raise output from None
            raise AuditFailure(exc.code, **details) from None
        except Exception as exc:
            safe = AuditFailure("full_audit_internal_unknown", failure_stage=artifact_stage, phase=phase,
                                exception_type=type(exc).__name__)
            self._record_failure(safe, directory, artifact_stage)
            raise safe from None


class _NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # A stage budget unit is one provider request, never an implicit second
        # request to a Location URL (which could also receive credentials).
        return None


class _EnvironmentFullClient:
    """Retain bounded provider responses before parsing; never read credential files."""

    MAX_RESPONSE_BYTES = 1024 * 1024
    MAX_REQUEST_BYTES = 4 * 1024 * 1024

    def __init__(self):
        self.key = os.environ.get("DEEPSEEK_API_KEY", "")
        self.model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
        self.request_count = 0
        self.opener = urllib.request.build_opener(_NoRedirects())

    def _response(self, raw, directory, stage, *, http_status=200, transport_incomplete=False):
        text = raw[:self.MAX_RESPONSE_BYTES].decode("utf-8", errors="replace")
        artifact = {"http_status": http_status, "raw_text": redact(text, (self.key,)),
                    "received_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
                    "captured_bytes": min(len(raw), self.MAX_RESPONSE_BYTES),
                    "truncated": len(raw) > self.MAX_RESPONSE_BYTES}
        if transport_incomplete:
            artifact["transport_incomplete"] = True
        # Preserve the complete bounded envelope even when candidate JSON is invalid.
        if not transport_incomplete and len(raw) <= self.MAX_RESPONSE_BYTES:
            try:
                artifact["envelope"] = redact_value(decode_json(raw), (self.key,))
            except (ValueError, UnicodeError, RecursionError):
                pass
        details = {"response_saved": False, "response_partial": transport_incomplete,
                   "captured_bytes": artifact["captured_bytes"]}
        if http_status is not None:
            details["http_status"] = http_status
        _store(Path(directory) / (stage + ".provider-response.json"), artifact, stage, **details)
        return {**details, "response_saved": True}

    def complete(self, system, payload, directory, stage):
        if not self.key:
            raise ProviderError("provider_not_configured", failure_stage=stage, phase="prepare")
        body = {"model": self.model, "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": json.dumps(redact_value(payload, (self.key,)), ensure_ascii=False)}],
                "response_format": {"type": "json_object"}, "thinking": {"type": "disabled"},
                "temperature": 0, "max_tokens": 10000, "stream": False}
        serialized = json.dumps(body, ensure_ascii=False, allow_nan=False).encode("utf-8")
        if len(serialized) > self.MAX_REQUEST_BYTES:
            raise ProviderError("provider_request_too_large", failure_stage=stage, phase="prepare")
        _store(Path(directory) / (stage + ".provider-request.json"), body, stage)
        request = urllib.request.Request("https://api.deepseek.com/chat/completions",
                    data=serialized, headers={"Authorization": "Bearer " + self.key,
                                              "Content-Type": "application/json"})
        self.request_count += 1
        http_status = None
        failure_code = "provider_network_or_timeout"
        phase = "connect"
        try:
            try:
                with self.opener.open(request, timeout=PROVIDER_TIMEOUT_SECONDS) as response:
                    http_status = 200
                    phase = "read"
                    raw = response.read(self.MAX_RESPONSE_BYTES + 1)
            except urllib.error.HTTPError as exc:
                http_status = exc.code
                failure_code = {401: "provider_authentication_failed", 402: "provider_quota_exhausted",
                                429: "provider_rate_limited"}.get(exc.code, "provider_http_error")
                phase = "read"
                raw = exc.read(self.MAX_RESPONSE_BYTES + 1)
        except http.client.IncompleteRead as exc:
            details = self._response(exc.partial, directory, stage, http_status=http_status, transport_incomplete=True)
            raise ProviderError(failure_code, failure_stage=stage, phase=phase,
                exception_type="IncompleteRead", transport_issue="read_incomplete",
                **({"error_category": "read_incomplete"} if failure_code == "provider_network_or_timeout" else {}),
                **details) from None
        except (urllib.error.URLError, TimeoutError, OSError, http.client.HTTPException) as exc:
            issue = "timeout" if isinstance(exc, TimeoutError) or (
                isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError)) else "connection"
            raise ProviderError(failure_code, failure_stage=stage, phase=phase,
                exception_type=type(exc).__name__, transport_issue=issue, response_saved=False,
                response_partial=False, **({"http_status": http_status} if http_status is not None else {}),
                **({"error_category": issue} if failure_code == "provider_network_or_timeout" else {})) from None
        except Exception as exc:
            raise AuditFailure("full_audit_internal_unknown", failure_stage=stage, phase=phase,
                exception_type=type(exc).__name__, response_saved=False, response_partial=False,
                **({"http_status": http_status} if http_status is not None else {})) from None
        details = self._response(raw, directory, stage, http_status=http_status)
        if http_status != 200:
            raise ProviderError(failure_code, failure_stage=stage, phase="read", exception_type="HTTPError", **details)
        if len(raw) > self.MAX_RESPONSE_BYTES:
            raise ProviderError("provider_response_too_large", failure_stage=stage, phase="parse", **details)
        def output_error(code, *, truncated=False):
            error = ModelOutputError(code, truncated=truncated)
            error.failure_details = failure_details(ProviderError(code, failure_stage=stage, phase="parse",
                exception_type="ModelOutputError", **details))
            return error
        try:
            value = decode_json(raw)
        except (ValueError, UnicodeError, RecursionError):
            raise output_error("provider_invalid_json") from None
        choice = value.get("choices") if isinstance(value, dict) else None
        if not isinstance(choice, list) or not choice or not isinstance(choice[0], dict):
            raise output_error("provider_invalid_candidate")
        if choice[0].get("finish_reason") != "stop":
            raise output_error("provider_incomplete_output", truncated=choice[0].get("finish_reason") == "length")
        message = choice[0].get("message")
        if not isinstance(message, dict) or not isinstance(message.get("content"), str):
            raise output_error("provider_invalid_candidate")
        try:
            candidate = decode_json(message["content"].encode("utf-8"))
        except (ValueError, UnicodeError, RecursionError):
            raise output_error("provider_invalid_candidate") from None
        if not isinstance(candidate, dict):
            raise output_error("provider_invalid_candidate")
        return candidate


def run_full_audit(payload, *, directory, client=None, max_sop_calls=64,
                   max_total_calls=80, stage_callback=None):
    """Run only after an explicit caller action; an injected client enables offline tests.

    The callback receives a string. It must not raise or perform provider calls.
    The caller owns asynchronous job state; this function does not start threads.
    """
    if type(max_sop_calls) is not int or not 0 <= max_sop_calls <= 64:
        raise ValueError("invalid_full_audit_sop_budget")
    if type(max_total_calls) is not int or not 1 <= max_total_calls <= 80:
        raise ValueError("invalid_full_audit_total_budget")
    package = prepare_full(payload)
    if not any(item["kind"] == "user_requirement" and item["content"].strip()
               for item in package["evidence"]):
        raise ValueError("missing_user_requirement")
    injected = client is not None
    client = client if injected else _EnvironmentFullClient()
    if not injected and not client.key:
        raise ValueError("provider_not_configured")
    directory = Path(directory).resolve()
    if directory == ROOT or ROOT in directory.parents:
        raise ValueError("full_audit_output_inside_engine")
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(directory.iterdir()):
        raise ValueError("full_audit_output_not_empty")
    directory.chmod(0o700)
    callback = stage_callback or (lambda stage: None)
    adapter = _ClientAdapter(client, max_total_calls, callback)
    stage, phase = "prepare", "store"
    try:
        _store(directory / "input.json", package, stage)
        stage, phase = "analyze", "engine"
        callback("输入已冻结；参考规则不代表项目历史生效 SOP")
        candidate = audit_engine.analyze(package, adapter, directory, callback)
        stage = "apply_policy"
        candidate = audit_policy.apply_policy(candidate, package)
        stage = "audit_sop"
        candidate = sop_audit.audit_sop(candidate, package, package["sop_catalog"], adapter,
                                        directory, stage_callback=callback, max_calls=max_sop_calls)
        stage, phase = "report_build", "report"
        frozen_tasks = directory / "frozen-tasks.json"
        exclusions = decode_json(frozen_tasks.read_bytes()).get("excluded_candidates", []) if frozen_tasks.exists() else []
        report = {
            **candidate, "schema_version": "2.1", "audit_id": uuid.uuid4().hex,
            "title": package["title"], "revision": 1,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "requirement_exclusions": exclusions,
            "evidence": copy.deepcopy(package["evidence"]), "rules": copy.deepcopy(package["rules"]),
            "audit_context": copy.deepcopy(package["audit_context"]),
            "rule_source": copy.deepcopy(package["rule_source"]),
            "summary": {"tasks": len(candidate["tasks"]), "checks": len(candidate["checks"]),
                        "results": dict(Counter(check["result"] for check in candidate["checks"])),
                        "findings": len(candidate["findings"])},
            "review_state": "model_candidate", "human_review": "not_reviewed", "formal_closed": False,
            "business_tests_executed": False, "audit_process_executes_business_code": False,
            "source_authenticated": False,
            "model_snapshot": {"provider": "injected_offline_client" if injected else "DeepSeek",
                               "model": adapter.model, "model_invoked": not injected and client.request_count > 0,
                               "api_request_count": 0 if injected else client.request_count,
                               "stage_call_count": adapter.calls, "max_total_calls": max_total_calls,
                               # Attempt history includes output errors recovered by bounded retries.
                               "failure_diagnostics": copy.deepcopy(adapter.failure_diagnostics),
                               "execution_mode": "offline_fake" if injected else "model"},
            "integration": {"engine": ENGINE_ID, "input_sha256": package["integration_input_sha256"],
                            "reference_only": True, "trusted_runner_supported": False,
                            "known_limitations": list(KNOWN_LIMITATIONS)},
        }
        published = redact_value(report, (getattr(client, "key", ""),))
        for original, displayed in zip(report["evidence"], published["evidence"]):
            displayed["original_sha256"] = original["original_sha256s"][0] if len(original["original_sha256s"]) == 1 else None
            displayed["display_sha256"] = audit_engine.sha(displayed["content"])
            displayed["display_redacted"] = any(value != displayed["display_sha256"] for value in original["original_sha256s"])
        stage, phase = "report_write", "store"
        _store(directory / "report.json", published, stage)
        callback("候选报告已生成；分析完成、业务结果与正式关闭分别判断")
        return published
    except Exception as exc:
        if stage in {"analyze", "audit_sop"} and adapter.current_stage != "prepare":
            stage = adapter.current_stage
        details = failure_details(exc, stage=stage, phase=phase)
        code = getattr(exc, "code", "full_audit_internal_unknown")
        if isinstance(exc, OSError) and phase == "store":
            code = "full_audit_storage_failed"
        safe = AuditFailure(code, **details)
        failure = {"code": "full_audit_failed", "report_preserved": (directory / "report.json").exists(),
                   **safe.failure_details}
        path = directory / "failure.json"
        if not path.exists():
            try:
                _store(path, failure, stage)
            except AuditFailure as storage:
                safe.failure_details["recording_error"] = failure_details(storage, stage=stage)
                safe = AuditFailure(safe.code, **safe.failure_details)
        raise safe from None

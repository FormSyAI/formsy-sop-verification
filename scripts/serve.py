#!/usr/bin/env python3
"""Loopback-only local UI for the existing candidate verifier; no dotenv loading."""

import argparse
from datetime import datetime, timezone
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import mimetypes
import os
from pathlib import Path
import sys
import threading
from urllib.parse import unquote, urlsplit
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from formsy_sop_verification.core import MAX_INPUT_BYTES, _redact_input, _redact_report, decode_json, verify  # noqa: E402
from formsy_sop_verification.local_full_audit import FullAuditJobs, FullAuditStartError, private_json  # noqa: E402
from formsy_sop_verification.model_client import ProviderError, THINKING_MODES, provider_configuration  # noqa: E402


def encoded(value):
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True,
                      separators=(",", ":")).encode("utf-8")


def sha256(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def configuration():
    result = {"model_configured": bool(os.environ.get("DEEPSEEK_API_KEY", "").strip())}
    try:
        return {**result, **provider_configuration()}
    except ProviderError:
        return {**result, "model_configured": False, "provider": None, "provider_endpoint": None, "model": None,
                "configuration_error": "provider_invalid_configuration"}


def full_configuration():
    mode = os.environ.get("DEEPSEEK_THINKING", "disabled")
    if mode not in THINKING_MODES:
        return {"thinking_mode": "invalid", "model_configured": False, "provider": None,
                "provider_endpoint": None, "model": None, "available": False, "default_available": False,
                "configuration_error": "provider_invalid_configuration", "max_sop_calls": 64, "max_total_calls": 80}
    execution = {"thinking_mode": mode}
    try:
        from formsy_sop_verification.full_audit import catalog_summary
    except ImportError:
        return {**configuration(), **execution, "available": False, "max_sop_calls": 64}
    try:
        return {**configuration(), **execution, **catalog_summary(), "available": True, "default_available": True}
    except (ValueError, OSError):
        return {**configuration(), **execution, "available": True, "default_available": False,
                "max_sop_calls": 64, "max_total_calls": 80, "max_upload_rules": 8,
                "default_error": "默认 FormSy SOP 规则尚未安装或未通过版本校验；可上传自定义规则。"}


def sop_template():
    return {"rules": [{"id": "CUSTOM01", "title": "保留显式零值", "version": "1.0",
                       "criterion": "满足条件：输入为0时保留0；输入缺失时才采用默认值。",
                       "required_evidence": ["目标版本完整源码", "覆盖0与缺失值的测试设计"],
                       "recheck": "补充证据后重新核查，不覆盖旧报告。",
                       "closure_policy": "人工复核候选结论后决定是否接受。"}]}


def full_demo():
    return {"title": "合成演示：只移除开头的前缀", "audit_context": {"profile": "code_fix"},
            "trace": {"messages": [{"role": "user", "content": "只移除一个开头前缀；中间出现的前缀保留。"}]},
            "commits": [{"sha": "a" * 40, "parent": "b" * 40, "repository": "synthetic/demo",
                         "diff": "diff --git a/demo.py b/demo.py\n--- a/demo.py\n+++ b/demo.py\n@@ -1,2 +1,2 @@\n def remove_prefix(value, prefix):\n-    return value.replace(prefix, '')\n+    return value[len(prefix):] if value.startswith(prefix) else value\n"}],
            "materials": [{"kind": "source", "name": "demo.py", "path": "demo.py", "version_id": "a" * 40,
                           "content": "def remove_prefix(value, prefix):\n    return value[len(prefix):] if value.startswith(prefix) else value\n"}]}


PUBLIC_DEMO_IDS = {"Melevir__cognitive_complexity-15", "akolar__ogn-lib-18",
                   "DCC-Lab__RayTracing-273", "tobymao__sqlglot-2063"}


def public_full_demos(root):
    """Read only allowlisted, hash-checked public fixtures; never scan saved audits."""
    directory = root / "examples/public-traces"
    catalog_path = directory / "catalog.json"
    if directory.resolve() != directory or catalog_path.is_symlink() or catalog_path.stat().st_size > 65536:
        raise ValueError("invalid_public_demo_catalog")
    catalog_raw = catalog_path.read_bytes()
    if len(catalog_raw) > 65536:
        raise ValueError("invalid_public_demo_catalog")
    catalog = decode_json(catalog_raw)
    if not isinstance(catalog, dict) or set(catalog) != {"examples"} or not isinstance(catalog["examples"], list):
        raise ValueError("invalid_public_demo_catalog")
    demos = {}
    for entry in catalog["examples"]:
        if not isinstance(entry, dict) or entry.get("id") not in PUBLIC_DEMO_IDS or entry["id"] in demos:
            raise ValueError("invalid_public_demo_catalog")
        demo_id = entry["id"]
        if entry.get("input_file") != demo_id + "/input.json":
            raise ValueError("invalid_public_demo_path")
        path = directory / entry["input_file"]
        if path.parent.is_symlink() or path.is_symlink() or path.stat().st_size > MAX_INPUT_BYTES:
            raise ValueError("invalid_public_demo_file")
        raw = path.read_bytes()
        if len(raw) > MAX_INPUT_BYTES or hashlib.sha256(raw).hexdigest() != entry.get("input_sha256"):
            raise ValueError("public_demo_hash_mismatch")
        metadata = {key: entry[key] for key in ("id", "title", "repository", "input_sha256", "source_url",
                    "license_files", "message_count", "material_count", "commit_shas") if key in entry}
        if not all(isinstance(metadata.get(key), str) and metadata[key] for key in
                   ("title", "repository", "source_url")):
            raise ValueError("invalid_public_demo_metadata")
        licenses = metadata.get("license_files")
        if not isinstance(licenses, list) or not licenses or any(not isinstance(name, str) or
                Path(name).is_absolute() or ".." in Path(name).parts for name in licenses):
            raise ValueError("invalid_public_demo_license")
        request = decode_json(raw)
        if not isinstance(request, dict):
            raise ValueError("invalid_public_demo_input")
        demos[demo_id] = {"demo": metadata, "request": request}
    return demos


def load_demo(root, demo_report=None):
    report_path = Path(demo_report) if demo_report else root / "examples/synthetic-live-report.json"
    live = report_path.is_file()
    if demo_report and not live:
        raise ValueError("Configured demo report is unavailable.")
    request_path = root / ("examples/model-request.json" if live else "examples/offline-request.json")
    if not live:
        report_path = root / "examples/offline-report.json"
    request = decode_json(request_path.read_bytes())
    report = decode_json(report_path.read_bytes())
    pin = {key: request["sop"][key] for key in ("project_id", "sop_id", "version", "digest")}
    if report.get("context") != request.get("context") or report.get("sop_pin") != pin:
        raise ValueError("Demo request and report identities do not match.")
    index = report.get("source_index", {})
    if set(index) != {source["id"] for source in request["sources"]}:
        raise ValueError("Demo request and report sources do not match.")
    for source in request["sources"]:
        entry = index[source["id"]]
        if (entry.get("original_sha256") != sha256(source["content"].encode("utf-8"))
                or entry.get("locator") != source["locator"]):
            raise ValueError("Demo source content does not match the saved report.")
    return {"request": request, "report": report,
            "mode": "synthetic_replay" if live else "offline_fixture"}


def save_record(directory, request, report):
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    input_sha256, report_sha256 = sha256(encoded(request)), sha256(encoded(report))
    secrets = (os.environ.get("DEEPSEEK_API_KEY", ""),)
    stored_request, stored_report = _redact_input(request, secrets), _redact_report(report, secrets)
    record = {"id": str(uuid.uuid4()), "created_at": datetime.now(timezone.utc).isoformat(),
              "input_sha256": input_sha256, "report_sha256": report_sha256,
              "stored_input_sha256": sha256(encoded(stored_request)),
              "stored_report_sha256": sha256(encoded(stored_report)),
              "input_storage_redacted": stored_request != request,
              "report_storage_redacted": stored_report != report}
    path = directory / (record["id"] + ".json")
    # Exclusive creation keeps local rounds append-only, with private file permissions.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(encoded({"record": record, "request": stored_request, "report": stored_report,
                                  "mode": request["mode"]}) + b"\n")
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    return record


def loopback_origin(value):
    parsed = urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost"}
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
            or parsed.port is None or not 1 <= parsed.port <= 65535
            or value != f"http://{parsed.hostname}:{parsed.port}"):
        raise ValueError("embed_origin_must_be_an_explicit_loopback_origin")
    return value


def make_server(root=ROOT, port=8769, demo_report=None, reports_dir=None, full_jobs=None, embed_origin=None):
    frame_ancestors = loopback_origin(embed_origin) if embed_origin else "'none'"
    root = Path(root).resolve()
    demo = load_demo(root, demo_report)
    web = (root / "web").resolve()
    records = Path(reports_dir) if reports_dir is not None else root / "reports/local"
    slots = threading.BoundedSemaphore(2)
    full_jobs = full_jobs or FullAuditJobs(records / "full")
    uploads = {}
    uploads_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "FormSyLocal/0.1"

        def setup(self):
            super().setup()
            self.connection.settimeout(15)

        def log_message(self, *_):
            # Paths, request bodies and provider errors may contain private input.
            pass

        def send_error(self, code, message=None, explain=None):
            self.error(code, "http_error", "The local request could not be processed.")

        def reply(self, status, body, content_type="application/json; charset=utf-8"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'self'; connect-src 'self'; "
                             "img-src 'self' data:; style-src 'self'; script-src 'self'; "
                             f"frame-ancestors {frame_ancestors}; base-uri 'none'; form-action 'self'")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def error(self, status, code, message):
            self.reply(status, encoded({"error": {"code": code, "message": message}}))

        def trusted(self, write=False):
            hosts = self.headers.get_all("Host", [])
            port = self.server.server_port
            allowed = {f"127.0.0.1:{port}", f"localhost:{port}"}
            if len(hosts) != 1 or hosts[0].lower() not in allowed:
                self.error(403, "untrusted_host", "Use this service through its loopback address.")
                return False
            origins = self.headers.get_all("Origin", [])
            if (len(origins) > 1 or (write and len(origins) != 1)
                    or (origins and origins[0].lower() != "http://" + hosts[0].lower())
                    or self.headers.get("Sec-Fetch-Site") == "cross-site"):
                self.error(403, "untrusted_origin", "Only requests from this local page are accepted.")
                return False
            return True

        def request_path(self):
            try:
                parsed = urlsplit(self.path)
                if parsed.scheme or parsed.netloc:
                    raise ValueError("absolute_target")
                return parsed.path
            except ValueError:
                self.error(400, "invalid_path", "Use a valid local request path.")
                return None

        def do_GET(self):
            if not self.trusted():
                return
            path = self.request_path()
            if path is None:
                return
            if path == "/api/config":
                self.reply(200, encoded(configuration()))
                return
            if path == "/api/demo":
                self.reply(200, encoded(demo))
                return
            if path == "/api/full-audit-config":
                self.reply(200, encoded(full_configuration()))
                return
            if path in {"/api/full-audit-demo", "/api/full-demo"}:
                self.reply(200, encoded(full_demo()))
                return
            if path == "/api/full-demo-catalog" or path.startswith("/api/full-demo/"):
                demo_id = path.removeprefix("/api/full-demo/")
                if path != "/api/full-demo-catalog" and demo_id not in PUBLIC_DEMO_IDS:
                    self.error(404, "full_demo_not_found", "This public demo is not available.")
                    return
                try:
                    demos = public_full_demos(root)
                except (OSError, ValueError, TypeError, KeyError):
                    self.error(503, "full_demo_unavailable", "The public demo catalog failed local integrity checks.")
                    return
                if path == "/api/full-demo-catalog":
                    self.reply(200, encoded({"demos": [value["demo"] for value in demos.values()]}))
                elif demo_id in demos:
                    self.reply(200, encoded(demos[demo_id]))
                else:
                    self.error(404, "full_demo_not_found", "This public demo is not available.")
                return
            if path == "/api/full-audits/active":
                self.reply(200, encoded({"job": full_jobs.active()}))
                return
            if path == "/api/sop-template":
                self.reply(200, encoded(sop_template()))
                return
            if path == "/api/sop-library":
                config = full_configuration()
                self.reply(200, encoded({key: value for key, value in config.items()
                                         if key not in {"model_configured", "model"}}))
                return
            if path.startswith("/api/sop-uploads/"):
                with uploads_lock:
                    upload = uploads.get(path.removeprefix("/api/sop-uploads/"))
                if upload is None:
                    self.error(404, "sop_upload_not_found", "This process has no matching SOP upload.")
                else:
                    self.reply(200, encoded(upload))
                return
            if path.startswith("/api/full-audits/"):
                job = full_jobs.get(path.removeprefix("/api/full-audits/"))
                if job is None:
                    self.error(404, "full_audit_not_found", "This local process has no matching audit job.")
                else:
                    self.reply(200, encoded(job))
                return
            if path.startswith("/api/"):
                self.error(404, "not_found", "Local endpoint not found.")
                return
            try:
                name = "index.html" if path == "/" else unquote(path).lstrip("/")
                target = (web / name).resolve()
                if not target.is_relative_to(web) or not target.is_file():
                    self.error(404, "not_found", "Local file not found.")
                    return
                body = target.read_bytes()
                mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
                self.reply(200, body, mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
            except (OSError, ValueError):
                self.error(404, "not_found", "Local file not found.")

        def do_POST(self):
            if not self.trusted(write=True):
                return
            path = self.request_path()
            if path is None:
                return
            if path not in ("/api/verify", "/api/full-audits", "/api/sop-uploads"):
                self.error(404, "not_found", "Local endpoint not found.")
                return
            lengths = self.headers.get_all("Content-Length", [])
            if self.headers.get("Transfer-Encoding") or len(lengths) != 1 or not lengths[0].isascii() or not lengths[0].isdigit():
                self.error(400, "invalid_length", "Provide one bounded Content-Length.")
                return
            if len(lengths[0]) > 10:
                self.error(413, "input_too_large", "The JSON request exceeds 2 MiB.")
                return
            length = int(lengths[0])
            if length > MAX_INPUT_BYTES:
                self.error(413, "input_too_large", "The JSON request exceeds 2 MiB.")
                return
            if self.headers.get_content_type() != "application/json":
                self.error(415, "json_required", "Use application/json.")
                return
            if not slots.acquire(blocking=False):
                self.error(429, "verification_busy", "Two local verifications are already running.")
                return
            try:
                raw = self.rfile.read(length)
                if len(raw) != length:
                    raise ValueError("incomplete_body")
                body = decode_json(raw)
                if path == "/api/sop-uploads":
                    from formsy_sop_verification.rule_sources import validate_upload
                    if not isinstance(body, dict) or set(body) != {"rules"}:
                        raise ValueError("sop_rules_wrapper_required")
                    prepared = validate_upload(body)
                    upload = {"id": str(uuid.uuid4()), "summary": prepared["summary"],
                              "rules": prepared["rules"], "model_invoked": False,
                              "created_at": datetime.now(timezone.utc).isoformat()}
                    directory = records / "sop-uploads"
                    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
                    private_json(directory / (upload["id"] + ".json"),
                                 {**upload, "original": body, "catalog": prepared["catalog"]})
                    with uploads_lock:
                        uploads[upload["id"]] = upload
                    self.reply(201, encoded(upload))
                    return
                if path == "/api/full-audits":
                    if not isinstance(body, dict) or set(body) != {"request", "mode"} or body["mode"] != "model":
                        raise ValueError("explicit_full_model_request_required")
                    config = full_configuration()
                    if config.get("configuration_error"):
                        self.error(503, "provider_invalid_configuration", "The full audit model configuration is invalid.")
                        return
                    if not config["available"]:
                        self.error(503, "full_engine_unavailable", "The full audit engine is unavailable.")
                        return
                    if not config["model_configured"]:
                        self.error(503, "model_unconfigured", "DeepSeek is not configured in this process.")
                        return
                    try:
                        job = full_jobs.submit(body["request"])
                    except FullAuditStartError as exc:
                        self.reply(503 if exc.error.get("error_category") == "start" else 500,
                                   encoded({"error": exc.error}))
                        return
                    self.reply(202, encoded(job))
                    return
                if not isinstance(body, dict) or set(body) != {"request"}:
                    raise ValueError("request_wrapper_required")
                request = body["request"]
                if not isinstance(request, dict) or request.get("mode") not in ("offline", "model"):
                    self.error(422, "explicit_mode_required", "Explicitly select offline or model mode.")
                    return
                if request["mode"] == "model" and not configuration()["model_configured"]:
                    self.error(503, "model_unconfigured", "DeepSeek is not configured in this process.")
                    return
                report = verify(request)
                if len(encoded(report)) > 1024 * 1024:
                    self.error(502, "report_too_large", "The candidate report exceeds 1 MiB.")
                    return
                record = save_record(records, request, report)
                secrets = (os.environ.get("DEEPSEEK_API_KEY", ""),)
                self.reply(201, encoded({"request": _redact_input(request, secrets),
                                         "report": _redact_report(report, secrets),
                                         "mode": request["mode"], "record": record}))
            except (ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, TimeoutError) as exc:
                if isinstance(exc, ValueError) and str(exc) == "credential_in_evidence_identity":
                    self.error(422, "credential_in_evidence_identity", "Remove credentials from project, SOP or source identity fields.")
                else:
                    self.error(422, "invalid_request", "Invalid, incomplete or oversized verification request.")
            except OSError:
                self.error(500, "local_storage_failed", "Could not save the local round; do not retry automatically.")
            except Exception:
                self.error(500, "verification_failed", "Local verification failed; do not retry automatically.")
            finally:
                slots.release()

    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8769)
    parser.add_argument("--demo-report", type=Path)
    parser.add_argument("--embed-origin", help="Allow this exact local FormSy preview origin to embed the UI.")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    try:
        server = make_server(port=args.port, demo_report=args.demo_report, embed_origin=args.embed_origin)
    except (OSError, ValueError, KeyError, TypeError):
        parser.exit(2, "Could not load matched demo files or bind the loopback port.\n")
    print(f"Local candidate review: http://127.0.0.1:{server.server_port}", flush=True)
    print("Synthetic replay/offline fixtures are separate from a new verification. No automatic model calls.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

"""Local asynchronous full audits. Inputs and final reports are append-only."""

from datetime import datetime, timezone
import copy
import json
import os
from pathlib import Path
import threading
import uuid


def private_json(path, value):
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)


class FullAuditJobs:
    def __init__(self, directory, *, runner=None, prepare=None):
        self.directory = Path(directory)
        self.runner = runner
        self.prepare = prepare
        self.lock = threading.Lock()
        self.jobs = {}
        self.slot = threading.BoundedSemaphore(1)

    def submit(self, request):
        request = copy.deepcopy(request)
        if self.prepare is None:
            from .full_audit import prepare_full
            prepare_full(request)
        else:
            self.prepare(request)
        if not self.slot.acquire(blocking=False):
            raise RuntimeError("full_audit_busy")
        job_id = str(uuid.uuid4())
        directory = self.directory / job_id
        try:
            directory.mkdir(parents=True, exist_ok=False, mode=0o700)
            private_json(directory / "request.json", request)
            job = {"id": job_id, "status": "queued", "progress": "等待完整审计启动",
                   "created_at": datetime.now(timezone.utc).isoformat()}
            with self.lock:
                self.jobs[job_id] = job
            thread = threading.Thread(target=self._run, args=(job_id, request, directory), daemon=True)
            thread.start()
            return dict(job)
        except BaseException:
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id].update(status="failed", progress="后台线程未能启动",
                                             error={"code": "full_audit_start_failed"})
            if directory.is_dir():
                try:
                    private_json(directory / "failure.json", {"code": "full_audit_start_failed"})
                except OSError:
                    pass
            self.slot.release()
            raise

    def _run(self, job_id, request, directory):
        def progress(stage):
            # Only stage names supplied by the engine enter the polling response.
            value = str(stage)
            if len(value) > 160:
                value = "完整审计处理中"
            with self.lock:
                self.jobs[job_id].update(status="running", progress=value)

        try:
            runner = self.runner
            if runner is None:
                from .full_audit import run_full_audit
                runner = run_full_audit
            progress("分析任务与适用规范")
            report = runner(request, directory=directory / "engine", max_sop_calls=64,
                            stage_callback=progress)
            private_json(directory / "report.json", report)
            if len(json.dumps(report, ensure_ascii=False).encode()) > 16 * 1024 * 1024:
                raise ValueError("full_report_too_large")
            with self.lock:
                self.jobs[job_id].update(status="completed", progress="审计返回；仍需检查分析失败与未核查项",
                                         report=report)
        except Exception as exc:
            failure = {"code": "full_audit_failed", "message": "完整审计未完成；本轮材料与已生成记录保留，未自动重试。"}
            # Expose only fixed provider codes, never arbitrary exception/source text.
            if str(exc) in {"provider_not_configured", "provider_authentication_failed",
                            "provider_quota_exhausted", "provider_rate_limited",
                            "provider_http_error", "provider_network_or_timeout"}:
                failure["provider_code"] = str(exc)
            try:
                private_json(directory / "failure.json", failure)
            except OSError:
                failure = {"code": "full_audit_storage_failed", "message": "本轮审计或记录保存失败；未自动重试。"}
            with self.lock:
                self.jobs[job_id].update(status="failed", progress="完整审计未完成", error=failure)
        finally:
            self.slot.release()

    def get(self, job_id):
        try:
            if str(uuid.UUID(job_id)) != job_id:
                return None
        except (ValueError, AttributeError):
            return None
        with self.lock:
            job = self.jobs.get(job_id)
            return dict(job) if job is not None else None

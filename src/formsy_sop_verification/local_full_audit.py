"""Local asynchronous full audits. Inputs and final reports are append-only."""

from datetime import datetime, timezone
import copy
import hashlib
import inspect
import json
import os
from pathlib import Path
import threading
import uuid

from .cancellation import AuditCancelled, check_cancelled
from .failure_reporting import failure_details, safe_stage


def private_json(path, value):
    raw = json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)


class FullAuditStartError(RuntimeError):
    def __init__(self, error):
        super().__init__("full_audit_start_failed")
        self.error = error


class FullAuditJobs:
    def __init__(self, directory, *, runner=None, prepare=None):
        self.directory = Path(directory)
        self.runner = runner
        self.prepare = prepare
        self.lock = threading.Lock()
        self.jobs = {}
        self.events = {}
        self.slot = threading.BoundedSemaphore(1)

    def submit(self, request):
        request = copy.deepcopy(request)
        if self.prepare is None:
            from .full_audit import prepare_full
            prepare_full(request)
        else:
            self.prepare(request)
        job_id = str(uuid.uuid4())
        directory = self.directory / job_id
        stage, phase = "prepare", "store"
        try:
            directory.mkdir(parents=True, exist_ok=False, mode=0o700)
            private_json(directory / "request.json", request)
            raw = json.dumps(request, ensure_ascii=False, allow_nan=False).encode("utf-8")
            job = {"id": job_id, "status": "queued", "progress": "等待旧审计退出后启动",
                   "created_at": datetime.now(timezone.utc).isoformat(),
                   "input_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(), "supersedes": []}
            event = threading.Event()
            stage, phase = "job_start", "job"
            # Starting under this lock prevents the worker from running before admission finishes.
            with self.lock:
                self.jobs[job_id] = job
                self.events[job_id] = event
                thread = threading.Thread(target=self._run, args=(job_id, request, directory), daemon=True)
                thread.start()
                previous = [old for old in self.jobs.values() if old["id"] != job_id
                            and old["status"] in {"queued", "running", "cancelling"}]
                job["supersedes"] = [old["id"] for old in previous]
                for old in previous:
                    now = datetime.now(timezone.utc).isoformat()
                    stop = {"code": "full_audit_cancel_requested", "reason": "superseded",
                            "superseded_by": job_id, "requested_at": now}
                    try:
                        private_json(self.directory / old["id"] / ("stop-requested-" + str(uuid.uuid4()) + ".json"), stop)
                    except Exception as exc:
                        old["stop_recording_error"] = failure_details(exc, stage="job_failure_write", phase="store")
                    old.update(status="cancelling", progress="已请求停止；等待当前调用退出并保留记录",
                               superseded_by=job_id, cancel_requested_at=now)
                    self.events[old["id"]].set()
                submitted = copy.deepcopy(job)
            return submitted
        except BaseException as exc:
            failure = {"code": "full_audit_start_failed", **failure_details(exc, stage=stage, phase=phase)}
            if stage == "job_start":
                failure["error_category"] = "start"
            if directory.is_dir():
                try:
                    private_json(directory / "failure.json", failure)
                except Exception as recording_exc:
                    failure["recording_error"] = failure_details(recording_exc, stage="job_failure_write", phase="store")
            with self.lock:
                if job_id in self.jobs:
                    self.jobs[job_id].update(status="failed", progress="后台线程未能启动", error=failure)
            if not isinstance(exc, Exception):
                raise
            raise FullAuditStartError(failure) from None

    def _run(self, job_id, request, directory):
        last_stage, phase = "job_run", "engine"
        event = self.events[job_id]

        def progress(stage):
            nonlocal last_stage
            check_cancelled(event, stage)
            # Only stage names supplied by the engine enter the polling response.
            value = str(stage)
            if not value.startswith("model:"):
                value = value.split("：", 1)[0]
            if len(value) > 160:
                value = "完整审计处理中"
            if value.startswith("model:"):
                last_stage = value
            with self.lock:
                if not event.is_set():
                    self.jobs[job_id].update(status="running", progress=value)

        self.slot.acquire()
        try:
            check_cancelled(event, last_stage)
            runner = self.runner
            if runner is None:
                from .full_audit import run_full_audit
                runner = run_full_audit
            progress("分析任务与适用规范")
            arguments = {"directory": directory / "engine", "max_sop_calls": 64, "stage_callback": progress}
            parameters = inspect.signature(runner).parameters
            if "cancellation_event" in parameters or any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
                arguments["cancellation_event"] = event
            report = runner(request, **arguments)
            last_stage, phase = "job_report_write", "store"
            private_json(directory / "report.json", report)
            last_stage, phase = "job_report_validation", "report"
            if len(json.dumps(report, ensure_ascii=False).encode()) > 16 * 1024 * 1024:
                raise ValueError("full_report_too_large")
            with self.lock:
                check_cancelled(event, last_stage)
                self.jobs[job_id].update(status="completed", progress="审计返回；仍需检查分析失败与未核查项",
                                         report=report)
        except AuditCancelled as exc:
            with self.lock:
                job = self.jobs[job_id]
                stop = {"code": "full_audit_cancelled", "reason": "superseded",
                        "superseded_by": job.get("superseded_by"),
                        "stage": safe_stage(getattr(exc, "stage", last_stage)),
                        "stopped_at": datetime.now(timezone.utc).isoformat()}
                if job.get("stop_recording_error"):
                    stop["recording_error"] = job["stop_recording_error"]
            try:
                private_json(directory / "stop.json", stop)
            except Exception as recording_exc:
                stop["recording_error"] = failure_details(recording_exc, stage="job_failure_write", phase="store")
            with self.lock:
                if stop.get("recording_error"):
                    self.jobs[job_id].update(status="failed", progress="审计已退出；停止记录保存失败", stop=stop,
                        error={"code": "full_audit_storage_failed", **stop["recording_error"]})
                else:
                    self.jobs[job_id].update(status="cancelled", progress="旧审计已停止；已有材料与响应保留",
                                             cancelled_at=stop["stopped_at"], stop=stop)
        except Exception as exc:
            failure = {"code": "full_audit_failed", "message": "完整审计未完成；本轮材料与已生成记录保留，未自动重试。",
                       **failure_details(exc, stage=last_stage, phase=phase)}
            try:
                private_json(directory / "failure.json", failure)
            except Exception as recording_exc:
                failure["recording_error"] = failure_details(recording_exc, stage="job_failure_write", phase="store")
            with self.lock:
                self.jobs[job_id].update(status="failed", error=failure)
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
            return copy.deepcopy(job) if job is not None else None

    def active(self):
        with self.lock:
            for job in reversed(list(self.jobs.values())):
                if job["status"] in {"queued", "running", "cancelling"}:
                    return {key: copy.deepcopy(job[key]) for key in
                            ("id", "status", "progress", "created_at", "input_sha256", "supersedes", "superseded_by")
                            if key in job}
        return None

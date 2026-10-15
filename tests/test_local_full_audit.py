import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.local_full_audit import FullAuditJobs, FullAuditStartError
from formsy_sop_verification.cancellation import check_cancelled
from formsy_sop_verification import local_full_audit
from formsy_sop_verification.failure_reporting import AuditFailure


class LocalFullAuditTests(unittest.TestCase):
    def terminal(self, jobs, job_id):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = jobs.get(job_id)
            if result["status"] in ("completed", "failed", "cancelled"):
                return result
            time.sleep(0.01)
        self.fail("Local fake job did not finish")

    def test_one_job_preserves_input_report_and_progress(self):
        started, release = threading.Event(), threading.Event()
        request = {"title": "frozen input"}

        def run(payload, *, directory, max_sop_calls, stage_callback):
            self.assertEqual(payload, request)
            self.assertEqual(max_sop_calls, 64)
            stage_callback("SOP")
            started.set()
            self.assertTrue(release.wait(5))
            return {"analysis_complete": False, "result": "unverified"}

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            first = jobs.submit(request)
            self.assertTrue(started.wait(5))
            self.assertEqual(jobs.get(first["id"])["progress"], "SOP")
            release.set()
            result = self.terminal(jobs, first["id"])
            self.assertEqual(result["status"], "completed")
            self.assertFalse(result["report"]["analysis_complete"])
            directory = Path(root) / first["id"]
            self.assertEqual(json.loads((directory / "request.json").read_text()), request)
            self.assertEqual(json.loads((directory / "report.json").read_text()), result["report"])
            self.assertEqual((directory / "request.json").stat().st_mode & 0o777, 0o600)
            self.assertIsNone(jobs.get("../request.json"))

    def test_failure_is_saved_without_retry_or_private_error_details(self):
        calls = []

        def run(*_, **__):
            calls.append(1)
            raise ValueError("private source text must not appear in polling errors")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            result = self.terminal(jobs, job["id"])
            self.assertEqual(result["status"], "failed")
            self.assertEqual(calls, [1])
            self.assertNotIn("private source", json.dumps(result))
            self.assertTrue((Path(root) / job["id"] / "failure.json").is_file())

    def test_submit_freezes_nested_input_before_the_background_worker(self):
        release = threading.Event()
        request = {"trace": {"messages": [{"content": "original"}]}}

        def run(payload, **_):
            self.assertTrue(release.wait(5))
            return {"seen": payload["trace"]["messages"][0]["content"]}

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit(request)
            request["trace"]["messages"][0]["content"] = "changed"
            release.set()
            result = self.terminal(jobs, job["id"])
            self.assertEqual(result["report"]["seen"], "original")
            saved = json.loads((Path(root) / job["id"] / "request.json").read_text())
            self.assertEqual(saved["trace"]["messages"][0]["content"], "original")

    def test_provider_unavailability_has_a_fixed_code_without_retry(self):
        calls = []

        def run(*_, **__):
            calls.append(1)
            raise ValueError("provider_quota_exhausted")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "synthetic quota fixture"})
            result = self.terminal(jobs, job["id"])
            self.assertEqual(result["error"]["provider_code"], "provider_quota_exhausted")
            self.assertEqual(result["error"]["code"], "full_audit_failed")
            self.assertEqual(result["error"]["error_category"], "quota")
            self.assertEqual(result["status"], "failed")
            self.assertEqual(calls, [1])

    def test_internal_failure_keeps_safe_model_stage_and_progress(self):
        def run(*_, stage_callback, **__):
            stage_callback("model:requirement-review-1.call-002")
            raise KeyError("private source text and secret value")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            result = self.terminal(jobs, job["id"])
            self.assertEqual(result["progress"], "model:requirement-review-1.call-002")
            error = result["error"]
            self.assertEqual(error["code"], "full_audit_failed")
            self.assertEqual(error["error_category"], "internal_unknown")
            self.assertEqual(error["failure_stage"], result["progress"])
            self.assertEqual(error["exception_type"], "KeyError")
            self.assertFalse(error["transport_retry"])
            saved = json.loads((Path(root) / job["id"] / "failure.json").read_text())
            self.assertEqual(saved, error)
            self.assertNotIn("private source", json.dumps(result))

    def test_failure_stage_and_progress_do_not_include_dynamic_task_titles(self):
        def run(*_, stage_callback, **__):
            stage_callback("选择任务适用的原SOP条款：private task title")
            raise ValueError("private exception message")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            result = self.terminal(jobs, job["id"])
            self.assertEqual(result["progress"], "选择任务适用的原SOP条款")
            self.assertEqual(result["error"]["failure_stage"], "job_run")
            self.assertNotIn("private", json.dumps(result))
            self.assertNotIn("private", (Path(root) / job["id"] / "failure.json").read_text())

    def test_typed_engine_failure_preserves_original_stage_and_transport_details(self):
        def run(*_, stage_callback, **__):
            stage_callback("model:analysis-1.call-003")
            raise AuditFailure("provider_network_or_timeout", error_category="timeout",
                               failure_stage="requirement-review-1.call-002", exception_type="TimeoutError",
                               phase="read", response_saved=True, response_partial=True, captured_bytes=7)

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            error = self.terminal(jobs, job["id"])["error"]
            self.assertEqual(error["code"], "full_audit_failed")
            self.assertEqual(error["provider_code"], "provider_network_or_timeout")
            self.assertEqual(error["failure_stage"], "requirement-review-1.call-002")
            self.assertEqual(error["error_category"], "timeout")
            self.assertEqual(error["exception_type"], "TimeoutError")
            self.assertEqual(error["phase"], "read")
            self.assertTrue(error["response_saved"])
            self.assertTrue(error["response_partial"])
            self.assertEqual(error["captured_bytes"], 7)

    def test_unlisted_exception_class_name_is_not_exposed(self):
        class PrivateCustomerException(Exception):
            pass

        def run(*_, **__):
            raise PrivateCustomerException("private error body")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            error = self.terminal(jobs, job["id"])["error"]
            self.assertEqual(error["exception_type"], "UnexpectedError")
            self.assertNotIn("PrivateCustomer", json.dumps(error))
            self.assertNotIn("private error", json.dumps(error))

    def test_report_write_failure_is_classified_as_storage(self):
        original = local_full_audit.private_json

        def save(path, value):
            if path.name == "report.json":
                raise PermissionError("private output path")
            original(path, value)

        with tempfile.TemporaryDirectory() as root, patch.object(local_full_audit, "private_json", side_effect=save):
            jobs = FullAuditJobs(root, runner=lambda *_, **__: {"candidate": True}, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            error = self.terminal(jobs, job["id"])["error"]
            self.assertEqual(error["code"], "full_audit_failed")
            self.assertEqual(error["error_category"], "storage")
            self.assertEqual(error["failure_stage"], "job_report_write")
            self.assertEqual(error["exception_type"], "PermissionError")
            self.assertEqual(error["phase"], "store")
            self.assertNotIn("private", json.dumps(error))
            self.assertEqual(json.loads((Path(root) / job["id"] / "failure.json").read_text()), error)

    def test_failure_record_write_error_does_not_replace_the_original_failure(self):
        calls = []
        original = local_full_audit.private_json

        def run(*_, stage_callback, **__):
            calls.append(1)
            stage_callback("model:analysis-1.call-001")
            raise KeyError("private first error")

        def save(path, value):
            if path.name == "failure.json":
                raise OSError("private recording path")
            original(path, value)

        with tempfile.TemporaryDirectory() as root, patch.object(local_full_audit, "private_json", side_effect=save):
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            job = jobs.submit({"title": "fixture"})
            result = self.terminal(jobs, job["id"])
            error = result["error"]
            self.assertEqual(calls, [1])
            self.assertEqual(error["code"], "full_audit_failed")
            self.assertEqual(error["error_category"], "internal_unknown")
            self.assertEqual(error["failure_stage"], "model:analysis-1.call-001")
            self.assertEqual(error["exception_type"], "KeyError")
            self.assertEqual(error["recording_error"]["error_category"], "storage")
            self.assertEqual(error["recording_error"]["failure_stage"], "job_failure_write")
            self.assertEqual(error["recording_error"]["exception_type"], "OSError")
            self.assertEqual(result["progress"], "model:analysis-1.call-001")
            self.assertNotIn("private", json.dumps(result))
            self.assertFalse((Path(root) / job["id"] / "failure.json").exists())

    def test_prepare_rejects_before_a_job_is_started(self):
        def reject(_):
            raise ValueError("bad fixture")

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, prepare=reject)
            with self.assertRaises(ValueError):
                jobs.submit({})
            self.assertEqual(jobs.jobs, {})
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_thread_start_failure_preserves_terminal_failure_and_releases_slot(self):
        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=lambda *_, **__: {}, prepare=lambda _: None)
            with patch("threading.Thread.start", side_effect=RuntimeError("thread unavailable")):
                with self.assertRaises(RuntimeError):
                    jobs.submit({"title": "fixture"})
            failed = next(iter(jobs.jobs.values()))
            self.assertEqual(failed["status"], "failed")
            self.assertEqual(failed["error"]["error_category"], "start")
            self.assertEqual(failed["error"]["failure_stage"], "job_start")
            self.assertTrue((Path(root) / failed["id"] / "failure.json").is_file())
            following = jobs.submit({"title": "next fixture"})
            self.assertEqual(self.terminal(jobs, following["id"])["status"], "completed")

    def test_latest_submission_cancels_old_and_queued_jobs_without_parallel_dispatch(self):
        started, release = threading.Event(), threading.Event()
        calls, concurrent = [], []
        active = 0
        guard = threading.Lock()

        def run(request, *, directory, cancellation_event, **_):
            nonlocal active
            with guard:
                active += 1
                concurrent.append(active)
                calls.append(request["title"])
            try:
                directory.mkdir()
                (directory / "old-provider-response.json").write_text('{"fixture":"preserved"}')
                if request["title"] == "first private title":
                    started.set()
                    self.assertTrue(release.wait(5))
                    check_cancelled(cancellation_event, "analysis-1.call-001")
                return {"candidate": request["title"]}
            finally:
                with guard:
                    active -= 1

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            first = jobs.submit({"title": "first private title", "trace": "private body"})
            self.assertEqual(first["status"], "queued")
            self.assertTrue(started.wait(5))
            second = jobs.submit({"title": "second"})
            third = jobs.submit({"title": "third"})
            self.assertEqual(second["supersedes"], [first["id"]])
            self.assertEqual(third["supersedes"], [first["id"], second["id"]])
            self.assertEqual(jobs.get(first["id"])["status"], "cancelling")
            self.assertEqual(jobs.get(second["id"])["status"], "cancelling")
            self.assertEqual(calls, ["first private title"])
            restored = jobs.active()
            self.assertEqual(restored["id"], third["id"])
            self.assertNotIn("private", json.dumps(restored))
            self.assertNotIn("request", restored)
            self.assertNotIn("report", restored)
            release.set()
            self.assertEqual(self.terminal(jobs, first["id"])["status"], "cancelled")
            self.assertEqual(self.terminal(jobs, second["id"])["status"], "cancelled")
            self.assertEqual(self.terminal(jobs, third["id"])["status"], "completed")
            self.assertEqual(calls, ["first private title", "third"])
            self.assertEqual(max(concurrent), 1)
            self.assertIsNone(jobs.active())
            old = Path(root) / first["id"]
            self.assertEqual(len(list(old.glob("stop-requested-*.json"))), 2)
            self.assertTrue((old / "engine/old-provider-response.json").is_file())
            stop = json.loads((old / "stop.json").read_text())
            self.assertEqual(stop["superseded_by"], third["id"])
            self.assertEqual(stop["stage"], "analysis-1.call-001")
            self.assertEqual(stop, jobs.get(first["id"])["stop"])
            self.assertEqual((old / "stop.json").stat().st_mode & 0o777, 0o600)

    def test_invalid_storage_or_thread_start_failure_never_cancels_running_job(self):
        for problem in ("prepare", "store", "thread"):
            with self.subTest(problem=problem), tempfile.TemporaryDirectory() as root:
                started, release = threading.Event(), threading.Event()

                def run(*_, **__):
                    started.set()
                    self.assertTrue(release.wait(5))
                    return {"old": "preserved"}

                def prepare(request):
                    if request.get("title") == "invalid":
                        raise ValueError("invalid input")

                jobs = FullAuditJobs(root, runner=run, prepare=prepare)
                first = jobs.submit({"title": "first"})
                self.assertTrue(started.wait(5))
                original = local_full_audit.private_json

                def save(path, value):
                    if path.name == "request.json":
                        raise PermissionError("private new input path")
                    return original(path, value)

                if problem == "prepare":
                    with self.assertRaises(ValueError):
                        jobs.submit({"title": "invalid"})
                elif problem == "store":
                    with patch.object(local_full_audit, "private_json", side_effect=save), self.assertRaises(FullAuditStartError) as exc:
                        jobs.submit({"title": "new"})
                    self.assertEqual(exc.exception.error["error_category"], "storage")
                else:
                    with patch("threading.Thread.start", side_effect=RuntimeError("private thread failure")), self.assertRaises(FullAuditStartError) as exc:
                        jobs.submit({"title": "new"})
                    self.assertEqual(exc.exception.error["error_category"], "start")
                self.assertEqual(jobs.get(first["id"])["status"], "running")
                self.assertFalse(jobs.events[first["id"]].is_set())
                self.assertEqual(jobs.active()["id"], first["id"])
                self.assertEqual(list((Path(root) / first["id"]).glob("stop*.json")), [])
                release.set()
                self.assertEqual(self.terminal(jobs, first["id"])["status"], "completed")

    def test_stop_recording_failure_is_explicit_and_never_claims_cancelled_success(self):
        for failed_name in ("stop.json", "stop-requested-"):
            with self.subTest(failed_name=failed_name), tempfile.TemporaryDirectory() as root:
                started, release = threading.Event(), threading.Event()

                def run(request, *, cancellation_event, **_):
                    if request["title"] == "first":
                        started.set()
                        self.assertTrue(release.wait(5))
                        check_cancelled(cancellation_event, "analysis-1.call-001")
                    return {"candidate": True}

                jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
                first = jobs.submit({"title": "first"})
                self.assertTrue(started.wait(5))
                original = local_full_audit.private_json

                def save(path, value):
                    if path.name == failed_name or path.name.startswith(failed_name):
                        raise PermissionError("private stop path")
                    original(path, value)

                with patch.object(local_full_audit, "private_json", side_effect=save):
                    second = jobs.submit({"title": "second"})
                    release.set()
                    result = self.terminal(jobs, first["id"])
                    self.assertEqual(result["status"], "failed")
                    self.assertEqual(result["error"]["code"], "full_audit_storage_failed")
                    self.assertEqual(result["stop"]["recording_error"]["error_category"], "storage")
                    self.assertNotIn("private stop", json.dumps(result))
                    self.assertEqual(self.terminal(jobs, second["id"])["status"], "completed")

    def test_legacy_injected_runner_finishes_before_slot_release_and_keeps_returned_candidate(self):
        started, release = threading.Event(), threading.Event()
        calls = []

        def run(request, *, directory, max_sop_calls, stage_callback):
            calls.append(request["title"])
            if request["title"] == "first":
                started.set()
                self.assertTrue(release.wait(5))
            return {"candidate": request["title"]}

        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=run, prepare=lambda _: None)
            first = jobs.submit({"title": "first"})
            self.assertTrue(started.wait(5))
            second = jobs.submit({"title": "second"})
            self.assertEqual(calls, ["first"])
            release.set()
            self.assertEqual(self.terminal(jobs, first["id"])["status"], "cancelled")
            self.assertEqual(self.terminal(jobs, second["id"])["status"], "completed")
            self.assertEqual(json.loads((Path(root) / first["id"] / "report.json").read_text()), {"candidate": "first"})



if __name__ == "__main__":
    unittest.main()

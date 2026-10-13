import json
from pathlib import Path
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.local_full_audit import FullAuditJobs
from formsy_sop_verification import local_full_audit
from formsy_sop_verification.failure_reporting import AuditFailure


class LocalFullAuditTests(unittest.TestCase):
    def terminal(self, jobs, job_id):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            result = jobs.get(job_id)
            if result["status"] in ("completed", "failed"):
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
            with self.assertRaisesRegex(RuntimeError, "full_audit_busy"):
                jobs.submit(request)
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

    def test_failure_directory_stat_error_keeps_start_failure_and_releases_slot(self):
        original = RuntimeError("private original thread failure")
        with tempfile.TemporaryDirectory() as root:
            jobs = FullAuditJobs(root, runner=lambda *_, **__: {}, prepare=lambda _: None)
            with patch("threading.Thread.start", side_effect=original), \
                 patch.object(Path, "is_dir", side_effect=PermissionError("private directory stat failure")):
                with self.assertRaises(RuntimeError) as caught:
                    jobs.submit({"title": "fixture"})
            self.assertIs(caught.exception, original)
            failed = next(iter(jobs.jobs.values()))
            self.assertEqual(failed["status"], "failed")
            error = failed["error"]
            self.assertEqual(error["error_category"], "start")
            self.assertEqual(error["exception_type"], "RuntimeError")
            self.assertEqual(error["recording_error"]["error_category"], "storage")
            self.assertEqual(error["recording_error"]["exception_type"], "PermissionError")
            self.assertEqual(error["recording_error"]["phase"], "store")
            self.assertNotIn("private", json.dumps(error))
            following = jobs.submit({"title": "next fixture"})
            self.assertEqual(self.terminal(jobs, following["id"])["status"], "completed")


if __name__ == "__main__":
    unittest.main()

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
            self.assertEqual(result["status"], "failed")
            self.assertEqual(calls, [1])

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
            self.assertTrue((Path(root) / failed["id"] / "failure.json").is_file())
            following = jobs.submit({"title": "next fixture"})
            self.assertEqual(self.terminal(jobs, following["id"])["status"], "completed")


if __name__ == "__main__":
    unittest.main()

"""Stop at the provider boundary without adopting or overwriting a partial answer."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from formsy_sop_verification.cancellation import AuditCancelled, check_cancelled
from formsy_sop_verification.full_audit import _ClientAdapter, _EnvironmentFullClient, run_full_audit
from formsy_sop_verification.failure_reporting import AuditFailure
from test_full_audit_stream import Response, event, DONE, KEY
from formsy_sop_verification.trace_audit.tests.test_engine import synthetic_payload, scripted_result
from formsy_sop_verification.trace_audit import sop_catalog


class FullAuditCancellationTests(unittest.TestCase):
    def setUp(self):
        environment = patch.dict('os.environ', {'DEEPSEEK_API_KEY': KEY,
            'DEEPSEEK_THINKING': 'enabled', 'DEEPSEEK_BASE_URL': 'https://tokenhub.tencentmaas.com/v1',
            'DEEPSEEK_MODEL': 'deepseek/deepseek-flash'}, clear=True)
        environment.start()
        self.addCleanup(environment.stop)
        root = Path(__file__).resolve().parents[1] / 'src/formsy_sop_verification/trace_audit'
        source = {'rules': json.loads((root / 'rules/default_rules.json').read_text()),
                  'catalog': sop_catalog.resolve_catalog(root),
                  'summary': {'source': {'kind': 'offline_packaged_test_fixture'}, 'max_upload_rules': 8}}
        catalog = patch('formsy_sop_verification.full_audit.default_catalog',
                        side_effect=lambda *_: copy.deepcopy(source))
        catalog.start()
        self.addCleanup(catalog.stop)

    def test_cancelled_before_request_makes_no_provider_call(self):
        cancelled = threading.Event()
        cancelled.set()
        client = _EnvironmentFullClient(cancellation_event=cancelled)
        with tempfile.TemporaryDirectory() as directory, patch.object(client.opener, 'open') as wire:
            with self.assertRaises(AuditCancelled):
                client.complete('Return JSON.', {}, directory, 'analysis-1')
            self.assertEqual(client.request_count, 0)
            wire.assert_not_called()
            self.assertFalse(list(Path(directory).iterdir()))

    def test_partial_sse_is_retained_redacted_and_not_retried_or_adopted(self):
        cancelled = threading.Event()
        raw = event({'reasoning_content': 'private ' + KEY})
        class CancelAfterChunk(Response):
            closed = False
            def read1(self, size):
                chunk = super().read1(size)
                cancelled.set()
                return chunk
            def __exit__(self, *args):
                self.closed = True
        response = CancelAfterChunk([raw, event({'content': '{"ok":true}'}), event({}, finish='stop'), DONE])
        client = _EnvironmentFullClient(cancellation_event=cancelled)
        adapter = _ClientAdapter(client, 8, lambda _: None)
        with tempfile.TemporaryDirectory() as directory, patch.object(client.opener, 'open', return_value=response) as wire:
            with self.assertRaises(AuditCancelled) as stopped:
                adapter.complete('Return JSON.', {}, directory, 'analysis-1')
            self.assertEqual(stopped.exception.stage, 'analysis-1.call-001')
            self.assertTrue(response.closed)
            self.assertEqual(wire.call_count, 1)
            self.assertEqual(client.request_count, 1)
            retained = json.loads((Path(directory)/'analysis-1.call-001.provider-response.json').read_bytes())
            self.assertTrue(retained['cancelled'])
            self.assertTrue(retained['transport_incomplete'])
            self.assertEqual(retained['captured_bytes'], len(raw))
            self.assertNotIn(KEY, json.dumps(retained))
            self.assertFalse((Path(directory)/'analysis-1.call-001.response.json').exists())
            self.assertFalse(adapter.failure_diagnostics)

    def test_callback_cancellation_is_not_wrapped_as_model_failure(self):
        def stop(stage):
            raise AuditCancelled(stage)
        class Never:
            model = 'fake'
            def complete(self, *args):
                raise AssertionError('Cancelled callback must not invoke provider')
        with tempfile.TemporaryDirectory() as directory:
            adapter = _ClientAdapter(Never(), 8, stop)
            with self.assertRaises(AuditCancelled):
                adapter.complete('Return JSON.', {}, directory, 'analysis-1')
            self.assertFalse(adapter.failure_diagnostics)

    def test_whole_run_retains_input_and_stop_without_success_report(self):
        cancelled = threading.Event()
        def stop_after_input(stage):
            cancelled.set()
            check_cancelled(cancelled, stage)
        class Never:
            model = 'fake'
            def complete(self, *args):
                raise AssertionError('No provider after stop')
        request = synthetic_payload()
        original = copy.deepcopy(request)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(AuditCancelled):
                run_full_audit(request, directory=directory, client=Never(),
                               cancellation_event=cancelled, stage_callback=stop_after_input)
            self.assertTrue((Path(directory)/'input.json').is_file())
            self.assertEqual(json.loads((Path(directory)/'cancelled.json').read_bytes())['status'], 'cancelled')
            self.assertFalse((Path(directory)/'report.json').exists())
            self.assertFalse((Path(directory)/'failure.json').exists())
            self.assertEqual(request, original)

    def test_cancel_receipt_write_failure_is_not_reported_as_successful_stop(self):
        class Never:
            model = 'fake'
            def complete(self, *args):
                raise AssertionError('No provider')
        def stop(stage):
            raise AuditCancelled(stage)
        from formsy_sop_verification import full_audit
        original_store = full_audit._store
        def fail_stop(path, *args, **kwargs):
            if Path(path).name == 'cancelled.json':
                raise AuditFailure('full_audit_storage_failed', failure_stage='job_failure_write', phase='store')
            return original_store(path, *args, **kwargs)
        with tempfile.TemporaryDirectory() as directory, patch.object(full_audit, '_store', side_effect=fail_stop):
            with self.assertRaises(AuditFailure) as error:
                run_full_audit(synthetic_payload(), directory=directory, client=Never(), stage_callback=stop)
            self.assertEqual(error.exception.code, 'full_audit_storage_failed')
            self.assertFalse((Path(directory)/'report.json').exists())

    def test_sop_cancellation_cannot_hide_partial_response_storage_failure(self):
        from formsy_sop_verification import full_audit
        cancelled = threading.Event()
        class CancelAfterChunk(Response):
            def read1(self, size):
                cancelled.set()
                return super().read1(size)
        client = _EnvironmentFullClient(cancellation_event=cancelled)
        original_store = full_audit._store
        def fail_partial(path, *args, **kwargs):
            if str(path).endswith('.provider-response.json'):
                raise AuditFailure('full_audit_storage_failed', failure_stage=args[1],
                                   phase='store', exception_type='PermissionError')
            return original_store(path, *args, **kwargs)
        response = CancelAfterChunk([event({'reasoning_content': 'synthetic partial'})])
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(client.opener, 'open', return_value=response) as wire, \
             patch.object(full_audit.audit_engine, 'analyze', side_effect=lambda package, *_: scripted_result(package)), \
             patch.object(full_audit, '_store', side_effect=fail_partial):
            with self.assertRaises(AuditFailure) as error:
                run_full_audit(synthetic_payload(), directory=directory, client=client,
                               cancellation_event=cancelled)
            self.assertEqual(error.exception.code, 'full_audit_storage_failed')
            self.assertEqual(wire.call_count, 1)
            stop = json.loads((Path(directory)/'cancelled.json').read_bytes())
            self.assertFalse(stop['artifacts_preserved'])
            self.assertEqual(stop['recording_error']['error_category'], 'storage')
            self.assertFalse((Path(directory)/'report.json').exists())
            self.assertFalse(list(Path(directory).glob('*.error.json')))

    def test_cancel_during_request_storage_prevents_http(self):
        from formsy_sop_verification import full_audit
        cancelled = threading.Event()
        client = _EnvironmentFullClient(cancellation_event=cancelled)
        original_store = full_audit._store
        def stop_after_request(path, *args, **kwargs):
            result = original_store(path, *args, **kwargs)
            cancelled.set()
            return result
        with tempfile.TemporaryDirectory() as directory, \
             patch.object(client.opener, 'open') as wire, \
             patch.object(full_audit, '_store', side_effect=stop_after_request):
            with self.assertRaises(AuditCancelled):
                client.complete('Return JSON.', {}, directory, 'analysis-1')
            wire.assert_not_called()
            self.assertEqual(client.request_count, 0)
            self.assertTrue((Path(directory)/'analysis-1.provider-request.json').is_file())


if __name__ == '__main__':
    unittest.main()

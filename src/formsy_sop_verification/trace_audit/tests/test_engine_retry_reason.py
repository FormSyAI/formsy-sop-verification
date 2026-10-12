"""Exercise the engine gate, including a plausible citation with an unsupported reason."""
import copy
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from .test_engine import RULES, scripted_result, synthetic_payload
from .test_engine_quote_retry import ScriptedClient, qid, select_refs


class EngineRetryReasonTests(unittest.TestCase):
    def test_valid_quote_cannot_retain_rejected_literal_in_analysis_or_counter_review(self):
        package = engine.normalize(synthetic_payload(), RULES)
        tasks = engine.validate_result(scripted_result({**engine.model_input(package, task_only=True),
                                                        'rules': []}), package, task_only=True)['tasks']
        source = next(e for e in package['evidence'] if e['kind'] == 'source')
        for stage_name in ('analysis', 'counter-review'):
            for retain in (True, False):
                with self.subTest(stage=stage_name, retain=retain), tempfile.TemporaryDirectory() as directory:
                    def mutate(value, payload, stage):
                        if stage == stage_name + '-1':
                            value['acceptance_checks'][0].update(
                                reason='The source defines RETRY_INVENTED_FLAG.',
                                run_refs=[{'evidence_id': source['id'], 'start_line': 1, 'end_line': 1,
                                           'quote': 'RETRY_INVENTED_FLAG = True'}])
                        elif stage == stage_name + '-2':
                            value = select_refs(value, payload, frozen_tasks=True)
                            value['acceptance_checks'][0].update(
                                reason='The source defines RETRY_INVENTED_FLAG.' if retain
                                       else 'The earlier source assertion is withdrawn; the behavior remains unknown.',
                                run_refs=[qid(payload, source['id'])])
                            self.assertTrue(any('RETRY_INVENTED_FLAG' in d.get('rejected_reason_anchors', [])
                                                for d in payload['reference_feedback']))
                        return value
                    client = ScriptedClient(mutate)
                    if retain:
                        with self.assertRaisesRegex(ValueError, '旧字面事实'):
                            engine.analyze(package, client, Path(directory), fixed_tasks=copy.deepcopy(tasks))
                        self.assertEqual(client.calls[-1]['stage'], stage_name + '-2')
                    else:
                        result = engine.analyze(package, client, Path(directory), fixed_tasks=copy.deepcopy(tasks))
                        self.assertEqual(result['tasks'], tasks)
                        if stage_name == 'counter-review':
                            self.assertNotIn('RETRY_INVENTED_FLAG', result['acceptance_checks'][0]['reason'])


if __name__ == '__main__':
    unittest.main()

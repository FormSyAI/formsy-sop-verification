"""Offline output-contract checks; empty advice never supplies missing evidence."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from .. import audit_engine as engine
from .test_engine import RULES, TARGET, check_for, reference, response_for, synthetic_payload
from .test_engine_quote_retry import ScriptedClient


class ImprovementContractTests(unittest.TestCase):
    def setUp(self):
        payload = synthetic_payload()
        payload['materials'].append({'name': 'tests/test_limit.py', 'kind': 'source',
            'version_id': TARGET, 'content': 'def test_zero():\n    assert resolve_limit(0) == 0\n'})
        self.package = engine.normalize(payload, RULES)

    def test_satisfied_check_with_no_gap_can_leave_advice_empty(self):
        value = response_for(self.package)
        check_for(value, 'FIX01').update(result='满足', missing_materials=[], improvement='')
        result = engine.validate_result(value, self.package)
        self.assertEqual(check_for(result, 'FIX01')['improvement'], '')
        self.assertEqual(check_for(result, 'FIX01')['local_result'], '满足')

    def test_unknown_failed_excluded_or_missing_evidence_still_requires_advice(self):
        cases = [('未核查', []), ('不满足', []), ('不适用', []), ('满足', ['Target source'])]
        for status, missing in cases:
            with self.subTest(status=status, missing=missing):
                value = response_for(self.package)
                check = check_for(value, 'FIX01')
                check.update(result=status, missing_materials=missing, improvement='')
                with self.assertRaisesRegex(ValueError, r'检查项.+/FIX01的improvement'):
                    engine.validate_result(value, self.package)

    def test_satisfied_implementation_and_assertions_can_leave_advice_empty(self):
        value = response_for(self.package)
        source = next(e for e in self.package['evidence'] if e['kind'] == 'source' and e['name'] == 'limit.py')
        test = next(e for e in self.package['evidence'] if e['kind'] == 'source' and e['name'] == 'tests/test_limit.py')
        value['acceptance_checks'][0].update(result='满足', test_design_result='满足',
            improvement='', no_change_reason='The target keeps explicit zero.',
            no_change_refs=[reference(source, 2)], assertion_refs=[reference(test, 2)])
        result = engine.validate_result(copy.deepcopy(value), self.package)
        self.assertEqual(result['acceptance_checks'][0]['improvement'], '')
        for field in ['result', 'test_design_result']:
            candidate = copy.deepcopy(value)
            candidate['acceptance_checks'][0][field] = '未核查'
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, r'验收点.+的improvement'):
                engine.validate_result(candidate, self.package)
        value['acceptance_checks'][0]['assertion_refs'] = []
        with self.assertRaisesRegex(ValueError, '断言设计满足必须引用'):
            engine.validate_result(value, self.package)

    def test_empty_findings_and_missing_or_null_advice_are_still_rejected(self):
        for category in ['checks', 'acceptance_checks', 'findings']:
            for action in ['empty', 'null', 'missing']:
                value = response_for(self.package)
                if action == 'missing':
                    value[category][0].pop('improvement')
                else:
                    value[category][0]['improvement'] = '' if action == 'empty' else None
                with self.subTest(category=category, action=action), self.assertRaises(ValueError):
                    engine.validate_result(value, self.package)

    def test_required_advice_feedback_reaches_bounded_repair_and_keeps_failure(self):
        tasks = engine.validate_result(response_for(self.package), self.package, task_only=True)['tasks']
        def mutate(value, payload, stage):
            if stage == 'analysis-1':
                value['checks'][0]['improvement'] = ''
            elif stage == 'analysis-2':
                self.assertIn('/FIX01的improvement', payload['validation_feedback'][0])
                self.assertIn('missing_materials=[]', payload['improvement_output_contract']['checks'])
                self.assertNotIn('citation_retry', payload)
            return value
        client = ScriptedClient(mutate)
        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(self.package, client, Path(directory), fixed_tasks=copy.deepcopy(tasks))
            retained = json.loads((Path(directory) / 'analysis-1.validation.json').read_text())
        self.assertEqual(result['tasks'], tasks)
        self.assertIn('/FIX01的improvement', retained['errors'][0])
        self.assertEqual(sum(call['stage'].startswith('analysis-') for call in client.calls), 2)


if __name__ == '__main__':
    unittest.main()

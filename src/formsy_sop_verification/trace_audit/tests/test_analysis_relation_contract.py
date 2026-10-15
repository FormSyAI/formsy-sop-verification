"""Replay the missing relation-field failure through the real bounded retry gate."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from .. import audit_engine as engine
from .test_engine import RULES, scripted_result, synthetic_payload, reference
from .test_engine_quote_retry import ScriptedClient


class AnalysisRelationContractTests(unittest.TestCase):
    def test_missing_relation_is_identified_and_repaired_without_invented_mapping(self):
        package = engine.normalize(synthetic_payload(), RULES)
        tasks = engine.validate_result(scripted_result({**engine.model_input(package, task_only=True),
            'rules': []}), package, task_only=True)['tasks']
        hunk = package['changes'][0]
        evidence = next(item for item in package['evidence'] if item['id'] == hunk['evidence_id'])
        ref = reference(evidence, hunk['changed_line_numbers'][-1])
        for repair in (False, True):
            with self.subTest(repair=repair), tempfile.TemporaryDirectory() as directory:
                def mutate(value, payload, stage):
                    if stage.startswith('analysis-'):
                        row = value['acceptance_checks'][0]
                        row.update(change_ids=[hunk['id']], change_refs=[copy.deepcopy(ref)])
                        if stage == 'analysis-2':
                            message = payload['validation_feedback'][0]
                            self.assertIn(row['acceptance_id'], message)
                            self.assertIn(hunk['id'], message)
                            self.assertNotIn('citation_retry', payload)
                            contract = payload['acceptance_output_contract']
                            self.assertIn('change_relations', contract['required_for_each_acceptance_check'])
                            if repair:
                                row['change_relations'] = [{'change_id': hunk['id'],
                                    'relation': 'unknown', 'reason': 'Causal relation remains unverified.',
                                    'evidence_refs': [copy.deepcopy(ref)]}]
                    return value
                client = ScriptedClient(mutate)
                if repair:
                    result = engine.analyze(package, client, Path(directory), fixed_tasks=copy.deepcopy(tasks))
                    self.assertEqual(result['tasks'], tasks)
                else:
                    with self.assertRaisesRegex(ValueError, '缺少change_relations'):
                        engine.analyze(package, client, Path(directory), fixed_tasks=copy.deepcopy(tasks))
                self.assertTrue((Path(directory) / 'analysis-1.validation.json').exists())
                self.assertEqual(sum(call['stage'].startswith('analysis-') for call in client.calls), 2)


if __name__ == '__main__':
    unittest.main()

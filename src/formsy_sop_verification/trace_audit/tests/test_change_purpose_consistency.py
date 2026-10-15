"""Offline reverse-mapping gates use program coverage, never source-word guesses."""
import copy
import unittest
from pathlib import Path

from ..sop_catalog import load_catalog
from ..sop_audit import reaggregate_sop
from ..sop_judgments import acceptance_consistency, PASS, FAIL, UNKNOWN


SHA, OLD, OTHER = 'a' * 40, 'b' * 40, 'c' * 40


class ChangePurposeConsistencyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        catalog = load_catalog(Path(__file__).resolve().parents[1])
        cls.rule = next(rule for rule in catalog['rules'] if rule['id'] == 'FIX02')

    def setUp(self):
        rule = copy.deepcopy(self.rule)
        condition = next(condition for condition in rule['conditions'] if condition['id'] == 'FIX02.C01')
        self.task = {'id': 'T1', 'commit_ids': [OLD, SHA], 'target_commit_ids': [SHA],
                     'acceptance_points': [{'id': 'R1', 'kind': 'behavior'}]}
        self.row = {**copy.deepcopy(condition), 'condition_id': condition['id'],
            'rule_id': 'FIX02', 'document_id': 'code-fix-0.1', 'task_id': 'T1',
            'target_commit_ids': [SHA], 'result': PASS, 'reason': 'Both directions were claimed complete.',
            'gap_type': '', 'evidence_refs': [], 'program_gates': [],
            'atomic_checks': [{'id': item['id'], 'text': item['text'], 'result': PASS,
                'reason': 'Original candidate reason ' + item['id'], 'gap_type': '',
                'evidence_refs': [], 'program_gates': []} for item in condition['contract']['items']]}
        self.change = {'id': 'H1', 'commit_id': SHA, 'task_ids': [],
                       'purpose_covered': False, 'unparsed': False}
        self.report = {'sop_rules': [rule], 'change_coverage': [copy.deepcopy(self.change)],
            'acceptance_checks': [{'task_id': 'T1', 'acceptance_id': 'R1', 'result': PASS}]}

    def check(self):
        acceptance_consistency(self.row, self.task, self.report)
        return self.row['atomic_checks'][1]

    def test_unresolved_final_change_downgrades_only_reverse_obligation(self):
        original = copy.deepcopy(self.row['atomic_checks'][1])
        check = self.check()
        self.assertEqual(self.row['result'], UNKNOWN)
        self.assertEqual(self.row['gap_type'], 'evidence_missing')
        self.assertEqual(self.row['atomic_checks'][0]['result'], PASS)
        self.assertEqual(check['result'], UNKNOWN)
        self.assertEqual(check['gap_type'], 'evidence_missing')
        self.assertEqual(check['model_candidate'], {'result': PASS, 'reason': original['reason']})
        self.assertEqual(check['evidence_refs'], original['evidence_refs'])
        proof = next(gate for gate in check['program_gates']
                     if gate['id'] == 'same_target_change_purpose_consistency')
        self.assertEqual(proof['change_ids'], ['H1'])
        self.assertEqual(proof['target_commit_ids'], [SHA])
        self.assertIn('H1', self.row['reason'])

    def test_unparsed_change_is_unresolved_even_with_a_mapping(self):
        self.report['change_coverage'][0].update(purpose_covered=True, unparsed=True, task_ids=['T1'])
        self.assertEqual(self.check()['result'], UNKNOWN)
        self.assertEqual(self.row['result'], UNKNOWN)

    def test_covered_changes_and_supporting_purpose_keep_candidate(self):
        self.report['change_coverage'][0].update(purpose_covered=True, relationship_status='supporting')
        self.assertEqual(self.check()['result'], PASS)
        self.assertEqual(self.row['result'], PASS)
        self.assertNotIn('model_candidate', self.row['atomic_checks'][1])

    def test_old_other_commit_and_explicit_other_task_changes_do_not_leak(self):
        for changed in ({'commit_id': OLD}, {'commit_id': OTHER}, {'task_ids': ['T2']}):
            with self.subTest(changed=changed):
                self.report['change_coverage'] = [{**self.change, **changed}]
                self.assertEqual(self.check()['result'], PASS)
                self.assertEqual(self.row['result'], PASS)

    def test_missing_or_wrong_row_target_and_other_task_are_excluded(self):
        for changed in ({'target_commit_ids': []}, {'target_commit_ids': [OLD]}, {'task_id': 'T2'}):
            with self.subTest(changed=changed):
                original = copy.deepcopy(self.row)
                self.row.update(changed)
                self.assertEqual(self.check()['result'], PASS)
                self.row = original

    def test_custom_rule_or_altered_native_source_or_contract_is_excluded(self):
        for change in ['uploaded', 'document', 'rule_id', 'text', 'source_ref', 'contract', 'rule_version', 'uploaded_rule']:
            with self.subTest(change=change):
                row, report = copy.deepcopy(self.row), copy.deepcopy(self.report)
                if change == 'uploaded':
                    self.row['contract']['origin'] = 'uploaded_explicit'
                elif change == 'document':
                    self.row['document_id'] = 'custom'
                elif change == 'rule_id':
                    self.row['rule_id'] = 'CUSTOM'
                elif change == 'text':
                    self.row['text'] += ' custom obligation'
                elif change == 'source_ref':
                    self.row['source_ref']['start_line'] += 1
                elif change == 'contract':
                    self.row['contract']['items'][1]['text'] += ' custom obligation'
                elif change == 'rule_version':
                    self.report['sop_rules'][0]['version'] = 'custom'
                else:
                    self.report['sop_rules'][0]['source_kind'] = 'uploaded_rule'
                self.assertEqual(self.check()['result'], PASS)
                self.assertEqual(self.row['result'], PASS)
                self.row, self.report = row, report

    def test_known_sibling_failure_and_program_failure_are_retained(self):
        for sibling_failure in [True, False]:
            with self.subTest(sibling_failure=sibling_failure):
                self.setUp()
                if sibling_failure:
                    self.row['atomic_checks'][0].update(result=FAIL, reason='Confirmed implementation counterexample.')
                else:
                    self.report['acceptance_checks'][0].update(result=FAIL, change_refs=[], assertion_refs=[], no_change_refs=[])
                check = self.check()
                self.assertEqual(check['result'], UNKNOWN)
                self.assertEqual(self.row['result'], FAIL)
                self.assertEqual(self.row['gap_type'], '')
                if sibling_failure:
                    self.assertEqual(self.row['atomic_checks'][0]['result'], FAIL)

    def test_repeated_aggregation_preserves_original_candidate_and_gate(self):
        self.report.update(tasks=[self.task], sop_condition_checks=[self.row], checks=[])
        reaggregate_sop(self.report)
        self.assertEqual(self.report['sop_coverage']['outcome'], UNKNOWN)
        expected = copy.deepcopy(self.report)
        reaggregate_sop(self.report)
        self.assertEqual(self.report, expected)


if __name__ == '__main__':
    unittest.main()

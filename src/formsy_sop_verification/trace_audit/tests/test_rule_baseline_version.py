"""Task rule versions never borrow code or auditor identities."""
import copy
import hashlib
from pathlib import Path
import unittest

from ..sop_audit import _condition_response, _require_original_statement_review
from ..sop_catalog import load_catalog
from ..sop_judgments import apply_atomic_gates
from .test_sop_audit import fixtures, ref, SHA


class RuleBaselineVersionTests(unittest.TestCase):
    def setUp(self):
        result, self.package, _ = fixtures()
        self.task = result['tasks'][0]
        self.condition = next(c for r in load_catalog(Path(__file__).resolve().parents[1])['rules']
                              for c in r['conditions'] if c['id'] == 'TC01.C01')
        self.answer = {'condition_id': 'TC01.C01', 'result': '满足', 'reason': '对象SHA就是规则版本。',
                       'gap_type': '', 'evidence_refs': [ref('U', '保留零值')], 'acceptance_ids': [],
                       'atomic_checks': [{'id': 'TC01.C01.I01', 'result': '满足', 'reason': '对象SHA就是规则版本。',
                          'gap_type': '', 'evidence_refs': [ref('U', '保留零值')], 'acceptance_ids': []}]}

    def baseline(self, kind='direct_requirement', eid='U', version=None):
        source = next(e for e in self.package['evidence'] if e['id'] == eid)
        proof = {'kind': kind, 'identity': eid, 'evidence_id': eid,
                 'version': version if version is not None else hashlib.sha256(source['content'].encode()).hexdigest(),
                 'evidence_refs': [ref(eid, source['content'])]}
        self.answer['atomic_checks'][0]['semantic_basis'] = {'rule_baseline': proof}
        return proof

    def evaluate(self):
        row = _condition_response({'conditions': [self.answer]}, self.task, [self.condition],
                                  self.package, strict_basis=True)[0]
        row['contract'] = copy.deepcopy(self.condition['contract'])
        apply_atomic_gates(row, self.task, self.package)
        return row

    def test_old_code_only_pass_becomes_unknown_with_candidate_retained(self):
        row = self.evaluate()
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['atomic_checks'][0]['rule_baseline_candidate']['result'], '满足')
        self.assertIn('对象SHA就是规则版本', row['atomic_checks'][0]['rule_baseline_candidate']['reason'])

    def test_original_user_baseline_own_hash_passes_without_date_or_tc14_verdict(self):
        self.baseline()
        row = self.evaluate()
        self.assertEqual(row['result'], '满足')
        self.assertIn('原用户规则基准', row['reason'])
        self.assertNotIn('对象SHA就是规则版本', row['reason'])
        self.assertEqual(self.answer['atomic_checks'][0]['reason'], '对象SHA就是规则版本。')

    def test_own_rule_identity_does_not_authenticate_selection(self):
        self.package['evidence'].append({'id': 'RULE', 'kind': 'context', 'version_id': 'team-2',
                                        'content': 'Team rule team-2 requires preserving zero.'})
        self.package['evidence'][0]['content'] += '；采用RULE作为本任务规则。'
        for kind in ('local', 'external'):
            with self.subTest(kind=kind):
                proof = self.baseline(kind, 'RULE', 'team-2')
                proof['selection_refs'] = [ref('U', '采用RULE作为本任务规则')]
                row = self.evaluate()
                self.assertEqual(row['result'], '未核查')
                self.assertTrue(row['atomic_checks'][0]['program_gates'][0]['identity_version_met'])

    def test_code_sha_auditor_pin_and_other_source_hash_do_not_prove_rule_version(self):
        for value in (SHA, 'traceaudit-r12', hashlib.sha256(b'other source').hexdigest()):
            with self.subTest(value=value):
                self.baseline(version=value)
                self.assertEqual(self.evaluate()['result'], '未核查')

    def test_missing_properties_and_cross_object_refs_are_unknown_not_failures(self):
        for change in ('missing_version', 'other_source'):
            proof = self.baseline()
            if change == 'missing_version':
                del proof['version']
            else:
                proof['evidence_id'] = 'S'
            with self.subTest(change=change):
                self.assertEqual(self.evaluate()['result'], '未核查')

    def test_bad_quote_and_foreign_user_still_reject(self):
        proof = self.baseline()
        proof['evidence_refs'][0]['quote'] = 'invented'
        with self.assertRaises(ValueError):
            self.evaluate()
        self.package['evidence'].append({'id': 'FOREIGN', 'kind': 'user_requirement', 'content': 'other task'})
        self.baseline(eid='FOREIGN')
        with self.assertRaises(ValueError):
            self.evaluate()

    def test_existing_failure_and_custom_same_id_keep_existing_behavior(self):
        for row in [self.answer, *self.answer['atomic_checks']]:
            row.update(result='不满足', reason='Existing same-scope candidate')
        self.assertEqual(self.evaluate()['result'], '不满足')
        for row in [self.answer, *self.answer['atomic_checks']]:
            row.update(result='满足', reason='Existing custom candidate')
        self.condition['contract']['origin'] = 'uploaded'
        self.assertEqual(self.evaluate()['result'], '满足')

    def test_missing_identity_and_implementation_body_hash_cannot_be_rule_baseline(self):
        proof = self.baseline()
        del proof['identity']
        self.assertEqual(self.evaluate()['result'], '未核查')
        proof = self.baseline('local', 'S')
        proof['selection_refs'] = [ref('U', '保留零值')]
        self.assertEqual(self.evaluate()['result'], '未核查')

    def test_local_context_needs_original_user_selection_and_never_fabricates_it(self):
        self.package['evidence'].append({'id': 'RULE', 'kind': 'context', 'version_id': 'team-2',
                                        'content': 'Team rule team-2 requires preserving zero.'})
        self.baseline('local', 'RULE', 'team-2')
        self.assertEqual(self.evaluate()['result'], '未核查')

    def test_all_statuses_reject_supplied_bad_baseline_and_selection_quotes(self):
        for status in ('满足', '未核查', '不满足'):
            for field in ('evidence_refs', 'selection_refs'):
                with self.subTest(status=status, field=field):
                    proof = self.baseline()
                    proof[field] = [ref('U', 'invented nested quote')]
                    for row in [self.answer, *self.answer['atomic_checks']]:
                        row.update(result=status, gap_type='evidence_missing' if status == '未核查' else '')
                    with self.assertRaises(ValueError):
                        self.evaluate()

    def test_local_rule_own_git_version_can_equal_code_commit_without_borrowing(self):
        self.package['evidence'].append({'id': 'RULE', 'kind': 'context', 'version_id': SHA,
                                        'content': 'Team rule requires preserving zero.'})
        self.package['evidence'][0]['content'] += '；采用RULE作为本任务规则。'
        proof = self.baseline('local', 'RULE', SHA)
        proof['selection_refs'] = [ref('U', '采用RULE作为本任务规则')]
        row = self.evaluate()
        self.assertEqual(row['result'], '未核查')
        self.assertTrue(row['atomic_checks'][0]['program_gates'][0]['identity_version_met'])
        proof['kind'] = 'external'
        self.assertEqual(self.evaluate()['result'], '未核查')

    def test_original_agent_sources_require_tc14_classification_not_assumed_claims(self):
        rules = load_catalog(Path(__file__).resolve().parents[1])['rules']
        selections = [{'rule_id': 'TC14', 'selection': 'not_applicable', 'reason': 'No external document adopted'}]
        before = copy.deepcopy(self.package)
        _require_original_statement_review(selections, self.task, self.package, rules)
        self.assertEqual(selections[0]['selection'], 'selected')
        self.assertEqual(selections[0]['model_selection'], 'not_applicable')
        self.assertEqual(selections[0]['program_review_scope']['statement_source_ids'], ['ASSISTANT'])
        self.assertEqual(self.package, before)

    def test_scope_review_does_not_borrow_foreign_agent_or_change_custom_rule(self):
        rules = load_catalog(Path(__file__).resolve().parents[1])['rules']
        next(e for e in self.package['evidence'] if e['id'] == 'ASSISTANT')['target_ids'] = ['OTHER_TASK']
        selections = [{'rule_id': 'TC14', 'selection': 'not_applicable', 'reason': 'Synthetic scope'}]
        _require_original_statement_review(selections, self.task, self.package, rules)
        self.assertEqual(selections[0]['selection'], 'not_applicable')
        next(e for e in self.package['evidence'] if e['id'] == 'ASSISTANT')['target_ids'] = ['T1']
        for rule in rules:
            if rule['id'] == 'TC14':
                for condition in rule['conditions']:
                    condition['contract']['origin'] = 'uploaded'
        _require_original_statement_review(selections, self.task, self.package, rules)
        self.assertEqual(selections[0]['selection'], 'not_applicable')

    def test_positive_negative_and_illustrative_selection_are_not_auto_certified(self):
        self.package['evidence'].append({'id': 'RULE', 'kind': 'context', 'version_id': 'team-2',
                                        'content': 'Team rule team-2 requires preserving zero.'})
        for statement in ('采用RULE', '不要采用RULE', 'RULE只是举例'):
            self.package['evidence'][0]['content'] += '；' + statement
            proof = self.baseline('local', 'RULE', 'team-2')
            proof['selection_refs'] = [ref('U', statement)]
            row = self.evaluate()
            self.assertEqual(row['result'], '未核查')
            self.assertEqual(row['atomic_checks'][0]['rule_baseline_candidate']['result'], '满足')
            self.assertTrue(row['atomic_checks'][0]['program_gates'][0]['identity_version_met'])

    def test_direct_own_hash_accepts_explicit_sha256_prefix_without_borrowing(self):
        proof = self.baseline()
        proof['version'] = 'sha256:' + proof['version']
        self.assertEqual(self.evaluate()['result'], '满足')
        proof['version'] = 'sha256:' + '0' * 64
        self.assertEqual(self.evaluate()['result'], '未核查')


if __name__ == '__main__':
    unittest.main()

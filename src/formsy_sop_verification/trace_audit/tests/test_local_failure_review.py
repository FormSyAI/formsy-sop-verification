"""Offline legacy counterexamples must cross the native independent proof boundary."""
import copy
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from ..audit_policy import apply_policy, project_local_failures
from ..sop_audit import audit_sop, reaggregate_sop
from ..sop_catalog import load_catalog
from ..sop_failures import review_local_failures
from .test_engine import ROOT, RULES, check_for, reference, response_for, synthetic_payload


class LocalFailureReviewTests(unittest.TestCase):
    def setup_case(self, rule='FIX03', *, broken=False, native=True):
        payload = synthetic_payload()
        if broken:
            payload['materials'][0]['content'] = 'def resolve_limit(value):\n    return value or 25\n'
            payload['commits'][0]['diff'] = ('--- a/limit.py\n+++ b/limit.py\n@@ -1 +1 @@\n'
                                           '-return value or 99\n+return value or 25\n')
        package = engine.normalize(payload, RULES)
        package['audit_context'] = {'profile': 'full_sop'}
        catalog = load_catalog(ROOT)
        catalog['rules'] = [r for r in catalog['rules'] if r['id'] in {'FIX02', 'FIX03'}]
        for row in catalog['rules']:
            row['conditions'] = [c for c in row['conditions'] if c['id'] == row['id'] + '.C01']
        if native:
            package['sop_catalog'] = catalog
            package['sop_selection'] = {'mode': 'auto'}
        value = response_for(package)
        source = next(e for e in package['evidence'] if e['kind'] == 'source')
        user = next(e for e in package['evidence'] if e['kind'] == 'user_requirement')
        diff = next(e for e in package['evidence'] if e['kind'] == 'commit_diff')
        value['acceptance_checks'][0].update(result='满足', reason='Synthetic candidate implementation.',
            change_ids=[package['changes'][0]['id']], change_refs=[reference(diff, 5)])
        check_for(value, rule).update(result='不满足',
            reason='A smaller patch was possible; the changed internal path was not explicitly authorized.',
            evidence_refs=[reference(source, 2)])
        if broken:
            check_for(value, rule).update(scope='Explicit zero at the public resolve_limit entry point.',
                reason='For explicit zero, the target implementation returns 25 rather than the required 0.')
        original = copy.deepcopy(value)
        result = engine.validate_result(value, package)
        task = result['tasks'][0]
        rows = []
        for rule_row in catalog['rules']:
            condition = rule_row['conditions'][0]
            rows.append({'task_id': task['id'], 'target_commit_ids': task['target_commit_ids'],
                'rule_id': rule_row['id'], 'condition_id': condition['id'], 'kind': condition.get('kind'),
                'document_id': rule_row['document_id'], 'source_ref': copy.deepcopy(condition['source_ref']),
                'text': condition['text'], 'contract': copy.deepcopy(condition['contract']),
                'result': '满足', 'reason': 'Independent native candidate.', 'gap_type': '',
                'evidence_refs': [reference(source, 2)], 'program_gates': [],
                'atomic_checks': [{'id': item['id'], 'text': item['text'], 'result': '满足',
                    'reason': 'Synthetic native proof.', 'gap_type': '', 'program_gates': [],
                    'evidence_refs': [reference(source, 2)], 'acceptance_ids': []}
                    for item in condition['contract']['items']]})
        result['sop_condition_checks'] = rows
        result['sop_rules'] = catalog['rules']
        result['sop_coverage'] = {'failures': [], 'unsupported_sections': []}
        return result, package, catalog, task, source, user, original

    def review(self, result, package, task, source, user, *, relation='evidence_insufficient',
               scope='same_scope', defect=None):
        calls, failures = [], []
        iid = check_for(result, 'FIX03' if check_for(result, 'FIX03').get('local_failure_candidate') else 'FIX02')['local_failure_review']['binding']['atomic_item_id']

        def call(stage, system, payload, validator, **kwargs):
            calls.append((stage, copy.deepcopy(payload), kwargs))
            self.assertEqual(kwargs['attempts'], 1)
            self.assertFalse(kwargs['final_failure'])
            self.assertIn('不能认证此候选理由', system)
            if defect == 'budget':
                return None, 'Shared call budget exhausted.', False
            answers = []
            for candidate in payload['candidates']:
                answer = {'id': candidate['id'], 'audit_object': candidate['audit_object'],
                    'dimension': candidate['dimension'], 'relation': relation, 'scope_consistency': scope,
                    'reason': ('The same zero-value input returns 25 instead of the required zero.'
                               if relation == 'direct_counterexample' else
                               'No effective scope restriction or same-input behavioral counterexample is established.'),
                    'violated_obligation': 'Preserve explicit zero.', 'expected': 'resolve_limit(0) is 0.',
                    'observed': 'Static source returns 25 for zero.', 'root_cause_id': '',
                    'obligation_refs': [reference(user)] if relation == 'direct_counterexample' else [],
                    'counterexample_refs': [reference(source, 2)] if relation == 'direct_counterexample' else []}
                if defect == 'wrong_version':
                    old = next(e for e in package['evidence'] if e['kind'] == 'test_log')
                    answer['counterexample_refs'] = [reference(old)]
                if defect == 'quote':
                    answer['counterexample_refs'][0]['quote'] = 'not present in original source'
                if defect == 'scope_missing':
                    answer.pop('scope_consistency')
                answers.append(answer)
            return validator({'reviews': answers, 'root_causes': []}), None, False

        before = copy.deepcopy(result['sop_condition_checks'])
        review_local_failures(result, task, package, engine.model_input(package, [task]), call,
                              'sop-failure-review-local-unit', failures)
        self.assertEqual(result['sop_condition_checks'], before, 'Temporary review rows must not replace native rows.')
        project_local_failures(result, package, {task['id']})
        return calls, failures, next(c for c in result['checks'] if c.get('local_failure_review', {}).get('binding', {}).get('atomic_item_id') == iid)

    def test_free_fail_is_pending_and_old_basic_entry_remains_compatible(self):
        for rule in ('FIX02', 'FIX03'):
            with self.subTest(rule=rule):
                result, package, _, task, _, _, original = self.setup_case(rule)
                check = check_for(result, rule)
                self.assertEqual(check['local_result'], '不满足')
                self.assertEqual(check['automated_result'], '未核查')
                self.assertEqual(check['local_failure_review']['status'], 'pending')
                self.assertEqual(check['local_failure_candidate']['reason'], check_for(original, rule)['reason'])
                self.assertFalse(result['automatic_review']['analysis_complete'])
                basic = self.setup_case(rule, native=False)[0]
                self.assertEqual(check_for(basic, rule)['automated_result'], '不满足')
                self.assertNotIn('local_failure_review', check_for(basic, rule))
                self.assertTrue(basic['automatic_review']['analysis_complete'])

    def test_missing_contract_or_only_path_difference_stays_unknown_without_native_mutation(self):
        for rule in ('FIX02', 'FIX03'):
            with self.subTest(rule=rule):
                result, package, _, task, source, user, original = self.setup_case(rule)
                calls, failures, check = self.review(result, package, task, source, user)
                self.assertEqual(len(calls), 1)
                self.assertFalse(failures)
                self.assertEqual(check['local_failure_review']['status'], 'completed')
                self.assertFalse(check['local_failure_review']['confirmed'])
                self.assertEqual(check['automated_result'], '未核查')
                self.assertNotIn('not explicitly authorized', check['reason'])
                self.assertEqual(check['local_failure_candidate']['reason'], check_for(original, rule)['reason'])
                self.assertTrue(result['automatic_review']['analysis_complete'])
                reaggregate_sop(result)
                self.assertEqual(check['sop_result'], '未核查')
                self.assertEqual(result['original_sop']['status'], '未核查')

    def test_real_same_scope_static_counterexample_remains_fail_and_reapply_is_stable(self):
        result, package, _, task, source, user, _ = self.setup_case(broken=True)
        calls, failures, check = self.review(result, package, task, source, user, relation='direct_counterexample')
        self.assertFalse(failures)
        self.assertEqual(len(calls), 1)
        self.assertTrue(check['local_failure_review']['confirmed'])
        self.assertEqual(check['automated_result'], '不满足')
        self.assertEqual(check['evidence_refs'], [reference(user), reference(source, 2)])
        receipt = copy.deepcopy(check['local_failure_review'])
        apply_policy(result, package)
        self.assertEqual(check['local_failure_review'], receipt)
        self.assertEqual(check['automated_result'], '不满足')
        reaggregate_sop(result)
        self.assertEqual(result['original_sop']['status'], '不满足')

    def test_another_property_cannot_confirm_the_frozen_legacy_reason(self):
        result, package, _, task, source, user, _ = self.setup_case(broken=True)
        _, failures, check = self.review(result, package, task, source, user,
                                        relation='direct_counterexample', scope='different_scope')
        self.assertFalse(failures)
        self.assertEqual(check['local_failure_review']['review']['relation'], 'direct_counterexample')
        self.assertFalse(check['local_failure_review']['confirmed'])
        self.assertEqual(check['automated_result'], '未核查')

    def test_contradictory_program_receipts_are_pending_without_certifying_failure(self):
        result, package, _, task, source, user, _ = self.setup_case(broken=True)
        self.review(result, package, task, source, user, relation='direct_counterexample')
        for changes in ({'effective_result': '未核查'}, {'confirmed': False, 'effective_result': '不满足'}):
            with self.subTest(changes=changes):
                corrupted = copy.deepcopy(result)
                check = check_for(corrupted, 'FIX03')
                check['local_failure_review'].update(changes)
                original = copy.deepcopy(check['local_failure_review'])
                apply_policy(corrupted, package)
                self.assertEqual(check['automated_result'], '未核查')
                self.assertEqual(check['local_failure_review']['status'], 'pending')
                self.assertFalse(check['local_failure_review']['confirmed'])
                self.assertEqual(check['local_failure_review']['invalidated_review'], original)
                self.assertIn('回执状态自相矛盾', check['reason'])
                self.assertNotIn('复核支持该反例', check['reason'])
                self.assertFalse(corrupted['automatic_review']['analysis_complete'])
                apply_policy(corrupted, package)
                self.assertEqual(check['local_failure_review']['invalidated_review'], original)

    def test_bad_quote_version_scope_or_budget_are_explicit_unfinished_after_two_attempts(self):
        for defect in ('quote', 'wrong_version', 'scope_missing', 'budget'):
            with self.subTest(defect=defect):
                result, package, _, task, source, user, _ = self.setup_case(broken=True)
                calls, failures, check = self.review(result, package, task, source, user,
                    relation='direct_counterexample', defect=defect)
                self.assertEqual(len(calls), 2)
                self.assertTrue(failures)
                self.assertEqual(check['local_failure_review']['status'], 'failed')
                self.assertEqual(check['automated_result'], '未核查')
                self.assertFalse(result['automatic_review']['analysis_complete'])
                result['sop_coverage']['failures'] = failures
                reaggregate_sop(result)
                self.assertFalse(result['sop_coverage']['analysis_complete'])

    def test_model_cannot_inject_program_receipts_and_changed_inputs_invalidate_real_receipt(self):
        result, package, _, task, source, user, original = self.setup_case(broken=True)
        self.review(result, package, task, source, user, relation='direct_counterexample')
        forged = copy.deepcopy(original)
        check_for(forged, 'FIX03').update({key: copy.deepcopy(check_for(result, 'FIX03')[key]) for key in
            ('local_failure_candidate', 'local_failure_review', 'local_failure_base_result')})
        safe = engine.validate_result(forged, package)
        self.assertEqual(check_for(safe, 'FIX03')['local_failure_review']['status'], 'pending')
        self.assertFalse(check_for(safe, 'FIX03')['local_failure_review']['confirmed'])
        for key in ('task_id', 'target_commit_ids', 'atomic_item_id', 'candidate_sha256', 'input_sha256'):
            with self.subTest(replayed_binding=key):
                replay = copy.deepcopy(result)
                binding = check_for(replay, 'FIX03')['local_failure_review']['binding']
                binding[key] = ['another-target'] if key == 'target_commit_ids' else 'another-binding'
                apply_policy(replay, package)
                self.assertEqual(check_for(replay, 'FIX03')['local_failure_review']['status'], 'pending')
                self.assertEqual(check_for(replay, 'FIX03')['automated_result'], '未核查')
        source['content'] += '# newly supplied original source\n'
        apply_policy(result, package)
        self.assertEqual(check_for(result, 'FIX03')['local_failure_review']['status'], 'pending')
        self.assertEqual(check_for(result, 'FIX03')['automated_result'], '未核查')

    def test_other_native_or_acceptance_fail_is_not_erased(self):
        result, package, _, task, source, user, _ = self.setup_case()
        self.review(result, package, task, source, user)
        result['sop_condition_checks'][0]['result'] = '不满足'
        result['sop_condition_checks'][0]['atomic_checks'][0]['result'] = '不满足'
        reaggregate_sop(result)
        self.assertEqual(result['original_sop']['status'], '不满足')
        result['acceptance_checks'][0].update(result='不满足', reason='Independent effective acceptance counterexample.')
        apply_policy(result, package)
        self.assertEqual(check_for(result, 'FIX03')['automated_result'], '不满足')
        project_local_failures(result, package, {task['id']})
        self.assertEqual(check_for(result, 'FIX03')['automated_result'], '不满足')

    def test_unselected_old_task_receipt_is_unchanged_and_no_free_fail_makes_no_calls(self):
        result, package, _, task, source, user, _ = self.setup_case()
        self.review(result, package, task, source, user)
        before = copy.deepcopy(result['checks'])
        apply_policy(result, package, task_ids={'another-selected-task'})
        project_local_failures(result, package, {'another-selected-task'})
        self.assertEqual(result['checks'], before)
        check = check_for(result, 'FIX03')
        check.pop('local_failure_candidate')
        check.pop('local_failure_review')
        check.update(local_result='满足', result='满足')
        def never(*args, **kwargs):
            raise AssertionError('No free local FAIL must make no model call.')
        review_local_failures(result, task, package, {}, never, 'unused', [])
        missing, missing_package, _, missing_task, _, _, _ = self.setup_case()
        missing['sop_condition_checks'] = []
        failures = []
        review_local_failures(missing, missing_task, missing_package, {}, never, 'missing-fixed-row', failures)
        project_local_failures(missing, missing_package, {missing_task['id']})
        self.assertTrue(failures)
        self.assertEqual(check_for(missing, 'FIX03')['local_failure_review']['status'], 'failed')
        self.assertFalse(missing['automatic_review']['analysis_complete'])

    def test_complete_native_pipeline_routes_free_failure_to_the_shared_review_and_matrix_is_unchanged(self):
        result, package, catalog, task, source, user, _ = self.setup_case()
        calls = []
        class Client:
            def complete(self, system, payload, directory, stage):
                calls.append(stage)
                if 'candidate_rules' in payload:
                    return {'rules': [{'rule_id': r['id'], 'selection': 'selected', 'reason': 'Synthetic native scope.',
                        'evidence_refs': [reference(user)]} for r in payload['candidate_rules']]}
                if 'candidates' in payload:
                    return {'reviews': [{'id': c['id'], 'audit_object': c['audit_object'], 'dimension': c['dimension'],
                        'relation': 'evidence_insufficient', 'scope_consistency': 'same_scope',
                        'reason': 'Only an alternative patch and internal path difference are established.',
                        'obligation_refs': [], 'counterexample_refs': [], 'root_cause_id': ''}
                        for c in payload['candidates']], 'root_causes': []}
                return {'conditions': [{'condition_id': c['id'], 'result': '满足', 'reason': 'Synthetic native positive proof.',
                    'gap_type': '', 'evidence_refs': [reference(source, 2)], 'acceptance_ids': [task['acceptance_points'][0]['id']],
                    'atomic_checks': [{'id': i['id'], 'result': '满足', 'reason': 'Synthetic native positive proof.',
                        'gap_type': '', 'evidence_refs': [reference(source, 2)], 'acceptance_ids': [task['acceptance_points'][0]['id']]}
                        for i in c['contract']['items']], 'improvement': '', 'verification': ''} for c in payload['conditions']]}
        with tempfile.TemporaryDirectory() as directory:
            report = audit_sop(result, package, catalog, Client(), directory, max_calls=8)
        self.assertTrue(any(stage.startswith('sop-failure-review-local-') for stage in calls))
        self.assertEqual(len(report['sop_condition_checks']), 2)
        self.assertTrue(all(row['result'] == '满足' for row in report['sop_condition_checks']))
        self.assertEqual(check_for(report, 'FIX03')['automated_result'], '未核查')
        self.assertTrue(report['sop_coverage']['analysis_complete'])
        self.assertEqual(report['sop_coverage']['request_count'], len(calls))

"""Offline paired boundaries for clause-specific counterexamples, not model accuracy."""
import copy
import unittest
from pathlib import Path
from unittest.mock import patch

from ..sop_catalog import load_catalog
from ..sop_contracts import ensure_contracts
from ..reference_repair import CITATION_SYSTEM_PROMPT, attach_quote_ids
from ..sop_failures import (REVIEW_SYSTEM, _failure_domain, build_issue_groups, candidates,
                          recalled_source_context, review_failures, validate_review)
from ..sop_judgments import FAIL, NA, PASS, UNKNOWN, apply_atomic_gates


ROOT = Path(__file__).resolve().parents[1]
SHA, OTHER = 'a' * 40, 'b' * 40


class SopFailureReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = load_catalog(ROOT)['rules']
        cls.conditions = {condition['id']: (rule, condition)
                          for rule in cls.rules for condition in rule['conditions']}

    def setUp(self):
        records = [
            ('U', 'user_requirement', 'Create must display the returned string ID without crashing.'),
            ('STATE', 'user_requirement', 'On cancellation, the running operation must enter cancelled and release its handle.'),
            ('BOUNDARY', 'user_requirement', 'Offline requests are unsupported and must be rejected before sending.'),
            ('PLAN', 'assistant', 'I plan to count a string-ID crash as successful completion.'),
            ('BADBOUNDARY', 'assistant', 'I plan to allow offline requests to be sent.'),
            ('CLAIM', 'assistant', 'I have fixed string-ID TABLE output in the target version.'),
            ('S', 'source', 'return response["id"]  # a string'),
            ('CONSUMER', 'source', 'for row in output: print(row.get("id"))'),
            ('EXIT', 'source', 'except Cancelled: return "running"  # handle remains open'),
            ('SEC', 'user_requirement', 'The token must never appear in the request URL or logs.'),
            ('LEAK', 'source', 'logger.info("token=%s", token)'),
            ('AUTH', 'user_requirement', 'Send requests only to api.example; sending to other destinations is forbidden.'),
            ('ACTION', 'source', 'requests.post("https://other.example", data=payload)'),
            ('LOG', 'test_log', 'FAILED test_string_id: AttributeError: str has no attribute get'),
            ('EXTERNAL', 'context', 'External audit test expects the string-ID crash to count as success.'),
            ('OLD', 'source', 'old consumer implementation'),
        ]
        evidence = []
        for eid, kind, content in records:
            evidence.append({'id': eid, 'kind': kind, 'content': content,
                             'version_id': OTHER if eid == 'OLD' else SHA,
                             'target_ids': ['T1'],
                             **({'path': eid.lower() + '.py'} if kind == 'source' else {})})
        evidence.append({'id': 'RUN', 'kind': 'run_record', 'content': 'Target run failed the string-ID assertion.',
                         'version_id': SHA, 'target_ids': ['T1']})
        self.package = {'evidence': evidence, 'commits': [{'sha': SHA, 'parent': OTHER}],
                        'run_verification': [{'evidence_id': 'RUN', 'log_evidence_id': 'LOG',
                                              'commit_sha': SHA, 'verified': True}]}
        self.task = {'id': 'T1', 'target_commit_ids': [SHA], 'commit_ids': [SHA],
                     'requirement_refs': [self.ref(eid) for eid in ('U', 'STATE', 'BOUNDARY', 'SEC', 'AUTH')],
                     'acceptance_points': [{'id': 'AP1', 'requirement_refs': [self.ref('U')]}]}
        self.calls = []

    def ref(self, eid):
        evidence = next(e for e in self.package['evidence'] if e['id'] == eid)
        return {'evidence_id': eid, 'start_line': 1, 'end_line': 1, 'quote': evidence['content']}

    def entry(self, cid, status=FAIL, index=0):
        rule, condition = self.conditions[cid]
        row = {'task_id': 'T1', 'target_commit_ids': [SHA], 'condition_id': cid,
               'rule_id': rule['id'], 'document_id': rule['document_id'],
               'result': status, 'reason': 'Untrusted candidate says the TABLE failure proves this clause.',
               'kind': condition.get('kind', 'semantic'), 'gap_type': '',
               'contract': copy.deepcopy(condition['contract']), 'evidence_refs': [self.ref('S')],
               'atomic_checks': [], 'program_gates': []}
        for number, item in enumerate(row['contract']['items']):
            selected = number == index
            row['atomic_checks'].append({'id': item['id'], 'text': item['text'],
                'result': status if selected else UNKNOWN, 'reason': row['reason'] if selected else 'Not checked.',
                'gap_type': '' if selected and status != UNKNOWN else 'evidence_missing',
                'evidence_refs': [self.ref('S')], 'acceptance_ids': ['AP1'], 'program_gates': []})
        return row, row['atomic_checks'][index], row['contract']['items'][index]

    def answer(self, entry, relation='direct_counterexample', obligation='U', contrary='S', **fields):
        item = entry[2]
        local_comparison = {}
        if item.get('direct_contract_source_review') and obligation == 'CONSUMER' and contrary == 'S':
            definite = relation in {'direct_counterexample', 'compatible_contract'}
            local_comparison = {'source_contract_analysis': {
                'attribute': 'producer_return_consumer_use',
                'producer': 'The producer returns a list of mappings.' if relation == 'compatible_contract' else
                            'The producer returns the response ID.',
                'consumer': 'The consumer iterates returned rows and invokes get.',
                'data_flow': 'The return is supplied as consumer output.' if definite else
                             'The supplied excerpts do not establish how this return reaches the consumer.',
                'gap': 'none' if definite else 'data_flow_unproven',
                'gap_reason': '' if definite else 'The call-site linkage is not established by the supplied excerpts.'}}
        answer = {'id': item['id'], 'audit_object': item['audit_object'],
                'dimension': item['judgment_dimension'], 'relation': relation,
                'reason': 'Only the cited obligation and its direct observation are compared.',
                'violated_obligation': 'The fixed local obligation.', 'expected': 'The specified result.',
                'observed': 'The directly conflicting observation.',
                'obligation_refs': [self.ref(obligation)], 'counterexample_refs': [self.ref(contrary)],
                'root_cause_id': '', **local_comparison, **fields}
        if answer.get('root_cause_id') and 'root_cause_binding' not in answer:
            answer['root_cause_binding'] = {'atomic_item_id': item['id'],
                'failure_domain': _failure_domain(entry[0], item),
                'mechanism_link': 'The cited mechanism directly causes this member obligation to fail.',
                'evidence_refs': copy.deepcopy(answer['obligation_refs'] + answer['counterexample_refs'])}
        return answer

    def run_review(self, entries, answers=None, causes=None, error=None, responses=None,
                   source_context_ids=()):
        rows = list({id(entry[0]): entry[0] for entry in entries}.values())
        by_id = {answer['id']: answer for answer in answers or []}

        def call(stage, system, payload, validator, **kwargs):
            self.calls.append((stage, copy.deepcopy(payload), kwargs))
            if error:
                return None, error, False
            response = copy.deepcopy(responses[min(len(self.calls) - 1, len(responses) - 1)]) if responses else {
                'reviews': [by_id[c['id']] for c in payload['candidates']], 'root_causes': causes or []}
            if isinstance(response, str):
                return None, response, False
            try:
                return validator(response), None, False
            except (ValueError, KeyError, TypeError) as exc:
                return None, str(exc), False

        failures = []
        request = {'task': copy.deepcopy(self.task), 'evidence': copy.deepcopy(self.package['evidence']),
                   'affected_source_context_ids': list(source_context_ids),
                   'candidate_rules': ['must be removed']}
        review_failures(rows, self.task, self.package, request, call, 'independent-counterexample', failures)
        return rows, failures

    def test_business_failure_cannot_be_the_design_or_traceability_counterexample(self):
        for cid in ('TC02.C01', 'TC06.C01', 'TC06.C03'):
            with self.subTest(cid=cid):
                entry = self.entry(cid)
                with self.assertRaises(ValueError):
                    validate_review(self.answer(entry, contrary='LOG'), entry, self.task, self.package)

    def test_external_audit_expectation_cannot_become_original_design(self):
        entry = self.entry('TC06.C01')
        with self.assertRaises(ValueError):
            validate_review(self.answer(entry, contrary='EXTERNAL'), entry, self.task, self.package)

    def test_explicit_original_plan_contradiction_can_remain_failed(self):
        entry = self.entry('TC06.C01')
        answer = self.answer(entry, obligation='U', contrary='PLAN')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')
        rows, failures = self.run_review([entry], [answer])
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertFalse(failures)

    def test_explicit_unsupported_boundary_contradiction_is_not_hidden(self):
        entry = self.entry('TC06.C03')
        answer = self.answer(entry, obligation='BOUNDARY', contrary='BADBOUNDARY')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')

    def test_state_exit_requires_explicit_kind_and_original_obligation(self):
        entry = self.entry('TC06.C02')
        for mutation in ('missing_kind', 'non_original_obligation'):
            with self.subTest(mutation=mutation):
                answer = self.answer(entry, obligation='STATE', contrary='EXIT',
                                     obligation_kind='explicit_state_exit')
                if mutation == 'missing_kind':
                    answer.pop('obligation_kind')
                else:
                    answer['obligation_refs'] = [self.ref('EXTERNAL')]
                with self.assertRaises(ValueError):
                    validate_review(answer, entry, self.task, self.package)
        answer = self.answer(entry, obligation='STATE', contrary='EXIT', obligation_kind='explicit_state_exit')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')

    def test_interface_and_data_types_can_have_a_static_double_sided_counterexample(self):
        for cid in ('TC04.C01', 'TC05.C01'):
            with self.subTest(cid=cid):
                entry = self.entry(cid)
                answer = self.answer(entry, obligation='CONSUMER', contrary='S')
                rows, failures = self.run_review([entry], [answer])
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertFalse(failures)

    def test_wrong_dimension_or_different_task_or_version_is_rejected(self):
        entry = self.entry('TC04.C01')
        for mutation in ('dimension', 'task', 'version'):
            with self.subTest(mutation=mutation):
                package = copy.deepcopy(self.package)
                answer = self.answer(entry, obligation='CONSUMER', contrary='S')
                if mutation == 'dimension':
                    answer['dimension'] = 'security_contract'
                elif mutation == 'task':
                    next(e for e in package['evidence'] if e['id'] == 'S')['target_ids'] = ['T2']
                else:
                    answer['counterexample_refs'] = [self.ref('OLD')]
                with self.assertRaises(ValueError):
                    validate_review(answer, entry, self.task, package)

    def test_same_quote_is_not_its_own_counterexample(self):
        entry = self.entry('TC04.C01')
        with self.assertRaises(ValueError):
            validate_review(self.answer(entry, obligation='S', contrary='S'), entry, self.task, self.package)

    def test_review_cannot_bind_current_evidence_to_a_different_saved_row(self):
        for mutation in ('task', 'version'):
            with self.subTest(mutation=mutation):
                entry = self.entry('TC04.C01')
                if mutation == 'task':
                    entry[0]['task_id'] = 'T2'
                else:
                    entry[0]['target_commit_ids'] = [OTHER]
                answer = self.answer(entry, obligation='CONSUMER', contrary='S')
                with self.assertRaises(ValueError):
                    validate_review(answer, entry, self.task, self.package)

    def test_independent_different_dimension_downgrades_without_promoting_pass(self):
        entries = [self.entry(cid) for cid in ('TC09.C02', 'SEC06.C02', 'TC07.C03')]
        answers = [self.answer(e, relation='different_dimension') for e in entries]
        rows, failures = self.run_review(entries, answers)
        self.assertEqual([r['result'] for r in rows], [UNKNOWN] * 3)
        self.assertFalse(failures)
        for _, check, _ in entries:
            self.assertEqual(check['model_result'], FAIL)
            self.assertEqual(check['failure_review']['relation'], 'different_dimension')

    def test_security_counterexample_requires_a_protection_chain(self):
        entry = self.entry('SEC06.C02')
        answer = self.answer(entry, obligation='SEC', contrary='LEAK')
        with self.assertRaises(ValueError):
            validate_review(answer, entry, self.task, self.package)
        answer['security_chain'] = {'asset': 'token', 'threat': 'log disclosure',
                                    'control': 'never log token values', 'scenario': 'request logging'}
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')

    def test_explicit_authorization_boundary_and_actual_action_can_remain_failed(self):
        entry = self.entry('TC09.C02')
        rows, failures = self.run_review([entry], [self.answer(entry, obligation='AUTH', contrary='ACTION')])
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertFalse(failures)

    def test_actual_resolution_claim_can_have_a_direct_runtime_counterexample(self):
        entry = self.entry('TC07.C03')
        answer = self.answer(entry, obligation='CLAIM', contrary='LOG')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')
        self.package['run_verification'][0]['verified'] = False
        with self.assertRaises(ValueError):
            validate_review(answer, entry, self.task, self.package)

    def test_state_transition_violation_does_not_require_a_completion_claim(self):
        entry = self.entry('SEC11.C04')
        answer = self.answer(entry, obligation='STATE', contrary='EXIT', obligation_kind='state_transition')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')

    def test_dependency_identity_conflict_does_not_require_a_completion_claim(self):
        self.package['evidence'].extend([
            {'id': 'DEP', 'kind': 'user_requirement', 'content': 'The target must use library X version 2.', 'target_ids': ['T1']},
            {'id': 'INSTALLED', 'kind': 'source', 'content': 'X==1', 'path': 'requirements.txt',
             'version_id': SHA, 'target_ids': ['T1']}])
        self.task['requirement_refs'].append(self.ref('DEP'))
        entry = self.entry('SEC09.C05')
        answer = self.answer(entry, obligation='DEP', contrary='INSTALLED', obligation_kind='dependency_identity')
        self.assertEqual(validate_review(answer, entry, self.task, self.package)['relation'],
                         'direct_counterexample')

    def test_resolution_failure_cannot_use_only_a_user_wish(self):
        entry = self.entry('TC07.C03')
        with self.assertRaises(ValueError):
            validate_review(self.answer(entry, obligation='U', contrary='LOG'), entry, self.task, self.package)

    def test_single_bad_quote_only_discards_its_own_review(self):
        first, second = self.entry('TC04.C01'), self.entry('TC05.C01')
        good = self.answer(first, obligation='CONSUMER', contrary='S')
        bad = self.answer(second, obligation='CONSUMER', contrary='S')
        bad['counterexample_refs'][0]['quote'] = 'fabricated quote'
        rows, failures = self.run_review([first, second], [good, bad])
        self.assertEqual([r['result'] for r in rows], [FAIL, UNKNOWN])
        self.assertEqual([f['atomic_item_id'] for f in failures], [second[2]['id']])
        self.assertEqual(second[1]['gap_type'], 'analysis_failed')
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([c['id'] for c in self.calls[1][1]['candidates']], [second[2]['id']])

    def test_budget_failure_is_explicit_and_preserves_verified_behavior_failure(self):
        behavior, design = self.entry('FIX05.C01'), self.entry('TC06.C01')
        behavior[0]['program_gates'] = [{'id': 'trusted_target_assertion_execution', 'result': FAIL,
                                        'evidence_ids': ['RUN']}]
        rows, failures = self.run_review([behavior, design], error='Model-call budget exhausted.')
        self.assertEqual([r['result'] for r in rows], [FAIL, UNKNOWN])
        self.assertEqual(design[1]['gap_type'], 'analysis_failed')
        self.assertEqual(len(failures), 2)
        self.assertEqual(behavior[1]['failure_review']['status'], 'failed')
        self.assertEqual(design[0]['analysis_status'], 'failed')
        self.assertEqual(len(self.calls), 2)

    def test_citation_contract_is_present_and_bare_quote_ids_stay_rejected(self):
        self.assertIn(CITATION_SYSTEM_PROMPT, REVIEW_SYSTEM)
        self.assertIn('{"quote_id":"Q-..."}', REVIEW_SYSTEM)
        entry = self.entry('TC04.C01')
        answer = self.answer(entry, obligation='CONSUMER', contrary='S')
        answer['counterexample_refs'] = ['Q-not-a-reference-object']
        rows, failures = self.run_review([entry], [answer])
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['failure_review']['status'], 'failed')
        self.assertEqual(len(failures), 1)
        self.assertEqual(len(self.calls), 2)

    def test_retry_only_invalid_item_and_retains_the_valid_first_answer(self):
        first, second = self.entry('TC04.C01'), self.entry('TC05.C01')
        good = self.answer(first, obligation='CONSUMER', contrary='S', reason='First valid reasoning.')
        bad = self.answer(second, obligation='CONSUMER', contrary='S')
        bad['counterexample_refs'][0]['quote'] = 'fabricated quote'
        fixed = self.answer(second, obligation='CONSUMER', contrary='S')
        rows, failures = self.run_review([first, second], responses=[
            {'reviews': [good, bad]}, {'reviews': [fixed]}])
        self.assertFalse(failures)
        self.assertEqual([row['result'] for row in rows], [FAIL, FAIL])
        self.assertEqual(first[1]['reason'], good['reason'])
        self.assertEqual([c['id'] for c in self.calls[1][1]['candidates']], [second[2]['id']])
        self.assertIn('原文不一致', self.calls[1][2]['initial_feedback'][0])
        self.assertTrue(self.calls[1][1]['reference_feedback'])

    def test_incomplete_envelope_has_only_one_bounded_whole_batch_retry(self):
        entries = [self.entry(cid) for cid in ('TC04.C01', 'TC05.C01')]
        answers = [self.answer(e, obligation='CONSUMER', contrary='S') for e in entries]
        rows, failures = self.run_review(entries, responses=[{'reviews': []}, {'reviews': answers}])
        self.assertFalse(failures)
        self.assertEqual([row['result'] for row in rows], [FAIL, FAIL])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(len(self.calls[1][1]['candidates']), 2)

    def test_grouping_retry_repairs_only_the_cause_and_preserves_valid_counterexample(self):
        entry = self.entry('TC04.C01')
        first = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1',
                            reason='Original valid counterexample.')
        second = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C2',
                             reason='Must not replace the accepted first judgment.')
        bad_cause = {'id': 'C1', **self.cause(cause_refs=[self.ref('OLD')])}
        valid_cause = {'id': 'C2', **self.cause()}
        rows, failures = self.run_review([entry], responses=[
            {'reviews': [first], 'root_causes': [bad_cause]},
            {'reviews': [second], 'root_causes': [valid_cause]}])
        self.assertFalse(failures)
        self.assertEqual(entry[1]['reason'], first['reason'])
        self.assertEqual(entry[1]['failure_review']['root_cause_id'], 'C2')
        self.assertEqual(entry[1]['failure_review']['root_cause'], self.cause())
        self.assertNotIn('grouping_error', entry[1]['failure_review'])
        self.assertEqual(self.calls[1][1]['candidates'][0]['review_mode'], 'root_cause_only')
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(len(report['sop_issue_groups']), 1)

    def test_failed_grouping_retry_cannot_erase_a_valid_counterexample(self):
        for failure in ('bad_quote', 'different_dimension', 'budget'):
            with self.subTest(failure=failure):
                self.setUp()
                entry = self.entry('TC04.C01')
                first = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1',
                                    reason='Valid first counterexample.')
                second = self.answer(entry, obligation='CONSUMER', contrary='S')
                if failure == 'bad_quote':
                    second['counterexample_refs'][0]['quote'] = 'fabricated'
                elif failure == 'different_dimension':
                    second['relation'] = 'different_dimension'
                else:
                    second = 'Model-call budget exhausted.'
                rows, failures = self.run_review([entry], responses=[
                    {'reviews': [first], 'root_causes': [{'id': 'C1', **self.cause(cause_refs=[self.ref('OLD')])}]},
                    second if isinstance(second, str) else {'reviews': [second]}])
                self.assertFalse(failures)
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertEqual(entry[1]['reason'], first['reason'])
                self.assertEqual(entry[1]['failure_review']['status'], 'completed')
                self.assertIn('grouping_error', entry[1]['failure_review'])
                self.assertNotEqual(rows[0].get('analysis_status'), 'failed')
                report = {'sop_condition_checks': rows}
                build_issue_groups(report)
                self.assertEqual(report['sop_issue_groups'], [])

    def test_empty_program_failure_marker_cannot_exempt_a_candidate(self):
        entry = self.entry('FIX05.C01')
        entry[0]['program_gates'] = [{'id': 'trusted_target_assertion_execution', 'result': FAIL}]
        rows, _ = self.run_review([entry], error='No review available.')
        self.assertEqual(rows[0]['result'], UNKNOWN)

    def test_verified_acceptance_only_protects_its_fixed_obligation(self):
        entry = self.entry('FIX02.C01')
        row = entry[0]
        row['atomic_checks'][1].update(result=FAIL, gap_type='')
        row['program_gates'] = [{'id': 'same_scope_acceptance_consistency', 'result': FAIL,
                                'dimension': 'implementation', 'acceptance_ids': ['AP1']}]
        rows, failures = self.run_review([entry], error='Budget exhausted.')
        self.assertEqual(rows[0]['atomic_checks'][0]['result'], FAIL)
        self.assertEqual(rows[0]['atomic_checks'][1]['result'], UNKNOWN)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(len(failures), 2)

    def test_review_input_contains_no_candidate_reason_or_previous_candidate_truth(self):
        entry = self.entry('TC06.C01')
        self.run_review([entry], [self.answer(entry, relation='evidence_insufficient')])
        candidate = self.calls[0][1]['candidates'][0]
        self.assertNotIn('reason', candidate)
        self.assertNotIn('result', candidate)
        self.assertNotIn('semantic_basis', candidate)
        self.assertNotIn('candidate_rules', self.calls[0][1])
        self.assertEqual(self.calls[0][2]['attempts'], 1)

    def test_only_verified_failures_are_reviewed_for_grouping_without_changing_failure(self):
        entry = self.entry('FIX05.C01')
        entry[0]['program_gates'] = [{'id': 'trusted_target_assertion_execution', 'result': FAIL,
                                     'evidence_ids': ['RUN']}]
        rows, failures = self.run_review([entry], [self.answer(entry, relation='different_dimension')])
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(self.calls[0][1]['candidates'][0]['review_mode'], 'root_cause_only')

    def test_non_failed_other_task_legacy_and_special_claims_are_not_candidates(self):
        failed = self.entry('TC04.C01')
        rows = [failed[0]]
        for status in (PASS, UNKNOWN, NA):
            rows.append(self.entry('TC05.C01', status=status)[0])
        legacy = self.entry('TC06.C01')[0]
        for item in legacy['contract']['items']:
            item.pop('failure_review', None)
        rows.append(legacy)
        other = self.entry('TC06.C02')[0]
        other['task_id'] = 'T2'
        rows.extend([other, self.entry('TC14.C02')[0]])
        frozen = copy.deepcopy(rows)
        self.assertEqual([e[2]['id'] for e in candidates(rows, self.task)], [failed[2]['id']])
        self.assertEqual(rows, frozen)

    def test_unknown_parent_still_reviews_its_failed_atomic_item(self):
        entry = self.entry('TC04.C01')
        entry[0].update(result=UNKNOWN, gap_type='evidence_missing', evidence_refs=[self.ref('U')])
        entry[0]['program_gates'] = [{'id': 'target_code_proof', 'met': False, 'reason': 'Missing code proof.'}]
        entry[1]['evidence_refs'] = [self.ref('U')]
        self.assertEqual([e[2]['id'] for e in candidates([entry[0]], self.task)], [entry[2]['id']])
        rows, failures = self.run_review([entry], [self.answer(entry, obligation='CONSUMER', contrary='S')])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(entry[1]['failure_review']['status'], 'completed')
        self.assertTrue(next(g for g in rows[0]['program_gates'] if g['id'] == 'target_code_proof')['met'])

    def test_valid_semantic_counterexample_cannot_bypass_missing_target_code_gate(self):
        entry = self.entry('TC06.C01')
        entry[0].update(result=UNKNOWN, gap_type='evidence_missing', evidence_refs=[self.ref('U')])
        entry[0]['program_gates'] = [{'id': 'target_code_proof', 'met': False, 'reason': 'Missing code proof.'},
                                   {'id': 'all_required_atomic_checks', 'met': False, 'result': FAIL}]
        for check in entry[0]['atomic_checks']:
            check['evidence_refs'] = [self.ref('U')]
        rows, failures = self.run_review([entry], [self.answer(entry, obligation='U', contrary='PLAN')])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['result'], UNKNOWN)
        self.assertEqual(entry[1]['failure_review']['relation'], 'direct_counterexample')
        self.assertFalse(next(g for g in entry[1]['program_gates'] if g['id'] == 'target_code_proof')['met'])
        self.assertEqual(next(g for g in rows[0]['program_gates'] if g['id'] == 'all_required_atomic_checks')['result'], UNKNOWN)

    def test_unknown_parent_cannot_hide_an_authoritative_failed_item(self):
        entry = self.entry('FIX05.C01')
        entry[0].update(result=UNKNOWN, gap_type='evidence_missing')
        entry[0]['program_gates'] = [{'id': 'trusted_target_assertion_execution', 'result': FAIL,
                                     'evidence_ids': ['RUN']},
                                    {'id': 'all_required_atomic_checks', 'result': UNKNOWN, 'met': False}]
        rows, failures = self.run_review([entry], [self.answer(entry, relation='different_dimension')])
        self.assertEqual(len(self.calls), 1)
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(entry[1]['result'], FAIL)
        self.assertEqual(next(g for g in rows[0]['program_gates'] if g['id'] == 'all_required_atomic_checks')['result'], FAIL)

    def test_uploaded_same_id_uses_its_own_review_and_cannot_borrow_program_exemption(self):
        from ..sop_audit import _base_condition
        for rid, cid in (('FIX05', 'FIX05.C01'), ('TC14', 'TC14.C02')):
            with self.subTest(rid=rid):
                uploaded = copy.deepcopy(next(rule for rule in self.rules if rule['id'] == rid))
                uploaded.update(source_kind='uploaded_rule', document_id='uploaded-rules')
                uploaded['conditions'] = [copy.deepcopy(self.conditions[cid][1])]
                uploaded['conditions'][0].update(kind='semantic', text='The uploaded clause has its own obligation.')
                rule = ensure_contracts({'rules': [uploaded]})['rules'][0]
                condition = rule['conditions'][0]
                item = condition['contract']['items'][0]
                self.assertEqual(item['judgment_dimension'], 'uploaded_rule_specific')
                self.assertEqual(item['failure_review']['version'], '1.9')
                self.assertNotIn('semantic_gate', item)
                self.assertNotIn('execution_dimension', condition['contract'])
                base = _base_condition(self.task, rule, condition, 'selected')
                self.assertEqual(base['kind'], 'semantic')
                entry = self.entry(cid)
                entry[0].update(contract=condition['contract'], document_id='uploaded-rules', kind='execution')
                entry[0]['program_gates'] = [{'id': 'trusted_target_assertion_execution',
                                             'result': FAIL, 'evidence_ids': ['RUN']}]
                self.assertEqual(len(candidates([entry[0]], self.task)), 1)

    def test_exact_execution_dimensions_are_visible_to_the_independent_reviewer(self):
        expected = {'FIX05.C01': ('execution', 'behavior'),
                    'FIX05.C02': ('skip_substitution', 'skip_substitution'),
                    'FIX05.C03': ('artifact_binding', 'artifact_binding'),
                    'FIX05.C04': ('evidence_completeness', 'evidence_completeness'),
                    'FIX05.C05': ('current_identity', 'current_identity'),
                    'FIX03.C02': ('execution_evidence', 'evidence_presence')}
        for cid, (dimension, execution_dimension) in expected.items():
            with self.subTest(cid=cid):
                entry = self.entry(cid)
                for item in entry[0]['contract']['items']:
                    self.assertEqual(item['judgment_dimension'], dimension)
                    self.assertEqual(item['failure_review']['dimension'], dimension)
                self.run_review([entry], [self.answer(entry, relation='evidence_insufficient')])
                payload = self.calls[-1][1]['candidates'][0]
                self.assertEqual(payload['dimension'], dimension)
                self.assertEqual(payload['execution_dimension'], execution_dimension)

    def cause(self, **fields):
        return {'title': 'String-ID TABLE contract mismatch', 'component': 'generate_table_result',
                'trigger': 'nonempty string ID', 'mechanism': 'string iterated as dictionary rows',
                'cause_refs': [self.ref('CONSUMER')], **fields}

    def attach_cause(self, entry, cause):
        entry[1]['failure_review'] = {'status': 'completed', 'relation': 'direct_counterexample',
                                      'root_cause': copy.deepcopy(cause),
                                      'root_cause_binding': {'atomic_item_id': entry[2]['id'],
                                          'failure_domain': _failure_domain(entry[0], entry[2]),
                                          'mechanism_link': 'This member fails through the cited mechanism.',
                                          'evidence_refs': copy.deepcopy(cause['cause_refs'])}}
        return entry[0]

    def test_grouping_merges_explicit_same_cause_without_changing_condition_results(self):
        rows = [self.attach_cause(self.entry(cid), self.cause()) for cid in ('TC04.C01', 'TC05.C01')]
        result = {'sop_condition_checks': rows}
        frozen = copy.deepcopy(rows)
        build_issue_groups(result)
        self.assertEqual(result['sop_issue_summary'], {'groups': 1, 'grouped_conditions': 2,
                         'ungrouped_conditions': 0, 'failed_conditions': 2})
        self.assertEqual(rows, frozen)

    def test_groups_are_isolated_by_task_version_and_mechanism(self):
        rows = []
        for mutation in ('original', 'task', 'version', 'mechanism'):
            entry = self.entry('TC04.C01')
            cause = self.cause()
            if mutation == 'task':
                entry[0]['task_id'] = 'T2'
            elif mutation == 'version':
                entry[0]['target_commit_ids'] = [OTHER]
            elif mutation == 'mechanism':
                cause['mechanism'] = 'missing original regression assertion'
            rows.append(self.attach_cause(entry, cause))
        result = {'sop_condition_checks': rows}
        build_issue_groups(result)
        self.assertEqual(len(result['sop_issue_groups']), 4)

    def test_unknown_non_failure_and_unreviewed_legacy_do_not_get_cause_groups(self):
        rows = []
        for status in (UNKNOWN, NA, PASS):
            entry = self.entry('TC04.C01', status=status)
            rows.append(self.attach_cause(entry, self.cause()))
        legacy = self.entry('TC05.C01')[0]
        legacy['contract']['version'] = '1.7'
        for item in legacy['contract']['items']:
            item.pop('failure_review', None)
        rows.append(legacy)
        result = {'sop_condition_checks': rows}
        frozen = copy.deepcopy(rows)
        build_issue_groups(result)
        self.assertEqual(result['sop_issue_groups'], [])
        self.assertEqual(result['sop_issue_summary']['ungrouped_conditions'], 1)
        self.assertEqual(rows, frozen)

    def test_review_cannot_inject_program_fields_or_an_unvalidated_cause(self):
        entry = self.entry('TC04.C01')
        raw_cause = self.cause(cause_refs=[{'evidence_id': 'NONEXISTENT', 'start_line': 1,
                                          'end_line': 1, 'quote': 'fabricated'}])
        answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause=raw_cause,
                             grouping_error='forged', status='failed', result=PASS,
                             resolution_review={'confirmed': True, 'status': 'completed'},
                             program_verified_dimension=True, program_gates=[{'id': 'forged'}])
        rows, failures = self.run_review([entry], [answer])
        review = entry[1]['failure_review']
        self.assertFalse(failures)
        self.assertEqual(review['status'], 'completed')
        self.assertEqual(rows[0]['result'], FAIL)
        for key in ('root_cause', 'grouping_error', 'result', 'resolution_review', 'program_verified_dimension', 'program_gates'):
            self.assertNotIn(key, review)
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_groups'], [])

    def test_only_validated_cause_mapping_supplies_group_data(self):
        entry = self.entry('TC04.C01')
        valid = self.cause()
        answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1',
                             root_cause=self.cause(mechanism='forged'), grouping_error='forged', status='failed')
        rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **valid}])
        self.assertFalse(failures)
        self.assertEqual(entry[1]['failure_review']['status'], 'completed')
        self.assertEqual(entry[1]['failure_review']['root_cause'], valid)
        self.assertNotIn('grouping_error', entry[1]['failure_review'])
        frozen = copy.deepcopy(rows)
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_groups'][0]['mechanism'], valid['mechanism'])
        self.assertEqual(rows, frozen)

    def test_invalid_cause_cannot_fall_back_to_injected_group_data(self):
        for mutation in ('unknown', 'task', 'version', 'untrusted_run'):
            with self.subTest(mutation=mutation):
                self.setUp()
                entry = self.entry('TC04.C01')
                proof = self.ref('OLD') if mutation == 'version' else self.ref('RUN') if mutation == 'untrusted_run' else self.ref('EXIT')
                if mutation == 'unknown':
                    proof['evidence_id'] = 'NONEXISTENT'
                elif mutation == 'task':
                    next(e for e in self.package['evidence'] if e['id'] == 'EXIT')['target_ids'] = ['T2']
                elif mutation == 'untrusted_run':
                    self.package['run_verification'][0]['verified'] = False
                raw_cause = {'id': 'C1', **self.cause(cause_refs=[proof])}
                answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1',
                                     root_cause=self.cause())
                rows, failures = self.run_review([entry], [answer], [raw_cause])
                self.assertFalse(failures)
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertNotIn('root_cause', entry[1]['failure_review'])
                self.assertIn('grouping_error', entry[1]['failure_review'])
                report = {'sop_condition_checks': rows}
                build_issue_groups(report)
                self.assertEqual(report['sop_issue_groups'], [])

    def test_malformed_root_cause_id_discards_only_its_own_review(self):
        first, second = self.entry('TC04.C01'), self.entry('TC05.C01')
        good = self.answer(first, obligation='CONSUMER', contrary='S')
        bad = self.answer(second, obligation='CONSUMER', contrary='S', root_cause_id=[])
        rows, failures = self.run_review([first, second], [good, bad])
        self.assertEqual([row['result'] for row in rows], [FAIL, UNKNOWN])
        self.assertEqual([f['atomic_item_id'] for f in failures], [second[2]['id']])
        self.assertEqual(second[1]['failure_review']['status'], 'failed')

    def test_grouping_requires_a_direct_completed_review(self):
        for relation in ('different_dimension', 'evidence_insufficient', None):
            with self.subTest(relation=relation):
                entry = self.entry('TC04.C01')
                row = self.attach_cause(entry, self.cause())
                entry[1]['failure_review']['relation'] = relation
                report = {'sop_condition_checks': [row]}
                frozen = copy.deepcopy(row)
                build_issue_groups(report)
                self.assertEqual(report['sop_issue_groups'], [])
                self.assertEqual(report['sop_issue_summary']['ungrouped_conditions'], 1)
                self.assertEqual(row, frozen)

    def test_resolution_scope_rejection_downgrades_and_clears_root_cause(self):
        entry = self.entry('TC07.C03')
        answer = self.answer(entry, obligation='CLAIM', contrary='LOG', root_cause_id='C1')
        result = {entry[2]['id']: {'confirmed': False, 'status': 'completed',
            'reason': 'Only a syntax edit and a future verification plan were stated.',
            'claims': [{'claim_type': 'plan'}], 'comparisons': []}}
        with patch('formsy_sop_verification.trace_audit.sop_resolution_review.review_resolution_claims', return_value=result) as review:
            rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **self.cause()}])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['gap_type'], 'evidence_missing')
        self.assertEqual(entry[1]['model_result'], FAIL)
        self.assertEqual(entry[1]['failure_review']['resolution_review'], result[entry[2]['id']])
        for key in ('root_cause_id', 'root_cause', 'grouping_error'):
            self.assertNotIn(key, entry[1]['failure_review'])
        review.assert_called_once()
        self.assertEqual(review.call_args.args[0][0][2]['id'], entry[2]['id'])
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_groups'], [])

    def test_actual_same_property_resolution_counterexample_remains_failed(self):
        entry = self.entry('TC07.C03')
        answer = self.answer(entry, obligation='CLAIM', contrary='LOG', root_cause_id='C1')
        result = {entry[2]['id']: {'confirmed': True, 'status': 'completed',
            'reason': 'Actual business resolution conflicts with the same-property target run.',
            'claims': [{'claim_type': 'actual_resolution'}], 'comparisons': [{'scope': 'same_property'}]}}
        with patch('formsy_sop_verification.trace_audit.sop_resolution_review.review_resolution_claims', return_value=result):
            rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **self.cause(
                cause_refs=[self.ref('CONSUMER'), self.ref('LOG')])}])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(entry[1]['failure_review']['resolution_review'], result[entry[2]['id']])
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(len(report['sop_issue_groups']), 1)

    def test_resolution_stage_failure_is_explicit_unknown_and_never_grouped(self):
        entry = self.entry('TC07.C03')
        answer = self.answer(entry, obligation='CLAIM', contrary='LOG', root_cause_id='C1')
        result = {entry[2]['id']: {'confirmed': False, 'status': 'failed',
            'reason': 'Resolution scope model-call budget exhausted.', 'claims': [], 'comparisons': []}}
        with patch('formsy_sop_verification.trace_audit.sop_resolution_review.review_resolution_claims', return_value=result):
            rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **self.cause()}])
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(rows[0]['analysis_status'], 'failed')
        self.assertEqual(entry[1]['gap_type'], 'analysis_failed')
        self.assertEqual(entry[1]['failure_review']['status'], 'failed')
        self.assertEqual([f['kind'] for f in failures], ['resolution_claim_review_failure'])
        self.assertNotIn('root_cause', entry[1]['failure_review'])

    def test_resolution_gate_does_not_recheck_non_direct_or_other_dimensions(self):
        first, second = self.entry('TC07.C03'), self.entry('TC04.C01')
        answers = [self.answer(first, relation='different_dimension'),
                   self.answer(second, obligation='CONSUMER', contrary='S')]
        with patch('formsy_sop_verification.trace_audit.sop_resolution_review.review_resolution_claims') as review:
            rows, failures = self.run_review([first, second], answers)
        review.assert_not_called()
        self.assertFalse(failures)
        self.assertEqual([row['result'] for row in rows], [UNKNOWN, FAIL])

    def test_real_resolution_stage_connection_preserves_same_property_and_source_boundaries(self):
        from ..sop_resolution_review import SOURCE_SYSTEM, COMPARE_SYSTEM
        for scope in ('same_property', 'different_property', 'budget'):
            with self.subTest(scope=scope):
                self.setUp()
                entry = self.entry('TC07.C03')
                answer = self.answer(entry, obligation='CLAIM', contrary='LOG')
                stages, failures = [], []

                def call(stage, system, payload, validator, **kwargs):
                    stages.append(stage)
                    self.assertEqual(kwargs['attempts'], 1)
                    if system == REVIEW_SYSTEM:
                        value = {'reviews': [answer], 'root_causes': []}
                    elif system == SOURCE_SYSTEM:
                        self.assertEqual([e['id'] for e in payload['evidence']], ['CLAIM'])
                        self.assertNotIn('counterexample_refs', payload['candidates'][0])
                        self.assertNotIn('fixed_target_commit_ids', payload)
                        value = {'resolutions': [{'id': entry[2]['id'], 'speech_act': 'business_resolved',
                            'reason': 'The complete original sentence claims business completion.',
                            'claims': [{'statement_id': payload['statement_choices'][0]['statement_id'],
                                        'claim_type': 'actual_state', 'claim_target': {
                                            'object': 'String-ID TABLE output', 'property': 'fixed', 'scope': 'effective_state'}}]}]}
                    else:
                        self.assertEqual(system, COMPARE_SYSTEM)
                        self.assertEqual([e['id'] for e in payload['evidence']], ['LOG'])
                        if scope == 'budget':
                            return None, 'Shared call budget exhausted.', False
                        value = {'scope_reviews': [{'claim_id': payload['frozen_claims'][0]['id'],
                            'scope_consistency': 'same_scope' if scope == 'same_property' else 'different_proposition',
                            'relation': 'exceeds_source', 'comparison_type': 'actual_state',
                            'comparison_scope': scope, 'observation_commit_ids': [SHA],
                            'source_refs': [self.ref('LOG')],
                            'reason': 'Same business result is contradicted.' if scope == 'same_property' else
                                      'The observation concerns a different property.'}]}
                    return validator(value), None, False

                request = {'evidence': copy.deepcopy(self.package['evidence'])}
                review_failures([entry[0]], self.task, self.package, request, call,
                                'sop-failure-review-integration', failures)
                self.assertEqual(len(stages), 3)
                self.assertEqual(entry[0]['result'], FAIL if scope == 'same_property' else UNKNOWN)
                self.assertEqual(entry[1]['failure_review']['resolution_review']['confirmed'], scope == 'same_property')
                self.assertEqual(bool(failures), scope == 'budget')
                if scope == 'budget':
                    self.assertEqual(entry[1]['gap_type'], 'analysis_failed')

    def test_unknown_contract_enters_review_only_with_same_version_production_context(self):
        entry = self.entry('TC04.C01', status=UNKNOWN)
        args = dict(source_context_ids=['S', 'CONSUMER'], package=self.package)
        self.assertEqual(candidates([entry[0]], self.task, **args)[0][2]['id'], entry[2]['id'])
        self.assertFalse(candidates([entry[0]], self.task))
        for cid in ('TC04.C02', 'TC04.C03', 'TC05.C02', 'TC05.C03', 'TC05.C04'):
            with self.subTest(condition=cid):
                self.assertFalse(candidates([self.entry(cid, status=UNKNOWN)[0]], self.task, **args))
        for mutation in ('version', 'test', 'other_task'):
            changed = copy.deepcopy(self.package)
            source = next(e for e in changed['evidence'] if e['id'] == 'CONSUMER')
            if mutation == 'version': source['version_id'] = OTHER
            elif mutation == 'test': source['path'] = 'tests/consumer.py'
            else: source['target_ids'] = ['OTHER_TASK']
            with self.subTest(mutation=mutation):
                self.assertFalse(candidates([entry[0]], self.task, source_context_ids=['S', 'CONSUMER'], package=changed))

    def test_unknown_contract_requires_direct_counterexample_before_becoming_failed(self):
        for relation, expected in [('direct_counterexample', FAIL), ('different_dimension', UNKNOWN),
                                   ('evidence_insufficient', UNKNOWN)]:
            entry = self.entry('TC04.C01', status=UNKNOWN)
            answer = self.answer(entry, relation=relation, obligation='CONSUMER', contrary='S')
            def call(stage, system, payload, validator, **kwargs):
                return validator({'reviews': [answer]}), None, False
            failures = []
            review_failures([entry[0]], self.task, self.package,
                {'evidence': self.package['evidence'], 'affected_source_context_ids': ['S', 'CONSUMER']},
                call, 'static-contract', failures)
            with self.subTest(relation=relation):
                self.assertFalse(failures)
                self.assertEqual(entry[0]['result'], expected)

    def test_pass_contract_enters_only_native_same_target_production_scope_review(self):
        for cid in ('TC04.C01', 'TC05.C01'):
            with self.subTest(condition=cid):
                entry = self.entry(cid, status=PASS)
                args = dict(source_context_ids=['S', 'CONSUMER'], package=self.package)
                self.assertEqual(candidates([entry[0]], self.task, **args), [entry])
                self.assertFalse(candidates([entry[0]], self.task))
        for cid in ('TC04.C02', 'TC05.C02', 'FIX03.C01', 'SEC06.C02'):
            self.assertFalse(candidates([self.entry(cid, status=PASS)[0]], self.task,
                source_context_ids=['S', 'CONSUMER'], package=self.package))
        for defect in ('uploaded', 'legacy', 'deferred_row', 'deferred_item', 'other_task', 'other_target'):
            entry = self.entry('TC04.C01', status=PASS)
            if defect == 'uploaded': entry[0]['contract']['origin'] = 'uploaded_explicit'
            elif defect == 'legacy': entry[0]['contract']['version'] = '1.8'
            elif defect == 'deferred_row': entry[0]['review_scope'] = {'status': 'deferred'}
            elif defect == 'deferred_item': entry[1]['assessment_scope'] = 'deferred'
            elif defect == 'other_task': entry[0]['task_id'] = 'T2'
            else: entry[0]['target_commit_ids'] = [OTHER]
            with self.subTest(defect=defect):
                self.assertFalse(candidates([entry[0]], self.task,
                    source_context_ids=['S', 'CONSUMER'], package=self.package))

    def test_pass_contract_cannot_use_test_document_old_or_other_task_context(self):
        for defect in ('test', 'document', 'version', 'other_task', 'same_path'):
            package = copy.deepcopy(self.package)
            source = next(e for e in package['evidence'] if e['id'] == 'CONSUMER')
            if defect == 'test': source['path'] = 'tests/consumer.py'
            elif defect == 'document': source['path'] = 'docs/contract.md'
            elif defect == 'version': source['version_id'] = OTHER
            elif defect == 'other_task': source['target_ids'] = ['T2']
            else: source['path'] = 's.py'
            with self.subTest(defect=defect):
                self.assertFalse(candidates([self.entry('TC04.C01', status=PASS)[0]], self.task,
                    source_context_ids=['S', 'CONSUMER'], package=package))

    def test_false_pass_with_bilateral_contract_conflict_becomes_failed(self):
        for cid in ('TC04.C01', 'TC05.C01'):
            entry = self.entry(cid, status=PASS)
            answer = self.answer(entry, obligation='CONSUMER', contrary='S',
                violated_obligation='Returned create output must support the consumer row.get calls.',
                expected='A sequence of mappings with get.', observed='The producer returns a string ID.')
            rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
            with self.subTest(condition=cid):
                self.assertFalse(failures)
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertEqual(entry[1]['model_result'], PASS)
                self.assertTrue(self.calls[-1][1]['candidates'][0]['source_contract_mode'])
                self.assertEqual(self.calls[-1][1]['production_source_context_ids'], ['CONSUMER', 'S'])
                self.assertEqual(entry[1]['failure_review']['relation'], 'direct_counterexample')

    def test_explicit_positive_contract_proof_preserves_existing_pass_without_grouping(self):
        next(e for e in self.package['evidence'] if e['id'] == 'S')['content'] = 'return [{"id": "record-1"}]'
        entry = self.entry('TC04.C01', status=PASS)
        original_reason = entry[1]['reason']
        answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S',
            violated_obligation='Create output must be iterable mapping rows.', expected='Rows implement get.',
            observed='The producer returns a list of mappings.',
            reason='The same returned rows meet the consumer get requirement.',
            root_cause={'title': 'Untrusted injected cause'})
        rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], PASS)
        self.assertEqual(entry[1]['model_reason'], original_reason)
        self.assertEqual(entry[1]['failure_review']['relation'], 'compatible_contract')
        self.assertNotIn('root_cause', entry[1]['failure_review'])
        proof = next(g for g in entry[1]['program_gates'] if g['id'] == 'source_contract_compatibility')
        self.assertTrue(proof['met'])
        self.assertIn(self.ref('CONSUMER'), entry[1]['evidence_refs'])
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_summary']['groups'], 0)

    def test_unknown_parent_cannot_hide_a_passed_contract_atom_conflict(self):
        for cid in ('TC04.C01', 'TC05.C01'):
            with self.subTest(condition=cid):
                entry = self.entry(cid, status=PASS)
                entry[0].update(result=UNKNOWN, gap_type='evidence_missing')
                self.assertEqual(candidates([entry[0]], self.task,
                    source_context_ids=['S', 'CONSUMER'], package=self.package), [entry])
                answer = self.answer(entry, obligation='CONSUMER', contrary='S',
                    expected='Consumer requires mapping rows supporting get.',
                    observed='Producer returns a string ID.')
                rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
                apply_atomic_gates(rows[0], self.task, self.package)
                self.assertFalse(failures)
                self.assertEqual(entry[1]['result'], FAIL)
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertEqual(entry[1]['model_result'], PASS)

    def test_compatible_type_proof_does_not_certify_an_unknown_compound_contract(self):
        next(e for e in self.package['evidence'] if e['id'] == 'S')['content'] = 'return [{"id": "record-1"}]'
        for cid in ('TC04.C01', 'TC05.C01'):
            with self.subTest(condition=cid):
                entry = self.entry(cid, status=PASS)
                entry[0].update(result=UNKNOWN, gap_type='evidence_missing')
                answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S',
                    expected='Rows implement get.', observed='Producer returns mapping rows.')
                rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
                apply_atomic_gates(rows[0], self.task, self.package)
                self.assertFalse(failures)
                self.assertEqual(entry[1]['failure_review']['relation'], 'compatible_contract')
                self.assertEqual(entry[1]['result'], UNKNOWN)
                self.assertEqual(rows[0]['result'], UNKNOWN)
                self.assertEqual(next(g for g in rows[0]['program_gates']
                    if g['id'] == 'all_required_atomic_checks')['result'], UNKNOWN)

    def test_failed_native_type_candidate_gets_the_same_narrow_source_comparison(self):
        entry = self.entry('TC04.C01')
        answer = self.answer(entry, obligation='CONSUMER', contrary='S')
        rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        candidate = self.calls[0][1]['candidates'][0]
        self.assertTrue(candidate['source_contract_mode'])
        self.assertEqual(candidate['source_contract_scope']['attribute'], 'producer_return_consumer_use')
        self.assertEqual(candidate['rule_context'], entry[0]['contract']['rule_context'])
        self.assertEqual(candidate['text'], entry[2]['text'])
        self.assertIn('remaining_obligations', candidate['source_contract_scope'])
        self.assertEqual(entry[1]['failure_review']['source_contract_analysis'], answer['source_contract_analysis'])

    def test_source_comparison_requires_a_real_structured_gap_instead_of_missing_document(self):
        for defect in ('missing_analysis', 'document_gap', 'no_gap', 'no_gap_explanation', 'wrong_attribute'):
            entry = self.entry('TC05.C01', status=UNKNOWN)
            answer = self.answer(entry, relation='evidence_insufficient', obligation='CONSUMER', contrary='S')
            if defect == 'missing_analysis': answer.pop('source_contract_analysis')
            elif defect == 'document_gap': answer['source_contract_analysis']['gap'] = 'independent_contract_document_missing'
            elif defect == 'no_gap': answer['source_contract_analysis']['gap'] = 'none'
            elif defect == 'no_gap_explanation': answer['source_contract_analysis']['gap_reason'] = ''
            else: answer['source_contract_analysis']['attribute'] = 'entire_data_lifecycle'
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                validate_review(answer, entry, self.task, self.package, source_context_ids=['S', 'CONSUMER'])

    def test_two_visible_files_do_not_prove_the_return_reaches_the_consumer(self):
        entry = self.entry('TC05.C01', status=UNKNOWN)
        answer = self.answer(entry, relation='evidence_insufficient', obligation='CONSUMER', contrary='S',
            reason='Both excerpts exist, but no call site links this returned value to this consumption.')
        rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['failure_review']['source_contract_analysis']['gap'], 'data_flow_unproven')

    def test_definite_source_comparison_cannot_keep_unproven_shape_or_link(self):
        for relation in ('direct_counterexample', 'compatible_contract'):
            for defect in ('gap', 'producer', 'consumer', 'data_flow'):
                entry = self.entry('TC04.C01', status=PASS)
                answer = self.answer(entry, relation=relation, obligation='CONSUMER', contrary='S')
                answer['source_contract_analysis'][defect] = 'return_shape_unproven' if defect == 'gap' else ''
                with self.subTest(relation=relation, defect=defect), self.assertRaises(ValueError):
                    validate_review(answer, entry, self.task, self.package, source_context_ids=['S', 'CONSUMER'])

    def test_local_source_comparison_does_not_become_a_non_native_contract_exception(self):
        for defect in ('legacy', 'uploaded', 'no_context'):
            entry = self.entry('TC04.C01')
            if defect == 'legacy': entry[0]['contract']['version'] = '1.8'
            elif defect == 'uploaded': entry[0]['contract']['origin'] = 'uploaded_explicit'
            answer = self.answer(entry, obligation='CONSUMER', contrary='S')
            validated = validate_review(answer, entry, self.task, self.package,
                source_context_ids=[] if defect == 'no_context' else ['S', 'CONSUMER'])
            with self.subTest(defect=defect):
                self.assertNotIn('source_contract_analysis', validated)

    def test_no_counterexample_or_budget_cannot_certify_an_existing_pass(self):
        for relation in ('different_dimension', 'evidence_insufficient', 'budget'):
            entry = self.entry('TC04.C01', status=PASS)
            rows, failures = self.run_review([entry],
                [self.answer(entry, relation=relation, obligation='CONSUMER', contrary='S')],
                error='Shared call budget exhausted.' if relation == 'budget' else None,
                source_context_ids=['S', 'CONSUMER'])
            with self.subTest(relation=relation):
                self.assertEqual(rows[0]['result'], UNKNOWN)
                self.assertEqual(bool(failures), relation == 'budget')
                self.assertEqual(entry[1]['gap_type'], 'analysis_failed' if relation == 'budget' else 'evidence_missing')

    def test_compatible_contract_never_promotes_original_unknown_to_pass(self):
        next(e for e in self.package['evidence'] if e['id'] == 'S')['content'] = 'return [{"id": "record-1"}]'
        entry = self.entry('TC05.C01', status=UNKNOWN)
        answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S',
            expected='Rows implement get.', observed='Producer returns mapping rows.')
        rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['result'], UNKNOWN)
        self.assertEqual(entry[1]['failure_review']['relation'], 'compatible_contract')
        self.assertIn('原未知', entry[1]['reason'])

    def test_compatible_relation_cannot_bypass_scope_proof_or_erase_existing_failure(self):
        for defect in ('no_context', 'failed', 'other_clause', 'user_wish', 'runtime', 'same_source',
                       'missing_expected', 'missing_observed', 'cause', 'other_task', 'old_version',
                       'unselected_source'):
            entry = self.entry('TC04.C01', status=FAIL if defect == 'failed' else PASS)
            if defect == 'other_clause': entry = self.entry('TC04.C02', status=PASS)
            package = copy.deepcopy(self.package)
            answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S')
            context = ['S', 'CONSUMER']
            if defect == 'no_context': context = []
            elif defect == 'user_wish': answer['obligation_refs'] = [self.ref('U')]
            elif defect == 'runtime': answer['counterexample_refs'] = [self.ref('LOG')]
            elif defect == 'same_source': answer['counterexample_refs'] = [self.ref('CONSUMER')]
            elif defect == 'missing_expected': answer['expected'] = ''
            elif defect == 'missing_observed': answer['observed'] = ''
            elif defect == 'cause': answer['root_cause_id'] = 'C1'
            elif defect == 'other_task': next(e for e in package['evidence'] if e['id'] == 'S')['target_ids'] = ['T2']
            elif defect == 'old_version': answer['counterexample_refs'] = [self.ref('OLD')]
            elif defect == 'unselected_source': answer['counterexample_refs'] = [self.ref('EXIT')]
            with self.subTest(defect=defect), self.assertRaises(ValueError):
                validate_review(answer, entry, self.task, package, source_context_ids=context)

    def test_source_contract_mode_does_not_take_business_failure_as_bilateral_proof(self):
        for contrary in ('LOG', 'RUN', 'EXTERNAL'):
            entry = self.entry('TC05.C01', status=UNKNOWN)
            answer = self.answer(entry, obligation='CONSUMER', contrary=contrary)
            with self.subTest(contrary=contrary), self.assertRaises(ValueError):
                validate_review(answer, entry, self.task, self.package, source_context_ids=['S', 'CONSUMER'])

    def test_compatible_contract_keeps_independent_parent_gate(self):
        next(e for e in self.package['evidence'] if e['id'] == 'S')['content'] = 'return [{"id": "record-1"}]'
        entry = self.entry('TC04.C01', status=PASS)
        entry[0]['program_gates'] = [{'id': 'condition_specific_execution_mapping', 'met': False,
                                     'reason': 'Independent required execution identity is missing.'},
                                    {'id': 'all_required_atomic_checks', 'result': PASS, 'met': True}]
        answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S')
        rows, failures = self.run_review([entry], [answer], source_context_ids=['S', 'CONSUMER'])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], UNKNOWN)
        self.assertEqual(entry[1]['gap_type'], 'automatic_check_unsupported')
        self.assertEqual(next(g for g in rows[0]['program_gates']
                              if g['id'] == 'all_required_atomic_checks')['result'], UNKNOWN)

    def test_compatible_proof_cannot_mix_two_individually_current_target_versions(self):
        self.task['target_commit_ids'].append(OTHER)
        self.package['evidence'].append({'id': 'OTHER_CONSUMER', 'kind': 'source',
            'path': 'other_consumer.py', 'version_id': OTHER, 'target_ids': ['T1'],
            'content': 'for row in output: row.get("id")'})
        entry = self.entry('TC04.C01', status=PASS)
        entry[0]['target_commit_ids'] = [SHA, OTHER]
        answer = self.answer(entry, relation='compatible_contract', obligation='CONSUMER', contrary='S')
        answer['counterexample_refs'] = [self.ref('OLD')]
        with self.assertRaisesRegex(ValueError, '同版'):
            validate_review(answer, entry, self.task, self.package,
                            source_context_ids=['S', 'CONSUMER', 'OLD', 'OTHER_CONSUMER'])

    def test_compact_quote_ids_resolve_without_editable_coordinates(self):
        entry = self.entry('TC04.C01')
        answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id=None)
        choices = {e['id']: e['numbered_lines'][0]['quote_id'] for e in
                   attach_quote_ids({'evidence': self.package['evidence']}, self.package)['evidence']}
        answer.pop('obligation_refs')
        answer.pop('counterexample_refs')
        answer.update(obligation_quote_ids=[choices['CONSUMER']], counterexample_quote_ids=[choices['S']])
        rows, failures = self.run_review([entry], [answer])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertEqual(entry[1]['failure_review']['obligation_refs'], [self.ref('CONSUMER')])
        self.assertEqual(entry[1]['failure_review']['root_cause_id'], '')

    def test_compact_and_manual_references_cannot_conflict_or_be_silently_stripped(self):
        entry = self.entry('TC04.C01')
        choices = attach_quote_ids({'evidence': self.package['evidence']}, self.package)['evidence']
        qid = next(e for e in choices if e['id'] == 'S')['numbered_lines'][0]['quote_id']
        for ids in ([qid], ['Q-unknown'], [qid, qid], [{'quote_id': qid}]):
            answer = self.answer(entry, obligation='CONSUMER', contrary='S')
            answer['counterexample_quote_ids'] = ids
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                validate_review(answer, entry, self.task, self.package)

    def test_root_cause_reuse_across_batches_keeps_one_validated_mechanism(self):
        first, second = self.entry('TC04.C01'), self.entry('TC05.C01')
        responses = [{'reviews': [self.answer(first, obligation='CONSUMER', contrary='S', root_cause_id='C1')],
                      'root_causes': [{'id': 'C1', **self.cause()}]},
                     {'reviews': [self.answer(second, obligation='CONSUMER', contrary='S', root_cause_id='C1')]}]
        with patch('formsy_sop_verification.trace_audit.sop_failures.MAX_ITEMS', 1):
            rows, failures = self.run_review([first, second], responses=responses)
        self.assertFalse(failures)
        self.assertEqual(self.calls[1][1]['validated_root_causes'], [{'id': 'C1', **self.cause()}])
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_summary']['groups'], 1)
        self.assertEqual(report['sop_issue_summary']['grouped_conditions'], 2)

    def test_reused_cause_id_cannot_overwrite_a_previously_validated_mechanism(self):
        first, second = self.entry('TC04.C01'), self.entry('TC05.C01')
        one = {'reviews': [self.answer(first, obligation='CONSUMER', contrary='S', root_cause_id='C1')],
               'root_causes': [{'id': 'C1', **self.cause()}]}
        two = {'reviews': [self.answer(second, obligation='CONSUMER', contrary='S', root_cause_id='C1')],
               'root_causes': [{'id': 'C1', **self.cause(mechanism='different mechanism')}]}
        with patch('formsy_sop_verification.trace_audit.sop_failures.MAX_ITEMS', 1):
            rows, failures = self.run_review([first, second], responses=[one, two, two])
        self.assertFalse(failures)
        self.assertEqual(rows[1]['result'], FAIL)
        self.assertNotIn('root_cause', second[1]['failure_review'])
        self.assertIn('已绑定', second[1]['failure_review']['grouping_error'])

    def test_unverified_run_cannot_certify_a_root_cause(self):
        entry = self.entry('TC04.C01')
        self.package['run_verification'][0]['verified'] = False
        answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1')
        raw_cause = {'id': 'C1', **self.cause(cause_refs=[self.ref('RUN')])}
        rows, failures = self.run_review([entry], [answer], [raw_cause])
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertFalse(failures)
        self.assertNotIn('root_cause', entry[1]['failure_review'])
        self.assertIn('grouping_error', entry[1]['failure_review'])

    def test_native_contract_citations_recall_missing_side_and_preserve_provenance(self):
        entry = self.entry('TC05.C01', status=UNKNOWN)
        entry[0]['evidence_refs'] = [self.ref('S'), self.ref('CONSUMER')]
        context, origins = recalled_source_context([entry[0]], self.task, self.package, ['CONSUMER'])
        self.assertEqual(set(context), {'S', 'CONSUMER'})
        self.assertEqual(origins['S'][0]['condition_id'], 'TC05.C01')
        self.assertEqual(origins['CONSUMER'][0]['origin'], 'acceptance_context')
        answer = self.answer(entry, obligation='CONSUMER', contrary='S')
        rows, failures = self.run_review([entry], [answer], source_context_ids=['CONSUMER'])
        self.assertFalse(failures)
        self.assertTrue(self.calls[0][1]['candidates'][0]['source_contract_mode'])
        self.assertEqual(self.calls[0][1]['production_source_context_ids'], ['CONSUMER', 'S'])
        self.assertEqual(rows[0]['result'], FAIL)

    def test_recall_does_not_import_unvalidated_or_unrelated_native_looking_citations(self):
        for defect in ('uploaded', 'legacy', 'deferred', 'other_task', 'old_version', 'test', 'invalid_quote'):
            with self.subTest(defect=defect):
                entry = self.entry('TC05.C01', status=UNKNOWN)
                entry[0]['evidence_refs'] = [self.ref('S'), self.ref('CONSUMER')]
                package = copy.deepcopy(self.package)
                if defect == 'uploaded': entry[0]['contract']['origin'] = 'uploaded_explicit'
                elif defect == 'legacy': entry[0]['contract']['version'] = '1.8'
                elif defect == 'deferred': entry[0]['review_scope'] = {'status': 'deferred'}
                elif defect == 'other_task': entry[0]['task_id'] = 'T2'
                elif defect == 'invalid_quote': entry[0]['evidence_refs'][1]['quote'] = 'not in source'
                else:
                    source = next(e for e in package['evidence'] if e['id'] == 'CONSUMER')
                    source['version_id' if defect == 'old_version' else 'path'] = OTHER if defect == 'old_version' else 'tests/consumer.py'
                self.assertFalse(candidates([entry[0]], self.task, source_context_ids=['S'], package=package))

    def test_recall_from_another_native_contract_still_requires_actual_data_flow(self):
        recalled = self.entry('TC04.C01', status=UNKNOWN)
        recalled[0]['evidence_refs'] = [self.ref('S'), self.ref('CONSUMER')]
        entry = self.entry('TC05.C01', status=UNKNOWN)
        answer = self.answer(entry, relation='evidence_insufficient', obligation='CONSUMER', contrary='S')
        answers = [self.answer(recalled, relation='evidence_insufficient', obligation='CONSUMER', contrary='S'), answer]
        rows, failures = self.run_review([recalled, entry], answers, source_context_ids=['CONSUMER'])
        self.assertFalse(failures)
        self.assertTrue(all(row['result'] == UNKNOWN for row in rows))
        self.assertEqual(entry[1]['failure_review']['source_contract_analysis']['gap'], 'data_flow_unproven')

    def test_shared_implementation_refs_cannot_explain_original_test_omission(self):
        entry = self.entry('TC13.C01')
        source = next(e for e in self.package['evidence'] if e['id'] == 'EXIT')
        source.update(path='tests/test_output.py', content='assert output([{"id": 1}])')
        answer = self.answer(entry, contrary='EXIT', root_cause_id='C1')
        rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **self.cause()}])
        self.assertFalse(failures)
        self.assertEqual(rows[0]['result'], FAIL)
        self.assertNotIn('root_cause', entry[1]['failure_review'])
        self.assertIn('grouping_error', entry[1]['failure_review'])

    def test_grouping_requires_member_binding_and_isolates_failure_domains(self):
        behavior = self.attach_cause(self.entry('TC04.C01'), self.cause())
        coverage = self.attach_cause(self.entry('TC13.C01'), self.cause())
        missing = self.attach_cause(self.entry('TC05.C01'), self.cause())
        missing['atomic_checks'][0]['failure_review'].pop('root_cause_binding')
        report = {'sop_condition_checks': [behavior, coverage, missing]}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_summary']['groups'], 2)
        self.assertEqual(report['sop_issue_summary']['ungrouped_conditions'], 1)

    def test_test_omission_can_group_with_its_own_delivered_test_mechanism(self):
        entry = self.entry('TC13.C01')
        source = next(e for e in self.package['evidence'] if e['id'] == 'EXIT')
        source.update(path='tests/test_output.py', content='assert output([{"id": 1}])')
        answer = self.answer(entry, contrary='EXIT', root_cause_id='C1')
        cause = self.cause(component='tests/test_output.py', mechanism='The original assertions omit the string-ID input.',
                           cause_refs=[self.ref('EXIT')])
        rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **cause}])
        self.assertFalse(failures)
        self.assertIn('root_cause', entry[1]['failure_review'])
        report = {'sop_condition_checks': rows}
        build_issue_groups(report)
        self.assertEqual(report['sop_issue_groups'][0]['failure_domain'], 'test_delivery')

    def test_member_cannot_borrow_an_unrelated_function_or_expression_in_same_file(self):
        for content, member_quote, cause_quote, member_line, cause_line in [
            ('def first(): pass\ndef unrelated(): pass', 'def first(): pass', 'def unrelated(): pass', 1, 2),
            ('first(); unrelated()', 'first()', 'unrelated()', 1, 1)]:
            with self.subTest(content=content):
                entry = self.entry('TC04.C01')
                source = next(e for e in self.package['evidence'] if e['id'] == 'CONSUMER')
                source['content'] = content
                answer = self.answer(entry, obligation='CONSUMER', contrary='S', root_cause_id='C1')
                member = {'evidence_id': 'CONSUMER', 'start_line': member_line, 'end_line': member_line,
                          'quote': member_quote}
                answer['obligation_refs'] = [member]
                answer['root_cause_binding']['evidence_refs'] = [member]
                cause = self.cause(cause_refs=[{'evidence_id': 'CONSUMER', 'start_line': cause_line,
                                              'end_line': cause_line, 'quote': cause_quote}])
                rows, failures = self.run_review([entry], [answer], [{'id': 'C1', **cause}])
                self.assertFalse(failures)
                self.assertEqual(rows[0]['result'], FAIL)
                self.assertNotIn('root_cause', entry[1]['failure_review'])


if __name__ == '__main__':
    unittest.main()

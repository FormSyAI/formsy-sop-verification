"""Rejected citation facts must be rejudged, not hidden by a valid replacement quote."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ..reference_repair import (SELECTOR_ONLY_RETRY_PROMPT, attach_quote_ids, reference_diagnostics, repair_references,
                              validate_quote_id_retry, validate_retry_reason_consistency, model_reference_feedback)
from ..sop_audit import audit_sop
from .test_sop_audit import Client, default_response, fixtures, ref


class RetryReasonConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, self.catalog = fixtures()
        self.package['evidence'].append({'id': 'P', 'kind': 'source', 'path': 'example.py',
            'version_id': self.result['tasks'][0]['target_commit_ids'][0],
            'content': "marker = 'DEMO_TOKEN'"})
        self.old = {'reason': '目标代码使用 DEMO_TOKEN 占位符。',
                    'evidence_refs': [ref('S', "marker = 'DEMO_TOKEN'")]}
        self.diagnostics = reference_diagnostics(self.old, self.package)

    def checked(self, row, visible=None):
        validate_quote_id_retry(row, self.package, available_evidence_ids=visible)
        expanded, _ = repair_references(row, self.package, available_evidence_ids=visible)
        validate_retry_reason_consistency(expanded, self.diagnostics, self.package,
                                          available_evidence_ids=visible)
        return expanded

    def test_diagnostic_freezes_only_old_reason_literals_absent_from_failed_source(self):
        self.assertEqual(self.diagnostics[0]['rejected_reason_anchors'], ['DEMO_TOKEN'])
        local = copy.deepcopy(self.old)
        local['reason'] = '原引用不合法，但没有声称该字面事实。'
        self.assertEqual(reference_diagnostics(local, self.package)[0]['rejected_reason_anchors'], [])

    def test_model_feedback_projection_removes_rejected_text_without_changing_diagnostics(self):
        original = [{'condition_id': 'C1', 'references': copy.deepcopy(self.diagnostics)}]
        before = copy.deepcopy(original)
        projected = model_reference_feedback(original)
        self.assertNotIn('rejected_quote', str(projected))
        self.assertEqual(projected[0]['references'][0]['rejected_reason_anchors'], ['DEMO_TOKEN'])
        self.assertEqual(projected[0]['references'][0]['choices'], self.diagnostics[0]['choices'])
        self.assertEqual(original, before)

    def test_valid_replacement_quote_cannot_preserve_old_fact_even_if_result_unknown(self):
        row = {'result': '未核查', 'reason': '范围未核查；目标代码仍使用 DEMO_TOKEN。',
               'evidence_refs': [ref('S', 'return 25 if value is None else value')]}
        before = copy.deepcopy(row)
        with self.assertRaisesRegex(ValueError, '旧字面事实.*DEMO_TOKEN'):
            self.checked(row)
        self.assertEqual(row, before)

    def test_withdrawal_and_actual_selected_literal_are_both_valid_rejudgments(self):
        for row in ({'reason': '原事实没有可见依据，真实范围仍缺证据。', 'evidence_refs': []},
                    {'reason': '新的 example.py 引用直接显示 DEMO_TOKEN 占位符。',
                     'evidence_refs': [ref('P', "marker = 'DEMO_TOKEN'")]}):
            with self.subTest(row=row):
                self.assertEqual(self.checked(row), row)

    def test_explicit_q_selection_must_support_literal_and_hidden_source_cannot_donate_it(self):
        def selector(eid):
            item = next(e for e in self.package['evidence'] if e['id'] == eid)
            return {'quote_id': attach_quote_ids({'evidence': [item]}, self.package)
                    ['evidence'][0]['numbered_lines'][0]['quote_id']}
        self.checked({'reason': '新例子明确使用 DEMO_TOKEN。', 'evidence_refs': [selector('P')]})
        with self.assertRaisesRegex(ValueError, '旧字面事实'):
            self.checked({'reason': '仍使用 DEMO_TOKEN。', 'evidence_refs': [selector('S')]})
        with self.assertRaises(ValueError):
            self.checked({'reason': '仍使用 DEMO_TOKEN。', 'evidence_refs': [selector('P')]}, {'S'})

    def test_atomic_reason_cannot_borrow_sibling_quote_or_uncited_full_content(self):
        row = {'reason': '总体范围仍缺证据。', 'atomic_checks': [
            {'id': 'A', 'reason': '该原子项使用 DEMO_TOKEN。',
             'evidence_refs': [ref('S', 'return 25 if value is None else value')]},
            {'id': 'B', 'reason': '另一个例子存在。', 'evidence_refs': [ref('P', "marker = 'DEMO_TOKEN'")]}]}
        with self.assertRaisesRegex(ValueError, r'atomic_checks\[0\].reason'):
            self.checked(row)
        row['atomic_checks'][0]['evidence_refs'] = []
        with self.assertRaisesRegex(ValueError, '旧字面事实'):
            self.checked(row)

    def test_ordinary_source_metadata_is_not_selected_support(self):
        with self.assertRaisesRegex(ValueError, '旧字面事实'):
            self.checked({'reason': '目标使用 DEMO_TOKEN。', 'source_metadata': {'evidence_id': 'P'},
                          'evidence_refs': []})

    def test_coordinate_only_error_or_literal_existing_in_original_source_is_not_banned(self):
        row = {'reason': '代码中的 value 为局部值。', 'evidence_refs': [ref('S', 'return value')]}
        diagnostics = reference_diagnostics(row, self.package)
        self.assertEqual(diagnostics[0]['rejected_reason_anchors'], [])
        repaired = {'reason': row['reason'], 'evidence_refs': [ref('S', 'return 25 if value is None else value')]}
        validate_retry_reason_consistency(repaired, diagnostics, self.package)

    def test_generic_identifiers_and_numbers_are_checked_without_sample_specific_rules(self):
        old = {'reason': 'SAMPLE_LIMIT 使用 73。', 'evidence_refs': [ref('S', 'SAMPLE_LIMIT = 73')]}
        diagnostics = reference_diagnostics(old, self.package)
        self.assertEqual(set(diagnostics[0]['rejected_reason_anchors']), {'SAMPLE_LIMIT', '73'})
        with self.assertRaisesRegex(ValueError, '旧字面事实'):
            validate_retry_reason_consistency({'reason': '代码使用 SAMPLE_LIMIT，值为73。',
                'evidence_refs': [ref('S', 'return 25 if value is None else value')]}, diagnostics, self.package)
        validate_retry_reason_consistency({'reason': '版本173仅是另一个编号。', 'evidence_refs': []},
                                          diagnostics, self.package)


class SopReasonRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, self.catalog = fixtures()
        self.catalog['rules'] = self.catalog['rules'][:1]
        self.result['checks'] = self.result['checks'][:1]
        first = self.catalog['rules'][0]['conditions'][0]
        self.catalog['rules'][0]['conditions'] = [first, {**first, 'id': 'FIX03.C02'}]

    def retry(self, retained, *, repeat_quote=False):
        calls = []
        def respond(payload):
            value = default_response(payload)
            if 'conditions' not in payload:
                return value
            calls.append(copy.deepcopy(payload))
            row = next(r for r in value['conditions'] if r['condition_id'] == 'FIX03.C02')
            if len(calls) == 1:
                row['reason'] = '当前代码使用 DEMO_TOKEN 占位符，范围仍缺扫描。'
                row['evidence_refs'] = [ref('S', "marker = 'DEMO_TOKEN'")]
            else:
                self.assertEqual([c['id'] for c in payload['conditions']], ['FIX03.C02'])
                self.assertIn('DEMO_TOKEN', str(payload['reference_feedback']))
                self.assertNotIn('rejected_quote', str(payload['reference_feedback']))
                self.assertEqual(payload['citation_retry']['mode'], 'visible_quote_selectors_only')
                row.update(result='未核查', gap_type='evidence_missing', acceptance_ids=[],
                    reason='仍显示 DEMO_TOKEN，范围未知。' if retained else '旧事实缺少可见来源，范围仍缺证据。')
                source = next(item for item in payload['evidence'] if item['id'] == 'S')
                row['evidence_refs'] = [{'quote_id': source['numbered_lines'][0]['quote_id']}]
                if repeat_quote:
                    row['evidence_refs'] = [ref('S', "marker = 'DEMO_TOKEN'")]
            return value
        client = Client(respond)
        with tempfile.TemporaryDirectory() as directory, patch.object(
                client, 'complete', wraps=client.complete) as complete:
            report = audit_sop(copy.deepcopy(self.result), self.package, self.catalog,
                               client, Path(directory))
            diagnostics = json.loads(next(Path(directory).glob('*.rows-validation.json')).read_text())
            self.assertIn("marker = 'DEMO_TOKEN'", str(diagnostics))
        systems = [call.args[0] for call in complete.call_args_list if 'conditions' in call.args[1]]
        self.assertNotIn(SELECTOR_ONLY_RETRY_PROMPT, systems[0])
        self.assertIn(SELECTOR_ONLY_RETRY_PROMPT, systems[1])
        self.assertEqual(len(calls), 2, 'Reason checks reuse the existing two-call row budget.')
        rows = {r['condition_id']: r for r in report['sop_condition_checks']}
        self.assertEqual(rows['FIX03.C01']['result'], '满足')
        self.assertEqual(rows['FIX03.C01']['analysis_status'], 'completed')
        return report, rows['FIX03.C02']

    def test_legal_replacement_with_stale_reason_is_failed_without_discarding_valid_sibling(self):
        report, row = self.retry(True)
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['analysis_status'], 'failed')
        self.assertNotIn('DEMO_TOKEN', row['reason'].split('旧字面事实：')[0])
        self.assertFalse(report['sop_coverage']['analysis_complete'])

    def test_retracted_old_fact_recovers_unknown_without_extra_call(self):
        report, row = self.retry(False)
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['analysis_status'], 'completed')
        self.assertTrue(report['sop_coverage']['analysis_complete'])

    def test_repeating_absent_quote_after_row_feedback_still_fails_exact_citations(self):
        report, row = self.retry(True, repeat_quote=True)
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['analysis_status'], 'failed')
        self.assertIn('禁止手写完整引用', row['reason'])
        self.assertFalse(report['sop_coverage']['analysis_complete'])

    def test_shared_inner_retry_also_requires_rejudged_reasons_with_no_added_calls(self):
        self.package['audit_context'] = {'profile': 'code_fix'}
        for retained in (True, False):
            with self.subTest(retained=retained):
                calls = []
                def respond(payload):
                    if 'source_inventory' not in payload or 'fixed_user_requirements' not in payload:
                        return default_response(payload)
                    calls.append(copy.deepcopy(payload))
                    reason = '用户要求使用 DEMO_TOKEN。'
                    refs = [ref('U', "token = 'DEMO_TOKEN'")]
                    if len(calls) == 2:
                        self.assertIn('DEMO_TOKEN', str(payload['reference_feedback']))
                        self.assertNotIn('rejected_quote', str(payload['reference_feedback']))
                        self.assertEqual(payload['citation_retry']['mode'], 'visible_quote_selectors_only')
                        user = next(item for item in payload['evidence'] if item['id'] == 'U')
                        refs = [{'quote_id': user['numbered_lines'][0]['quote_id']}]
                        if not retained:
                            reason = '旧事实无用户来源，阶段范围仍不确定。'
                    return {'reviewed_source_ids': payload['source_inventory'], 'intents': [
                        {'name': name, 'status': 'uncertain', 'reason': reason, 'evidence_refs': refs}
                        for name in ('design_full', 'formal_closure', 'full_security')]}
                with tempfile.TemporaryDirectory() as directory:
                    report = audit_sop(copy.deepcopy(self.result), self.package, self.catalog,
                                       Client(respond), Path(directory))
                self.assertEqual(len(calls), 2)
                failures = [f for f in report['sop_coverage']['failures']
                            if f['stage'].startswith('sop-condition-scope-')]
                self.assertEqual(bool(failures), retained)


if __name__ == '__main__':
    unittest.main()

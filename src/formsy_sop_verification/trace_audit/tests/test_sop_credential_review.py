"""Offline boundary tests; a structured receipt never proves model semantics."""
import copy
from pathlib import Path
import tempfile
import unittest

from ..sop_catalog import load_catalog
from ..sop_credential_review import (SURFACES, FLOW_SUBJECT, review_input,
                                      review_response, review_credential_absence)
from .test_sop_audit import fixtures, ref


class CredentialReviewTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.source = next(e for e in self.package['evidence'] if e['id'] == 'S')
        condition = next(c for r in load_catalog(Path(__file__).resolve().parents[1])['rules']
                         for c in r['conditions'] if c['id'] == 'SEC06.C02')
        self.row = {'task_id': self.task['id'], 'target_commit_ids': self.task['target_commit_ids'],
                    'rule_id': 'SEC06', 'document_id': 'security-0.1', 'condition_id': 'SEC06.C02',
                    'result': '满足', 'reason': 'Placeholder candidate', 'gap_type': '',
                    'evidence_refs': [ref('S', self.source['content'])],
                    'contract': copy.deepcopy(condition['contract']), 'atomic_checks': [{
                        'id': 'SEC06.C02.I01', 'result': '满足', 'reason': 'Placeholder atom',
                        'gap_type': '', 'evidence_refs': [ref('S', self.source['content'])]}]}
        self.row['credential_review_candidate'] = {k: copy.deepcopy(self.row[k]) for k in
                    ('result', 'reason', 'gap_type', 'evidence_refs', 'atomic_checks')}
        self.payload = review_input(self.row, self.task, self.package)
        self.proof = ref('S', self.source['content'].splitlines()[0])

    def answer(self):
        # Only the validator's structure is tested; this stub is not a semantic proof.
        return {'reviewed_evidence_ids': [e['id'] for e in self.payload['evidence']],
                'source_coverage': [{'evidence_id': e['evidence_id'], 'start_line': 1 if e['line_count'] else 0,
                                    'end_line': e['line_count']} for e in self.payload['target_source_inventory']],
                'surfaces': [{'id': k, 'property': text, 'status': 'verified', 'coverage': 'complete',
                              'scope': 'Fixture scope only', 'reason': 'Typed test receipt',
                              'evidence_refs': [copy.deepcopy(self.proof)]} for k, text in SURFACES.items()],
                'credential_flow': {'subject': FLOW_SUBJECT, 'status': 'protected',
                    'reason': 'Typed path receipt', **{k: [copy.deepcopy(self.proof)]
                    for k in ('entry_refs', 'boundary_refs', 'sink_refs')}}}

    def evaluate(self, answer):
        return review_response(answer, self.task, self.package, self.payload)

    def test_valid_structure_does_not_waive_any_surface_or_flow(self):
        self.assertEqual(self.evaluate(self.answer())['result'], '满足')
        for surface in SURFACES:
            for field, value in [('status', 'unknown'), ('coverage', 'partial'), ('evidence_refs', [])]:
                with self.subTest(surface=surface, field=field):
                    answer = self.answer()
                    next(s for s in answer['surfaces'] if s['id'] == surface)[field] = value
                    self.assertEqual(self.evaluate(answer)['result'], '未核查')
        for status in ['unknown', 'unprotected']:
            answer = self.answer(); answer['credential_flow']['status'] = status
            self.assertEqual(self.evaluate(answer)['result'], '未核查')
        for field in ['entry_refs', 'boundary_refs', 'sink_refs']:
            answer = self.answer(); answer['credential_flow'][field] = []
            self.assertEqual(self.evaluate(answer)['result'], '未核查')

    def test_declared_partial_or_unknown_file_extent_cannot_be_certified_by_complete_label(self):
        for content, path in [('[File: client.py (349 lines total)]\n1: def load_secret(passcode="-1"):\n2: return passcode', 'client.py'),
                              ('def load_secret(passcode="-1"):\n    return passcode', None)]:
            self.source['content'] = content
            if path is None: self.source.pop('path', None)
            else: self.source['path'] = path
            self.row['credential_review_candidate']['evidence_refs'] = []
            self.payload = review_input(self.row, self.task, self.package)
            self.proof = {'evidence_id': 'S', 'start_line': len(content.splitlines()),
                          'end_line': len(content.splitlines()), 'quote': content.splitlines()[-1]}
            answer = self.answer(); answer['credential_flow']['status'] = 'no_secret_inputs'
            checked = self.evaluate(answer)
            self.assertEqual(checked['result'], '未核查')
            self.assertEqual(checked['surfaces'][0]['status'], 'verified')
            self.assertIn('整文件范围', checked['reason'])

    def test_missing_duplicate_or_narrowed_inventory_and_properties_are_rejected(self):
        cases = []
        for key in ['reviewed_evidence_ids', 'source_coverage', 'surfaces']:
            a = self.answer(); a[key] = []; cases.append(a)
            a = self.answer(); a[key].append(copy.deepcopy(a[key][0])); cases.append(a)
        a = self.answer(); a['surfaces'][0]['property'] = 'No hardcoded placeholder'; cases.append(a)
        a = self.answer(); a['credential_flow']['subject'] = 'Default test value'; cases.append(a)
        a = self.answer(); a['source_coverage'][0]['end_line'] -= 1; cases.append(a)
        for answer in cases:
            with self.subTest(answer=answer):
                with self.assertRaises(ValueError): self.evaluate(answer)

    def test_known_empty_source_is_complete_without_fabricated_lines_or_refs(self):
        empty = {**self.source, 'id': 'EMPTY', 'path': 'tests/__init__.py', 'content': ''}
        self.package['evidence'].append(empty)
        self.payload = review_input(self.row, self.task, self.package)
        extent = next(e for e in self.payload['target_source_inventory'] if e['evidence_id'] == 'EMPTY')
        self.assertTrue(extent['extent_complete'])
        answer = self.answer()
        self.assertEqual(self.evaluate(answer)['result'], '满足')
        empty_coverage = next(c for c in answer['source_coverage'] if c['evidence_id'] == 'EMPTY')
        self.assertEqual((empty_coverage['start_line'], empty_coverage['end_line']), (0, 0))
        empty_coverage['start_line'] = 1
        with self.assertRaises(ValueError): self.evaluate(answer)

    def test_bad_quote_parent_user_or_original_self_claim_cannot_prove_target_flow(self):
        for proof in [dict(self.proof, quote='not in source'), ref('U', self.package['evidence'][0]['content'])]:
            answer = self.answer(); answer['credential_flow']['entry_refs'] = [proof]
            with self.assertRaises(ValueError): self.evaluate(answer)
        self.package['evidence'].append({'id': 'OLD', 'kind': 'source', 'name': 'old',
            'version_id': 'b' * 40, 'content': 'old secret boundary'})
        self.package['evidence'].append({'id': 'A', 'kind': 'assistant', 'content': 'already safe',
                                        'target_ids': [self.task['id']]})
        self.payload = review_input(self.row, self.task, self.package)
        self.assertNotIn('OLD', {e['id'] for e in self.payload['evidence']})
        self.assertIn('A', self.payload['evidence_surface_only_ids'])
        answer = self.answer(); answer['credential_flow']['entry_refs'] = [ref('A', 'already safe')]
        with self.assertRaises(ValueError): self.evaluate(answer)

    def test_hidden_candidate_proof_never_leaks_to_the_new_provider_stage(self):
        row = copy.deepcopy(self.row)
        request = {'evidence': [e for e in self.package['evidence'] if e['id'] != 'S']}
        with tempfile.TemporaryDirectory() as directory:
            review_credential_absence(row, self.task, self.package, request,
                lambda *args: self.fail('Unavailable candidate must never be sent'),
                'hidden', [], directory=directory)
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['credential_scope_review']['status'], 'completed')
        self.assertNotIn(self.source['content'], row['reason'])
        self.assertNotIn('S', row['credential_scope_review']['scope_rejections'][0])

    def test_real_audit_hook_keeps_shared_budget_and_completed_unknown(self):
        from ..sop_audit import audit_sop
        from .test_sop_audit import Client, default_response
        catalog = load_catalog(Path(__file__).resolve().parents[1])
        rule = copy.deepcopy(next(r for r in catalog['rules'] if r['id'] == 'SEC06'))
        rule['conditions'] = [c for c in rule['conditions'] if c['id'] == 'SEC06.C02']
        catalog = {**catalog, 'rules': [rule]}
        def respond(payload):
            if 'surface_obligations' in payload:
                answer = self.answer()
                next(s for s in answer['surfaces'] if s['id'] == 'package')['status'] = 'unknown'
                return answer
            if 'candidate_rules' in payload:
                return {'rules': [{'rule_id': 'SEC06', 'audit_object': 'target_product',
                    'selection': 'selected', 'reason': 'Synthetic review scope',
                    'evidence_refs': [ref('U', '保留零值')]}]}
            return default_response(payload)
        for budget in (2, 3):
            with self.subTest(budget=budget), tempfile.TemporaryDirectory() as directory:
                result = copy.deepcopy(self.result)
                result['checks'] = [{'task_id': self.task['id'], 'rule_id': 'SEC06',
                    'result': '未核查', 'local_result': '满足', 'automated_result': '满足'}]
                client = Client(respond)
                audit_sop(result, self.package, catalog, client, Path(directory), max_calls=budget)
                self.assertEqual(len(client.calls), budget)
                self.assertEqual(result['sop_coverage']['request_count'], budget)
                self.assertEqual(result['sop_coverage']['analysis_complete'], budget == 3)
                self.assertEqual(result['sop_condition_checks'][0]['result'], '未核查')
                self.assertEqual(result['sop_condition_checks'][0]['credential_review_candidate']['result'], '满足')
                if budget == 3:
                    self.assertIn('sop-credential-review-', client.calls[-1][0])
                    self.assertEqual(result['sop_condition_checks'][0]['credential_scope_review']['status'], 'completed')

    def test_stage_preserves_candidate_and_failed_or_uncertain_reviews_never_spread_fail(self):
        for mode in ['unknown', 'failed']:
            row = copy.deepcopy(self.row); calls = []; failures = []; package_before = copy.deepcopy(self.package)
            def call(stage, system, payload, validator):
                calls.append(stage)
                if mode == 'failed': return None, 'provider_invalid_candidate', False
                answer = self.answer(); answer['surfaces'][0]['status'] = 'unknown'
                return validator(answer), None, False
            with tempfile.TemporaryDirectory() as directory:
                review_credential_absence(row, self.task, self.package, {}, call, 'credential', failures,
                                          directory=directory)
                self.assertTrue((Path(directory) / 'credential.credential-review.json').exists())
            self.assertEqual(row['result'], '未核查')
            aggregate_gate = next(g for g in row['program_gates'] if g['id'] == 'all_required_atomic_checks')
            self.assertFalse(aggregate_gate['met'])
            self.assertEqual(aggregate_gate['result'], '未核查')
            if mode == 'unknown':
                self.assertIn(self.proof, row['evidence_refs'])
                self.assertIn(self.proof, row['atomic_checks'][0]['evidence_refs'])
            self.assertEqual(row['credential_review_candidate']['result'], '满足')
            self.assertEqual(row['atomic_checks'][0]['credential_review_candidate']['result'], '满足')
            self.assertEqual(row['credential_scope_review']['status'], 'failed' if mode == 'failed' else 'completed')
            self.assertEqual(bool(failures), mode == 'failed')
            self.assertEqual(self.package, package_before)
            self.assertEqual(calls, ['credential'])
        for field, value in [('result', '不满足'), ('document_id', 'custom'), ('task_id', 'other')]:
            row = copy.deepcopy(self.row); row[field] = value
            review_credential_absence(row, self.task, self.package, {},
                lambda *args: self.fail('Noncandidate/custom rows must not call provider'), 'skip', [], directory=Path('.'))


if __name__ == '__main__':
    unittest.main()

"""Source identity does not migrate between local code and adopted external material."""
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

from ..sop_audit import audit_sop
from ..sop_catalog import load_catalog
from ..sop_source_review import source_review_input, source_review_response, review_source_identity
from ..reference_repair import _quote_choices
from .test_sop_audit import fixtures, ref, Client


class SourceReviewTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.evidence('S')['content'] += '  # source date: 2026-10-14'
        self.task = self.result['tasks'][0]
        self.rule = next(r for r in load_catalog(Path(__file__).resolve().parents[1])['rules'] if r['id'] == 'TC14')
        self.condition = copy.deepcopy(self.rule['conditions'][0])
        self.row = {'task_id': self.task['id'], 'target_commit_ids': self.task['target_commit_ids'],
                    'rule_id': 'TC14', 'document_id': 'technical-0.2', 'condition_id': 'TC14.C01',
                    'result': '满足', 'reason': 'Original code SHA candidate', 'gap_type': '',
                    'evidence_refs': [ref('S', self.evidence('S')['content'])],
                    'contract': copy.deepcopy(self.condition['contract']),
                    'atomic_checks': [{'id': 'TC14.C01.I01', 'result': '满足',
                        'reason': 'Original atom', 'gap_type': '',
                        'evidence_refs': [ref('S', self.evidence('S')['content'])]}]}
        self.request = {'evidence': self.package['evidence'], 'commits': self.package['commits'],
                        'candidate_rules': [], 'adjacent_conditions': [{'condition_id': 'TC14.C03', 'result': '未核查'}]}

    def evidence(self, eid):
        return next(e for e in self.package['evidence'] if e['id'] == eid)

    def property(self, eid, name):
        e = self.evidence(eid)
        if name == 'date' and e['kind'] == 'user_requirement':
            return {'status': 'excluded_trace_timestamp', 'value': '',
                    'reason': 'Original user message time excluded', 'evidence_refs': []}
        value = (e.get('version_id') or hashlib.sha256(e['content'].encode()).hexdigest() if name == 'version'
                 else e.get('path', e['id']) if name == 'location' else '2026-10-14' if name == 'date'
                 else 'Current fixed requirement')
        return {'status': 'verified', 'value': value, 'reason': 'Same basis property',
                'evidence_refs': [ref(eid, e['content'].splitlines()[0])]}

    def answer(self, *, external=False, provided=False):
        rows = []
        bases = []
        for source_id, proof_id, kind in [('U', 'U', 'direct_requirement'), ('ASSISTANT', 'S', 'local')]:
            bid = 'B-' + proof_id
            rows.append({'evidence_id': source_id, 'classification': 'adopted', 'reason': 'Original adoption',
                         'adoption_refs': [ref(source_id, self.evidence(source_id)['content'].splitlines()[0])],
                         'basis_ids': [bid]})
            bases.append({'id': bid, 'kind': kind, 'identity': proof_id,
                          'adoption_refs': copy.deepcopy(rows[-1]['adoption_refs']), 'basis_evidence_ids': [proof_id],
                          'properties': {name: self.property(proof_id, name)
                                         for name in ['version', 'date', 'location', 'applicability']}})
        if external:
            rows[0]['basis_ids'].append('B-spec')
            bases.append({'id': 'B-spec', 'kind': 'external', 'identity': 'Cognitive Complexity specification',
                          'adoption_refs': copy.deepcopy(rows[0]['adoption_refs']),
                          'basis_evidence_ids': ['SPEC'] if provided else [],
                          'properties': {name: {'status': 'unknown', 'value': '', 'reason': 'No external material',
                                               'evidence_refs': []}
                                         for name in ['version', 'date', 'location', 'applicability']}})
            if provided:
                for name, value in [('version', 'v1.7'), ('date', '2026-09-30'),
                                    ('location', 'SPEC'), ('applicability', 'B1 applies')]:
                    bases[-1]['properties'][name] = {'status': 'verified', 'value': value, 'reason': 'External original',
                                                     'evidence_refs': [ref('SPEC', self.evidence('SPEC')['content'])]}
        return {'reviewed_source_ids': ['U', 'ASSISTANT'], 'source_reviews': rows, 'bases': bases}

    def payload(self):
        self.row.setdefault('source_review_candidate', copy.deepcopy(self.row))
        return source_review_input(self.row, self.task, self.package, self.request)

    def validate(self, answer):
        return source_review_response(answer, self.task, self.package, self.payload())

    def test_missing_duplicate_basis_refs_use_only_explicit_validated_origin_links(self):
        self.package['evidence'].append({'id': 'A2', 'kind': 'assistant', 'content': 'Use local S again.'})
        for empty in (False, True):
            with self.subTest(empty=empty):
                answer = self.answer()
                answer['reviewed_source_ids'].append('A2')
                answer['source_reviews'].append({'evidence_id': 'A2', 'classification': 'adopted',
                    'reason': 'A second explicit use of S', 'adoption_refs': [ref('A2', 'Use local S again.')],
                    'basis_ids': ['B-S']})
                if empty:
                    answer['bases'][1]['adoption_refs'] = []
                original = copy.deepcopy(answer)
                result = self.validate(answer)
                basis = result['bases'][1]
                self.assertEqual(result['result'], '满足')
                self.assertEqual(answer, original)
                self.assertEqual(basis['adoption_refs'], original['bases'][1]['adoption_refs'])
                selected = [r for s in original['source_reviews'] if 'B-S' in s['basis_ids']
                            for r in s['adoption_refs']]
                self.assertEqual(basis['effective_adoption_refs'], selected)
                self.assertEqual(basis['adoption_ref_additions']['origin'], 'validated_source_reviews')
                self.assertEqual(basis['adoption_ref_additions']['evidence_refs'],
                                 selected if empty else selected[1:])
                self.assertEqual(basis['properties'], original['bases'][1]['properties'])
                basis['effective_adoption_refs'][0]['quote'] = 'Changed returned copy only.'
                self.assertEqual(answer, original)

    def test_nonadopted_origin_is_not_merged_and_cannot_donate_basis_refs(self):
        self.package['evidence'].append({'id': 'A2', 'kind': 'assistant', 'content': 'Mention only, no adoption.'})
        for classification in ('no_basis', 'mention_only', 'uncertain'):
            with self.subTest(classification=classification):
                answer = self.answer()
                answer['reviewed_source_ids'].append('A2')
                answer['source_reviews'].append({'evidence_id': 'A2', 'classification': classification,
                    'reason': 'No confirmed use of this basis.',
                    'adoption_refs': [ref('A2', 'Mention only, no adoption.')], 'basis_ids': []})
                answer['bases'][1]['adoption_refs'] = []
                result = self.validate(answer)
                self.assertNotIn('A2', {r['evidence_id'] for r in result['bases'][1]['effective_adoption_refs']})
                if classification == 'uncertain':
                    self.assertEqual(result['result'], '未核查')
                answer['bases'][1]['adoption_refs'] = copy.deepcopy(answer['source_reviews'][-1]['adoption_refs'])
                with self.assertRaisesRegex(ValueError, '采用引用须来自原采用来源'):
                    self.validate(answer)

    def test_valid_origin_links_never_heal_bad_model_or_source_quotes(self):
        for field in ('bases', 'source_reviews'):
            with self.subTest(field=field):
                answer = self.answer()
                answer[field][1]['adoption_refs'][0]['quote'] = 'Invented adoption quote.'
                original = copy.deepcopy(answer)
                with self.assertRaises(ValueError):
                    self.validate(answer)
                self.assertEqual(answer, original)

    def test_empty_basis_refs_do_not_bypass_source_identity_or_version_gates(self):
        self.package['evidence'].append({'id': 'MAINT', 'kind': 'context', 'path': 'limit.py',
            'version_id': self.evidence('S')['version_id'], 'content': 'Audit maintained on 2026-10-14.'})
        answer = self.answer()
        answer['bases'][1]['adoption_refs'] = []
        answer['bases'][1]['basis_evidence_ids'].append('MAINT')
        answer['bases'][1]['properties']['date']['evidence_refs'] = [ref('MAINT', self.evidence('MAINT')['content'])]
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertFalse(result['bases'][1]['source_binding_check']['met'])
        self.assertEqual(result['bases'][1]['effective_properties']['date']['status'], 'unknown')
        self.evidence('S')['version_id'] = 'c' * 40
        answer = self.answer()
        answer['bases'][1]['adoption_refs'] = []
        with self.assertRaisesRegex(ValueError, '其他版本源码'):
            self.validate(answer)

    def test_real_orchestration_completes_unknown_for_copy_omission_without_extra_call(self):
        rule = copy.deepcopy(self.rule)
        rule['conditions'] = [copy.deepcopy(self.condition)]
        catalog = {'rules': [rule], 'documents': [], 'sha256': 'synthetic'}
        raw = []

        def respond(payload):
            if 'candidate_rules' in payload:
                return {'rules': [{'rule_id': 'TC14', 'selection': 'selected', 'reason': 'Local source',
                                  'evidence_refs': [ref('S', self.evidence('S')['content'])]}]}
            if 'adoption_source_inventory' in payload:
                answer = self.answer()
                for basis in answer['bases']:
                    basis['adoption_refs'] = []
                answer['bases'][1]['properties']['date'].update(
                    status='unknown', value='', reason='Source date unavailable', evidence_refs=[])
                raw.append(copy.deepcopy(answer))
                return answer
            if 'conditions' in payload:
                return {'conditions': [{key: copy.deepcopy(self.row[key]) for key in
                         ['condition_id', 'result', 'reason', 'gap_type', 'evidence_refs', 'atomic_checks']}]}
            raise AssertionError('unexpected request')

        client = Client(respond)
        with tempfile.TemporaryDirectory() as directory:
            report = audit_sop(copy.deepcopy(self.result), copy.deepcopy(self.package), catalog,
                               client, directory, max_calls=3)
        row = report['sop_condition_checks'][0]
        self.assertEqual(len(client.calls), 3)
        self.assertFalse(report['sop_coverage']['failures'])
        self.assertTrue(report['sop_coverage']['analysis_complete'])
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['source_identity_review']['status'], 'completed')
        self.assertNotEqual(row.get('analysis_status'), 'failed')
        self.assertEqual(len(raw), 1)
        for original, effective in zip(raw[0]['bases'], row['source_identity_review']['bases']):
            self.assertEqual(original['adoption_refs'], [])
            self.assertEqual(effective['adoption_refs'], [])
            self.assertTrue(effective['effective_adoption_refs'])

    def test_local_and_direct_user_sources_can_pass_without_adjacent_unknown_propagation(self):
        payload = self.payload()
        self.assertNotIn('adjacent_conditions', payload)
        self.assertNotIn('candidate_rules', payload)
        self.assertEqual(self.validate(self.answer())['result'], '满足')

    def test_adopted_external_unknown_does_not_change_frozen_user_requirements(self):
        original = copy.deepcopy(self.task)
        result = self.validate(self.answer(external=True))
        self.assertEqual(result['result'], '未核查')
        self.assertEqual(self.task, original)
        self.assertEqual(result['bases'][0]['kind'], 'direct_requirement')
        self.assertEqual(result['bases'][0]['properties']['date']['status'], 'excluded_trace_timestamp')
        self.assertTrue(all(p['status'] == 'verified' for k, p in result['bases'][0]['properties'].items() if k != 'date'))

    def test_provided_external_source_own_properties_can_pass(self):
        self.package['evidence'].append({'id': 'SPEC', 'kind': 'context',
                                        'content': 'Specification v1.7; source date: 2026-09-30; B1 applies'})
        self.assertEqual(self.validate(self.answer(external=True, provided=True))['result'], '满足')
        def call(stage, system, payload, validator):
            return validator(self.answer(external=True, provided=True)), None, False
        with tempfile.TemporaryDirectory() as directory:
            review_source_identity(self.row, self.task, self.package, self.request, call,
                                   'test-source', [], directory=directory)
        self.assertIn('SPEC', {r['evidence_id'] for r in self.row['evidence_refs']})
        self.assertNotIn('SPEC', {r['evidence_id'] for r in self.row['source_review_candidate']['evidence_refs']})

    def test_external_version_cannot_borrow_code_sha_even_with_valid_quote(self):
        answer = self.answer(external=True)
        basis = answer['bases'][-1]
        basis['basis_evidence_ids'] = ['S']
        basis['properties']['version'] = self.property('S', 'version')
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertEqual(result['bases'][-1]['properties'], basis['properties'])
        self.assertEqual(result['bases'][-1]['effective_properties']['version']['status'], 'unknown')
        self.assertIn('不能借目标/父源码SHA', result['program_rejections'][0]['reason'])

    def test_basis_properties_cannot_reference_another_source(self):
        answer = self.answer()
        answer['bases'][0]['properties']['applicability'] = self.property('S', 'applicability')
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertEqual(result['bases'][0]['effective_properties']['applicability']['evidence_refs'], [])

    def test_only_mentioned_url_requires_original_classification_and_not_external_authentication(self):
        self.evidence('ASSISTANT')['content'] = 'Here is a URL for later reading, not used for this decision.'
        answer = self.answer()
        answer['source_reviews'][1].update(classification='mention_only', basis_ids=[])
        answer['bases'] = answer['bases'][:1]
        self.assertEqual(self.validate(answer)['result'], '满足')
        answer['source_reviews'][1]['adoption_refs'] = []
        with self.assertRaisesRegex(ValueError, '仅提及须原文引用'):
            self.validate(answer)

    def test_missing_and_duplicate_original_inventory_cannot_pass(self):
        for field in ['reviewed_source_ids', 'source_reviews']:
            answer = self.answer()
            answer[field] = answer[field][:1]
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.validate(answer)
        answer = self.answer()
        answer['source_reviews'][1] = copy.deepcopy(answer['source_reviews'][0])
        with self.assertRaises(ValueError):
            self.validate(answer)

    def test_original_adoption_must_refer_to_its_linked_basis(self):
        answer = self.answer()
        answer['bases'][1]['adoption_refs'] = copy.deepcopy(answer['bases'][0]['adoption_refs'])
        with self.assertRaisesRegex(ValueError, '采用引用须来自原采用来源'):
            self.validate(answer)

    def test_assistant_cannot_authenticate_source_property(self):
        answer = self.answer()
        answer['bases'][1]['basis_evidence_ids'] = ['ASSISTANT']
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertTrue(any('助手/工具只证明采用' in r['reason'] for r in result['program_rejections']))

    def test_bad_quote_and_foreign_task_remain_validation_errors(self):
        answer = self.answer()
        answer['bases'][0]['properties']['version']['evidence_refs'][0]['quote'] = 'invented'
        with self.assertRaises(ValueError):
            self.validate(answer)
        self.evidence('S')['target_ids'] = ['OTHER']
        with self.assertRaises(ValueError):
            self.validate(self.answer())

    def test_wrong_local_version_value_and_unrelated_commit_cannot_prove_identity(self):
        answer = self.answer()
        answer['bases'][1]['properties']['version']['value'] = 'other-version'
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertIn('匹配其自身版本', result['program_rejections'][0]['reason'])
        self.evidence('S')['version_id'] = 'c' * 40
        self.package['commits'].append({'sha': 'c' * 40, 'parent': 'd' * 40, 'evidence_id': 'UNRELATED'})
        with self.assertRaisesRegex(ValueError, '其他版本源码'):
            self.validate(self.answer())

    def test_source_date_missing_is_unknown_and_hash_does_not_prove_date(self):
        answer = self.answer()
        prop = answer['bases'][1]['properties']['date']
        prop.update(status='unknown', value='', reason='Source date unavailable', evidence_refs=[])
        self.assertEqual(self.validate(answer)['result'], '未核查')
        prop.update(status='verified', value=hashlib.sha256(self.evidence('S')['content'].encode()).hexdigest(),
                    evidence_refs=[ref('S', self.evidence('S')['content'])])
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertIn('不能由哈希', result['program_rejections'][0]['reason'])

    def test_trace_time_exclusion_is_only_for_direct_current_user_requirement(self):
        for kind in ['local', 'external']:
            answer = self.answer()
            answer['bases'][1]['kind'] = kind
            if kind == 'external':
                answer['bases'][1]['properties']['version'].update(status='unknown', value='', evidence_refs=[])
            answer['bases'][1]['properties']['date'] = copy.deepcopy(answer['bases'][0]['properties']['date'])
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, '仅当前原user'):
                self.validate(answer)
        self.package['evidence'].append({'id': 'OTHER-USER', 'kind': 'user_requirement', 'content': 'Other request'})
        answer = self.answer()
        answer['bases'][0]['basis_evidence_ids'] = ['OTHER-USER']
        self.assertNotIn('OTHER-USER', {e['id'] for e in self.payload()['evidence']})
        with self.assertRaises(ValueError):
            self.validate(answer)

    def test_other_source_and_audit_maintenance_dates_cannot_fill_this_basis_date(self):
        self.package['evidence'].append({'id': 'MAINT', 'kind': 'context', 'name': 'audit-maintenance',
                                        'content': 'Audit maintained on 2026-10-14'})
        answer = self.answer()
        answer['bases'][1]['properties']['date']['evidence_refs'] = [ref('MAINT', self.evidence('MAINT')['content'])]
        self.assertEqual(self.validate(answer)['result'], '未核查')
        answer['bases'][1]['basis_evidence_ids'].append('MAINT')
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertFalse(result['bases'][1]['source_binding_check']['met'])

    def test_identical_complete_source_duplicates_can_share_one_basis(self):
        duplicate = copy.deepcopy(self.evidence('S'))
        duplicate['id'] = 'S-COPY'
        self.package['evidence'].append(duplicate)
        answer = self.answer()
        answer['bases'][1]['basis_evidence_ids'].append('S-COPY')
        answer['bases'][1]['properties']['date']['evidence_refs'] = [ref('S-COPY', duplicate['content'])]
        self.assertEqual(self.validate(answer)['result'], '满足')

    def test_same_path_and_version_do_not_bind_different_source_bytes_to_maintenance_date(self):
        self.evidence('S')['content'] = 'return 25 if value is None else value'
        maintenance = {'id': 'MAINT', 'kind': 'context', 'path': 'limit.py',
                       'version_id': self.evidence('S')['version_id'],
                       'content': 'Audit maintained on 2026-10-14; source creation date is unknown.'}
        self.package['evidence'].append(maintenance)
        answer = self.answer()
        answer['bases'][1]['basis_evidence_ids'].append('MAINT')
        answer['bases'][1]['properties']['date']['evidence_refs'] = [ref('MAINT', maintenance['content'])]
        original = copy.deepcopy(answer)
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertEqual(answer, original)
        self.assertEqual(result['bases'][1]['properties'], original['bases'][1]['properties'])
        self.assertEqual(result['bases'][1]['effective_properties']['date']['status'], 'unknown')
        self.assertTrue(result['program_rejections'])
        self.assert_semantic_unknown_wrapper(answer, forbidden='MAINT')

    def test_same_context_path_empty_version_does_not_bind_external_doc_and_maintenance_date(self):
        self.package['evidence'] += [
            {'id': 'SPEC', 'kind': 'context', 'path': 'specification.md', 'version_id': '',
             'content': 'Specification v1.7; B1 applies; original source date not provided.'},
            {'id': 'MAINT', 'kind': 'context', 'path': 'specification.md', 'version_id': '',
             'content': 'Audit maintained on 2026-10-14; this is not the specification source date.'}]
        answer = self.answer(external=True, provided=True)
        answer['bases'][-1]['basis_evidence_ids'].append('MAINT')
        answer['bases'][-1]['properties']['date'].update(value='2026-10-14',
                evidence_refs=[ref('MAINT', self.evidence('MAINT')['content'])])
        result = self.validate(answer)
        self.assertEqual(result['result'], '未核查')
        self.assertEqual(result['bases'][-1]['properties']['date']['status'], 'verified')
        self.assertEqual(result['bases'][-1]['effective_properties']['date']['status'], 'unknown')
        self.assert_semantic_unknown_wrapper(answer, forbidden='MAINT')

    def assert_semantic_unknown_wrapper(self, answer, *, forbidden):
        def call(stage, system, payload, validator):
            return validator(answer), None, False
        with tempfile.TemporaryDirectory() as directory:
            failures = []
            review_source_identity(self.row, self.task, self.package, self.request, call,
                                   'test-source', failures, directory=directory)
        self.assertFalse(failures)
        self.assertEqual(self.row['source_identity_review']['status'], 'completed')
        self.assertEqual(self.row['result'], '未核查')
        self.assertEqual(self.row['gap_type'], 'evidence_missing')
        self.assertNotEqual(self.row.get('analysis_status'), 'failed')
        self.assertEqual(self.row['atomic_checks'][0]['gap_type'], 'evidence_missing')
        self.assertNotIn(forbidden, {r['evidence_id'] for r in self.row['evidence_refs']})
        self.assertNotIn(forbidden, {r['evidence_id'] for r in self.row['atomic_checks'][0]['evidence_refs']})

    def test_selected_parent_allowed_but_parent_of_unrelated_commit_is_not(self):
        self.evidence('S')['version_id'] = self.package['commits'][0]['parent']
        self.assertEqual(self.validate(self.answer())['result'], '满足')
        self.package['commits'].append({'sha': 'c' * 40, 'parent': 'd' * 40, 'evidence_id': 'UNRELATED'})
        self.evidence('S')['version_id'] = 'd' * 40
        with self.assertRaisesRegex(ValueError, '其他版本源码'):
            self.validate(self.answer())

    def test_mixed_identity_unknown_does_not_skip_actual_wrong_version_citation(self):
        other = copy.deepcopy(self.evidence('S'))
        other.update(id='OTHER', version_id='c' * 40)
        self.package['evidence'].append(other)
        answer = self.answer()
        answer['bases'][1]['basis_evidence_ids'].append('OTHER')
        answer['bases'][1]['properties']['date']['evidence_refs'] = [ref('OTHER', other['content'])]
        with self.assertRaisesRegex(ValueError, '其他版本源码'):
            self.validate(answer)

    def test_review_wrapper_retains_original_candidate_and_completed_unknown(self):
        original = copy.deepcopy(self.row)
        answer = self.answer(external=True)
        calls = []
        def call(stage, system, payload, validator):
            calls.append(stage)
            return validator(answer), None, False
        with tempfile.TemporaryDirectory() as directory:
            failures = []
            review_source_identity(self.row, self.task, self.package, self.request, call,
                                   'test-source', failures, directory=directory)
            self.assertEqual(len(calls), 1)
            self.assertFalse(failures)
            self.assertEqual(self.row['result'], '未核查')
            self.assertEqual(self.row['source_identity_review']['status'], 'completed')
            self.assertEqual(self.row['source_review_candidate']['reason'], original['reason'])
            self.assertEqual(self.row['atomic_checks'][0]['source_review_candidate']['reason'], 'Original atom')
            self.assertTrue((Path(directory) / 'test-source.source-review.json').is_file())

    def test_exhausted_or_unavailable_review_is_explicit_analysis_failure(self):
        calls = []
        def call(*args):
            calls.append(args[0])
            return None, 'existing budget exhausted', False
        with tempfile.TemporaryDirectory() as directory:
            failures = []
            review_source_identity(self.row, self.task, self.package, self.request, call,
                                   'test-source', failures, directory=directory)
        self.assertEqual(len(calls), 1)
        self.assertEqual(self.row['analysis_status'], 'failed')
        self.assertEqual(self.row['gap_type'], 'analysis_failed')
        self.assertEqual(self.row['atomic_checks'][0]['gap_type'], 'analysis_failed')
        self.assertEqual(failures[0]['kind'], 'stage_analysis_failure')

    def test_uploaded_or_wrong_task_candidate_does_not_trigger_native_review(self):
        def call(*args):
            self.fail('non-native review should not call model')
        for field, value in [('document_id', 'uploaded-rules'), ('task_id', 'OTHER')]:
            row = copy.deepcopy(self.row)
            row[field] = value
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                review_source_identity(row, self.task, self.package, self.request, call,
                                       'test-source', [], directory=directory)
            self.assertNotIn('source_review_candidate', row)

    def test_real_audit_sop_orchestration_uses_existing_call_and_budget(self):
        rule = copy.deepcopy(self.rule)
        rule['conditions'] = [copy.deepcopy(self.condition)]
        catalog = {'rules': [rule], 'documents': [], 'sha256': 'synthetic'}
        def respond(payload):
            if 'candidate_rules' in payload:
                return {'rules': [{'rule_id': 'TC14', 'selection': 'selected', 'reason': 'Local source',
                                  'evidence_refs': [ref('S', self.evidence('S')['content'])]}]}
            if 'adoption_source_inventory' in payload:
                return self.answer(external=True)
            if 'conditions' in payload:
                return {'conditions': [{key: copy.deepcopy(self.row[key]) for key in
                         ['condition_id', 'result', 'reason', 'gap_type', 'evidence_refs', 'atomic_checks']}]}
            raise AssertionError('unexpected request')
        for budget, expected, failed in [(3, 'completed', False), (2, 'failed', True)]:
            client = Client(respond)
            with self.subTest(budget=budget), tempfile.TemporaryDirectory() as directory:
                result = audit_sop(copy.deepcopy(self.result), copy.deepcopy(self.package), catalog,
                                   client, directory, max_calls=budget)
            row = result['sop_condition_checks'][0]
            self.assertEqual(row['source_identity_review']['status'], expected)
            self.assertEqual(row['result'], '未核查')
            self.assertLessEqual(len(client.calls), budget)
            self.assertEqual(bool(result['sop_coverage']['failures']), failed)

    def test_actual_citation_retry_is_bounded_and_unresolved_failure_remains_visible(self):
        rule = copy.deepcopy(self.rule)
        rule['conditions'] = [copy.deepcopy(self.condition)]
        catalog = {'rules': [rule], 'documents': [], 'sha256': 'synthetic'}
        selectors = {(r['evidence_id'], r['quote']): q for q, r in _quote_choices(self.package).items()}
        def compact(value):
            if isinstance(value, list):
                return [compact(v) for v in value]
            if isinstance(value, dict):
                if set(value) == {'evidence_id', 'start_line', 'end_line', 'quote'}:
                    return selectors[(value['evidence_id'], value['quote'])]
                return {k: compact(v) for k, v in value.items()}
            return value
        for recover in [True, False]:
            seen = []
            def respond(payload):
                if 'candidate_rules' in payload:
                    return {'rules': [{'rule_id': 'TC14', 'selection': 'selected', 'reason': 'Local source',
                                      'evidence_refs': [ref('S', self.evidence('S')['content'])]}]}
                if 'adoption_source_inventory' in payload:
                    seen.append(copy.deepcopy(payload))
                    answer = self.answer(external=True)
                    if len(seen) == 1:
                        answer['bases'][0]['properties']['version']['evidence_refs'][0]['quote'] = 'invented'
                    else:
                        answer = compact(answer)
                        if not recover:
                            answer['bases'][0]['properties']['version']['evidence_refs'] = ['Q-missing']
                    return answer
                return {'conditions': [{key: copy.deepcopy(self.row[key]) for key in
                         ['condition_id', 'result', 'reason', 'gap_type', 'evidence_refs', 'atomic_checks']}]}
            with self.subTest(recover=recover), tempfile.TemporaryDirectory() as directory:
                client = Client(respond)
                result = audit_sop(copy.deepcopy(self.result), copy.deepcopy(self.package), catalog,
                                   client, directory, max_calls=4)
                self.assertTrue(list(Path(directory).glob('sop-source-review-*.validation.json')))
            self.assertEqual(len(seen), 2)
            self.assertTrue(seen[1]['citation_retry']['selector_only'])
            self.assertEqual(result['sop_condition_checks'][0]['source_identity_review']['status'],
                             'completed' if recover else 'failed')
            self.assertEqual(bool(result['sop_coverage']['failures']), not recover)
            self.assertLessEqual(len(client.calls), 4)


if __name__ == '__main__':
    unittest.main()

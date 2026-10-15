"""Valid missing evidence stays unknown; malformed citations and truncation stay visible."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from ..sop_audit import _condition_response
from ..sop_catalog import load_catalog
from ..reference_repair import _quote_choices
from ..sop_exclusions import review_exclusions, review_input, validate_review
from ..sop_judgments import apply_atomic_gates
from .test_sop_audit import fixtures, ref


class EvidenceGapTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.rules = load_catalog(Path(__file__).resolve().parents[1])['rules']
        self.conditions = {c['id']: (r, c) for r in self.rules for c in r['conditions']}

    def candidate(self, cid):
        _, condition = self.conditions[cid]
        answer = {'condition_id': cid, 'result': '满足', 'reason': 'Synthetic unsupported conclusion',
                  'gap_type': '', 'acceptance_ids': [], 'evidence_refs': [],
                  'atomic_checks': [{'id': i['id'], 'result': '满足', 'reason': 'Synthetic missing evidence',
                                     'gap_type': '', 'acceptance_ids': [], 'evidence_refs': []}
                                    for i in condition['contract']['items']]}
        return condition, answer

    def test_valid_empty_and_assistant_only_evidence_cannot_pass_or_fail(self):
        for cid in ('FIX01.C02', 'TC07.C03'):
            for verdict in ('满足', '不满足'):
                for references in ([], [ref('ASSISTANT', '已全部完成')]):
                    with self.subTest(cid=cid, verdict=verdict, references=references):
                        condition, answer = self.candidate(cid)
                        for item in [answer, *answer['atomic_checks']]:
                            item.update(result=verdict, evidence_refs=references)
                        row = _condition_response({'conditions': [answer]}, self.task, [condition],
                                                  self.package, strict_basis=True)[0]
                        self.assertEqual((row['result'], row['gap_type']), ('未核查', 'evidence_missing'))
                        self.assertEqual(row['model_candidate']['result'], verdict)
                        self.assertTrue(all(c['result'] == '未核查' for c in row['atomic_checks']))

    def test_bad_quote_foreign_task_and_wrong_target_are_not_missing_evidence(self):
        self.package['evidence'].append({'id': 'FOREIGN', 'kind': 'user_requirement', 'content': 'other task'})
        for bad in (ref('ASSISTANT', 'invented quote'), ref('FOREIGN', 'other task'),
                    ref('OLD', 'return value or 25')):
            with self.subTest(bad=bad):
                condition, answer = self.candidate('TC07.C03')
                answer['evidence_refs'] = [bad]
                with self.assertRaises(ValueError):
                    _condition_response({'conditions': [answer]}, self.task, [condition], self.package)

    def test_missing_sibling_retains_valid_target_citation(self):
        condition, answer = self.candidate('FIX01.C02')
        source = ref('S', 'return 25 if value is None else value')
        answer['evidence_refs'] = [source]
        answer['atomic_checks'][3]['evidence_refs'] = [source]
        row = _condition_response({'conditions': [answer]}, self.task, [condition], self.package)[0]
        row['contract'] = condition['contract']
        apply_atomic_gates(row, self.task, self.package)
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['atomic_checks'][3]['result'], '满足')
        self.assertEqual(row['atomic_checks'][2]['gap_type'], 'evidence_missing')

    def exclusion_rows(self, condition_ids=('SEC02.C01', 'SEC02.C02')):
        rows = []
        for cid in condition_ids:
            rule, condition = self.conditions[cid]
            rows.append({'task_id': self.task['id'], 'target_commit_ids': self.task['target_commit_ids'],
                         'condition_id': cid, 'rule_id': rule['id'], 'document_id': rule['document_id'],
                         'contract': copy.deepcopy(condition['contract']), 'kind': 'semantic',
                         'result': '不适用', 'reason': 'Synthetic exclusion', 'gap_type': '',
                         'evidence_refs': [ref('S', 'return 25 if value is None else value')],
                         'atomic_checks': [], 'program_gates': []})
        return rows

    def exclusion_answer(self, cid, eid, kind='external_input'):
        row = self.exclusion_rows((cid,))[0]
        item = row['contract']['items'][0]
        quote_id, reference = next((oid, value) for oid, value in _quote_choices(self.package).items()
                                   if value['evidence_id'] == eid)
        answer = {'id': item['id'], 'task_id': self.task['id'],
                  'target_commit_ids': self.task['target_commit_ids'], 'relation': 'contradicted',
                  'reason': 'Synthetic direct trigger', 'excluded_scope': '', 'evidence_refs': [reference],
                  'scope_analysis': {'audit_object': item['audit_object'],
                      'judgment_dimension': item['judgment_dimension'], 'trigger_state': 'present',
                      'basis': 'direct_capability', 'observations': [{'kind': kind, 'state': 'present',
                          'relevance': 'direct', 'note': 'Synthetic material input',
                          'evidence_quote_ids': [quote_id], 'acceptance_ids': []}]}}
        return (row, {'id': item['id']}, item), answer

    def test_task_delivery_material_input_can_refute_exclusion_without_product_source(self):
        self.package['evidence'].append({'id': 'CONTEXT', 'kind': 'context',
                                        'content': 'The task includes an external specification.'})
        for cid in ('TC14.C03', 'TC14.C04', 'TC12.C01'):
            for eid in ('U', 'CONTEXT'):
                with self.subTest(cid=cid, eid=eid):
                    entry, answer = self.exclusion_answer(cid, eid)
                    original = copy.deepcopy(answer)
                    checked = validate_review(answer, entry, self.task, self.package)
                    self.assertEqual(checked['relation'], 'contradicted')
                    self.assertTrue(checked['scope_consistency']['met'])
                    self.assertEqual(answer, original)

    def test_material_input_does_not_prove_product_capability_side_effect_or_skipped_scope(self):
        for cid, kind in (('SEC02.C01', 'external_input'), ('TC14.C03', 'side_effect'),
                          ('TC14.C03', 'skipped_scope')):
            with self.subTest(cid=cid, kind=kind):
                entry, answer = self.exclusion_answer(cid, 'U', kind)
                checked = validate_review(answer, entry, self.task, self.package)
                self.assertEqual(checked['relation'], 'unknown')
                self.assertFalse(checked['scope_consistency']['met'])
                self.assertEqual(checked['scope_consistency']['candidate_relation'], 'contradicted')
        entry, answer = self.exclusion_answer('SEC02.C01', 'S')
        checked = validate_review(answer, entry, self.task, self.package)
        self.assertEqual(checked['relation'], 'contradicted')
        self.assertTrue(checked['scope_consistency']['met'])

    def test_task_delivery_material_input_keeps_task_version_and_object_boundaries(self):
        for source in ({'id': 'FOREIGN', 'kind': 'user_requirement', 'content': 'Other task specification'},
                       {'id': 'FOREIGN', 'kind': 'context', 'content': 'Other task specification',
                        'target_ids': ['T2']},
                       {'id': 'FOREIGN', 'kind': 'context', 'content': 'Old specification',
                        'version_id': 'b' * 40}):
            with self.subTest(source=source):
                self.package['evidence'].append(source)
                entry, answer = self.exclusion_answer('TC14.C03', 'FOREIGN')
                with self.assertRaises(ValueError):
                    validate_review(answer, entry, self.task, self.package)
                self.package['evidence'].pop()
        entry, answer = self.exclusion_answer('TC14.C03', 'OLD')
        with self.assertRaises(ValueError):
            validate_review(answer, entry, self.task, self.package)
        entry, answer = self.exclusion_answer('SEC02.C01', 'U')
        answer['scope_analysis']['audit_object'] = 'task_delivery'
        with self.assertRaises(ValueError):
            validate_review(answer, entry, self.task, self.package)

    def test_excluded_source_inventory_records_presence_without_creating_proof_or_quote_choices(self):
        self.package['evidence'].extend([
            {'id': 'TOOL', 'kind': 'tool', 'name': 'original tool', 'content': 'EXCLUDED_TOOL_BODY'},
            {'id': 'FOREIGN', 'kind': 'source', 'version_id': self.task['target_commit_ids'][0],
             'target_ids': ['T2'], 'content': 'EXCLUDED_FOREIGN_BODY'},
            {'id': 'UNSELECTED_USER', 'kind': 'user_requirement', 'content': 'EXCLUDED_USER_BODY'},
            {'id': 'OLD_CONTEXT', 'kind': 'context', 'version_id': 'b' * 40, 'content': 'EXCLUDED_OLD_BODY'}])
        before = copy.deepcopy(self.package)
        payload, scoped = review_input(self.task, self.package)
        excluded = {item['id']: item for item in payload['excluded_evidence_inventory']}
        self.assertEqual(excluded['ASSISTANT']['why'], 'not_independent_scope_proof')
        self.assertEqual(excluded['TOOL']['why'], 'not_independent_scope_proof')
        self.assertEqual(excluded['FOREIGN']['why'], 'other_task')
        self.assertEqual(excluded['UNSELECTED_USER']['why'], 'outside_frozen_user_requirements')
        self.assertEqual(excluded['OLD']['why'], 'not_current_target_version')
        self.assertEqual(excluded['OLD_CONTEXT']['why'], 'not_current_target_version')
        self.assertTrue(all(set(item) == {'id', 'kind', 'name', 'why'} for item in excluded.values()))
        visible = {item['id'] for item in payload['evidence']}
        self.assertFalse(visible & set(excluded))
        self.assertEqual(visible, {item['id'] for item in scoped['evidence']})
        self.assertFalse({ref['evidence_id'] for ref in _quote_choices(scoped).values()} & set(excluded))
        self.assertNotIn('EXCLUDED_', json.dumps(payload))
        self.assertEqual(self.package, before)

    def test_original_assistant_reference_remains_identifiable_but_cannot_prove_an_exclusion(self):
        rows, failures, calls = self.exclusion_rows(('TC14.C04',)), [], []
        original = ref('ASSISTANT', '已全部完成')
        rows[0]['evidence_refs'] = [original]
        before = copy.deepcopy(self.package)
        def call(stage, system, payload, validator, **kwargs):
            calls.append(payload)
            candidate = payload['candidates'][0]['original_exclusion_candidate']
            self.assertEqual(candidate['evidence_refs'], [original])
            ids = {item['id'] for item in payload['excluded_evidence_inventory']}
            self.assertIn(candidate['evidence_refs'][0]['evidence_id'], ids)
            self.assertNotIn('ASSISTANT', {item['id'] for item in payload['evidence']})
            entry, invalid = self.exclusion_answer('TC14.C04', 'ASSISTANT')
            _, scoped = review_input(self.task, self.package)
            with self.assertRaises(ValueError):
                validate_review(invalid, entry, self.task, scoped)
            answer = self.exclusion_answer('TC14.C04', 'U')[1]
            answer.update(relation='unknown', reason='原助手来源存在，但本阶段不采用其自述作为独立排除证明。', evidence_refs=[])
            answer['scope_analysis'].update(trigger_state='unknown', basis='unknown', observations=[])
            return validator({'reviews': [answer], 'reviewed_source_ids': [
                source['id'] for source in payload['source_context_inventory']]}), None, False
        review_exclusions(rows, self.task, self.package, {}, call, 'original-source-test', failures)
        self.assertEqual(len(calls), 1)
        self.assertEqual(failures, [])
        self.assertEqual(rows[0]['result'], '未核查')
        self.assertIn('原助手来源存在', rows[0]['atomic_checks'][0]['exclusion_review']['reason'])
        self.assertEqual(self.package, before)

    def test_excluded_inventory_does_not_weaken_current_user_or_target_version_exclusion_gates(self):
        user = next(item for item in self.package['evidence'] if item['id'] == 'U')
        user['content'] += '\nOnly audit limit.py.'
        boundary = {'evidence_id': 'U', 'start_line': 2, 'end_line': 2, 'quote': 'Only audit limit.py.'}
        self.task['requirement_refs'].append(boundary)
        payload, scoped = review_input(self.task, self.package)
        entry, answer = self.exclusion_answer('TC14.C04', 'U')
        quote_id = next(oid for oid, value in _quote_choices(scoped).items() if value == boundary)
        answer.update(relation='justified', reason='User explicitly limits the audited object.',
                      excluded_scope='Objects outside limit.py', evidence_refs=[boundary])
        answer['scope_analysis'].update(trigger_state='absent', basis='explicit_user_boundary', observations=[{
            'kind': 'scope_boundary', 'state': 'absent', 'relevance': 'direct', 'note': 'Explicit object boundary.',
            'evidence_quote_ids': [quote_id], 'acceptance_ids': []}])
        self.assertEqual(validate_review(answer, entry, self.task, scoped)['relation'], 'justified')
        self.assertIn('ASSISTANT', {item['id'] for item in payload['excluded_evidence_inventory']})
        for eid in ('ASSISTANT', 'OLD'):
            bad = copy.deepcopy(answer)
            source = next(item for item in self.package['evidence'] if item['id'] == eid)
            bad['evidence_refs'] = [ref(eid, source['content'])]
            with self.subTest(eid=eid), self.assertRaises(ValueError):
                validate_review(bad, entry, self.task, scoped)
    def test_refuted_task_delivery_exclusion_remains_unknown_until_condition_review(self):
        rows, failures = self.exclusion_rows(('TC14.C03', 'TC14.C04')), []
        def call(stage, system, payload, validator, **kwargs):
            answers = [self.exclusion_answer(candidate['condition_id'], 'U')[1]
                       for candidate in payload['candidates']]
            return validator({'reviews': answers, 'reviewed_source_ids': [
                source['id'] for source in payload['source_context_inventory']]}), None, False
        review_exclusions(rows, self.task, self.package, {}, call, 'material-input-test', failures)
        self.assertEqual(failures, [])
        for row in rows:
            self.assertEqual((row['result'], row['gap_type']), ('未核查', 'applicability_uncertain'))
            checked = row['atomic_checks'][0]['exclusion_review']
            self.assertEqual(checked['relation'], 'contradicted')
            self.assertTrue(checked['scope_consistency']['met'])

    def test_exclusion_initial_batches_have_three_items_and_complete_context(self):
        rows = self.exclusion_rows(('SEC02.C01', 'SEC02.C02', 'SEC03.C01', 'SEC03.C02'))
        calls, failures = [], []
        def call(stage, system, payload, validator, **kwargs):
            calls.append(copy.deepcopy(payload))
            answers = [{'id': c['id'], 'task_id': c['task_id'], 'target_commit_ids': c['target_commit_ids'],
                'relation': 'unknown', 'reason': 'Synthetic uncertain scope', 'excluded_scope': '',
                'evidence_refs': [], 'scope_analysis': {'audit_object': c['audit_object'],
                    'judgment_dimension': c['judgment_dimension'], 'trigger_state': 'unknown',
                    'basis': 'unknown', 'observations': []}} for c in payload['candidates']]
            return validator({'reviews': answers, 'reviewed_source_ids': [
                source['id'] for source in payload['source_context_inventory']]}), None, False
        review_exclusions(rows, self.task, self.package, {}, call, 'exclusions-test', failures)
        self.assertEqual([len(payload['candidates']) for payload in calls], [3, 1])
        self.assertEqual(calls[0]['evidence'], calls[1]['evidence'])
        self.assertEqual(calls[0]['source_context_inventory'], calls[1]['source_context_inventory'])
        self.assertEqual(failures, [])
        self.assertTrue(all(row['result'] == '未核查' for row in rows))
        self.assertTrue(all(row['atomic_checks'][0]['exclusion_review']['status'] == 'completed' for row in rows))

    def test_truncated_exclusions_split_without_dropping_context_or_faking_pass(self):
        rows, calls, failures = self.exclusion_rows(), [], []
        def call(stage, system, payload, validator, **kwargs):
            calls.append((stage, copy.deepcopy(payload)))
            if len(payload['candidates']) > 1:
                return None, 'synthetic output truncation', True
            answers = [{'id': c['id'], 'task_id': c['task_id'], 'target_commit_ids': c['target_commit_ids'],
                        'relation': 'unknown', 'reason': 'Synthetic evidence gap', 'excluded_scope': '',
                        'evidence_refs': [], 'scope_analysis': {'audit_object': c['audit_object'],
                        'judgment_dimension': c['judgment_dimension'], 'trigger_state': 'unknown',
                        'basis': 'unknown', 'observations': []}} for c in payload['candidates']]
            return validator({'reviews': answers, 'reviewed_source_ids': [s['id'] for s in payload['source_context_inventory']]}), None, False
        review_exclusions(rows, self.task, self.package, {}, call, 'exclusions-test', failures)
        self.assertEqual([len(p['candidates']) for _, p in calls], [2, 1, 1])
        self.assertEqual(len({s for s, _ in calls}), 3)
        self.assertEqual(calls[0][1]['evidence'], calls[1][1]['evidence'])
        self.assertEqual(failures, [])
        for row in rows:
            self.assertEqual(row['result'], '未核查')
            self.assertEqual(row['atomic_checks'][0]['exclusion_recovery'][0]['action'], 'split_truncated_batch')

    def test_leaf_truncation_and_budget_stop_remain_failures(self):
        for budget in (False, True):
            rows, failures, calls = self.exclusion_rows(), [], []
            def call(stage, system, payload, validator, **kwargs):
                calls.append(stage)
                return None, 'budget exhausted' if budget and len(calls)>1 else 'truncated', not (budget and len(calls)>1)
            review_exclusions(rows, self.task, self.package, {}, call, 'exclusions-test', failures)
            self.assertEqual(len(calls), 3)
            self.assertEqual(len(failures), 2)
            self.assertTrue(all(row['gap_type'] == 'analysis_failed' for row in rows))

    def test_exclusion_retries_only_invalid_item_and_preserves_stage_errors(self):
        for persist in (False, True):
            with self.subTest(persist=persist), tempfile.TemporaryDirectory() as directory:
                rows, calls, failures = self.exclusion_rows(), [], []
                def call(stage, system, payload, validator, **kwargs):
                    calls.append(copy.deepcopy(payload))
                    self.assertEqual(payload['acceptance_id_choices'], ['A1'])
                    if len(calls) == 2:
                        self.assertEqual([c['id'] for c in payload['candidates']], ['SEC02.C01.I01'])
                        error = payload['item_validation_feedback']['SEC02.C01.I01']
                        self.assertIn('observations[0].acceptance_ids', error)
                        self.assertIn('不能使用task_id', error)
                    answers = []
                    for c in payload['candidates']:
                        bad = c['id'] == 'SEC02.C01.I01' and (len(calls) == 1 or persist)
                        answers.append({'id': c['id'], 'task_id': c['task_id'],
                            'target_commit_ids': c['target_commit_ids'], 'relation': 'unknown',
                            'reason': 'Synthetic uncertain scope', 'excluded_scope': '', 'evidence_refs': [],
                            'scope_analysis': {'audit_object': c['audit_object'],
                                'judgment_dimension': c['judgment_dimension'], 'trigger_state': 'unknown',
                                'basis': 'unknown', 'observations': [{'kind': 'scope_boundary',
                                    'state': 'unknown', 'relevance': 'unknown', 'note': 'Synthetic unknown scope',
                                    'evidence_quote_ids': [], 'acceptance_ids': [self.task['id']] if bad else []}]}})
                    return validator({'reviews': answers, 'reviewed_source_ids': [
                        s['id'] for s in payload['source_context_inventory']]}), None, False
                review_exclusions(rows, self.task, self.package, {}, call, 'exclusions-test', failures,
                                  directory=directory)
                self.assertEqual(len(calls), 2)
                self.assertEqual(calls[0]['evidence'], calls[1]['evidence'])
                self.assertEqual(len(failures), int(persist))
                self.assertEqual(rows[1]['result'], '未核查')
                self.assertNotEqual(rows[1]['gap_type'], 'analysis_failed')
                artifacts = list(Path(directory).glob('*.rows-validation.json'))
                self.assertEqual(len(artifacts), 2)
                first = json.loads(next(p for p in artifacts if '-retry.' not in p.name).read_text())
                self.assertEqual(first['retained_item_ids'], ['SEC02.C02.I01'])
                self.assertIn('SEC02.C01.I01', first['errors'])
                self.assertEqual(rows[0]['atomic_checks'][0]['exclusion_recovery'][0]['action'], 'retry_invalid_item')

    def test_unknown_excluded_scope_is_empty_string_and_array_has_precise_feedback(self):
        entry, answer = self.exclusion_answer('TC14.C01', 'U')
        answer.update(relation='unknown', excluded_scope='', reason='Scope remains unknown')
        checked = validate_review(answer, entry, self.task, self.package)
        self.assertEqual(checked['relation'], 'unknown')
        self.assertEqual(checked['excluded_scope'], '')
        answer['excluded_scope'] = []
        with self.assertRaisesRegex(ValueError, 'excluded_scope必须是字符串'):
            validate_review(answer, entry, self.task, self.package)
        self.assertEqual(answer['excluded_scope'], [])


    def test_exclusion_source_inventory_reports_missing_extra_and_duplicate(self):
        rows, failures = self.exclusion_rows(('SEC02.C01',)), []
        def call(stage, system, payload, validator, **kwargs):
            answers = [{'id': c['id'], 'task_id': c['task_id'], 'target_commit_ids': c['target_commit_ids'],
                'relation': 'unknown', 'reason': 'Synthetic uncertain scope', 'excluded_scope': '',
                'evidence_refs': [], 'scope_analysis': {'audit_object': c['audit_object'],
                    'judgment_dimension': c['judgment_dimension'], 'trigger_state': 'unknown',
                    'basis': 'unknown', 'observations': []}} for c in payload['candidates']]
            sources = [item['id'] for item in payload['source_context_inventory']]
            self.assertTrue(sources)
            cases = ((sources[:-1], "missing=" + repr([sources[-1]])),
                     (sources + ['UNLISTED'], "extra=['UNLISTED']"),
                     (sources + sources[:1], 'duplicates=True'))
            for supplied, expected in cases:
                with self.subTest(supplied=supplied):
                    valid, invalid = validator({'reviews': answers, 'reviewed_source_ids': supplied})
                    self.assertEqual(valid, {})
                    self.assertEqual(set(invalid), {c['id'] for c in payload['candidates']})
                    self.assertTrue(all(expected in reason for reason in invalid.values()))
            for supplied in ([], answers * 2, [{**answers[0], 'id': 'UNLISTED_ITEM'}]):
                valid, invalid = validator({'reviews': supplied, 'reviewed_source_ids': sources})
                self.assertEqual(valid, {})
                self.assertEqual(set(invalid), {c['id'] for c in payload['candidates']})
            for malformed in ({'reviews': answers, 'reviewed_source_ids': [{}]},
                              {'reviews': answers},
                              {'reviews': answers, 'reviewed_source_ids': sources, 'extra': True},
                              {'reviews': {}, 'reviewed_source_ids': sources}):
                with self.assertRaises(ValueError):
                    validator(malformed)
            return validator({'reviews': answers, 'reviewed_source_ids': sources}), None, False
        review_exclusions(rows, self.task, self.package, {}, call, 'source-ids-test', failures)
        self.assertEqual(failures, [])



    def test_coverage_mismatch_uses_only_existing_one_shot_recovery(self):
        for second_valid in (True, False):
            with self.subTest(second_valid=second_valid):
                rows, failures, calls = self.exclusion_rows(('SEC02.C01',)), [], []
                def call(stage, system, payload, validator, **kwargs):
                    calls.append(copy.deepcopy(payload))
                    self.assertEqual(kwargs['attempts'], 1)
                    answers = [{'id': c['id'], 'task_id': c['task_id'], 'target_commit_ids': c['target_commit_ids'],
                        'relation': 'unknown', 'reason': 'Synthetic uncertain scope', 'excluded_scope': '',
                        'evidence_refs': [], 'scope_analysis': {'audit_object': c['audit_object'],
                            'judgment_dimension': c['judgment_dimension'], 'trigger_state': 'unknown',
                            'basis': 'unknown', 'observations': []}} for c in payload['candidates']]
                    sources = [source['id'] for source in payload['source_context_inventory']]
                    if len(calls) == 1 or not second_valid:
                        sources.append('UNLISTED')
                    return validator({'reviews': answers, 'reviewed_source_ids': sources}), None, False
                with tempfile.TemporaryDirectory() as directory:
                    review_exclusions(rows, self.task, self.package, {}, call,
                                      'coverage-recovery-test', failures, directory=directory)
                    receipts = [json.loads(p.read_text()) for p in sorted(Path(directory).glob('*.rows-validation.json'))]
                self.assertEqual(len(calls), 2)
                self.assertEqual(len(receipts), 2)
                first = next(receipt for receipt in receipts if receipt['errors'])
                self.assertEqual(first['retained_item_ids'], [])
                self.assertTrue(all("extra=['UNLISTED']" in reason for reason in first['errors'].values()))
                self.assertEqual(bool(failures), not second_valid)
                self.assertTrue(all(row['result'] == '未核查' for row in rows))
                self.assertTrue(all(row.get('gap_type') == 'analysis_failed' for row in rows) if not second_valid else True)



class OriginalTriggerVersionTests(unittest.TestCase):
    setUp = EvidenceGapTests.setUp
    candidate = EvidenceGapTests.candidate

    def test_direct_parent_proves_original_trigger_without_fake_target_ref(self):
        condition, answer = self.candidate('FIX03.C03')
        for atom in answer['atomic_checks']:
            atom['evidence_refs'] = [ref('S', 'return 25 if value is None else value')]
        answer['evidence_refs'] = [ref('S', 'return 25 if value is None else value')]
        answer['atomic_checks'][0]['evidence_refs'] = [ref('OLD', 'return value or 25')]
        row = _condition_response({'conditions': [answer]}, self.task, [condition], self.package)[0]
        self.assertEqual(row['atomic_checks'][0]['result'], '满足')
        self.assertEqual(row['atomic_checks'][0]['evidence_refs'][0]['evidence_id'], 'OLD')
        for bad_case in ('wrong_quote', 'wrong_version', 'foreign_task', 'sibling', 'custom'):
            cond, ans, pkg = copy.deepcopy((condition, answer, self.package))
            if bad_case == 'wrong_quote':
                ans['atomic_checks'][0]['evidence_refs'][0]['quote'] = 'invented'
            elif bad_case == 'wrong_version':
                next(e for e in pkg['evidence'] if e['id'] == 'OLD')['version_id'] = 'c' * 40
            elif bad_case == 'foreign_task':
                next(e for e in pkg['evidence'] if e['id'] == 'OLD')['target_ids'] = ['OTHER']
            elif bad_case == 'sibling':
                ans['atomic_checks'][1]['evidence_refs'] = ans['atomic_checks'][0]['evidence_refs']
            else:
                cond['contract']['origin'] = 'uploaded'
            with self.subTest(case=bad_case), self.assertRaises(ValueError):
                _condition_response({'conditions': [ans]}, self.task, [cond], pkg)

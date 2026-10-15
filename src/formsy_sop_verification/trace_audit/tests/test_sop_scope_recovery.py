"""Length recovery shrinks claims, retains full truth, and never retries transport failures."""
import copy
import json
import unittest
from unittest.mock import patch

from ..audit_engine import model_input
from ..model_client import ModelOutputError
from ..sop_audit import audit_sop
from ..sop_claim_review import _run_scope_batch, extract_response, review_claim_scope
from ..sop_judgments import statement_review_inventory
from . import test_sop_claim_review as original
from . import test_sop_audit as audit_fixtures


class ScopeRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.f = original.ClaimStageTests()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.task, self.package, self.directory = self.f.task, self.f.package, self.f.directory
        self.request = model_input(self.package, [self.task])
        self.truth = {'fixed_task': self.task, 'evidence': [e for e in self.request['evidence'] if e['kind'] != 'assistant'],
                      'commits': self.request['commits'], 'program_run_verification': []}
        reviews = extract_response({'sources': self.f.sources()}, statement_review_inventory(self.task, self.package),
                                   self.task, self.package)
        self.claims = [c for s in reviews for c in s['claims']]
        self.candidates = {c['id']: {**c, **{k: v for k, v in row.items() if k != 'claim_id'}}
                           for c, row in zip(self.claims, self.f.compare(self.claims)['comparisons'])}
        self.calls = []

    def response(self, payload):
        return {'scope_reviews': [{**row, 'scope_consistency': 'same_scope'}
                                  for row in self.f.compare(payload['frozen_claims'])['comparisons']]}

    def run_batch(self, call):
        return _run_scope_batch(self.claims, self.candidates, self.task, self.package, self.truth,
                                call, 'scope', self.directory)

    def record(self, stage, payload, kwargs):
        self.calls.append((stage, copy.deepcopy(payload), copy.deepcopy(kwargs)))
        self.assertEqual(kwargs, {'attempts': 1, 'final_failure': False})

    def test_length_splits_complete_claims_and_truth_and_drops_only_recovered_parent_error(self):
        before = copy.deepcopy((self.claims, self.candidates))
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            if len(payload['frozen_claims']) > 1:
                return None, 'provider_incomplete_output', True
            return validator(self.response(payload)), None, False
        rows, errors = self.run_batch(call)
        self.assertFalse(errors)
        self.assertEqual([len(p['frozen_claims']) for _, p, _ in self.calls], [2, 1, 1])
        self.assertEqual([r['relation'] for r in rows], ['supported', 'supported'])
        self.assertEqual({r['claim_id'] for r in rows}, set(self.candidates))
        self.assertEqual((self.claims, self.candidates), before)
        for _, payload, _ in self.calls:
            self.assertEqual(payload['evidence'], self.calls[0][1]['evidence'])
            for claim in payload['frozen_claims']:
                self.assertEqual(claim, next(c for c in before[0] if c['id'] == claim['id']))
        saved = json.loads((self.directory / 'scope.batch-split.json').read_text())
        self.assertEqual(saved['reason'], 'provider_incomplete_output')
        self.assertEqual(saved['child_ids'], [[self.claims[0]['id']], [self.claims[1]['id']]])
        self.assertEqual(len(list(self.directory.glob('*.scope-attempt.json'))), 3)

    def test_http_failure_is_not_retried_or_split(self):
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            return None, 'HTTP 503', False
        rows, errors = self.run_batch(call)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(errors, ['HTTP 503'])
        self.assertTrue(all(r['relation'] == 'uncertain' for r in rows))
        self.assertFalse(list(self.directory.glob('*.batch-split.json')))

    def test_single_claim_length_is_final_and_keeps_stage_error(self):
        self.claims = self.claims[:1]
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            return None, 'provider_incomplete_output', True
        rows, errors = self.run_batch(call)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(errors, ['provider_incomplete_output'])
        self.assertEqual(rows[0]['relation'], 'uncertain')
        self.assertFalse(list(self.directory.glob('*.batch-split.json')))

    def test_repeated_length_stops_at_single_claim_without_extra_retry(self):
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            return None, 'provider_incomplete_output', True
        rows, errors = self.run_batch(call)
        self.assertEqual([len(p['frozen_claims']) for _, p, _ in self.calls], [2, 1, 1])
        self.assertEqual(len(errors), 2)
        self.assertTrue(all(r['relation'] == 'uncertain' for r in rows))

    def test_shared_budget_exhaustion_preserves_completed_sibling_and_unknown_pending(self):
        dispatched = []
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            if len(dispatched) >= 2:
                return None, 'shared budget exhausted', False
            dispatched.append(stage)
            if len(payload['frozen_claims']) > 1:
                return None, 'provider_incomplete_output', True
            return validator(self.response(payload)), None, False
        rows, errors = self.run_batch(call)
        self.assertEqual(len(dispatched), 2)
        self.assertEqual([r['relation'] for r in rows], ['supported', 'uncertain'])
        self.assertEqual(errors, ['shared budget exhausted'])

    def test_invalid_row_is_isolated_without_splitting_or_retrying_other_rows(self):
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            value = self.response(payload)
            value['scope_reviews'][0]['source_refs'][0]['quote'] = 'invented quote'
            return validator(value), None, False
        rows, errors = self.run_batch(call)
        self.assertEqual(len(self.calls), 1)
        self.assertEqual([r['relation'] for r in rows], ['uncertain', 'supported'])
        self.assertEqual(len(errors), 1)
        self.assertEqual(rows[0]['source_refs'], self.candidates[self.claims[0]['id']]['source_refs'])

    def test_incomplete_unique_envelope_never_adopts_a_partial_response(self):
        def call(stage, system, payload, validator, **kwargs):
            self.record(stage, payload, kwargs)
            value = self.response(payload)
            value['scope_reviews'] = value['scope_reviews'][:1]
            try:
                return validator(value), None, False
            except ValueError as exc:
                return None, str(exc), False
        rows, errors = self.run_batch(call)
        self.assertEqual(len(self.calls), 1)
        self.assertTrue(all(r['relation'] == 'uncertain' for r in rows))
        self.assertEqual(len(errors), 1)

    def pipeline_call(self, *, fail_last=False, narrowed=False):
        def call(stage, system, payload, validator, **kwargs):
            if 'source_inventory' in payload:
                return validator({'sources': self.f.sources()}), None, False
            if 'scope_candidates' not in payload:
                return validator(self.f.compare(payload['frozen_claims'])), None, False
            self.record(stage, payload, kwargs)
            self.assertIn('不能把完整命题裁成存在事实后判supported', system)
            if len(payload['frozen_claims']) > 1:
                return None, 'provider_incomplete_output', True
            if fail_last and stage.endswith('split-2'):
                return None, 'HTTP 503', False
            response = self.response(payload)
            if narrowed and stage.endswith('split-1'):
                response['scope_reviews'][0].update(scope_consistency='narrowed_scope', relation='uncertain',
                    reason='Only file presence is proven; runner discovery/use inference remains unknown.')
            return validator(response), None, False
        return call

    def test_pipeline_keeps_whole_mixed_sentence_and_independent_narrowed_scope_after_split(self):
        self.package['evidence'][next(i for i,e in enumerate(self.package['evidence']) if e['id'] == 'A')]['content'] = (
            'The file is present, which suggests that the runner should discover and use it.')
        original_sources = self.f.sources
        def sources():
            value = original_sources()
            value[0]['claims'][0]['claim_target']['property'] = 'file presence'
            return value
        self.f.sources = sources
        row = review_claim_scope(self.task, self.package, self.f.condition,
                                 model_input(self.package, [self.task]), self.pipeline_call(narrowed=True),
                                 'claims', self.directory, lambda _: None)
        claims = row['atomic_checks'][0]['semantic_basis']['claims']
        self.assertEqual(claims[0]['proposition'], self.package['evidence'][-2]['content'])
        self.assertIn('runner should discover and use it', claims[0]['proposition'])
        self.assertEqual([c['relation'] for c in claims], ['uncertain', 'supported'])
        self.assertFalse(row['analysis_stage_errors'])
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['gap_type'], 'evidence_missing')

    def test_pipeline_preserves_unrecovered_child_scope_errors(self):
        row = review_claim_scope(self.task, self.package, self.f.condition, self.request,
                                 self.pipeline_call(fail_last=True), 'claims', self.directory, lambda _: None)
        self.assertEqual(row['analysis_stage_errors'], ['HTTP 503'])
        saved = json.loads((self.directory / 'claims.claim-review.json').read_text())
        self.assertEqual(saved['scope_errors'], ['HTTP 503'])
        self.assertEqual([c['relation'] for c in row['atomic_checks'][0]['semantic_basis']['claims']],
                         ['supported', 'uncertain'])
        self.assertEqual(len(self.calls), 3)

    def test_original_top_level_batch_cap_does_not_block_truncated_children(self):
        with patch('formsy_sop_verification.trace_audit.sop_claim_review.SCOPE_BATCH', 2), \
             patch('formsy_sop_verification.trace_audit.sop_claim_review.MAX_SCOPE_BATCHES', 1):
            row = review_claim_scope(self.task, self.package, self.f.condition, self.request,
                                     self.pipeline_call(), 'claims', self.directory, lambda _: None)
        self.assertEqual(len(self.calls), 3)
        self.assertFalse(row['analysis_stage_errors'])
        self.assertEqual(row['result'], '满足')

    def native_audit(self, *, single_length=False, budget=64):
        # Retain the native contract and only this condition; exercise the actual shared call closure.
        catalog_rule = {'id': 'TC14', 'document_id': 'technical-0.2', 'version': '0.2',
                        'title': 'Source scope', 'applicability': '外部依据与继承证据',
                        'source_ref': self.f.condition['source_ref'],
                        'conditions': [copy.deepcopy(self.f.condition)]}
        def respond(payload):
            if 'candidate_rules' in payload:
                return {'rules': [{'rule_id': 'TC14', 'selection': 'selected', 'reason': 'Source review applies',
                                  'evidence_refs': [audit_fixtures.ref('S', 'return 25 if value is None else value')]}]}
            if 'source_inventory' in payload:
                return {'sources': self.f.sources()}
            if 'scope_candidates' not in payload:
                return self.f.compare(payload['frozen_claims'])
            if len(payload['frozen_claims']) > 1 or single_length and payload['frozen_claims'][0]['statement_refs'][0]['evidence_id'] == 'A2':
                raise ModelOutputError('provider_incomplete_output', truncated=True)
            return self.response(payload)
        client = audit_fixtures.Client(respond)
        result = audit_sop(copy.deepcopy(self.f.result), copy.deepcopy(self.package),
                           {'rules': [catalog_rule], 'documents': [], 'sha256': 'synthetic'},
                           client, self.directory, max_calls=budget)
        return result, client

    def test_actual_audit_call_does_not_keep_recovered_parent_failure_in_final_failures(self):
        result, client = self.native_audit()
        self.assertTrue(result['sop_coverage']['analysis_complete'])
        self.assertFalse(result['sop_coverage']['failures'])
        self.assertTrue(list(self.directory.glob('*scope*.validation.json')))
        self.assertTrue(list(self.directory.glob('*scope*.batch-split.json')))
        self.assertEqual(len([s for s, _ in client.calls if '-scope-' in s]), 3)

    def test_actual_audit_keeps_single_length_and_budget_exhaustion_as_analysis_failures(self):
        for options in [{'single_length': True}, {'budget': 5}]:
            with self.subTest(options=options):
                result, client = self.native_audit(**options)
                row = result['sop_condition_checks'][0]
                self.assertFalse(result['sop_coverage']['analysis_complete'])
                self.assertTrue(result['sop_coverage']['failures'])
                self.assertEqual(row['gap_type'], 'analysis_failed')
                self.assertEqual([c['relation'] for c in row['atomic_checks'][0]['semantic_basis']['claims']],
                                 ['supported', 'uncertain'])
                self.assertLessEqual(len(client.calls), options.get('budget', 64))


if __name__ == '__main__':
    unittest.main()

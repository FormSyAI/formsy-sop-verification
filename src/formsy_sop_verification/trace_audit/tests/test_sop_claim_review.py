"""Claim extraction is source-only; comparison cannot rewrite original meaning."""
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ..audit_engine import model_input
from ..sop_catalog import load_catalog
from ..sop_claim_review import comparison_response, extract_response, review_claim_scope, statement_choices, scope_response
from ..sop_judgments import apply_atomic_gates, statement_review_inventory, FAIL, PASS, UNKNOWN
from .test_sop_audit import fixtures, ref, SHA, PARENT


class ClaimStageTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.package['evidence'] = [item for item in self.package['evidence'] if item['kind'] != 'assistant']
        self.package['evidence'].extend([
            {'id': 'A', 'kind': 'assistant', 'content': 'The file changed. I plan to verify it.'},
            {'id': 'A2', 'kind': 'assistant', 'content': 'The original code never preserved zero.'}])
        rule = next(rule for rule in load_catalog(Path(__file__).resolve().parents[1])['rules'] if rule['id'] == 'TC14')
        self.condition = next(condition for condition in rule['conditions'] if condition['id'] == 'TC14.C02')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.calls = []

    def sources(self):
        choices = statement_choices(self.package, {'A', 'A2'})
        output = []
        for eid in ('A', 'A2'):
            choice = next(choice for choice in choices if choice['evidence_id'] == eid)
            hedged = choice['proposition'].startswith('Maybe')
            output.append({'evidence_id': eid, 'classification': 'claims', 'reason': 'Explicit original statement.',
                           'claims': [{'statement_id': choice['statement_id'],
                                       'claim_type': 'diagnosis' if hedged else 'fact',
                                       'claim_target': {'object': 'original code', 'property': choice['proposition'],
                                                        'scope': 'cause_hypothesis' if hedged else 'effective_state',
                                                        'state_assertion': None}}]})
        return output

    def compare(self, claims, relation='supported'):
        return {'comparisons': [{'claim_id': claim['id'], 'relation': relation, 'comparison_type': claim['claim_type'],
                'comparison_scope': 'same_property', 'observation_commit_ids': [SHA],
                'source_refs': [ref('S', 'return 25 if value is None else value')],
                'reason': 'The same property is compared without upgrading a plan to execution.'} for claim in claims]}

    def review(self, respond=None):
        def call(stage, system, payload, validator, **kwargs):
            self.calls.append(copy.deepcopy(payload))
            value = (respond(payload) if respond else {'sources': self.sources()} if 'source_inventory' in payload
                     else self.compare(payload['frozen_claims']))
            if 'scope_candidates' in payload and 'comparisons' in value:
                value = {'scope_reviews': [{**row, 'scope_consistency': 'same_scope'} for row in value['comparisons']]}
            return validator(value), None, False
        row = review_claim_scope(self.task, self.package, self.condition,
                                 model_input(self.package, [self.task]), call, 'claims', self.directory, lambda _: None)
        row['contract'] = self.condition['contract']
        apply_atomic_gates(row, self.task, self.package)
        return row

    def test_extraction_never_receives_patch_user_goal_or_execution_outcome(self):
        before = copy.deepcopy(self.package)
        row = self.review()
        payload = self.calls[0]
        self.assertEqual(set(payload), {'source_inventory', 'evidence', 'statement_choices'})
        self.assertEqual({item['kind'] for item in payload['evidence']}, {'assistant'})
        self.assertNotIn('return 25', json.dumps(payload))
        self.assertNotIn('acceptance_checks', payload)
        self.assertEqual(self.package, before)
        self.assertEqual(row['result'], PASS)

    def test_frozen_proposition_and_type_are_program_assembled_not_regenerated(self):
        row = self.review()
        frozen = json.loads((self.directory / 'claims.frozen-claims.json').read_text())
        claims = [claim for source in frozen['sources'] for claim in source['claims']]
        final = row['atomic_checks'][0]['semantic_basis']['claims']
        self.assertEqual([(claim['proposition'], claim['claim_type'], claim['claim_target'], claim['statement_refs'])
                          for claim in claims], [(claim['proposition'], claim['claim_type'], claim['claim_target'],
                                                  claim['statement_refs']) for claim in final])
        self.assertEqual(len(frozen['sources']), 2)

    def test_extraction_rejects_paraphrase_and_wrong_speaker(self):
        sources = self.sources()
        inventory = statement_review_inventory(self.task, self.package)
        sources[0]['claims'][0]['proposition'] = 'Verification succeeded.'
        with self.assertRaisesRegex(ValueError, '裁剪'):
            extract_response({'sources': sources}, inventory, self.task, self.package)
        sources = self.sources()
        sources[0]['claims'][0]['statement_id'] = sources[1]['claims'][0]['statement_id']
        with self.assertRaisesRegex(ValueError, '同一原Agent'):
            extract_response({'sources': sources}, inventory, self.task, self.package)

    def test_source_inventory_cannot_skip_duplicate_or_invent_sources(self):
        inventory = statement_review_inventory(self.task, self.package)
        for sources in [self.sources()[:1], self.sources()[:1] * 2,
                        [dict(self.sources()[0], evidence_id='INVENTED'), self.sources()[1]]]:
            with self.assertRaisesRegex(ValueError, '完整且唯一'):
                extract_response({'sources': sources}, inventory, self.task, self.package)

    def test_comparison_cannot_overwrite_frozen_fields(self):
        claim = extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                 self.task, self.package)[0]['claims'][0]
        for key, val in [('id', 'REPLACED-ID'), ('proposition', 'It passed.'),
                         ('claim_type', 'actual_state'), ('statement_refs', []),
                         ('claim_target', {'object': 'subclass', 'property': 'no direct assignment',
                                           'scope': 'local_structure', 'state_assertion': None})]:
            value = self.compare([claim])
            value['comparisons'][0][key] = val
            with self.assertRaisesRegex(ValueError, '不能重新提取'):
                comparison_response(value, [claim], self.task, self.package)

    def test_fact_rebutted_as_actual_success_is_not_a_confirmed_failure(self):
        def respond(payload):
            if 'source_inventory' in payload:
                return {'sources': self.sources()}
            value = self.compare(payload['frozen_claims'])
            value['comparisons'][0].update(relation='exceeds_source', comparison_type='actual_state')
            return value
        self.assertEqual(self.review(respond)['result'], UNKNOWN)

    def test_local_fact_counterexample_survives_an_uncertain_plan(self):
        def respond(payload):
            if 'source_inventory' in payload:
                return {'sources': self.sources()}
            value = self.compare(payload['frozen_claims'])
            value['comparisons'][0].update(relation='uncertain', comparison_scope='unknown', source_refs=[])
            value['comparisons'][1].update(relation='exceeds_source', observation_commit_ids=[PARENT],
                                          source_refs=[ref('OLD', 'return value or 25')])
            return value
        self.assertEqual(self.review(respond)['result'], FAIL)

    def test_uncertain_source_review_does_not_become_all_claims_pass(self):
        def respond(payload):
            if 'source_inventory' in payload:
                sources = self.sources()
                sources[1].update(classification='uncertain', claims=[])
                return {'sources': sources}
            return self.compare(payload['frozen_claims'])
        self.assertEqual(self.review(respond)['result'], UNKNOWN)

    def test_extraction_failure_retains_full_inventory_and_no_success(self):
        row = review_claim_scope(self.task, self.package, self.condition,
              model_input(self.package, [self.task]), lambda *args, **kwargs: (None, 'budget exhausted', False),
              'claims', self.directory, lambda _: None)
        basis = row['atomic_checks'][0]['semantic_basis']
        self.assertEqual(row['result'], UNKNOWN)
        self.assertEqual(basis['covered_source_ids'], ['A', 'A2'])
        self.assertTrue(all(source['classification'] == 'uncertain' for source in basis['source_reviews']))
        self.assertEqual(basis['claims'], [])
        self.assertEqual(row['analysis_stage_errors'], ['budget exhausted'])

    def test_model_cannot_delete_hedging_from_program_sentence_choice(self):
        self.package['evidence'][ -1]['content'] = 'Maybe the domain was never initialized.'
        choices = statement_choices(self.package, {'A2'})
        self.assertEqual(choices[0]['proposition'], 'Maybe the domain was never initialized.')
        sources = self.sources()
        extracted = extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                                     self.task, self.package)
        self.assertEqual(extracted[1]['claims'][0]['proposition'], 'Maybe the domain was never initialized.')

    def test_multi_batch_extraction_does_not_drop_a_later_source(self):
        self.package['evidence'].extend({'id': 'A' + str(index), 'kind': 'assistant', 'content': 'Inspect the file.'}
                                        for index in range(3, 16))
        def respond(payload):
            return {'sources': [{'evidence_id': item['evidence_id'], 'classification': 'no_claim',
                                 'reason': 'Only an instruction to inspect, no fact claim.', 'claims': []}
                                for item in payload['source_inventory']]}
        row = self.review(respond)
        self.assertEqual([len(payload['source_inventory']) for payload in self.calls], [12, 3])
        self.assertEqual(len(row['atomic_checks'][0]['semantic_basis']['source_reviews']), 15)
        self.assertEqual(row['result'], UNKNOWN, 'Source enumeration alone is not substantive proof.')

    def test_composite_diagnosis_keeps_asserted_premise_separate_without_deleting_hedge(self):
        sentence = 'This is likely the cause, as the attribute is used without being set.'
        self.package['evidence'][-1]['content'] = sentence
        sources = self.sources()
        choice = next(choice for choice in statement_choices(self.package, {'A2'})
                      if choice['evidence_id'] == 'A2')
        sources[1]['claims'] = [
            {'statement_id': choice['statement_id'], 'claim_type': 'diagnosis',
             'claim_target': {'object': 'error cause', 'property': 'likely caused by unset attribute',
                              'scope': 'cause_hypothesis', 'state_assertion': None}},
            {'statement_id': choice['statement_id'], 'claim_type': 'fact',
             'claim_target': {'object': 'instance attribute', 'property': 'asserted unset before use',
                              'scope': 'effective_state', 'state_assertion': None}}]
        extracted = extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                                     self.task, self.package)[1]['claims']
        self.assertEqual(len({claim['id'] for claim in extracted}), 2)
        self.assertEqual([claim['proposition'] for claim in extracted], [sentence, sentence])
        self.assertEqual([claim['claim_target']['scope'] for claim in extracted],
                         ['cause_hypothesis', 'effective_state'])
        self.assertTrue(all(claim['statement_refs'][0]['quote'] == sentence for claim in extracted))

    def test_pure_intent_is_recorded_without_comparison_or_vacuous_pass(self):
        self.package['evidence'] = [item for item in self.package['evidence'] if item['id'] != 'A2']
        next(item for item in self.package['evidence'] if item['id'] == 'A')['content'] = 'I plan to verify it.'
        choice = statement_choices(self.package, {'A'})[0]
        source = {'evidence_id': 'A', 'classification': 'claims', 'reason': 'Only future verification intent.',
                  'claims': [{'statement_id': choice['statement_id'], 'claim_type': 'plan',
                              'claim_target': {'object': 'verification', 'property': 'future intent only',
                                               'scope': 'plan_intent', 'state_assertion': None}}]}
        row = self.review(lambda payload: {'sources': [source]})
        self.assertEqual(len(self.calls), 1, 'Pure intentions must not consume comparison calls.')
        self.assertEqual(row['result'], UNKNOWN)
        frozen = json.loads((self.directory / 'claims.frozen-claims.json').read_text())['sources'][0]
        self.assertEqual(frozen['classification'], 'no_claim')
        self.assertEqual(frozen['claims'], [])
        self.assertEqual(len(frozen['excluded_intents']), 1)
        self.assertIn('不进入事实真假比较', frozen['reason'])

    def test_mixed_source_keeps_fact_and_excludes_only_future_intent(self):
        sources = self.sources()
        choice = next(choice for choice in statement_choices(self.package, {'A'})
                      if choice['proposition'].startswith('I plan'))
        sources[0]['claims'].append({'statement_id': choice['statement_id'], 'claim_type': 'plan',
                                    'claim_target': {'object': 'verification', 'property': 'future intent only',
                                                     'scope': 'plan_intent', 'state_assertion': None}})
        def respond(payload):
            return {'sources': sources} if 'source_inventory' in payload else self.compare(payload['frozen_claims'])
        row = self.review(respond)
        self.assertEqual(row['result'], PASS)
        self.assertEqual(len(self.calls[1]['frozen_claims']), 2)
        self.assertFalse(any(claim['claim_type'] == 'plan' for claim in self.calls[1]['frozen_claims']))
        frozen = json.loads((self.directory / 'claims.frozen-claims.json').read_text())['sources'][0]
        self.assertEqual(frozen['classification'], 'claims')
        self.assertEqual(len(frozen['claims']), 1)
        self.assertEqual(len(frozen['excluded_intents']), 1)

    def test_plan_with_factual_premise_keeps_the_premise_for_comparison(self):
        sentence = 'Since the instance attribute is unset, I plan to initialize it.'
        self.package['evidence'][-1]['content'] = sentence
        sources = self.sources()
        target = sources[1]['claims'][0]['claim_target']
        target.update(object='instance attribute', property='asserted unset', scope='effective_state')
        sources[1]['claims'].append({'statement_id': sources[1]['claims'][0]['statement_id'],
                                    'claim_type': 'plan', 'claim_target': {
                                        'object': 'initialization', 'property': 'future initialization intent',
                                        'scope': 'plan_intent', 'state_assertion': None}})
        result = extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                                  self.task, self.package)[1]
        self.assertEqual(result['classification'], 'claims')
        self.assertEqual(result['claims'][0]['proposition'], sentence)
        self.assertEqual(result['claims'][0]['claim_target']['scope'], 'effective_state')
        self.assertEqual(len(result['excluded_intents']), 1)

    def test_assistant_cannot_authenticate_itself_even_when_relation_uncertain(self):
        claim = extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                 self.task, self.package)[0]['claims'][0]
        for relation in ('supported', 'uncertain'):
            value = self.compare([claim], relation)
            value['comparisons'][0]['source_refs'] = [ref('A', 'The file changed.')]
            with self.assertRaisesRegex(ValueError, claim['id'] + '.*evidence_id=A.*kind=assistant'):
                comparison_response(value, [claim], self.task, self.package)

    def test_mixed_real_and_assistant_source_is_rejected_without_silently_keeping_supported(self):
        claim = extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                 self.task, self.package)[0]['claims'][0]
        value = self.compare([claim])
        value['comparisons'][0]['source_refs'].append(ref('A', 'The file changed.'))
        with self.assertRaisesRegex(ValueError, 'kind=assistant'):
            comparison_response(value, [claim], self.task, self.package)

    def test_field_feedback_names_claim_and_exact_extra_or_missing_fields(self):
        claim = extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                 self.task, self.package)[0]['claims'][0]
        value = self.compare([claim])
        value['comparisons'][0]['observation_class'] = 'invented'
        with self.assertRaisesRegex(ValueError, claim['id'] + ".*extra=.*observation_class"):
            comparison_response(value, [claim], self.task, self.package)
        value = self.compare([claim])
        del value['comparisons'][0]['observation_commit_ids']
        with self.assertRaisesRegex(ValueError, claim['id'] + ".*missing=.*observation_commit_ids"):
            comparison_response(value, [claim], self.task, self.package)

    def test_many_intent_sources_preserve_inventory_and_leave_comparison_budget(self):
        self.package['evidence'] = [item for item in self.package['evidence'] if item['id'] != 'A2']
        self.package['evidence'].extend({'id': 'P' + str(i), 'kind': 'assistant',
                                        'content': 'I plan to inspect step ' + str(i) + '.'} for i in range(45))
        def respond(payload):
            if 'source_inventory' not in payload:
                return self.compare(payload['frozen_claims'])
            sources = []
            for source in payload['source_inventory']:
                eid = source['evidence_id']
                choice = next(c for c in payload['statement_choices'] if c['evidence_id'] == eid)
                sources.append({'evidence_id': eid, 'classification': 'claims',
                                'reason': 'Original fact.' if eid == 'A' else 'Pure future inspection intent.',
                                'claims': [{'statement_id': choice['statement_id'],
                                            'claim_type': 'fact' if eid == 'A' else 'plan',
                                            'claim_target': {'object': 'file' if eid == 'A' else 'inspection',
                                                             'property': choice['proposition'],
                                                             'scope': 'effective_state' if eid == 'A'
                                                             else 'plan_intent', 'state_assertion': None}}]})
            return {'sources': sources}
        row = self.review(respond)
        self.assertEqual(row['result'], PASS)
        self.assertEqual(len(self.calls), 6, '46 sources need four extraction calls, one fact comparison and one scope review.')
        frozen = json.loads((self.directory / 'claims.frozen-claims.json').read_text())['sources']
        self.assertEqual(len(frozen), 46)
        self.assertEqual(sum(len(source['claims']) for source in frozen), 1)
        self.assertEqual(sum(len(source['excluded_intents']) for source in frozen), 45)
        self.assertEqual(sum(source['classification'] == 'no_claim' for source in frozen), 45)


class ScopeConsistencyTests(unittest.TestCase):
    compare = ClaimStageTests.compare
    review = ClaimStageTests.review

    def setUp(self):
        ClaimStageTests.setUp(self)
        self.package['evidence'] = [item for item in self.package['evidence'] if item['id'] != 'A2']
        self.scope = 'effective_state'
        self.set_statement('The Child instance domain was never initialized.')

    def set_statement(self, sentence):
        next(item for item in self.package['evidence'] if item['id'] == 'A')['content'] = sentence

    def sources(self):
        choice = statement_choices(self.package, {'A'})[0]
        return [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Full original statement.',
                 'claims': [{'statement_id': choice['statement_id'], 'claim_type': 'fact',
                             'claim_target': {'object': 'Child instance domain', 'property': choice['proposition'],
                                              'scope': self.scope, 'state_assertion': ({'kind': 'normal_initialization',
                                                  'attribute': 'domain', 'predicate': 'unassigned', 'strength': 'asserted'}
                                                  if self.scope == 'effective_state' else None)}}]}]

    def scope_rows(self, payload, **updates):
        rows = self.compare(payload['frozen_claims'])['comparisons']
        return {'scope_reviews': [{**row, 'scope_consistency': 'same_scope', **updates} for row in rows]}

    def inheritance_sources(self):
        self.package['evidence'].extend([
            {'id': 'BASE', 'kind': 'source', 'version_id': SHA, 'path': 'base.py',
             'content': 'class Base:\n    def __init__(self):\n        self.domain = "example.org"'},
            {'id': 'CHILD', 'kind': 'source', 'version_id': SHA, 'path': 'child.py',
             'content': 'from base import Base\nclass Child(Base):\n    def __init__(self):\n        super().__init__()'}])
        return [{'evidence_id': 'BASE', 'start_line': 1, 'end_line': 3,
                 'quote': self.package['evidence'][-2]['content']},
                {'evidence_id': 'CHILD', 'start_line': 1, 'end_line': 4,
                 'quote': self.package['evidence'][-1]['content']}]

    def test_effective_state_cannot_pass_from_only_subclass_structure(self):
        refs = self.inheritance_sources()
        self.package['evidence'] = [item for item in self.package['evidence'] if item['id'] != 'BASE']
        def respond(payload):
            if 'source_inventory' in payload:
                return {'sources': self.sources()}
            if 'scope_candidates' in payload:
                return self.scope_rows(payload, scope_consistency='narrowed_scope',
                                       source_refs=[refs[1]], reason='Only direct subclass statements were checked.')
            value = self.compare(payload['frozen_claims'])
            value['comparisons'][0]['source_refs'] = [refs[1]]
            return value
        row = self.review(respond)
        self.assertEqual(row['result'], UNKNOWN)
        claim = row['atomic_checks'][0]['semantic_basis']['claims'][0]
        self.assertEqual(claim['relation'], 'uncertain')
        self.assertEqual(claim['claim_target']['scope'], 'effective_state')
        candidate = json.loads((self.directory / 'claims.comparison-candidates.json').read_text())['claims'][0]
        self.assertEqual(candidate['relation'], 'supported', 'Keep the original candidate for diagnosis.')
        self.assertEqual(candidate['proposition'], claim['proposition'])
        self.assertTrue((self.directory / 'claims-scope-1.raw.json').exists())

    def test_same_scope_parent_initialization_counterexample_retains_failure(self):
        refs = self.inheritance_sources()
        def respond(payload):
            if 'source_inventory' in payload:
                return {'sources': self.sources()}
            if 'scope_candidates' in payload:
                return self.scope_rows(payload, relation='exceeds_source', source_refs=refs,
                        reason='The same-version child calls Base.__init__, which initializes this instance property.')
            return self.compare(payload['frozen_claims'])
        row = self.review(respond)
        self.assertEqual(row['result'], FAIL)
        claim = row['atomic_checks'][0]['semantic_basis']['claims'][0]
        self.assertEqual(claim['relation'], 'exceeds_source')
        self.assertEqual({item['evidence_id'] for item in claim['source_refs']}, {'BASE', 'CHILD'})
        frozen = json.loads((self.directory / 'claims.frozen-claims.json').read_text())['sources'][0]['claims'][0]
        self.assertEqual(claim['claim_target'], frozen['claim_target'])
        self.assertEqual(claim['statement_refs'], frozen['statement_refs'])

    def test_explicit_local_structure_supported_claim_does_not_require_effective_state_review(self):
        self.scope = 'local_structure'
        self.set_statement('The subclass __init__ body has no direct self.domain assignment.')
        row = self.review()
        self.assertEqual(row['result'], PASS)
        self.assertEqual(len(self.calls), 2)
        self.assertFalse(any('scope_candidates' in payload for payload in self.calls))

    def test_directory_and_full_file_path_are_not_automatically_a_contradiction(self):
        self.scope = 'observed_event'
        self.set_statement('The command ran in /workspace.')
        self.package['evidence'].append({'id': 'TOOL', 'kind': 'tool',
                                         'content': 'cwd=/workspace; python /workspace/reproduce.py'})
        self.package['trace'] = {'messages': [
            {'role': 'tool', 'evidence_id': 'TOOL', 'content': self.package['evidence'][-1]['content']},
            {'role': 'assistant', 'evidence_id': 'A', 'content': 'The command ran in /workspace.'}]}
        def respond(payload):
            if 'source_inventory' in payload:
                return {'sources': self.sources()}
            if 'scope_candidates' in payload:
                return self.scope_rows(payload, scope_consistency='different_proposition', relation='exceeds_source',
                    source_refs=[ref('TOOL', 'cwd=/workspace; python /workspace/reproduce.py')],
                    observation_commit_ids=[], reason='The candidate compares a directory with the complete script path.')
            value = self.compare(payload['frozen_claims'], 'exceeds_source')
            value['comparisons'][0].update(
                source_refs=[ref('TOOL', 'cwd=/workspace; python /workspace/reproduce.py')],
                observation_commit_ids=[])
            return value
        row = self.review(respond)
        self.assertEqual(row['result'], UNKNOWN)
        self.assertEqual(row['atomic_checks'][0]['semantic_basis']['claims'][0]['relation'], 'uncertain')
        self.assertEqual(len(self.calls), 3, 'An exceeds_source candidate requires review regardless of target scope.')

    def test_failed_review_cannot_leave_a_sensitive_supported_or_failed_candidate_definite(self):
        for relation in ('supported', 'exceeds_source'):
            with self.subTest(relation=relation):
                def call(stage, system, payload, validator, **kwargs):
                    if 'scope_candidates' in payload:
                        self.assertEqual(kwargs, {'attempts': 1})
                        return None, 'scope budget exhausted', False
                    value = ({'sources': self.sources()} if 'source_inventory' in payload
                             else self.compare(payload['frozen_claims'], relation))
                    return validator(value), None, False
                row = review_claim_scope(self.task, self.package, self.condition,
                    model_input(self.package, [self.task]), call, 'failed-' + relation,
                    self.directory, lambda _: None)
                self.assertEqual(row['result'], UNKNOWN)
                self.assertEqual(row['analysis_stage_errors'], ['scope budget exhausted'])
                self.assertEqual(row['atomic_checks'][0]['semantic_basis']['claims'][0]['relation'], 'uncertain')

    def test_comparison_and_review_receive_no_other_assistant_diagnostics_or_audit_outcomes(self):
        self.scope = 'other'
        self.package['evidence'].append({'id': 'UNRELATED', 'kind': 'assistant', 'target_ids': ['OTHER'],
                                         'content': 'DIAGNOSTIC_ONLY_THE_SUBCLASS_COUNTS'})
        request = model_input(self.package, [self.task])
        request['old_audit_outcome'] = 'DIAGNOSTIC_ONLY_THE_SUBCLASS_COUNTS'
        request['acceptance_checks'] = [{'reason': 'DIAGNOSTIC_ONLY_THE_SUBCLASS_COUNTS'}]
        def call(stage, system, payload, validator, **kwargs):
            self.calls.append(copy.deepcopy(payload))
            if 'source_inventory' in payload:
                value = {'sources': self.sources()}
            else:
                self.assertEqual(set(payload), {'fixed_task', 'evidence', 'commits',
                    'program_run_verification', 'frozen_claims', 'prior_tool_observations',
                    'original_statement_context', 'visible_source_extents'}
                    | ({'scope_candidates'} if 'scope_candidates' in payload else set()))
                self.assertNotIn('DIAGNOSTIC_ONLY_THE_SUBCLASS_COUNTS', json.dumps(payload))
                self.assertTrue(all(item['kind'] != 'assistant' for item in payload['evidence']))
                self.assertEqual(payload['frozen_claims'][0]['statement_refs'][0]['quote'],
                                 'The Child instance domain was never initialized.')
                value = self.scope_rows(payload) if 'scope_candidates' in payload else self.compare(payload['frozen_claims'])
            return validator(value), None, False
        row = review_claim_scope(self.task, self.package, self.condition, request, call,
                                 'filtered', self.directory, lambda _: None)
        self.assertEqual(row['result'], PASS)
        self.assertEqual(len(self.calls), 2)

    def test_review_validator_rejects_foreign_id_assistant_and_wrong_version_sources(self):
        claims = extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                  self.task, self.package)[0]['claims']
        candidates = {claim['id']: self.compare([claim])['comparisons'][0] for claim in claims}
        payload = {'frozen_claims': claims}
        value = self.scope_rows(payload)
        value['scope_reviews'][0]['claim_id'] = 'invented'
        with self.assertRaisesRegex(ValueError, '完整且唯一'):
            scope_response(value, claims, candidates, self.task, self.package)
        value = self.scope_rows(payload, source_refs=[ref('A', 'The Child instance domain was never initialized.')])
        with self.assertRaisesRegex(ValueError, 'kind=assistant'):
            scope_response(value, claims, candidates, self.task, self.package)
        value = self.scope_rows(payload, observation_commit_ids=['c' * 40])
        with self.assertRaisesRegex(ValueError, '本任务以外'):
            scope_response(value, claims, candidates, self.task, self.package)
        value = self.scope_rows(payload, observation_commit_ids=[PARENT])
        with self.assertRaisesRegex(ValueError, '观察版本不一致'):
            scope_response(value, claims, candidates, self.task, self.package)

    def test_scope_batches_are_bounded_and_unreviewed_claims_remain_unknown(self):
        self.set_statement('The instance domain was never initialized; the timeout was never initialized.')
        original_sources = self.sources
        def sources():
            rows = original_sources()
            rows[0]['claims'][0]['claim_target']['state_assertion'] = None
            choice = statement_choices(self.package, {'A'})[1]
            rows[0]['claims'].append({'statement_id': choice['statement_id'], 'claim_type': 'fact',
                'claim_target': {'object': 'instance timeout', 'property': choice['proposition'], 'scope': 'effective_state', 'state_assertion': None}})
            return rows
        self.sources = sources
        with patch('formsy_sop_verification.trace_audit.sop_claim_review.SCOPE_BATCH', 1), patch('formsy_sop_verification.trace_audit.sop_claim_review.MAX_SCOPE_BATCHES', 1):
            row = self.review()
        self.assertEqual(len([payload for payload in self.calls if 'scope_candidates' in payload]), 1)
        self.assertEqual(row['result'], UNKNOWN)
        self.assertIn('固定批次上限', row['analysis_stage_errors'][0])
        self.assertEqual([claim['relation'] for claim in row['atomic_checks'][0]['semantic_basis']['claims']],
                         ['supported', 'uncertain'])


class ClaimBudgetIntegrationTests(unittest.TestCase):
    setUp = ClaimStageTests.setUp
    sources = ClaimStageTests.sources
    compare = ClaimStageTests.compare

    def test_real_audit_entry_marks_unexecuted_comparison_as_incomplete(self):
        from ..sop_audit import audit_sop

        catalog = load_catalog(Path(__file__).resolve().parents[1])
        rule = copy.deepcopy(next(rule for rule in catalog['rules'] if rule['id'] == 'TC14'))
        rule['conditions'] = [copy.deepcopy(self.condition)]
        catalog['rules'] = [rule]
        observed_stages = []
        owner = self

        class BudgetClient:
            def complete(self, system, payload, directory, stage):
                observed_stages.append(stage)
                if 'candidate_rules' in payload:
                    return {'rules': [{'rule_id': 'TC14', 'selection': 'selected',
                        'reason': 'The original Agent made statements that require source comparison.',
                        'evidence_refs': [ref('U', owner.package['evidence'][0]['content'])]}]}
                if 'source_inventory' in payload:
                    return {'sources': owner.sources()}
                owner.fail('The comparison model must not run after the shared call budget is exhausted.')

        report = audit_sop(self.result, self.package, catalog, BudgetClient(), self.directory, max_calls=2)
        self.assertEqual(len(observed_stages), 2)
        self.assertIn('-extract-', observed_stages[-1])
        self.assertEqual(report['sop_coverage']['request_count'], 2)
        self.assertFalse(report['sop_coverage']['analysis_complete'])
        self.assertTrue(any(failure['kind'] == 'stage_analysis_failure'
                            for failure in report['sop_coverage']['failures']))
        row = report['sop_condition_checks'][0]
        self.assertEqual(row['result'], UNKNOWN)
        self.assertEqual(row['analysis_status'], 'failed')
        self.assertEqual(row['gap_type'], 'analysis_failed')
        self.assertTrue(row['analysis_stage_errors'])
        self.assertEqual(row['atomic_checks'][0]['semantic_basis']['covered_source_ids'], ['A', 'A2'])

    def test_real_audit_budget_cannot_preserve_definite_candidate_without_scope_review(self):
        from ..sop_audit import audit_sop

        catalog = load_catalog(Path(__file__).resolve().parents[1])
        rule = copy.deepcopy(next(rule for rule in catalog['rules'] if rule['id'] == 'TC14'))
        rule['conditions'] = [copy.deepcopy(self.condition)]
        catalog['rules'] = [rule]
        owner = self
        for relation in ('supported', 'exceeds_source'):
            with self.subTest(relation=relation):
                observed_stages = []
                class BudgetClient:
                    def complete(self, system, payload, directory, stage):
                        observed_stages.append(stage)
                        if 'candidate_rules' in payload:
                            return {'rules': [{'rule_id': 'TC14', 'selection': 'selected',
                                'reason': 'Original Agent claims require source comparison.',
                                'evidence_refs': [ref('U', '保留零值')]}]}
                        if 'source_inventory' in payload:
                            return {'sources': owner.sources()}
                        if 'scope_candidates' in payload:
                            owner.fail('The independent review must share the same exhausted budget.')
                        return owner.compare(payload['frozen_claims'], relation)
                report = audit_sop(self.result, self.package, catalog, BudgetClient(),
                                   self.directory / relation, max_calls=3)
                self.assertEqual(len(observed_stages), 3)
                self.assertIn('-compare-', observed_stages[-1])
                self.assertEqual(report['sop_coverage']['request_count'], 3)
                self.assertFalse(report['sop_coverage']['analysis_complete'])
                row = report['sop_condition_checks'][0]
                self.assertEqual(row['result'], UNKNOWN)
                self.assertEqual(row['analysis_status'], 'failed')
                self.assertEqual(row['gap_type'], 'analysis_failed')
                self.assertTrue(any('预算上限' in error for error in row['analysis_stage_errors']))
                self.assertTrue(all(claim['relation'] == 'uncertain'
                                    for claim in row['atomic_checks'][0]['semantic_basis']['claims']))


if __name__ == '__main__':
    unittest.main()


class InitializationProofTests(unittest.TestCase):
    """The predicate is frozen from words; the counterexample comes from a bounded code chain."""
    review = ClaimStageTests.review

    def setUp(self):
        ClaimStageTests.setUp(self)
        self.package['evidence'] = [e for e in self.package['evidence'] if e['id'] != 'A2']
        next(e for e in self.package['evidence'] if e['id'] == 'A')['content'] = (
            'The Child `__init__` method never initializes the `token` attribute. This is likely the cause of the error.')
        self.package['evidence'].extend([
            {'id': 'BASE', 'kind': 'source', 'version_id': SHA, 'path': 'pkg/base.py',
             'content': 'class Base:\n    def __init__(self, config):\n        self.token = config.get("token")'},
            {'id': 'CHILD', 'kind': 'source', 'version_id': SHA, 'path': 'pkg/child.py',
             'content': 'from pkg.base import Base as Parent\nclass Child(Parent):\n    def __init__(self, config):\n        super(Child, self).__init__(config)'}])

    def source(self, eid):
        return next(e for e in self.package['evidence'] if e['id'] == eid)

    def full_ref(self, eid):
        content = self.source(eid)['content']
        return {'evidence_id': eid, 'start_line': 1, 'end_line': len(content.splitlines()), 'quote': content}

    def sources(self):
        choice = statement_choices(self.package, {'A'})[0]
        return [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Definite unset premise, cause hedged separately.',
                 'claims': [{'statement_id': choice['statement_id'], 'claim_type': 'fact',
                             'claim_target': {'object': 'Child instance initialized by __init__',
                                'property': 'token initialization', 'scope': 'effective_state',
                                'state_assertion': {'kind': 'normal_initialization', 'attribute': 'token',
                                                    'predicate': 'unassigned', 'strength': 'asserted'}}}]}]

    def claim(self):
        return extract_response({'sources': self.sources()}, statement_review_inventory(self.task, self.package),
                                self.task, self.package, strict_state=True)[0]['claims'][0]

    def compare(self, claims):
        return {'comparisons': [{'claim_id': c['id'], 'relation': 'supported', 'comparison_type': c['claim_type'],
                 'comparison_scope': 'same_property', 'observation_commit_ids': [SHA],
                 'source_refs': [self.full_ref('CHILD')],
                 'reason': 'The subclass body has no direct assignment, so the original assertion is supported.'}
                for c in claims]}

    def proof(self, claim=None, comparison=None):
        from ..sop_claim_review import initialization_proof
        claim = claim or self.claim()
        comparison = comparison or self.compare([claim])['comparisons'][0]
        return initialization_proof(claim, comparison, self.task, self.package)

    def test_both_models_cannot_shrink_effective_state_to_child_direct_assignments(self):
        row = self.review()
        self.assertEqual(row['result'], FAIL)
        final = row['atomic_checks'][0]['semantic_basis']['claims'][0]
        self.assertEqual(final['relation'], 'exceeds_source')
        self.assertEqual(final['proposition'], self.claim()['proposition'])
        self.assertNotIn('likely', final['proposition'])
        self.assertIn('likely', final['statement_refs'][0]['quote'])
        self.assertEqual({r['evidence_id'] for r in final['source_refs']}, {'BASE', 'CHILD'})
        self.assertTrue(any('super(Child, self)' in r['quote'] for r in final['source_refs']))
        self.assertTrue(any('self.token =' in r['quote'] for r in final['source_refs']))
        self.assertTrue(any('import Base as Parent' in r['quote'] for r in final['source_refs']))
        candidates = json.loads((self.directory / 'claims.comparison-candidates.json').read_text())
        self.assertEqual(candidates['claims'][0]['relation'], 'supported')
        self.assertEqual(len(self.calls), 3, 'No extra model vote is used for the static counterexample.')

    def test_normal_assignment_does_not_certify_nonempty_value_or_execution(self):
        self.source('BASE')['content'] = 'class Base:\n    def __init__(self, config):\n        self.token = None'
        proof = self.proof()
        self.assertEqual(proof['status'], 'assigned')
        self.assertIn('不证明属性值非空', proof['reason'])
        claim = self.claim()
        claim['claim_type'] = 'actual_state'
        self.assertIsNone(self.proof(claim))

    def test_inherited_constructor_without_child_override_and_explicit_parent_call(self):
        for body in ('    pass', '    def __init__(self, config):\n        Parent.__init__(self, config)'):
            with self.subTest(body=body):
                self.source('CHILD')['content'] = 'from pkg.base import Base as Parent\nclass Child(Parent):\n' + body
                proof = self.proof()
                self.assertEqual(proof['status'], 'assigned')
                self.assertEqual({r['evidence_id'] for r in proof['source_refs']}, {'BASE', 'CHILD'})

    def test_missing_unimported_or_wrong_version_parent_cannot_prove_state(self):
        for change in ('missing', 'unimported', 'version'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.package)
                if change == 'missing':
                    self.package['evidence'] = [e for e in self.package['evidence'] if e['id'] != 'BASE']
                elif change == 'unimported':
                    self.source('CHILD')['content'] = self.source('CHILD')['content'].replace(
                        'from pkg.base import Base as Parent\n', '')
                else:
                    self.source('BASE')['version_id'] = PARENT
                self.assertEqual(self.proof()['status'], 'uncertain')
                self.package = original

    def test_conditional_dynamic_deleted_or_escaped_attribute_is_unknown(self):
        bodies = [
            '        if config:\n            self.token = "value"',
            '        self.token = "value"\n        del self.token',
            '        self.token = "value"\n        self.__dict__ = {}',
            '        self.token = "value"\n        setattr(self, "token", None)',
            '        self.token = "value"\n        self.configure()',
            '        self.token = "value"\n        mutate(instance=self)',
            '        self.token = "value"\n        mutate([self])',
            '        self.token: str',
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.source('BASE')['content'] = 'class Base:\n    def __init__(self, config):\n' + body
                self.assertEqual(self.proof()['status'], 'uncertain')

    def test_unrelated_configuration_branch_does_not_hide_later_unconditional_write(self):
        self.source('BASE')['content'] = (
            'class Base:\n    def __init__(self, config):\n'
            '        if config:\n            self.config = config\n'
            '        else:\n            self.config = {}\n'
            '        self.token = self.config.get("token")')
        self.assertEqual(self.proof()['status'], 'assigned')

    def test_no_super_call_does_not_invent_inherited_effect(self):
        self.source('CHILD')['content'] = (
            'from pkg.base import Base as Parent\nclass Child(Parent):\n    def __init__(self, config):\n        pass')
        self.assertEqual(self.proof()['status'], 'uncertain')

    def test_descriptors_multiple_inheritance_rebound_base_or_constructor_are_unknown(self):
        variants = [
            ('BASE', 'class Base:\n    def __init__(self, config):\n        self.token = \"x\"\n    def __init__(self, config):\n        pass'),
            ('BASE', 'class Base:\n    def __init__(self, config):\n        self.token = \"x\"\n    __init__ = replacement'),
            ('BASE', 'class Base:\n    __slots__ = []\n    def __init__(self, config):\n        self.token = \"x\"'),
            ('BASE', 'class Base:\n    token = property(lambda self: None)\n    def __init__(self, config):\n        self.token = "x"'),
            ('CHILD', 'from pkg.base import Base as Parent\nclass Child(Parent, object):\n    def __init__(self, config):\n        super().__init__(config)'),
            ('CHILD', 'from pkg.base import Base as Parent\nParent = Other\nclass Child(Parent):\n    def __init__(self, config):\n        super().__init__(config)'),
            ('CHILD', 'from pkg.base import Base as Parent\nclass Child(Parent):\n    def __init__(self, config):\n        super().__init__(config)\nChild.__init__ = replacement'),
            ('CHILD', 'from pkg.base import Base as Parent\nclass Child(Parent):\n    def __init__(self, config):\n        super = replacement\n        super().__init__(config)'),
        ]
        for eid, content in variants:
            with self.subTest(content=content):
                original = self.source(eid)['content']
                self.source(eid)['content'] = content
                self.assertEqual(self.proof()['status'], 'uncertain')
                self.source(eid)['content'] = original

    def test_current_code_does_not_refute_known_older_statement_or_other_task_source(self):
        self.source('A')['version_id'] = PARENT
        self.assertEqual(self.proof()['status'], 'uncertain')
        self.source('A')['version_id'] = SHA
        self.source('BASE')['target_ids'] = ['OTHER_TASK']
        self.assertEqual(self.proof()['status'], 'uncertain')

    def test_wrong_observation_version_other_attribute_or_bad_quote_is_unknown(self):
        claim = self.claim()
        comparison = self.compare([claim])['comparisons'][0]
        for update in ({'observation_commit_ids': ['c' * 40]}, {'observation_commit_ids': [SHA, PARENT]},
                       {'source_refs': [{**self.full_ref('CHILD'), 'quote': 'invented'}]}):
            with self.subTest(update=update):
                self.assertEqual(self.proof(claim, {**comparison, **update})['status'], 'uncertain')
        self.source('BASE')['content'] = self.source('BASE')['content'].replace('self.token', 'self.other')
        self.assertEqual(self.proof()['status'], 'uncertain')

    def test_source_protocol_rejects_missing_null_init_or_attribute_from_later_code(self):
        inventory = statement_review_inventory(self.task, self.package)
        for change in ('missing', 'null', 'different_attribute'):
            with self.subTest(change=change):
                sources = self.sources()
                target = sources[0]['claims'][0]['claim_target']
                if change == 'missing':
                    del target['state_assertion']
                elif change == 'null':
                    target['state_assertion'] = None
                else:
                    target['state_assertion']['attribute'] = 'other'
                    self.source('A')['content'] += '\nself.other = value'
                with self.assertRaisesRegex(ValueError, 'state_assertion|初始化谓词|逐字'):
                    extract_response({'sources': sources}, inventory, self.task, self.package, strict_state=True)

    def test_hedged_cause_and_explicit_local_structure_do_not_become_static_fact(self):
        claim = self.claim()
        for scope, strength, kind in (('cause_hypothesis', 'hypothetical', 'diagnosis'),
                                       ('local_structure', 'asserted', 'fact')):
            with self.subTest(scope=scope):
                altered = copy.deepcopy(claim)
                altered['claim_type'] = kind
                altered['claim_target']['scope'] = scope
                altered['claim_target']['state_assertion']['strength'] = strength
                self.assertIsNone(self.proof(altered))
        sources = self.sources()
        sources[0]['claims'][0]['claim_target']['state_assertion']['strength'] = 'hypothetical'
        with self.assertRaisesRegex(ValueError, '假设初始化'):
            extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                             self.task, self.package, strict_state=True)

    def test_parent_only_citation_cannot_skip_child_constructor(self):
        self.source('CHILD')['content'] = (
            'from pkg.base import Base as Parent\nclass Child(Parent):\n    def __init__(self, config):\n        pass')
        claim = self.claim()
        comparison = self.compare([claim])['comparisons'][0]
        comparison['source_refs'] = [self.full_ref('BASE')]
        self.assertEqual(self.proof(claim, comparison)['status'], 'uncertain')

    def test_wrong_original_object_or_ambiguous_same_named_class_cannot_choose_anchor(self):
        claim = self.claim()
        claim['claim_target']['object'] = 'Base instance'
        self.assertEqual(self.proof(claim)['status'], 'uncertain')
        self.package['evidence'].append({'id': 'SIBLING', 'kind': 'source', 'version_id': SHA,
            'path': 'other/child.py', 'content': 'class Child:\n    def __init__(self):\n        self.token = "other"'})
        self.assertEqual(self.proof()['status'], 'uncertain')

    def observed_claim(self):
        from ..sop_claim_review import freeze_initialization_observation
        self.source('A')['content'] = 'The `__init__` method does not initialize the `token` attribute.'
        source = self.source('CHILD')
        lines = source['content'].splitlines()
        content = '[File: /repo/' + source['path'] + ' (' + str(len(lines)) + ' lines total)]\n'
        content += '\n'.join(str(i) + ':' + line for i, line in enumerate(lines, 1))
        self.package['evidence'] = [e for e in self.package['evidence'] if e['id'] != 'OBS']
        self.package['evidence'].append({'id': 'OBS', 'kind': 'tool', 'content': content})
        self.package['trace'] = {'messages': [{'role': 'tool', 'evidence_id': 'OBS', 'content': content},
            {'role': 'assistant', 'evidence_id': 'A', 'content': self.source('A')['content']}]}
        claim = self.claim()
        claim['claim_target']['object'] = '__init__ instance'
        observation = freeze_initialization_observation(claim, self.task, self.package)
        if observation:
            claim['initialization_observation'] = observation
        return claim

    def test_original_display_freezes_unique_entry_even_with_multiple_class_names(self):
        self.package['evidence'].append({'id': 'SIBLING', 'kind': 'source', 'version_id': SHA,
            'path': 'other/child.py', 'content': 'class Child:\n    def __init__(self):\n        self.token = "other"'})
        claim = self.observed_claim()
        self.assertEqual(claim['initialization_observation']['path'], 'pkg/child.py')
        self.assertEqual(claim['initialization_observation']['version_id'], SHA)
        proof = self.proof(claim)
        self.assertEqual(proof['status'], 'assigned')
        self.assertEqual({r['evidence_id'] for r in proof['source_refs']}, {'OBS', 'CHILD', 'BASE'})
        comparison = self.compare([claim])['comparisons'][0]
        comparison['source_refs'] = [self.full_ref('BASE')]
        self.assertEqual(self.proof(claim, comparison)['status'], 'uncertain')

    def test_display_binding_rejects_bad_lines_incomplete_constructor_wrong_role_or_ambiguous_version(self):
        from ..sop_claim_review import freeze_initialization_observation
        for change in ('bad_line', 'incomplete', 'role', 'version', 'forged_observation'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.package)
                claim = self.observed_claim()
                if change == 'bad_line':
                    self.source('OBS')['content'] = self.source('OBS')['content'].replace('super(Child, self)', 'super(Other, self)')
                    self.package['trace']['messages'][0]['content'] = self.source('OBS')['content']
                elif change == 'incomplete':
                    self.source('OBS')['content'] = '\n'.join(self.source('OBS')['content'].splitlines()[:-1])
                    self.package['trace']['messages'][0]['content'] = self.source('OBS')['content']
                elif change == 'role':
                    self.package['trace']['messages'][0]['role'] = 'assistant'
                elif change == 'version':
                    duplicate = copy.deepcopy(self.source('CHILD'))
                    duplicate.update(id='OLDER', version_id=PARENT)
                    self.package['evidence'].append(duplicate)
                else:
                    claim['initialization_observation']['class_name'] = 'Base'
                if change == 'forged_observation':
                    self.assertEqual(self.proof(claim)['status'], 'uncertain')
                else:
                    self.assertIsNone(freeze_initialization_observation(claim, self.task, self.package))
                    self.assertEqual(self.proof(claim)['status'], 'uncertain')
                self.package = original

    def test_package_filenames_paths_and_longer_identifiers_are_not_constructor_predicates(self):
        sentences = [
            'The `lexicon` directory does contain an `__init__.py` file, which means it should be recognized as a package.',
            'The package file is `/repo/pkg/__init__.py`.',
            r'The package file is `C:\repo\pkg\__init__.py`.',
            'The directory is `/repo/__init__/`.',
            'The identifier is `prefix__init__suffix`.',
        ]
        for sentence in sentences:
            with self.subTest(sentence=sentence):
                self.source('A')['content'] = sentence
                sources = self.sources()
                sources[0]['claims'][0]['claim_target'].update(
                    object='package location', property='package identity', state_assertion=None)
                checked = extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                                           self.task, self.package, strict_state=True)
                self.assertEqual(checked[0]['claims'][0]['proposition'], sentence)
                self.assertIsNone(checked[0]['claims'][0]['claim_target']['state_assertion'])

    def test_real_constructor_null_guard_retains_statement_specific_error(self):
        for sentence in ('The `__init__` method never initializes the `token` attribute.',
                         'The Child.__init__ method never initializes the token attribute.',
                         'The constructor method is __init__.'):
            with self.subTest(sentence=sentence):
                self.source('A')['content'] = sentence
                sources = self.sources()
                claim = sources[0]['claims'][0]
                claim['claim_target']['state_assertion'] = None
                with self.assertRaisesRegex(ValueError, 'A/' + claim['statement_id'] + '.*初始化谓词'):
                    extract_response({'sources': sources}, statement_review_inventory(self.task, self.package),
                                     self.task, self.package, strict_state=True)

    def test_explicit_class_constructor_with_frozen_predicate_still_checks_parent_chain(self):
        self.source('A')['content'] = 'The Child.__init__ method never initializes the token attribute.'
        claim = self.claim()
        self.assertEqual(claim['claim_target']['state_assertion']['predicate'], 'unassigned')
        self.assertEqual(self.proof(claim)['status'], 'assigned')


class ObservationAndCauseBoundaryTests(unittest.TestCase):
    def setUp(self):
        result, self.package, _ = fixtures()
        self.task = result['tasks'][0]
        self.package['evidence'] = [e for e in self.package['evidence'] if e['kind'] != 'assistant']
        self.package['evidence'].extend([
            {'id': 'A', 'kind': 'assistant', 'content': 'This could be due to how the token is sent.'},
            {'id': 'OBS', 'kind': 'tool', 'content': 'HTTPError: 403 Forbidden'},
            {'id': 'MECH', 'kind': 'source', 'version_id': SHA, 'path': 'auth.py',
             'content': 'if not valid_token(request.headers): raise Forbidden()'}])
        self.package['trace'] = {'messages': [
            {'role': e['kind'], 'evidence_id': e['id'], 'content': e['content']}
            for oid in ('OBS', 'A') for e in self.package['evidence'] if e['id'] == oid]}

    def claim(self, scope='cause_hypothesis'):
        text = next(e['content'] for e in self.package['evidence'] if e['id'] == 'A')
        return {'id': 'C', 'proposition': text, 'claim_type': 'diagnosis' if scope == 'cause_hypothesis' else 'fact',
                'claim_target': {'object': 'request', 'property': 'token handling causes rejection',
                                 'scope': scope, 'state_assertion': None}, 'statement_refs': [ref('A', text)]}

    def answer(self, claim, *, basis=None, refs=None, relation='supported'):
        row = {'claim_id': claim['id'], 'relation': relation, 'comparison_type': claim['claim_type'],
               'comparison_scope': 'same_property', 'observation_commit_ids': [SHA],
               'source_refs': refs or [ref('OBS', 'HTTPError: 403 Forbidden')],
               'reason': 'The original hypothesis is compatible with a rejected request.'}
        if basis is not None:
            row['causal_basis'] = basis
        return {'comparisons': [row]}

    def checked(self, answer, claim=None):
        return comparison_response(answer, [claim or self.claim()], self.task, self.package)[0]

    def mechanism(self):
        return {'kind': 'mechanism', 'evidence_refs': [ref('MECH', 'if not valid_token(request.headers): raise Forbidden()')],
                'reason': 'The independent code maps an invalid token to rejection; the claim remains a hypothesis.'}

    def test_outcome_compatibility_and_unlabelled_cause_do_not_become_supported(self):
        claim = self.claim()
        for kind in (None, 'outcome_only', 'compatibility_only', 'mechanism'):
            with self.subTest(kind=kind):
                basis = None if kind is None else {'kind': kind,
                    'evidence_refs': [ref('OBS', 'HTTPError: 403 Forbidden')], 'reason': 'Only rejection was observed.'}
                checked = self.checked(self.answer(claim, basis=basis))
                self.assertEqual(checked['relation'], 'uncertain')
                self.assertIn('不能代替因果支持', checked['reason'])
                self.assertEqual(claim['proposition'], checked.get('proposition', claim['proposition']))

    def test_independent_code_mechanism_can_support_the_hedged_same_property(self):
        claim = self.claim()
        refs = self.mechanism()['evidence_refs'] + [ref('OBS', 'HTTPError: 403 Forbidden')]
        checked = self.checked(self.answer(claim, basis=self.mechanism(), refs=refs))
        self.assertEqual(checked['relation'], 'supported')
        self.assertEqual(checked['comparison_type'], 'diagnosis')
        self.assertIn('could', claim['proposition'])
        self.assertEqual(checked['causal_basis'], self.mechanism())

    def test_observed_rejection_is_still_a_supported_fact_without_causal_basis(self):
        claim = self.claim('observed_event')
        self.assertEqual(self.checked(self.answer(claim), claim)['relation'], 'supported')

    def test_mechanism_neither_upgrades_unknown_nor_bypasses_attribute_or_version(self):
        claim = self.claim()
        refs = self.mechanism()['evidence_refs']
        value = self.answer(claim, basis=self.mechanism(), refs=refs, relation='uncertain')
        self.assertEqual(self.checked(value)['relation'], 'uncertain')
        for change in ('version', 'scope', 'type'):
            value = self.answer(claim, basis=self.mechanism(), refs=refs)
            row = value['comparisons'][0]
            if change == 'version':
                row['observation_commit_ids'] = [PARENT]
                with self.assertRaisesRegex(ValueError, '观察版本不一致'):
                    self.checked(value)
                continue
            elif change == 'scope':
                row['comparison_scope'] = 'different_property'
            else:
                row['comparison_type'] = 'actual_state'
            self.assertEqual(self.checked(value)['relation'], 'uncertain')

    def test_mechanism_quotes_are_strict_current_task_and_cannot_self_authenticate(self):
        claim = self.claim()
        for change in ('bad_quote', 'foreign_task', 'missing_source_ref', 'assistant'):
            with self.subTest(change=change):
                before = copy.deepcopy(self.package)
                basis = self.mechanism()
                refs = copy.deepcopy(basis['evidence_refs'])
                if change == 'bad_quote':
                    basis['evidence_refs'][0]['quote'] = 'invented causal mechanism'
                    refs = copy.deepcopy(basis['evidence_refs'])
                elif change == 'foreign_task':
                    next(e for e in self.package['evidence'] if e['id'] == 'MECH')['target_ids'] = ['OTHER']
                elif change == 'missing_source_ref':
                    refs = [ref('OBS', 'HTTPError: 403 Forbidden')]
                else:
                    basis['evidence_refs'] = [copy.deepcopy(claim['statement_refs'][0])]
                    refs = copy.deepcopy(basis['evidence_refs'])
                with self.assertRaises(ValueError):
                    self.checked(self.answer(claim, basis=basis, refs=refs))
                self.package = before

    def test_tool_code_display_can_locate_mechanism_but_its_error_line_cannot(self):
        tool = next(e for e in self.package['evidence'] if e['id'] == 'OBS')
        tool['content'] += '\n[File: /pkg/auth.py (1 lines total)]\n1:if not valid_token(request.headers): raise Forbidden()'
        mechanism = {'evidence_id': 'OBS', 'start_line': 3, 'end_line': 3,
                     'quote': '1:if not valid_token(request.headers): raise Forbidden()'}
        basis = {'kind': 'mechanism', 'evidence_refs': [mechanism], 'reason': 'Independent displayed code path.'}
        self.assertEqual(self.checked(self.answer(self.claim(), basis=basis, refs=[mechanism]))['relation'], 'supported')
        basis['evidence_refs'] = [ref('OBS', 'HTTPError: 403 Forbidden')]
        self.assertEqual(self.checked(self.answer(self.claim(), basis=basis))['relation'], 'uncertain')

    def test_scope_review_cannot_restore_outcome_only_causal_support(self):
        claim = self.claim()
        candidate = self.answer(claim)['comparisons'][0]
        checked = scope_response({'scope_reviews': [{**candidate, 'scope_consistency': 'same_scope'}]},
                                 [claim], {'C': candidate}, self.task, self.package)
        self.assertEqual(checked[0]['relation'], 'uncertain')

    def test_original_prior_tool_is_priority_only_and_has_no_invented_version(self):
        from ..sop_claim_review import _comparison_input
        request = model_input(self.package, [self.task])
        truth = {**request, 'evidence': [e for e in request['evidence'] if e['kind'] != 'assistant']}
        before = copy.deepcopy(self.package)
        value = _comparison_input(truth, [self.claim()], self.task, self.package)
        self.assertEqual(value['evidence'][0]['id'], 'OBS')
        self.assertEqual(value['prior_tool_observations'], [{'claim_id': 'C', 'evidence_id': 'OBS',
            'version_id': None, 'relationship': 'immediately_preceding_original_tool'}])
        self.assertEqual(self.package, before)
        self.assertNotIn('relation', value['prior_tool_observations'][0])
        self.assertIn('quote_id', value['evidence'][0]['numbered_lines'][0])
        self.assertEqual(self.checked(self.answer(self.claim()))['relation'], 'uncertain')

    def test_prior_observation_does_not_guess_across_task_version_role_or_changed_content(self):
        from ..sop_claim_review import _comparison_input
        for change in ('foreign_task', 'foreign_version', 'statement_foreign_task', 'statement_foreign_version',
                       'changed_assistant', 'changed_tool', 'intervening_user', 'duplicate_source'):
            with self.subTest(change=change):
                original = copy.deepcopy(self.package)
                if change == 'foreign_task':
                    next(e for e in self.package['evidence'] if e['id'] == 'OBS')['target_ids'] = ['OTHER']
                elif change == 'foreign_version':
                    next(e for e in self.package['evidence'] if e['id'] == 'OBS')['version_id'] = 'c' * 40
                elif change == 'statement_foreign_task':
                    next(e for e in self.package['evidence'] if e['id'] == 'A')['target_ids'] = ['OTHER']
                elif change == 'statement_foreign_version':
                    next(e for e in self.package['evidence'] if e['id'] == 'A')['version_id'] = 'c' * 40
                elif change == 'changed_assistant':
                    self.package['trace']['messages'][1]['content'] += ' changed'
                elif change == 'changed_tool':
                    self.package['trace']['messages'][0]['content'] += ' changed'
                elif change == 'intervening_user':
                    self.package['trace']['messages'].insert(1, {'role': 'user', 'content': 'Another task.'})
                else:
                    self.package['trace']['messages'].append(copy.deepcopy(self.package['trace']['messages'][1]))
                request = model_input(self.package, [self.task])
                self.assertEqual(_comparison_input(request, [self.claim()], self.task, self.package)['prior_tool_observations'], [])
                self.package = original

    def test_four_real_failure_shapes_receive_their_own_original_tool_without_extra_calls(self):
        samples = [
            ('It seems that I attempted to edit the wrong file.', '[File: /pkg/config.py (1 lines total)]\n1:provider.authenticate()'),
            ('It seems that I attempted to edit the wrong file again.', '[File: /pkg/reproduce.py (1 lines total)]\n1:        self.token = config.resolve("token")'),
            ('The edit command failed due to an indentation error.', 'ERRORS:\n- E999 IndentationError: unexpected indent'),
            ('The edit command failed due to an undefined name error.', 'ERRORS:\n- F821 undefined name method')]
        self.package['evidence'] = [e for e in self.package['evidence'] if e['id'] not in {'A', 'OBS'}]
        messages = []
        for index, (sentence, tool) in enumerate(samples):
            for role, content, oid in [('tool', tool, 'O' + str(index)), ('assistant', sentence, 'A' + str(index))]:
                self.package['evidence'].append({'id': oid, 'kind': role, 'content': content})
                messages.append({'role': role, 'content': content, 'evidence_id': oid})
        self.package['trace'] = {'messages': messages}
        catalog = load_catalog(Path(__file__).resolve().parents[1])
        condition = next(c for r in catalog['rules'] if r['id'] == 'TC14' for c in r['conditions'] if c['id'] == 'TC14.C02')
        calls = []
        def call(stage, system, payload, validator, **kwargs):
            calls.append(stage)
            if 'source_inventory' in payload:
                choices = payload['statement_choices']
                value = {'sources': [{'evidence_id': item['evidence_id'], 'classification': 'claims',
                    'reason': 'Original observed editing fact.', 'claims': [{'statement_id': item['statement_id'],
                        'claim_type': 'fact', 'claim_target': {'object': 'editing action', 'property': item['proposition'],
                            'scope': 'observed_event', 'state_assertion': None}}]} for item in choices]}
            else:
                self.assertNotIn('source_inventory', payload)
                mapping = {x['claim_id']: x['evidence_id'] for x in payload['prior_tool_observations']}
                self.assertEqual(set(mapping.values()), {'O0', 'O1', 'O2', 'O3'})
                self.assertEqual({e['id'] for e in payload['evidence'][:4]}, set(mapping.values()))
                evidence = {e['id']: e for e in self.package['evidence']}
                comparisons = []
                for claim in payload['frozen_claims']:
                    item = evidence[mapping[claim['id']]]
                    source = {'evidence_id': item['id'], 'start_line': 1,
                              'end_line': len(item['content'].splitlines()), 'quote': item['content']}
                    comparisons.append(self.answer(claim, refs=[source])['comparisons'][0])
                value = {'comparisons': comparisons}
            return validator(value), None, False
        with tempfile.TemporaryDirectory() as directory:
            row = review_claim_scope(self.task, self.package, condition, model_input(self.package, [self.task]),
                                     call, 'observations', Path(directory), lambda _: None)
        self.assertEqual(row['result'], PASS)
        self.assertEqual(len(calls), 2, 'One extraction and one comparison, with no extra model vote.')


class ComparisonIsolationTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.package['evidence'] = [e for e in self.package['evidence'] if e['kind'] != 'assistant']
        self.package['evidence'].extend([
            {'id': 'OLD', 'kind': 'tool', 'content': 'IndentationError: unexpected indent in another file'},
            {'id': 'OBS1', 'kind': 'tool', 'content': 'IndentationError: expected a block in current file'},
            {'id': 'A1', 'kind': 'assistant', 'content': 'The edit command failed due to an indentation error.'},
            {'id': 'OBS2', 'kind': 'tool', 'content': 'File updated.'},
            {'id': 'A2', 'kind': 'assistant', 'content': 'The file was updated.'}])
        evidence = {e['id']: e for e in self.package['evidence']}
        self.package['trace'] = {'messages': [
            {'role': evidence[oid]['kind'], 'evidence_id': oid, 'content': evidence[oid]['content']}
            for oid in ('OBS1', 'A1', 'OBS2', 'A2')]}
        self.claims = [{'id': 'C' + str(n), 'proposition': evidence['A' + str(n)]['content'],
            'claim_type': 'fact', 'claim_target': {'object': 'original event ' + str(n),
                'property': 'observed edit outcome', 'scope': 'observed_event', 'state_assertion': None},
            'statement_refs': [ref('A' + str(n), evidence['A' + str(n)]['content'])]} for n in (1, 2)]
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.calls = []

    def row(self, claim):
        oid = 'OBS' + claim['id'][-1]
        text = next(e['content'] for e in self.package['evidence'] if e['id'] == oid)
        return {'claim_id': claim['id'], 'relation': 'supported', 'comparison_type': 'fact',
                'comparison_scope': 'same_property', 'observation_commit_ids': [],
                'source_refs': [ref(oid, text)], 'reason': 'The original event is located by its original prior tool.'}

    def run_batch(self, respond, *, hidden=()):
        from ..reference_repair import repair_references
        from ..sop_claim_review import _compare_batch, SOURCE_KINDS
        request = model_input(self.package, [self.task])
        truth = {'fixed_task': self.task, 'commits': request['commits'], 'program_run_verification': [],
                 'evidence': [e for e in request['evidence'] if e['kind'] in SOURCE_KINDS and e['id'] not in hidden]}

        def call(stage, system, payload, validator, **kwargs):
            self.calls.append(copy.deepcopy(payload))
            self.assertEqual(kwargs['attempts'], 1)
            self.assertFalse(kwargs['final_failure'])
            value = respond(len(self.calls), payload)
            if value is None:
                return None, 'shared budget exhausted', False
            try:
                kwargs['before_repair'](value)
                repaired, _ = repair_references(value, self.package, [self.task],
                    available_evidence_ids={e['id'] for e in payload['evidence']})
                return validator(repaired), None, False
            except (ValueError, KeyError, TypeError) as exc:
                return None, str(exc), False

        return _compare_batch(self.claims, self.task, self.package, truth, call, 'compare', self.directory)

    def test_invalid_scope_only_retries_its_claim_without_coercion_or_sibling_loss(self):
        def respond(attempt, payload):
            rows = [self.row(c) for c in payload['frozen_claims']]
            rows[-1]['comparison_scope'] = 'cause_hypothesis'
            return {'comparisons': rows}
        rows, errors = self.run_batch(respond)
        self.assertEqual([r['relation'] for r in rows], ['supported', 'uncertain'])
        self.assertEqual([c['id'] for c in self.calls[1]['frozen_claims']], ['C2'])
        self.assertEqual(len(errors), 1)
        self.assertIn('C2', errors[0])
        self.assertIn('same_property|different_property|unknown', errors[0])
        self.assertEqual(rows[1]['comparison_scope'], 'unknown')

    def test_bad_quote_isolated_and_exact_visible_retry_can_recover(self):
        def respond(attempt, payload):
            rows = [self.row(c) for c in payload['frozen_claims']]
            if attempt == 1:
                rows[-1]['source_refs'] = ['Q-not-in-visible-directory']
            return {'comparisons': rows}
        rows, errors = self.run_batch(respond)
        self.assertEqual([r['relation'] for r in rows], ['supported', 'supported'])
        self.assertEqual(errors, [])
        self.assertEqual(len(self.calls), 2)
        self.assertEqual([c['id'] for c in self.calls[1]['frozen_claims']], ['C2'])
        self.assertTrue(self.calls[1]['reference_feedback'])
        self.assertEqual(rows[0], self.row(self.claims[0]))

    def test_retry_inexact_full_ref_cannot_be_repaired_and_does_not_hurt_sibling(self):
        def respond(attempt, payload):
            rows = [self.row(c) for c in payload['frozen_claims']]
            if attempt == 1:
                rows[-1]['source_refs'] = ['Q-missing']
            else:
                rows[0]['source_refs'][0].update(start_line=2, end_line=2)
            return {'comparisons': rows}
        rows, errors = self.run_batch(respond)
        self.assertEqual([r['relation'] for r in rows], ['supported', 'uncertain'])
        self.assertEqual(len(errors), 1)
        self.assertIn('C2', errors[0])
        self.assertIn('不自动纠错', errors[0])

    def test_retry_must_withdraw_rejected_literal_fact_after_selecting_valid_quote(self):
        from ..reference_repair import _quote_choices
        quote_id = next(oid for oid, source in _quote_choices(self.package).items()
                        if source['evidence_id'] == 'OBS2')
        for corrected_reason in (False, True):
            with self.subTest(corrected_reason=corrected_reason):
                self.calls.clear()
                def respond(attempt, payload):
                    rows = [self.row(c) for c in payload['frozen_claims']]
                    rows[-1]['reason'] = 'The update includes DEMO_SECRET.'
                    if attempt == 1:
                        rows[-1]['source_refs'] = [ref('OBS2', "token = 'DEMO_SECRET'")]
                    else:
                        rows[-1]['source_refs'] = [{'quote_id': quote_id}]
                        if corrected_reason:
                            rows[-1]['reason'] = 'The original tool confirms only that the file was updated.'
                    return {'comparisons': rows}
                rows, errors = self.run_batch(respond)
                self.assertEqual(rows[0], self.row(self.claims[0]))
                self.assertEqual(len(self.calls), 2)
                self.assertEqual([c['id'] for c in self.calls[1]['frozen_claims']], ['C2'])
                feedback = self.calls[1]['reference_feedback']
                self.assertIn('DEMO_SECRET', feedback[0]['rejected_reason_anchors'])
                if corrected_reason:
                    self.assertEqual(rows[1]['relation'], 'supported')
                    self.assertEqual(errors, [])
                else:
                    self.assertEqual(rows[1]['relation'], 'uncertain')
                    self.assertEqual(len(errors), 1)
                    self.assertIn('旧字面事实', errors[0])

    def test_incomplete_or_duplicate_envelope_cannot_donate_an_apparently_valid_row(self):
        for shape in ('missing', 'duplicate', 'extra_field'):
            with self.subTest(shape=shape):
                self.calls.clear()
                def respond(attempt, payload):
                    rows = [self.row(c) for c in payload['frozen_claims']]
                    if attempt == 1:
                        if shape == 'missing':
                            return {'comparisons': rows[:1]}
                        if shape == 'duplicate':
                            return {'comparisons': [rows[0], rows[0]]}
                        return {'comparisons': rows, 'confirmed': True}
                    rows[0]['relation'] = 'uncertain'
                    return {'comparisons': rows}
                rows, errors = self.run_batch(respond)
                self.assertEqual(len(self.calls[1]['frozen_claims']), 2)
                self.assertEqual([r['relation'] for r in rows], ['uncertain', 'supported'])
                self.assertEqual(errors, [])

    def test_budget_failure_keeps_valid_sibling_and_marks_only_pending_unknown(self):
        def respond(attempt, payload):
            if attempt > 1:
                return None
            rows = [self.row(c) for c in payload['frozen_claims']]
            rows[1]['source_refs'] = ['Q-unknown']
            return {'comparisons': rows}
        rows, errors = self.run_batch(respond)
        self.assertEqual([r['relation'] for r in rows], ['supported', 'uncertain'])
        self.assertEqual(errors, ['C2: shared budget exhausted'])
        self.assertEqual(len(self.calls), 2)

    def test_program_original_statement_access_does_not_allow_hidden_truth_sources(self):
        self.package['evidence'].append({'id': 'HIDDEN', 'kind': 'context', 'content': 'A hidden observation.'})
        def respond(attempt, payload):
            self.assertNotIn('HIDDEN', {e['id'] for e in payload['evidence']})
            rows = [self.row(c) for c in payload['frozen_claims']]
            rows[-1]['source_refs'] = [ref('HIDDEN', 'A hidden observation.')]
            return {'comparisons': rows}
        rows, errors = self.run_batch(respond, hidden={'HIDDEN'})
        self.assertEqual([r['relation'] for r in rows], ['supported', 'uncertain'])
        self.assertEqual(len(errors), 1)

    def test_every_definite_source_and_statement_version_is_bound(self):
        for relation in ('supported', 'exceeds_source'):
            for change in ('missing_observation', 'wrong_source_version', 'unbound_source', 'statement_version'):
                with self.subTest(relation=relation, change=change):
                    original = copy.deepcopy(self.package)
                    row = self.row(self.claims[0])
                    row.update(relation=relation, observation_commit_ids=[SHA],
                               source_refs=[ref('S', 'return 25 if value is None else value')])
                    if change == 'missing_observation':
                        row['observation_commit_ids'] = []
                    elif change == 'wrong_source_version':
                        row['observation_commit_ids'] = [PARENT]
                    elif change == 'unbound_source':
                        next(e for e in self.package['evidence'] if e['id'] == 'S')['version_id'] = None
                    else:
                        next(e for e in self.package['evidence'] if e['id'] == 'A1')['version_id'] = PARENT
                    with self.assertRaisesRegex(ValueError, '观察版本不一致'):
                        comparison_response({'comparisons': [row]}, self.claims[:1], self.task, self.package)
                    self.package = original

    def test_original_tool_event_cannot_be_replaced_by_a_similar_earlier_error(self):
        for relation in ('supported', 'exceeds_source'):
            row = self.row(self.claims[0])
            row.update(relation=relation, source_refs=[ref('OLD', 'IndentationError: unexpected indent in another file')])
            checked = comparison_response({'comparisons': [row]}, self.claims[:1], self.task, self.package)[0]
            self.assertEqual(checked['relation'], 'uncertain')
            self.assertIn('另一时点', checked['reason'])
        row = self.row(self.claims[0])
        self.assertEqual(comparison_response({'comparisons': [row]}, self.claims[:1], self.task,
                                            self.package)[0]['relation'], 'supported')
        self.package['trace'] = {'messages': []}
        self.assertEqual(comparison_response({'comparisons': [row]}, self.claims[:1], self.task,
                                            self.package)[0]['relation'], 'uncertain')

    def test_definite_row_cannot_have_empty_sources_or_change_frozen_property_or_type(self):
        for relation in ('supported', 'exceeds_source'):
            for change in ('empty_sources', 'different_property', 'different_type'):
                with self.subTest(relation=relation, change=change):
                    row = self.row(self.claims[0])
                    row['relation'] = relation
                    if change == 'empty_sources':
                        row['source_refs'] = []
                    elif change == 'different_property':
                        row['comparison_scope'] = 'different_property'
                    else:
                        row['comparison_type'] = 'actual_state'
                    if change == 'empty_sources':
                        with self.assertRaisesRegex(ValueError, '非空来源引用'):
                            comparison_response({'comparisons': [row]}, self.claims[:1], self.task, self.package)
                    else:
                        checked = comparison_response({'comparisons': [row]}, self.claims[:1], self.task,
                                                      self.package)[0]
                        self.assertEqual(checked['relation'], 'uncertain')
                        self.assertEqual(checked['comparison_scope'], row['comparison_scope'])
                        self.assertEqual(checked['comparison_type'], row['comparison_type'])

    def test_real_review_path_uses_original_package_without_exposing_assistant_as_truth(self):
        rule = next(r for r in load_catalog(Path(__file__).resolve().parents[1])['rules'] if r['id'] == 'TC14')
        condition = next(c for c in rule['conditions'] if c['id'] == 'TC14.C02')
        calls = []
        def call(stage, system, payload, validator, **kwargs):
            calls.append(copy.deepcopy(payload))
            if 'source_inventory' in payload:
                choices = statement_choices(self.package, {s['evidence_id'] for s in payload['source_inventory']})
                value = {'sources': [{'evidence_id': x['evidence_id'], 'classification': 'claims',
                    'reason': 'Original local event, without using outcomes as purpose.', 'claims': [{
                    'statement_id': x['statement_id'], 'claim_type': 'fact', 'claim_target': {
                    'object': 'local edit event', 'property': x['proposition'],
                    'scope': 'observed_event', 'state_assertion': None}}]} for x in choices]}
            else:
                self.assertTrue(all(e['kind'] != 'assistant' for e in payload['evidence']))
                observed = {o['claim_id']: o['evidence_id'] for o in payload['prior_tool_observations']}
                self.assertEqual(set(observed.values()), {'OBS1', 'OBS2'})
                value = {'comparisons': [{**self.row(self.claims[n]), 'claim_id': claim['id']}
                    for n, claim in enumerate(payload['frozen_claims'])]}
                kwargs['before_repair'](value)
            return validator(value), None, False
        answer = review_claim_scope(self.task, self.package, condition, model_input(self.package, [self.task]),
                                    call, 'actual-review', self.directory, lambda _: None)
        self.assertEqual(answer['result'], PASS)
        self.assertEqual(answer['analysis_stage_errors'], [])
        self.assertEqual(len(calls), 2)

    def test_scope_bad_row_is_isolated_but_ambiguous_envelope_is_not_partially_adopted(self):
        from ..sop_claim_review import _scope_batch
        candidates = {c['id']: self.row(c) for c in self.claims}
        rows = [{**self.row(c), 'scope_consistency': 'same_scope'} for c in self.claims]
        rows[1]['source_refs'] = [ref('NONEXISTENT', 'File updated.')]
        result = _scope_batch({'scope_reviews': rows}, self.claims, candidates, self.task, self.package)
        self.assertEqual([r['relation'] for r in result['rows']], ['supported', 'uncertain'])
        self.assertEqual(len(result['errors']), 1)
        self.assertIn('C2', result['errors'][0])
        self.assertEqual(result['rows'][1]['source_refs'], candidates['C2']['source_refs'])
        for bad in (rows[:1], [rows[0], rows[0]]):
            with self.assertRaisesRegex(ValueError, '完整且唯一'):
                _scope_batch({'scope_reviews': bad}, self.claims, candidates, self.task, self.package)

    def test_real_scope_path_keeps_valid_sibling_with_one_call_and_explicit_local_error(self):
        rule = next(r for r in load_catalog(Path(__file__).resolve().parents[1])['rules'] if r['id'] == 'TC14')
        condition = next(c for c in rule['conditions'] if c['id'] == 'TC14.C02')
        calls = []
        def call(stage, system, payload, validator, **kwargs):
            calls.append(stage)
            if 'source_inventory' in payload:
                choices = statement_choices(self.package, {s['evidence_id'] for s in payload['source_inventory']})
                value = {'sources': [{'evidence_id': x['evidence_id'], 'classification': 'claims',
                    'reason': 'Original observed fact.', 'claims': [{'statement_id': x['statement_id'],
                    'claim_type': 'fact', 'claim_target': {'object': 'observed edit',
                    'property': x['proposition'], 'scope': 'effective_state', 'state_assertion': None}}]}
                    for x in choices]}
            else:
                rows = [{**self.row(self.claims[n]), 'claim_id': claim['id']}
                        for n, claim in enumerate(payload['frozen_claims'])]
                if 'scope_candidates' in payload:
                    self.assertEqual(kwargs, {'attempts': 1})
                    rows = [{**r, 'scope_consistency': 'same_scope'} for r in rows]
                    rows[-1]['source_refs'] = [ref('NONEXISTENT', 'File updated.')]
                    value = {'scope_reviews': rows}
                else:
                    value = {'comparisons': rows}
                    kwargs['before_repair'](value)
            return validator(value), None, False
        answer = review_claim_scope(self.task, self.package, condition, model_input(self.package, [self.task]),
                                    call, 'actual-scope', self.directory, lambda _: None)
        claims = answer['atomic_checks'][0]['semantic_basis']['claims']
        self.assertEqual([c['relation'] for c in claims], ['supported', 'uncertain'])
        self.assertEqual(answer['result'], UNKNOWN)
        self.assertEqual(len(answer['analysis_stage_errors']), 1)
        self.assertEqual(len(calls), 3, 'One extraction, one comparison, one scope call; no added retry.')


class WholeFileCoverageTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.sentence = 'The `Config` class is not defined in the `config.py` file.'
        self.content = 'class ConfigResolver:\n    pass\n' + '\n'.join('# unchanged' for _ in range(347))
        self.package['evidence'].extend([
            {'id': 'A', 'kind': 'assistant', 'content': self.sentence},
            {'id': 'FULL', 'kind': 'source', 'path': 'config.py', 'version_id': SHA, 'content': self.content}])
        self.claim = {'id': 'C', 'proposition': self.sentence, 'claim_type': 'fact',
            'statement_refs': [ref('A', self.sentence)], 'claim_target': {'object': 'config.py',
            'property': 'Config definition absent', 'scope': 'effective_state', 'state_assertion': None,
            'source_extent': {'kind': 'whole_file_absence', 'path': 'config.py'}}}

    def display(self, count):
        text = '[File: /pkg/config.py (349 lines total)]\n' + '\n'.join(
            str(n) + ':' + line for n, line in enumerate(self.content.splitlines()[:count], 1))
        self.package['evidence'].append({'id': 'OBS', 'kind': 'tool', 'content': text})
        return text

    def row(self, eid='OBS', coverage=None, relation='supported'):
        item = next(e for e in self.package['evidence'] if e['id'] == eid)
        row = {'claim_id': 'C', 'relation': relation, 'comparison_type': 'fact',
               'comparison_scope': 'same_property', 'observation_commit_ids': [SHA] if eid == 'FULL' else [],
               'source_refs': [ref(eid, item['content'].splitlines()[0])],
               'reason': 'The named definition is absent from the inspected file.'}
        if coverage is not None:
            row['source_coverage'] = [{'evidence_id': eid, 'start_line': start, 'end_line': end}
                                      for start, end in coverage]
        return row

    def checked(self, row, package=None):
        return comparison_response({'comparisons': [row]}, [self.claim], self.task, package or self.package)[0]

    def extract_sentence(self, sentence, *, extent=None, subject='config.py', scope='effective_state'):
        next(e for e in self.package['evidence'] if e['id'] == 'A')['content'] = sentence
        choice = statement_choices(self.package, {'A'})[0]
        target = {'object': subject, 'property': sentence, 'scope': scope,
                  'state_assertion': None, 'source_extent': extent}
        response = {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Original file observation.',
            'claims': [{'statement_id': choice['statement_id'], 'claim_type': 'fact', 'claim_target': target}]}]}
        return extract_response(response, [{'evidence_id': 'A'}], self.task,
                                self.package, strict_state=True)[0]['claims'][0]

    def test_real_hedged_missing_content_requires_extent_without_changing_original(self):
        sentence = 'However, it seems that the `config.py` file does not have a `sources` attribute or module.'
        for scope in ('effective_state', 'observed_event'):
            with self.subTest(scope=scope):
                with self.assertRaisesRegex(ValueError, 'source_extent'):
                    self.extract_sentence(sentence, scope=scope)
                frozen = self.extract_sentence(sentence, scope=scope, extent={
                    'kind': 'whole_file_absence', 'path': 'config.py'})
                self.assertEqual(frozen['proposition'], sentence)
                self.assertEqual(frozen['claim_type'], 'fact')
                self.assertEqual(frozen['claim_target']['scope'], scope)
                self.assertEqual(frozen['statement_refs'], [ref('A', sentence)])

    def test_file_content_absence_forms_require_extent(self):
        for sentence in (
                'The config.py file does not have a ConfigSource definition.',
                'The config.py file does not contain a ConfigSource definition.',
                'The config.py file does not include a ConfigSource definition.',
                'The config.py file has no ConfigSource definitions.',
                'The config.py file contains no ConfigSource definitions.',
                'The config.py file includes no ConfigSource definitions.',
                'The config.py file lacks a ConfigSource definition.',
                'The config.py file appears to lack a ConfigSource definition.',
                'The config.py file does not contain the error shown in the log.'):
            with self.subTest(sentence=sentence):
                with self.assertRaisesRegex(ValueError, 'source_extent'):
                    self.extract_sentence(sentence)
        with self.assertRaisesRegex(ValueError, 'source_extent'):
            self.extract_sentence('The and.py file contains no definitions.', subject='and.py')

    def test_explicit_local_absence_does_not_require_whole_file_extent(self):
        for sentence in (
                'The config.py file does not have a ConfigSource definition in its first 100 lines.',
                'The config.py file contains no ConfigSource definitions within lines 20-40.',
                'The config.py file lacks a ConfigSource definition in the displayed excerpt.',
                'The displayed part of config.py contains no ConfigSource definitions.',
                'ConfigSource is not defined in the first 100 lines of config.py.',
                'The visible excerpt of config.py contains only ConfigResolver.'):
            with self.subTest(sentence=sentence):
                self.assertIsNone(self.extract_sentence(sentence)['claim_target']['source_extent'])

    def test_file_absence_cannot_borrow_another_clause_or_objects_predicate(self):
        for sentence in (
                'config.py loads correctly but helper.py contains no ConfigSource definitions.',
                'config.py imports helper.py which lacks a ConfigSource definition.',
                'ConfigSource is not defined in helper.py and config.py loads correctly.',
                'The edit of config.py was not applied.',
                'The import of config.py failed; helper.py contains no ConfigSource definitions.'):
            with self.subTest(sentence=sentence):
                self.assertIsNone(self.extract_sentence(sentence)['claim_target']['source_extent'])
        sentence = 'config.py contains no ConfigSource definitions but helper.py has one in its first 100 lines.'
        with self.assertRaisesRegex(ValueError, 'source_extent'):
            self.extract_sentence(sentence)
        sentence = 'config.py lacks ConfigSource definitions compared with the displayed excerpt of helper.py.'
        with self.assertRaisesRegex(ValueError, 'source_extent'):
            self.extract_sentence(sentence)
        sentence = 'The src directory contains no config.py file.'
        self.assertIsNone(self.extract_sentence(sentence, subject='src directory',
                                               scope='observed_event')['claim_target']['source_extent'])

    def test_modal_obligation_effect_and_access_are_not_file_content_inventory(self):
        for sentence in (
                'config.py does not have to be edited.',
                'config.py has no effect on this error.',
                'config.py lacks permission to read the settings.',
                'The config.py file lacks read access.',
                'The config.py file does not have write permissions.'):
            with self.subTest(sentence=sentence):
                self.assertIsNone(self.extract_sentence(sentence)['claim_target']['source_extent'])

    def test_hedged_absence_needs_actual_full_coverage_but_positive_counterexample_is_local(self):
        sentence = 'However, it seems that the `config.py` file does not have a `sources` attribute or module.'
        self.claim = self.extract_sentence(sentence, extent={'kind': 'whole_file_absence', 'path': 'config.py'})
        self.claim['id'] = 'C'
        text = self.display(100)
        partial = self.checked(self.row(coverage=[[1, len(text.splitlines())]]))
        self.assertEqual(partial['relation'], 'uncertain')
        self.assertEqual(partial['source_coverage_check']['status'], 'incomplete')
        self.assertEqual(self.checked(self.row('FULL'))['relation'], 'uncertain')
        self.assertEqual(self.checked(self.row('FULL', [[1, 100], [101, 349]]))['relation'], 'supported')
        full = next(e for e in self.package['evidence'] if e['id'] == 'FULL')
        full['content'] = '\n'.join(full['content'].splitlines()[:-1] + ['sources = []'])
        row = self.row('FULL', relation='exceeds_source')
        row['source_refs'] = [{'evidence_id': 'FULL', 'start_line': 349, 'end_line': 349, 'quote': 'sources = []'}]
        self.assertEqual(self.checked(row)['relation'], 'exceeds_source')
        self.assertEqual(self.claim['proposition'], sentence)

    def test_prefix_cannot_support_whole_file_absence_even_with_complete_file_available(self):
        text = self.display(100)
        result = self.checked(self.row(coverage=[[1, len(text.splitlines())]]))
        self.assertEqual(result['relation'], 'uncertain')
        self.assertEqual(result['source_coverage_check']['status'], 'incomplete')
        self.assertEqual(self.claim['proposition'], self.sentence)

    def test_complete_display_requires_explicit_review_range_but_then_can_support_absence(self):
        text = self.display(349)
        self.assertEqual(self.checked(self.row())['relation'], 'uncertain')
        complete = self.checked(self.row(coverage=[[1, len(text.splitlines())]]))
        self.assertEqual(complete['relation'], 'supported')
        self.assertEqual(complete['source_coverage_check']['complete_evidence_ids'], ['OBS'])

    def test_complete_same_version_source_needs_whole_review_not_one_cited_definition(self):
        self.assertEqual(self.checked(self.row('FULL', [[1, 100]]))['relation'], 'uncertain')
        self.assertEqual(self.checked(self.row('FULL', [[1, 100], [101, 349]]))['relation'], 'supported')

    def test_full_package_does_not_override_partial_visible_source_lines(self):
        from ..sop_claim_review import _comparison_input, _visible_package
        request = model_input(self.package, [self.task])
        full = next(e for e in request['evidence'] if e['id'] == 'FULL')
        full['numbered_lines'] = full['numbered_lines'][:100]
        truth = {**request, 'evidence': [e for e in request['evidence'] if e['kind'] != 'assistant']}
        payload = _comparison_input(truth, [self.claim], self.task, self.package)
        extent = next(e for e in payload['visible_source_extents'] if e['evidence_id'] == 'FULL')
        self.assertEqual(extent['visible_file_ranges'], [[1, 100]])
        self.assertEqual(extent['total_lines'], 349)
        self.assertEqual(self.checked(self.row('FULL', [[1, 349]]),
                                     _visible_package(self.package, truth))['relation'], 'uncertain')

    def test_one_positive_counterexample_does_not_need_whole_file_coverage(self):
        self.display(100)
        full = next(e for e in self.package['evidence'] if e['id'] == 'FULL')
        full['content'] = '\n'.join(full['content'].splitlines()[:-1] + ['class Config: pass'])
        row = self.row('FULL', relation='exceeds_source')
        row['source_refs'] = [{'evidence_id': 'FULL', 'start_line': 349, 'end_line': 349, 'quote': 'class Config: pass'}]
        self.assertEqual(self.checked(row)['relation'], 'exceeds_source')
        local = copy.deepcopy(self.claim)
        local['claim_target']['source_extent'] = None
        self.assertEqual(comparison_response({'comparisons': [self.row()]}, [local],
                                            self.task, self.package)[0]['relation'], 'supported')

    def test_coverage_cannot_borrow_uncited_file_or_claim_out_of_bounds_or_noninteger_lines(self):
        self.display(100)
        for coverage in ([{'evidence_id': 'FULL', 'start_line': 1, 'end_line': 349}],
                         [{'evidence_id': 'OBS', 'start_line': 1, 'end_line': 349}],
                         [{'evidence_id': 'OBS', 'start_line': True, 'end_line': 100}]):
            with self.subTest(coverage=coverage):
                row = self.row()
                row['source_coverage'] = coverage
                with self.assertRaisesRegex(ValueError, 'source_coverage'):
                    self.checked(row)

    def test_scope_vote_cannot_restore_partial_whole_file_support(self):
        self.display(100)
        row = self.row(coverage=[[1, 101]])
        result = scope_response({'scope_reviews': [{**row, 'scope_consistency': 'same_scope'}]},
                                [self.claim], {'C': row}, self.task, self.package)[0]
        self.assertEqual(result['relation'], 'uncertain')

    def test_global_inventory_predicate_requires_frozen_extent_but_local_failure_does_not(self):
        inventory = [{'evidence_id': 'A'}]
        choice = statement_choices(self.package, {'A'})[0]
        claim = {'statement_id': choice['statement_id'], 'claim_type': 'fact',
                 'claim_target': {k: v for k, v in self.claim['claim_target'].items() if k != 'source_extent'}}
        response = {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Whole-file inventory.',
                                 'claims': [claim]}]}
        with self.assertRaisesRegex(ValueError, 'source_extent'):
            extract_response(response, inventory, self.task, self.package, strict_state=True)
        claim['claim_target']['source_extent'] = self.claim['claim_target']['source_extent']
        frozen = extract_response(response, inventory, self.task, self.package, strict_state=True)[0]['claims'][0]
        self.assertEqual(frozen['claim_target']['source_extent']['path'], 'config.py')
        next(e for e in self.package['evidence'] if e['id'] == 'A')['content'] = 'The edit of config.py was not applied.'
        claim['statement_id'] = statement_choices(self.package, {'A'})[0]['statement_id']
        claim['claim_target'].pop('source_extent')
        self.assertEqual(len(extract_response(response, inventory, self.task, self.package,
                                             strict_state=True)[0]['claims']), 1)

    def test_missing_truth_refs_cannot_erase_the_frozen_original_statement(self):
        from ..sop_claim_review import _comparison_input
        request = model_input(self.package, [self.task])
        truth = {**request, 'evidence': [e for e in request['evidence'] if e['kind'] != 'assistant']}
        payload = _comparison_input(truth, [self.claim], self.task, self.package)
        self.assertEqual(payload['original_statement_context'][0]['availability'], 'frozen_present')
        self.assertTrue(all(e['kind'] != 'assistant' for e in payload['evidence']))
        row = self.row('FULL')
        row.update(relation='uncertain', source_refs=[], reason='A is absent, so the original statement has no source.')
        checked = self.checked(row)
        self.assertIn('已按冻结statement_refs逐字定位', checked['reason'])
        self.assertNotIn('A is absent', checked['reason'])
        self.assertEqual(checked['model_reason'], row['reason'])

    def test_real_directory_and_import_failures_do_not_require_unrelated_file_inventory(self):
        samples = [
            ('Since the `src` directory is not found, we should look through the files in the current directory '
             'to find the `memset.py` file.', 'src目录'),
            ('The error indicates that the `lexicon.config.sources` module is not found.', 'lexicon.config.sources模块'),
            ('The error indicates that the `lexicon.config.sources` module is not found.', 'lexicon.config.sources'),
            ('The module `lexicon.config.sources` is not found.', 'lexicon.config.sources'),
            ('lexicon.config.sources模块未找到。', 'lexicon.config.sources')]
        for sentence, subject in samples:
            with self.subTest(sentence=sentence):
                next(e for e in self.package['evidence'] if e['id'] == 'A')['content'] = sentence
                choice = statement_choices(self.package, {'A'})[0]
                claim = {'statement_id': choice['statement_id'], 'claim_type': 'fact', 'claim_target': {
                    'object': subject, 'property': 'Original failed lookup observation', 'scope': 'observed_event',
                    'state_assertion': None, 'source_extent': None}}
                response = {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Original observation.',
                                         'claims': [claim]}]}
                frozen = extract_response(response, [{'evidence_id': 'A'}], self.task,
                                          self.package, strict_state=True)[0]['claims'][0]
                self.assertIsNone(frozen['claim_target']['source_extent'])
                self.assertEqual(frozen['proposition'], sentence)

    def test_file_label_and_content_absence_still_require_extent_for_dotted_names(self):
        for sentence, subject in (
                ('The lexicon.config.sources file contains no definitions.', 'lexicon.config.sources'),
                ('lexicon/config.py contains no sources attribute.', 'lexicon/config.py'),
                ('config.py contains no sources attribute or module.', 'config.py')):
            with self.subTest(sentence=sentence):
                with self.assertRaisesRegex(ValueError, 'source_extent'):
                    self.extract_sentence(sentence, subject=subject)
                frozen = self.extract_sentence(sentence, subject=subject, extent={
                    'kind': 'whole_file_absence', 'path': subject})
                self.assertEqual(frozen['proposition'], sentence)
                self.assertEqual(frozen['claim_target']['source_extent']['path'], subject)

    def test_mislabelled_observed_scope_cannot_bypass_real_whole_file_absence_extent(self):
        choice = statement_choices(self.package, {'A'})[0]
        claim = {'statement_id': choice['statement_id'], 'claim_type': 'fact', 'claim_target': {
            'object': 'config.py文件', 'property': 'Config is absent from the file', 'scope': 'observed_event',
            'state_assertion': None, 'source_extent': None}}
        response = {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Whole-file content claim.',
                                 'claims': [claim]}]}
        with self.assertRaisesRegex(ValueError, 'A/' + choice['statement_id'] + '.*source_extent'):
            extract_response(response, [{'evidence_id': 'A'}], self.task, self.package, strict_state=True)
        claim['claim_target']['source_extent'] = {'kind': 'whole_file_absence', 'path': 'config.py'}
        frozen = extract_response(response, [{'evidence_id': 'A'}], self.task,
                                  self.package, strict_state=True)[0]['claims'][0]
        self.assertEqual(frozen['claim_target']['source_extent']['path'], 'config.py')

    def test_chinese_text_adjacent_to_file_suffix_cannot_hide_whole_file_absence(self):
        for sentence in ('config.py中不存在Config类定义。', '在config.py中不存在Config类定义。'):
            with self.subTest(sentence=sentence):
                next(e for e in self.package['evidence'] if e['id'] == 'A')['content'] = sentence
                choice = statement_choices(self.package, {'A'})[0]
                claim = {'statement_id': choice['statement_id'], 'claim_type': 'fact', 'claim_target': {
                    'object': 'config.py', 'property': '不存在Config类定义', 'scope': 'observed_event',
                    'state_assertion': None, 'source_extent': None}}
                response = {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': '完整文件内容否定。',
                                         'claims': [claim]}]}
                with self.assertRaisesRegex(ValueError, 'source_extent'):
                    extract_response(response, [{'evidence_id': 'A'}], self.task, self.package, strict_state=True)
                claim['claim_target']['source_extent'] = {'kind': 'whole_file_absence', 'path': 'config.py'}
                self.assertEqual(len(extract_response(response, [{'evidence_id': 'A'}], self.task,
                                                     self.package, strict_state=True)[0]['claims']), 1)


class EditTargetObservationTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, _ = fixtures()
        self.task = self.result['tasks'][0]
        self.sentence = ('It seems that I attempted to edit the wrong file again. '
                         'I need to edit the `memset.py` file instead of the `reproduce.py` file.')
        self.tool = ('This is how your edit would have looked if applied\n'
                     '[File: /pkg/reproduce.py (2 lines total)]\n1:pass\n2:    self.domain = config.resolve("domain")\n'
                     'This is the original code before your edit\n[File: /pkg/reproduce.py (1 lines total)]\n1:pass\n'
                     'Your changes have NOT been applied. Please fix your edit command and try again.\n'
                     '(Current directory: /pkg)')
        self.package['evidence'] = [e for e in self.package['evidence'] if e['kind'] != 'assistant']
        self.package['evidence'].extend([{'id': 'OBS', 'kind': 'tool', 'content': self.tool},
                                         {'id': 'A', 'kind': 'assistant', 'content': self.sentence}])
        self.package['trace'] = {'messages': [{'role': 'tool', 'evidence_id': 'OBS', 'content': self.tool},
                                              {'role': 'assistant', 'evidence_id': 'A', 'content': self.sentence}]}

    def extraction(self, scope='observed_event'):
        return {'sources': [{'evidence_id': 'A', 'classification': 'claims', 'reason': 'Hedged original operation.',
            'claims': [{'statement_id': statement_choices(self.package, {'A'})[0]['statement_id'],
                'claim_type': 'diagnosis', 'claim_target': {'object': 'prior editing action',
                'property': 'attempted target differs from stated intended target', 'scope': scope,
                'state_assertion': None, 'edit_target': {'intended_path': 'memset.py'}}}]}]}

    def claim(self):
        return extract_response(self.extraction(), [{'evidence_id': 'A'}], self.task,
                                self.package, strict_state=True)[0]['claims'][0]

    def test_hedged_edit_target_observation_cannot_be_frozen_as_a_cause_hypothesis(self):
        response = self.extraction('cause_hypothesis')
        response['sources'][0]['claims'][0]['claim_target']['edit_target'] = None
        with self.assertRaisesRegex(ValueError, '原操作目标观察'):
            extract_response(response, [{'evidence_id': 'A'}], self.task, self.package, strict_state=True)
        frozen = self.claim()
        self.assertEqual(frozen['claim_type'], 'diagnosis')
        self.assertEqual(frozen['claim_target']['scope'], 'observed_event')
        self.assertIn('It seems', frozen['proposition'])

    def test_original_intent_and_independent_rejected_attempt_prove_only_target_mismatch(self):
        from ..sop_claim_review import edit_target_proof
        proof = edit_target_proof(self.claim(), self.task, self.package)
        self.assertEqual(proof['status'], 'target_mismatch')
        self.assertEqual(proof['attempted_path'], '/pkg/reproduce.py')
        self.assertEqual(proof['intended_path'], '/pkg/memset.py')
        self.assertEqual({r['evidence_id'] for r in proof['source_refs']}, {'OBS'})
        self.assertEqual(proof['observation_commit_ids'], [])
        self.assertIn('工具明确未应用修改', proof['reason'])

    def test_same_path_missing_cwd_ambiguous_target_and_version_conflict_remain_unknown(self):
        from ..sop_claim_review import edit_target_proof
        for change in ('same_path', 'missing_cwd', 'different_headers', 'different_version', 'hidden_marker'):
            with self.subTest(change=change):
                package = copy.deepcopy(self.package)
                claim = self.claim()
                tool = next(e for e in package['evidence'] if e['id'] == 'OBS')
                if change == 'same_path':
                    claim['claim_target']['edit_target']['intended_path'] = 'reproduce.py'
                elif change == 'missing_cwd':
                    tool['content'] = tool['content'].replace('(Current directory: /pkg)', '')
                elif change == 'different_headers':
                    tool['content'] = tool['content'].replace(
                        '[File: /pkg/reproduce.py (1 lines total)]', '[File: /pkg/memset.py (1 lines total)]')
                elif change == 'different_version':
                    next(e for e in package['evidence'] if e['id'] == 'A')['version_id'] = SHA
                    tool['version_id'] = PARENT
                else:
                    tool['numbered_lines'] = [{'line': n, 'text': text} for n, text in enumerate(
                        tool['content'].splitlines(), 1) if 'NOT been applied' not in text]
                package['trace']['messages'][0]['content'] = tool['content']
                self.assertEqual(edit_target_proof(claim, self.task, package)['status'], 'uncertain')

    def test_real_review_path_keeps_frozen_hedge_and_repairs_observation_without_extra_model_vote(self):
        catalog = load_catalog(Path(__file__).resolve().parents[1])
        condition = next(c for r in catalog['rules'] if r['id'] == 'TC14' for c in r['conditions'] if c['id'] == 'TC14.C02')
        calls = []
        def call(stage, system, payload, validator, **kwargs):
            calls.append(stage)
            if 'source_inventory' in payload:
                value = self.extraction()
            else:
                claim = payload['frozen_claims'][0]
                value = {'comparisons': [{'claim_id': claim['id'], 'relation': 'uncertain',
                    'comparison_type': 'diagnosis', 'comparison_scope': 'unknown', 'observation_commit_ids': [],
                    'source_refs': [], 'reason': 'No independent cause mechanism.'}]}
            return validator(value), None, False
        with tempfile.TemporaryDirectory() as directory:
            row = review_claim_scope(self.task, self.package, condition, model_input(self.package, [self.task]),
                                     call, 'wrong-target', Path(directory), lambda _: None)
            proof = json.loads((Path(directory) / 'wrong-target.edit-target-proofs.json').read_text())
        self.assertEqual(row['result'], PASS)
        claim = row['atomic_checks'][0]['semantic_basis']['claims'][0]
        self.assertEqual(claim['claim_type'], 'diagnosis')
        self.assertIn('It seems', claim['proposition'])
        self.assertEqual(claim['comparison_scope'], 'same_property')
        self.assertEqual(proof['checks'][0]['status'], 'target_mismatch')
        self.assertEqual(len(calls), 2)

    def test_hidden_original_tool_cannot_become_program_truth(self):
        from ..sop_claim_review import edit_target_proof, _visible_package
        request = model_input(self.package, [self.task])
        truth = {**request, 'evidence': [e for e in request['evidence'] if e['kind'] not in {'assistant', 'tool'}]}
        self.assertEqual(edit_target_proof(self.claim(), self.task, _visible_package(self.package, truth))['status'],
                         'uncertain')

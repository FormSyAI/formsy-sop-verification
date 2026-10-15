"""Selector-only retries keep raw failures, siblings and the existing call budget."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from ..reference_repair import (CITATION_RETRY_PROMPT, attach_quote_ids, reference_diagnostics,
                               repair_references, resolve_quote_ids, validate_quote_id_retry)
from ..sop_audit import CONDITION_SYSTEM, audit_sop
from .test_sop_audit import Client, default_response, fixtures


FIXTURE = Path(__file__).parent / 'semantic_fixtures_v3' / 'citation-json-punctuation.json'


class SelectorOnlyRetryTests(unittest.TestCase):
    def setUp(self):
        self.sample = json.loads(FIXTURE.read_text())
        # Empty padding preserves excerpt coordinates; it is not additional source context.
        content = '\n' * (self.sample['excerpt_start_line'] - 1) + '\n'.join(self.sample['excerpt_lines'])
        self.package = {'evidence': [
            {'id': 'CITATION_LOG', 'kind': 'test_log', 'version_id': 'a' * 40, 'content': content},
            {'id': 'HIDDEN', 'kind': 'source', 'version_id': 'b' * 40, 'content': 'hidden = True'}]}
        numbered = attach_quote_ids({'evidence': self.package['evidence']}, self.package)['evidence']
        self.ids = [line['quote_id'] for line in numbered[0]['numbered_lines'] if 'quote_id' in line]
        self.hidden = numbered[1]['numbered_lines'][0]['quote_id']
        self.exact = {'evidence_id': 'CITATION_LOG', 'start_line': 16, 'end_line': 18,
                      'quote': '\n'.join(self.sample['excerpt_lines'])}

    def check(self, value):
        validate_quote_id_retry(value, self.package, available_evidence_ids={'CITATION_LOG'})

    def test_actual_punctuation_failure_and_even_exact_manual_retry_are_rejected(self):
        self.assertEqual(self.sample['first_quote'], self.sample['retry_quote'])
        self.assertEqual(self.sample['retry_quote'].splitlines()[0], self.sample['excerpt_lines'][0] + '",')
        for quote in (self.sample['retry_quote'], self.exact['quote']):
            row = {'evidence_refs': [{**self.exact, 'quote': quote}]}
            before = copy.deepcopy(row)
            with self.assertRaisesRegex(ValueError, '禁止.*手写|禁止手写'):
                self.check(row)
            self.assertEqual(row, before)
        bad = {'evidence_refs': [{**self.exact, 'quote': self.sample['first_quote']}]}
        self.assertEqual(reference_diagnostics(bad, self.package)[0]['error_kind'], 'quote_absent_from_evidence')
        repaired, repairs = repair_references(bad, self.package)
        self.assertEqual(repaired, bad)
        self.assertEqual(repairs, [], 'No punctuation repair is permitted.')

    def test_visible_object_bare_compact_and_empty_selectors_are_accepted_without_guessing(self):
        for refs in ([], self.ids, [{'quote_id': oid} for oid in self.ids]):
            row = {'evidence_refs': refs}
            self.check(row)
            expanded, _ = repair_references(row, self.package, available_evidence_ids={'CITATION_LOG'})
            self.assertEqual(expanded['evidence_refs'], resolve_quote_ids(
                self.ids if refs else [], self.package, available_evidence_ids={'CITATION_LOG'}))
        self.check({'evidence_quote_ids': self.ids})

    def test_hidden_unknown_duplicate_mixed_and_manual_supplement_are_rejected(self):
        qid = self.ids[0]
        invalid = [[self.hidden], ['Q-unknown'], [qid, qid],
                   [{'quote_id': qid}, {'quote_id': qid}], [qid, {'quote_id': qid}],
                   [{'quote_id': qid, 'quote': 'supplement'}], [self.exact], [qid, self.exact], None]
        for refs in invalid:
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                self.check({'nested': {'source_refs': refs}})
        with self.assertRaises(ValueError):
            self.check({'source_refs': [], 'source_quote_ids': self.ids})

    def test_nonreference_line_metadata_and_first_pass_exact_citations_are_unchanged(self):
        metadata = {'source_extent': {'source_evidence_id': 'CITATION_LOG', 'start_line': 1, 'end_line': 18},
                    'source_coverage': [{'evidence_id': 'CITATION_LOG', 'start_line': 16, 'end_line': 18}],
                    'location': {'start_line': 16, 'end_line': 18, 'label': 'line metadata'},
                    'evidence_refs': [{'quote_id': self.ids[0]}]}
        self.check(metadata)
        self.assertEqual(reference_diagnostics(metadata, self.package), [])
        incomplete = {'evidence_refs': [{'evidence_id': 'CITATION_LOG', 'start_line': 16, 'end_line': 18}]}
        self.assertTrue(reference_diagnostics(incomplete, self.package))
        with self.assertRaises(ValueError):
            self.check(incomplete)
        row = {'evidence_refs': [self.exact]}
        repaired, repairs = repair_references(row, self.package)
        self.assertEqual(repaired, row)
        self.assertEqual(repairs, [])

    def test_condition_prompt_separates_history_from_target_and_preserves_claim_observation_exception(self):
        for text in ('reason和atomic_checks.reason', '历史观察，未绑定目标版本',
                     '不能把删除行说成目标版本仍存在', 'TC14原主张比较仍可使用该主张原观察的父版本'):
            self.assertIn(text, CONDITION_SYSTEM)
        self.assertIn('禁止手写quote/evidence_id/行号', CITATION_RETRY_PROMPT)
        self.assertNotIn('compact', CITATION_RETRY_PROMPT)
        self.assertNotIn('*_quote_ids', CITATION_RETRY_PROMPT)
        self.assertIn('标准*_refs数组', CITATION_RETRY_PROMPT)

    def test_real_row_retry_preserves_sibling_and_raw_with_exactly_two_condition_calls(self):
        for correction in ('repeat_raw', 'exact_manual', 'selector', 'withdraw'):
            with self.subTest(correction=correction):
                result, package, catalog = fixtures()
                package['evidence'].append(copy.deepcopy(self.package['evidence'][0]))
                catalog['rules'] = catalog['rules'][:1]
                result['checks'] = result['checks'][:1]
                first = catalog['rules'][0]['conditions'][0]
                catalog['rules'][0]['conditions'] = [first, {**first, 'id': 'FIX03.C02'}]
                calls, raw = [], []
                def respond(payload):
                    value = default_response(payload)
                    if 'conditions' not in payload:
                        return value
                    calls.append(copy.deepcopy(payload))
                    row = next(r for r in value['conditions'] if r['condition_id'] == first['id'])
                    row.update(result='未核查', gap_type='evidence_missing', acceptance_ids=[],
                               reason='The visible log reports AttributeError; execution identity remains unverified.')
                    row['evidence_refs'] = [{**self.exact, 'quote': self.sample['first_quote']}]
                    row.pop('atomic_checks', None)
                    if len(calls) == 2:
                        self.assertEqual([r['id'] for r in payload['conditions']], [first['id']])
                        self.assertTrue(payload['citation_retry']['selector_only'])
                        if correction == 'exact_manual':
                            row['evidence_refs'] = [copy.deepcopy(self.exact)]
                        elif correction == 'selector':
                            selectors = attach_quote_ids({'evidence': [package['evidence'][-1]]}, package)['evidence'][0]
                            row['evidence_refs'] = [{'quote_id': line['quote_id']} for line in selectors['numbered_lines']
                                                    if 'quote_id' in line]
                        elif correction == 'withdraw':
                            row.update(evidence_refs=[], reason='The earlier assertion is withdrawn; keep the scope unknown.')
                    raw.append(copy.deepcopy(value))
                    return value
                before = copy.deepcopy(package)
                with tempfile.TemporaryDirectory() as directory:
                    class PromptClient(Client):
                        def complete(inner, system, payload, directory, stage):
                            if payload.get('citation_retry', {}).get('selector_only'):
                                self.assertEqual(system.count(CITATION_RETRY_PROMPT), 1)
                                self.assertEqual(payload['citation_retry']['condition_ids'], [first['id']])
                            return super().complete(system, payload, directory, stage)
                    report = audit_sop(result, package, catalog, PromptClient(respond), Path(directory))
                    rows = {row['condition_id']: row for row in report['sop_condition_checks']}
                self.assertEqual(len(calls), 2)
                self.assertEqual(package, before)
                self.assertEqual(raw[0]['conditions'][0]['evidence_refs'][0]['quote'], self.sample['first_quote'])
                self.assertEqual(rows['FIX03.C02']['analysis_status'], 'completed')
                self.assertEqual(rows['FIX03.C02']['result'], '满足')
                self.assertEqual(rows[first['id']]['analysis_status'],
                                 'completed' if correction in ('selector', 'withdraw') else 'failed',
                                 rows[first['id']]['reason'])
                self.assertEqual(rows[first['id']]['result'], '未核查')


if __name__ == '__main__':
    unittest.main()

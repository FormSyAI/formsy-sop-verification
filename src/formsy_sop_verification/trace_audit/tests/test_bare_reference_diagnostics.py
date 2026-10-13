"""Bare-Q diagnostics agree with citation validation, without accepting semantic errors."""
import copy
import json
import unittest

from ..reference_repair import (attach_quote_ids, reference_diagnostics, repair_references,
                              validate_quote_id_retry)
from ..sop_claim_review import comparison_response


class BareReferenceDiagnosticsTests(unittest.TestCase):
    def setUp(self):
        self.version = 'a' * 40
        self.package = {'commits': [], 'evidence': [
            {'id': 'S', 'name': 'current.py', 'kind': 'source', 'version_id': self.version,
             'content': 'def first():\n    return 1\ndef second():\n    return 2'},
            {'id': 'H', 'name': 'HIDDEN_NAME', 'kind': 'source', 'version_id': 'b' * 40,
             'content': 'HIDDEN_SOURCE_BODY'},
            {'id': 'A', 'name': 'Original statement', 'kind': 'assistant', 'version_id': None,
             'content': 'The source defines both functions.'}]}
        numbered = attach_quote_ids({'evidence': self.package['evidence']}, self.package)['evidence']
        self.ids = {item['id']: [line['quote_id'] for line in item['numbered_lines']]
                    for item in numbered}
        self.visible = {'S', 'A'}

    def diagnose(self, value):
        return reference_diagnostics(value, self.package, available_evidence_ids=self.visible)

    def test_visible_unique_bare_q_arrays_do_not_fabricate_citation_errors(self):
        for field in ('source_refs', 'evidence_refs', 'run_refs'):
            with self.subTest(field=field):
                value = {'comparisons': [{field: [self.ids['S'][0], self.ids['S'][2]],
                                          'reason': 'A separate semantic check rejected this row.'}]}
                before = copy.deepcopy((value, self.package))
                validate_quote_id_retry(value, self.package, available_evidence_ids=self.visible)
                self.assertEqual(self.diagnose(value), [])
                self.assertEqual((value, self.package), before)

    def test_unknown_hidden_duplicate_mixed_and_material_ids_still_fail(self):
        qid = self.ids['S'][0]
        exact = {'evidence_id': 'S', 'start_line': 1, 'end_line': 1, 'quote': 'def first():'}
        for refs in ([qid, 'Q-unknown'], [self.ids['H'][0]], [qid, qid],
                     [qid, {'quote_id': qid}], [qid, exact], ['S'], [qid, None]):
            with self.subTest(refs=refs):
                value = {'source_refs': refs}
                before = copy.deepcopy(value)
                feedback = self.diagnose(value)
                self.assertEqual(feedback[0]['path'], '$.source_refs')
                with self.assertRaises(ValueError):
                    validate_quote_id_retry(value, self.package, available_evidence_ids=self.visible)
                self.assertEqual(value, before)
                for hidden in ('HIDDEN_NAME', 'HIDDEN_SOURCE_BODY', self.ids['H'][0], 'b' * 40):
                    self.assertNotIn(hidden, json.dumps(feedback))

    def test_valid_sibling_does_not_hide_invalid_nested_bare_refs(self):
        value = {'comparisons': [{'source_refs': [self.ids['S'][0]],
                                  'proof': {'counterexample_refs': ['Q-unknown']}}]}
        feedback = self.diagnose(value)
        self.assertEqual([item['path'] for item in feedback],
                         ['$.comparisons[0].proof.counterexample_refs'])

    def test_stale_content_or_version_qids_remain_unknown(self):
        value = {'source_refs': [self.ids['S'][0]]}
        for field, changed in (('content', 'replaced source'), ('version_id', 'c' * 40)):
            with self.subTest(field=field):
                package = copy.deepcopy(self.package)
                package['evidence'][0][field] = changed
                self.assertTrue(reference_diagnostics(value, package, available_evidence_ids=self.visible))

    def test_empty_and_explicit_selector_refs_remain_valid(self):
        for refs in ([], [{'quote_id': self.ids['S'][0]}]):
            self.assertEqual(self.diagnose({'source_refs': refs}), [])

    def test_selector_only_retry_accepts_visible_selectors_and_rejects_even_exact_full_refs(self):
        qid = self.ids['S'][0]
        exact = {'evidence_id': 'S', 'start_line': 1, 'end_line': 1, 'quote': 'def first():'}
        validate_quote_id_retry({'source_refs': [exact]}, self.package)
        for value in ({'source_refs': []}, {'source_refs': [qid]},
                      {'source_refs': [{'quote_id': qid}]}, {'source_quote_ids': [qid]}):
            with self.subTest(value=value):
                validate_quote_id_retry(value, self.package, available_evidence_ids=self.visible,
                                        selector_only=True)
        for value in ({'source_refs': [exact]}, {'proof': {'counterexample_refs': [exact]}}):
            with self.subTest(value=value), self.assertRaisesRegex(ValueError, '禁止手写完整引用'):
                validate_quote_id_retry(value, self.package, selector_only=True)

    def test_selector_only_does_not_accept_hidden_stale_or_mixed_selectors(self):
        qid = self.ids['S'][0]
        for refs in ([self.ids['H'][0]], ['Q-stale'], [qid, qid], [qid, {'quote_id': qid}], ['S']):
            with self.subTest(refs=refs), self.assertRaises(ValueError):
                validate_quote_id_retry({'source_refs': refs}, self.package,
                                        available_evidence_ids=self.visible, selector_only=True)

    def test_valid_bare_qids_do_not_fill_or_bypass_observation_version(self):
        row = {'claim_id': 'CL1', 'relation': 'supported', 'comparison_type': 'fact',
               'comparison_scope': 'same_property', 'observation_commit_ids': [],
               'source_refs': [self.ids['S'][0], self.ids['S'][2]],
               'reason': 'The current source defines both functions.'}
        claim = {'id': 'CL1', 'claim_type': 'fact',
                 'claim_target': {'scope': 'effective_state'},
                 'statement_refs': [{'evidence_id': 'A', 'start_line': 1, 'end_line': 1,
                                     'quote': 'The source defines both functions.'}]}
        task = {'id': 'T1', 'commit_ids': [self.version], 'target_commit_ids': [self.version]}
        before = copy.deepcopy(row)
        self.assertEqual(self.diagnose(row), [])
        fixed, repairs = repair_references({'comparisons': [row]}, self.package,
                                           available_evidence_ids=self.visible)
        self.assertEqual([item['kind'] for item in repairs], ['quote_id_string'] * 2)
        with self.assertRaisesRegex(ValueError, '所比较观察版本不一致'):
            comparison_response(fixed, [claim], task, self.package)
        self.assertEqual(row, before)
        self.assertEqual(fixed['comparisons'][0]['observation_commit_ids'], [])


if __name__ == '__main__':
    unittest.main()

"""Extraction retries isolate invalid sources without supplying missing claim fields."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from ..audit_engine import model_input
from ..sop_claim_review import _extract_batch, statement_choices
from ..sop_judgments import statement_review_inventory
from .test_sop_audit import fixtures


class ClaimExtractionRecoveryTests(unittest.TestCase):
    def setUp(self):
        result, self.package, _ = fixtures()
        self.task = result['tasks'][0]
        self.package['evidence'] = [item for item in self.package['evidence'] if item['kind'] != 'assistant']
        self.package['evidence'].extend(
            {'id': f'A{index}', 'kind': 'assistant',
             'content': f'file{index}.py does not contain a definition.' if index >= 10 else 'The file changed.'}
            for index in range(12))
        self.sources = statement_review_inventory(self.task, self.package)
        self.request = model_input(self.package, [self.task])
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.calls = []

    def response(self, payload, invalid=()):
        choices = {row['evidence_id']: row for row in payload['statement_choices']}
        rows = []
        for source in payload['source_inventory']:
            eid = source['evidence_id']
            index = int(eid[1:])
            rows.append({'evidence_id': eid, 'classification': 'claims', 'reason': 'Original statement.',
                         'claims': [{'statement_id': choices[eid]['statement_id'], 'claim_type': 'fact',
                                     'claim_target': {'object': f'file{index}.py', 'property': choices[eid]['proposition'],
                                                      'scope': 'effective_state', 'state_assertion': None,
                                                      'source_extent': {'kind': 'whole_file_absence',
                                                                        'path': f'file{index}.py'}
                                                      if index >= 10 and eid not in invalid else None}}]})
        return {'sources': rows}

    def extract(self, respond):
        def call(stage, system, payload, validator, **kwargs):
            self.calls.append(copy.deepcopy(payload))
            self.assertEqual(kwargs['attempts'], 1)
            self.assertFalse(kwargs['final_failure'])
            try:
                return validator(respond(payload, len(self.calls))), None, False
            except (ValueError, KeyError, TypeError) as exc:
                return None, str(exc), False
        return _extract_batch(self.sources, self.task, self.package, self.request, call,
                              'extract', self.directory)

    def test_ten_then_eleven_valid_sources_survive_final_single_source_failure(self):
        rows, errors = self.extract(lambda payload, attempt:
                                    self.response(payload, ('A10', 'A11') if attempt == 1 else ('A11',)))
        self.assertEqual([row['evidence_id'] for row in rows], [f'A{index}' for index in range(12)])
        self.assertEqual([source['evidence_id'] for source in self.calls[1]['source_inventory']], ['A10', 'A11'])
        self.assertEqual({item['id'] for item in self.calls[1]['evidence']}, {'A10', 'A11'})
        self.assertEqual({item['evidence_id'] for item in self.calls[1]['statement_choices']}, {'A10', 'A11'})
        self.assertEqual(sum(row['classification'] == 'claims' for row in rows), 11)
        self.assertEqual(rows[-1]['classification'], 'uncertain')
        self.assertEqual(rows[-1]['claims'], [])
        self.assertEqual(len(errors), 1)
        self.assertIn('A11', errors[0])
        self.assertNotIn('A10', errors[0])
        self.assertTrue(all(row['claims'][0]['claim_target']['source_extent'] is None for row in rows[:10]))
        retained = json.loads((self.directory / 'extract.sources-validation.json').read_text())
        self.assertEqual(len(retained['retained_source_ids']), 10)
        self.assertEqual(set(retained['pending_errors']), {'A10', 'A11'})
        final = json.loads((self.directory / 'extract-retry.sources-validation.json').read_text())
        self.assertEqual(len(final['retained_source_ids']), 11)
        self.assertEqual(set(final['pending_errors']), {'A11'})

    def test_successful_retry_removes_only_recovered_errors(self):
        rows, errors = self.extract(lambda payload, attempt:
                                    self.response(payload, ('A10', 'A11') if attempt == 1 else ()))
        self.assertEqual(len(self.calls), 2)
        self.assertEqual(errors, [])
        self.assertTrue(all(row['classification'] == 'claims' for row in rows))

    def test_missing_or_duplicate_envelope_does_not_adopt_valid_siblings(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                self.calls = []
                def malformed(payload, attempt):
                    value = self.response(payload)
                    if duplicate:
                        value['sources'][-1] = copy.deepcopy(value['sources'][0])
                    else:
                        value['sources'].pop()
                    return value
                rows, errors = self.extract(malformed)
                self.assertEqual([len(call['source_inventory']) for call in self.calls], [12, 12])
                self.assertTrue(all(row['classification'] == 'uncertain' and row['claims'] == [] for row in rows))
                self.assertEqual(len(errors), 1)
                self.assertIn('完整且唯一', errors[0])

    def test_invalid_envelope_retry_cannot_erase_previously_valid_sources(self):
        def respond(payload, attempt):
            value = self.response(payload, ('A10', 'A11'))
            if attempt == 2:
                value['sources'][-1] = copy.deepcopy(value['sources'][0])
            return value
        rows, errors = self.extract(respond)
        self.assertEqual(sum(row['classification'] == 'claims' for row in rows), 10)
        self.assertTrue(all(row['classification'] == 'uncertain' for row in rows[-2:]))
        self.assertEqual(len(errors), 1)
        self.assertEqual(len(self.calls), 2)


if __name__ == '__main__':
    unittest.main()

"""Wrong-source hunk refs recover only through explicit diff selection, offline."""
import copy
import json
from pathlib import Path
import tempfile
import unittest

from .. import audit_engine as engine
from .test_engine import RULES, scripted_result, synthetic_payload, reference
from .test_engine_quote_retry import ScriptedClient, qid


class HunkReferenceFeedbackTests(unittest.TestCase):
    def setUp(self):
        payload = synthetic_payload(task_count=2)
        payload['commits'][0]['diff'] += '@@ -20 +20 @@\n-return retry or 2\n+return retry\n'
        self.package = engine.normalize(payload, RULES)
        self.tasks = engine.validate_result(scripted_result({
            **engine.model_input(self.package, task_only=True), 'rules': []}),
            self.package, task_only=True)['tasks']
        self.hunk = self.package['changes'][0]
        self.source = next(e for e in self.package['evidence'] if e['kind'] == 'source')

    def test_upfront_hunk_choices_are_exact_visible_diff_lines_without_mutation(self):
        before = copy.deepcopy(self.package)
        data = engine.model_input(self.package, self.tasks)
        for hunk in data['changes']:
            choices = hunk['actual_changed_line_choices']
            self.assertEqual([row['line'] for row in choices], hunk['changed_line_numbers'])
            self.assertEqual(choices, [{'line': line,
                'quote_id': qid(data, hunk['evidence_id'], line)['quote_id']}
                for line in hunk['changed_line_numbers']])
        hidden = copy.deepcopy(self.package)
        diff = next(e for e in hidden['evidence'] if e['id'] == self.hunk['evidence_id'])
        diff['target_ids'] = ['unselected-task']
        scoped = engine.model_input(hidden, self.tasks[:1])
        self.assertNotIn(diff['id'], {e['id'] for e in scoped['evidence']})
        self.assertTrue(all(not hunk['actual_changed_line_choices']
                            for hunk in scoped['changes'] if hunk['evidence_id'] == diff['id']))
        baseline = engine.model_input(self.package, task_only=True)
        self.assertNotIn('changes', baseline)
        data['changes'][0]['changed_line_numbers'].append(999)
        data['changes'][0]['actual_changed_line_choices'].clear()
        self.assertEqual(self.package, before)

    def test_long_changed_line_retains_full_evidence_without_invented_selector(self):
        payload = synthetic_payload(task_count=1)
        long_line = '+' + 'x' * 700
        payload['commits'][0]['diff'] += '@@ -20 +20 @@\n-old\n' + long_line + '\n'
        package = engine.normalize(payload, RULES)
        data = engine.model_input(package)
        hunk = data['changes'][-1]
        diff = next(e for e in data['evidence'] if e['id'] == hunk['evidence_id'])
        original = next(row for row in diff['numbered_lines'] if row['text'] == long_line)
        self.assertIn(original['line'], hunk['changed_line_numbers'])
        self.assertNotIn('quote_id', original)
        self.assertNotIn(original['line'], [row['line'] for row in hunk['actual_changed_line_choices']])
        self.assertIn(long_line, diff['content'])
        self.assertTrue(hunk['actual_changed_line_choices'])

    def test_real_bounded_retry_identifies_diff_choices_and_preserves_sibling(self):
        for repair in (False, True):
            with self.subTest(repair=repair), tempfile.TemporaryDirectory() as directory:
                raw, sibling = [], []

                def mutate(value, payload, stage):
                    row = value['acceptance_checks'][0]
                    row['change_relations'] = [{
                        'change_id': self.hunk['id'], 'relation': 'unknown',
                        'reason': 'The causal relationship remains uncertain.',
                        'evidence_refs': [reference(self.source, 2)]}]
                    if stage == 'analysis-1':
                        sibling.append(copy.deepcopy(value['acceptance_checks'][1]))
                    elif stage == 'analysis-2':
                        self.assertEqual(value['acceptance_checks'][1], sibling[0])
                        old = payload['repair_candidate']['acceptance_checks'][0]
                        self.assertEqual(old['change_relations'][0]['evidence_refs'],
                                         raw[0]['acceptance_checks'][0]['change_relations'][0]['evidence_refs'])
                        message = payload['validation_feedback'][0]
                        self.assertIn('$.acceptance_checks[0].change_relations[0].evidence_refs', message)
                        for marker in (self.tasks[0]['id'], row['acceptance_id'], self.hunk['id'],
                                       self.hunk['path'], self.hunk['evidence_id'], self.hunk['commit_id']):
                            self.assertIn(marker, message)
                        samples = json.loads(message.split('实际增删行示例=', 1)[1].split('。从本阶段', 1)[0])
                        self.assertEqual([item['line'] for item in samples],
                                         self.hunk['changed_line_numbers'][:5])
                        choices = [qid(payload, self.hunk['evidence_id'], item['line']) for item in samples]
                        self.assertEqual([item['quote_id'] for item in samples],
                                         [item['quote_id'] for item in choices])
                        self.assertNotIn(self.package['changes'][1]['id'], message)
                        self.assertNotIn('citation_retry', payload,
                                         'A valid but wrong-role quote must not force siblings to rewrite refs.')
                        if repair:
                            row['change_relations'][0]['evidence_refs'] = [choices[-1]]
                    elif stage.startswith('counter-review-'):
                        row['change_relations'][0]['evidence_refs'] = [
                            qid(payload, self.hunk['evidence_id'], self.hunk['changed_line_numbers'][-1])]
                    raw.append(copy.deepcopy(value))
                    return value

                before = copy.deepcopy(self.package)
                client = ScriptedClient(mutate)
                if repair:
                    result = engine.analyze(self.package, client, Path(directory),
                                            fixed_tasks=copy.deepcopy(self.tasks))
                    expected = engine.validate_result(scripted_result(engine.model_input(
                        self.package, self.tasks)), self.package, copy.deepcopy(self.tasks))
                    self.assertEqual(result['tasks'], self.tasks)
                    self.assertEqual(result['acceptance_checks'][1], expected['acceptance_checks'][1])
                    relation = result['acceptance_checks'][0]['change_relations'][0]
                    self.assertEqual(relation['relation'], 'unknown')
                    self.assertEqual(relation['evidence_refs'][0]['evidence_id'], self.hunk['evidence_id'])
                    self.assertEqual(result['acceptance_checks'][0]['change_ids'], [],
                                     'A repaired citation must not invent an implementation relationship.')
                else:
                    with self.assertRaisesRegex(ValueError, '改动关系引用必须命中对应hunk实际变更'):
                        engine.analyze(self.package, client, Path(directory),
                                       fixed_tasks=copy.deepcopy(self.tasks))
                    self.assertEqual([call['stage'] for call in client.calls], ['analysis-1', 'analysis-2'])
                self.assertEqual(sum(c['stage'].startswith('analysis-') for c in client.calls), 2)
                saved = json.loads((Path(directory) / 'analysis-1.validation.json').read_text())
                self.assertIn('change_relations[0].evidence_refs', saved['errors'][0])
                self.assertEqual(raw[0]['acceptance_checks'][0]['change_relations'][0]['evidence_refs'],
                                 [reference(self.source, 2)])
                self.assertEqual(self.package, before)

    def test_wrong_hunk_or_context_quote_still_fails_without_source_migration(self):
        diff = next(e for e in self.package['evidence'] if e['id'] == self.hunk['evidence_id'])
        for line in (self.hunk['start_line'], self.package['changes'][1]['changed_line_numbers'][-1]):
            with self.subTest(line=line):
                value = scripted_result(engine.model_input(self.package, self.tasks))
                value['acceptance_checks'][0]['change_relations'] = [{
                    'change_id': self.hunk['id'], 'relation': 'unknown', 'reason': 'Unverified relationship.',
                    'evidence_refs': [reference(diff, line)]}]
                before = copy.deepcopy(value)
                with self.assertRaisesRegex(ValueError, r'change_relations\[0\].evidence_refs'):
                    engine.validate_result(value, self.package, copy.deepcopy(self.tasks))
                self.assertEqual(value, before)


if __name__ == '__main__':
    unittest.main()

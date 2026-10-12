"""Summary text preserves user speech acts before a baseline can freeze."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from ..requirement_review import (RequirementProvenanceError, RequirementSummarySupportError,
                                summary_review_units)
from .test_engine import RULES, reference, scripted_result, synthetic_payload
from .test_requirement_isolation import baseline_for, support_for
from .test_requirement_review import ORIGINAL_ISSUE, fixtures


class RequirementSummaryTests(unittest.TestCase):
    def setUp(self):
        self.package, self.tasks, self.review = fixtures()
        self.user = next(item for item in self.package['evidence'] if item['kind'] == 'user_requirement')

    def goal(self, fragments, *, supported=True):
        self.tasks[0]['goal'] = ''.join(fragment['text'] for fragment in fragments)
        summary = next(row for row in self.review['tasks'][0]['summary_checks'] if row['field'] == 'goal')
        summary.update(supported=supported, reason='目标逐段保留用户语气。', fragments=fragments)
        return summary

    def fragment(self, text, classification, presentation, line=1):
        return {'text': text, 'source_class': classification, 'presentation': presentation,
                'source_refs': [reference(self.user, line)]}

    def validate(self):
        return engine.validate_requirement_support(self.review, self.tasks, self.package, strict_semantics=True)

    def supported_point_only(self):
        self.tasks[0]['acceptance_points'] = self.tasks[0]['acceptance_points'][:1]
        self.review['tasks'][0]['acceptance_points'] = self.review['tasks'][0]['acceptance_points'][:1]

    def test_supported_behavior_cannot_hide_factualized_diagnosis_in_goal(self):
        self.supported_point_only()
        self.goal([self.fragment('默认TABLE应正确完成；', 'reported_problem', 'requirement'),
                   self.fragment('报错因输出为字符串导致。', 'diagnostic_hypothesis', 'asserted_fact', 3)],
                  supported=False)
        before = copy.deepcopy((self.tasks, self.review))
        with self.assertRaises(engine.RequirementSupportError) as raised:
            self.validate()
        self.assertIn('goal', str(raised.exception))
        self.assertEqual(engine.exclude_unsupported_points(self.tasks, raised.exception.review), (None, []))
        self.assertEqual((self.tasks, self.review), before)

    def test_qualified_diagnosis_observation_and_workaround_can_remain_background(self):
        self.supported_point_only()
        self.goal([self.fragment('默认TABLE应正确完成；', 'reported_problem', 'requirement'),
                   self.fragment('用户怀疑字符串类型是原因；', 'diagnostic_hypothesis', 'hypothesis', 3),
                   self.fragment('用户观察到JSON显示带引号ID；', 'observation', 'observation', 4),
                   self.fragment('用户暂时以QUIET绕行。', 'workaround', 'workaround', 5)])
        before = copy.deepcopy(self.tasks)
        self.validate()
        self.assertEqual(self.tasks, before)

    def test_background_cannot_become_a_requirement_or_asserted_fact(self):
        self.supported_point_only()
        for classification, presentation, line in (
                ('diagnostic_hypothesis', 'asserted_fact', 3),
                ('diagnostic_hypothesis', 'requirement', 3),
                ('observation', 'requirement', 4), ('workaround', 'requirement', 5),
                ('uncertain', 'uncertain', 1)):
            with self.subTest(classification=classification, presentation=presentation):
                self.goal([self.fragment('候选摘要', classification, presentation, line)])
                with self.assertRaisesRegex(ValueError, '摘要不能'):
                    self.validate()

    def test_summary_fragments_must_cover_every_character_of_both_fields(self):
        self.supported_point_only()
        mutations = [lambda rows: rows.pop(),
                     lambda rows: rows[1].update(field='title'),
                     lambda rows: rows[1]['fragments'][0].update(text='只检查正确半句'),
                     lambda rows: rows[1].update(fragments=[]),
                     lambda rows: rows[1]['fragments'][0].update(source_refs=[])]
        for mutate in mutations:
            original = copy.deepcopy(self.review)
            mutate(self.review['tasks'][0]['summary_checks'])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.validate()
            self.review = original

    def test_explicit_implementation_instruction_is_allowed_even_after_a_hypothesis(self):
        self.supported_point_only()
        text = 'Use a dictionary internally because callers must access named fields.'
        self.user['content'] += '\n' + text
        self.tasks[0]['requirement_refs'].append(reference(self.user, 6))
        units = summary_review_units([{'id': 'T1', 'title': '', 'goal': text}])[1]['units']
        self.goal([self.fragment(unit['text'], 'explicit_request', 'requirement', 6)
                   for unit in units])
        self.validate()

    def test_summary_same_user_id_cannot_expand_past_candidate_selected_lines(self):
        self.supported_point_only()
        self.tasks[0]['requirement_refs'] = [reference(self.user)]
        self.review['tasks'][0]['summary_checks'][0]['fragments'][0]['source_refs'] = [reference(self.user)]
        self.goal([self.fragment('用户怀疑字符串类型是原因。', 'diagnostic_hypothesis', 'hypothesis', 3)])
        before = copy.deepcopy((self.tasks, self.review))
        with self.assertRaises(RequirementProvenanceError) as raised:
            self.validate()
        self.assertEqual(raised.exception.changes[0]['summary_field'], 'goal')
        self.assertEqual(raised.exception.changes[0]['source_refs'][0], reference(self.user, 3))
        self.assertEqual((self.tasks, self.review), before)

    def test_summary_references_remain_user_only_and_task_bound(self):
        self.supported_point_only()
        for invalid in ({'id': 'SOURCE', 'kind': 'source', 'content': 'Goal from implementation'},
                        {'id': 'OTHER', 'kind': 'user_requirement', 'content': 'Other task request',
                         'target_ids': ['other-task']}):
            with self.subTest(invalid=invalid['id']):
                package = copy.deepcopy(self.package)
                package['evidence'].append(invalid)
                review = copy.deepcopy(self.review)
                review['tasks'][0]['summary_checks'][1]['fragments'][0]['source_refs'] = [reference(invalid)]
                with self.assertRaises(ValueError):
                    engine.validate_requirement_support(review, self.tasks, package, strict_semantics=True)

    def test_unsupported_summary_reextracts_before_freezing_without_mutating_candidate(self):
        raw = synthetic_payload()
        raw['trace']['messages'] = [{'role': 'user', 'content': ORIGINAL_ISSUE}]
        package = engine.normalize(raw, RULES)
        user = next(item for item in package['evidence'] if item['kind'] == 'user_requirement')
        stages, responses = [], []

        class Client:
            def complete(client, system, payload, directory, stage):
                stages.append(stage)
                if stage.startswith('task-extraction'):
                    value = baseline_for(package)
                    task = value['tasks'][0]
                    task['goal'] = ('默认TABLE应正确完成。' if '-recheck-' in stage
                                    else '默认TABLE应正确完成；报错因输出为字符串导致。')
                    task['acceptance_points'][0]['requirement'] = '默认TABLE应正确完成。'
                    task['requirement_refs'].append(reference(user, 3))
                elif stage.startswith('requirement-review'):
                    value = support_for(payload['candidate_tasks'])
                    if '-recheck-' not in stage:
                        goal = next(row for row in value['tasks'][0]['summary_checks'] if row['field'] == 'goal')
                        goal.update(supported=False, reason='用户I think是原因假设，目标写成了确定原因。',
                            fragments=[{'text': '默认TABLE应正确完成；', 'source_class': 'reported_problem',
                                        'presentation': 'requirement', 'source_refs': [reference(user)]},
                                       {'text': '报错因输出为字符串导致。', 'source_class': 'diagnostic_hypothesis',
                                        'presentation': 'asserted_fact', 'source_refs': [reference(user, 3)]}])
                else:
                    value = scripted_result(payload)
                responses.append((value, copy.deepcopy(value)))
                return value

        with tempfile.TemporaryDirectory() as directory:
            result = engine.analyze(package, Client(), directory)
            frozen = json.loads((Path(directory) / 'frozen-tasks.json').read_text())
        self.assertEqual(stages[:4], ['task-extraction-1', 'requirement-review-1',
                                     'task-extraction-recheck-1', 'requirement-review-recheck-1'])
        self.assertEqual(result['tasks'][0]['goal'], '默认TABLE应正确完成。')
        self.assertEqual(frozen['tasks'], result['tasks'])
        self.assertEqual(frozen['support_review']['tasks'][0]['summary_checks'][1]['field'], 'goal')
        self.assertTrue(all(value == before for value, before in responses))


if __name__ == '__main__':
    unittest.main()

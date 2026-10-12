"""Intent classification is an explicit gate, not a keyword-based user parser."""
import copy
import unittest

from .. import audit_engine as engine
from ..reference_repair import _quote_choices, repair_references
from ..requirement_review import (REQUIREMENT_REVIEW_SYSTEM, validate_requirement_review,
                                summary_review_units)
from .test_engine import RULES, reference, synthetic_payload, summary_support_for


ORIGINAL_ISSUE = '\n'.join([
    'When using the Memset provider with the default table formatting I get this error:',
    'TypeError: string indices must be integers',
    'I think this is because `output` is a string not an array - when I added `print output` I got a string like `969f9caabe19859c11249333dd80aa15`.',
    'When I use `--output JSON` I get the same ID plus quotes:',
    "For now I'll work around it with `--output QUIET` since I don't really care about the output here.",
])


def fixtures(messages=None):
    payload = synthetic_payload()
    payload['trace']['messages'] = messages or [{'role': 'user', 'content': ORIGINAL_ISSUE}]
    package = engine.normalize(payload, RULES)
    users = [item for item in package['evidence'] if item['kind'] == 'user_requirement']
    points = [{'id': 'R1', 'kind': 'behavior', 'requirement': '默认TABLE操作应正确完成。',
               'requirement_refs': [reference(users[0], 1)]},
              {'id': 'R2', 'kind': 'behavior', 'requirement': '必须将字符串改成字典列表。',
               'requirement_refs': [reference(users[0], 3)]},
              {'id': 'R3', 'kind': 'behavior', 'requirement': '必须保持JSON带引号的字符串输出。',
               'requirement_refs': [reference(users[0], 4)]},
              {'id': 'R4', 'kind': 'behavior', 'requirement': '必须改用QUIET输出。',
               'requirement_refs': [reference(users[0], 5)]}]
    task = {'id': 'T1', 'title': '修复默认TABLE报错', 'goal': '原触发下正确完成',
            'requirement_refs': [ref for point in points for ref in point['requirement_refs']],
            'acceptance_points': points}
    classes = ['reported_problem', 'diagnostic_hypothesis', 'observation', 'workaround']
    review = {'tasks': [{'task_id': 'T1', 'supported': True, 'reason': '原话报告待修行为。',
        'summary_checks': summary_support_for(task),
        'acceptance_points': [{'acceptance_id': point['id'], 'supported': index == 0,
            'reason': '原操作正确完成是目标；诊断、其它模式现状和绕行不是新增义务。',
            'source_class': classes[index], 'source_refs': copy.deepcopy(point['requirement_refs']),
            'duplicate_of': 'R1' if index == 1 else ''} for index, point in enumerate(points)],
        'missing_requirements': []}]}
    return package, [task], review


class RequirementIntentReviewTests(unittest.TestCase):
    def setUp(self):
        self.package, self.tasks, self.review = fixtures()

    def validate(self, value=None, tasks=None, package=None):
        return validate_requirement_review(value if value is not None else self.review,
            tasks if tasks is not None else self.tasks, package if package is not None else self.package)

    def test_original_issue_keeps_one_behavior_not_type_json_or_workaround_obligations(self):
        before = copy.deepcopy((self.package, self.tasks, self.review))
        result = self.validate()
        with self.assertRaises(engine.RequirementSupportError) as error:
            engine.validate_requirement_support(result, self.tasks, self.package)
        filtered, excluded = engine.exclude_unsupported_points(self.tasks, error.exception.review)
        self.assertEqual([p['id'] for p in filtered[0]['acceptance_points']], ['R1'])
        self.assertEqual(len(excluded), 3)
        self.assertEqual(result['tasks'][0]['acceptance_points'][1]['duplicate_of'], 'R1')
        self.assertEqual((self.package, self.tasks, self.review), before)
        result['tasks'][0]['reason'] = 'edited'
        self.assertNotEqual(result, self.review)

    def test_current_observation_with_true_boolean_is_rejected_before_freeze(self):
        # The real previous response said JSON was only observed, yet set supported=true.
        self.review['tasks'][0]['acceptance_points'][2]['supported'] = True
        with self.assertRaisesRegex(ValueError, '硬性要求'):
            self.validate()

    def test_every_non_obligation_class_is_blocked_even_with_a_valid_quote(self):
        for classification in ('observation', 'diagnostic_hypothesis', 'workaround', 'uncertain'):
            with self.subTest(classification=classification):
                value = copy.deepcopy(self.review)
                point = value['tasks'][0]['acceptance_points'][0]
                point.update(source_class=classification, supported=True)
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_explicit_later_feedback_can_promote_observation_to_compatibility(self):
        package, tasks, review = fixtures([
            {'role': 'user', 'content': ORIGINAL_ISSUE},
            {'role': 'user', 'content': 'Keep the existing JSON output unchanged while fixing the default table error.'}])
        later = next(e for e in package['evidence'] if e['kind'] == 'user_requirement'
                     and e['content'].startswith('Keep '))
        point = review['tasks'][0]['acceptance_points'][2]
        point.update(source_class='compatibility_constraint', supported=True,
                     reason='后续用户明确要求保留JSON行为。', source_refs=[reference(later)])
        tasks[0]['acceptance_points'][2]['requirement_refs'].append(reference(later))
        result = self.validate(review, tasks, package)
        self.assertTrue(result['tasks'][0]['acceptance_points'][2]['supported'])
        self.assertEqual(result['tasks'][0]['acceptance_points'][2]['source_refs'][0]['evidence_id'], later['id'])

    def test_later_feedback_not_in_candidate_cannot_silently_change_frozen_provenance(self):
        package, tasks, review = fixtures([
            {'role': 'user', 'content': ORIGINAL_ISSUE},
            {'role': 'user', 'content': 'Keep the existing JSON output unchanged.'}])
        later = next(e for e in package['evidence'] if e['kind'] == 'user_requirement'
                     and e['content'].startswith('Keep '))
        point = review['tasks'][0]['acceptance_points'][2]
        point.update(source_class='compatibility_constraint', supported=True,
                     reason='后续用户明确要求保留。', source_refs=[reference(later)])
        with self.assertRaisesRegex(ValueError, '重新提取'):
            self.validate(review, tasks, package)

    def test_source_ref_can_be_a_literal_subfragment_inside_candidate_selected_range(self):
        ref = self.review['tasks'][0]['acceptance_points'][0]['source_refs'][0]
        ref['quote'] = 'default table formatting'
        self.validate()
        ref.update(start_line=2, end_line=2, quote='TypeError: string indices must be integers')
        with self.assertRaisesRegex(ValueError, '超出候选'):
            self.validate()

    def test_distinct_boundary_scope_and_test_delivery_remain_independent(self):
        message = 'Fix the parse error.\nFor empty input return an empty list.\nDo not change the public API.\nAdd regression assertions for both inputs.'
        payload = synthetic_payload()
        payload['trace']['messages'] = [{'role': 'user', 'content': message}]
        package = engine.normalize(payload, RULES)
        user = next(e for e in package['evidence'] if e['kind'] == 'user_requirement')
        task = {'id': 'T1', 'title': '修复解析并保持明确边界', 'goal': message, 'acceptance_points': [
            {'id': 'R' + str(index), 'kind': kind, 'requirement': sentence,
             'requirement_refs': [reference(user, index)]}
            for index, (kind, sentence) in enumerate(zip(
                ['behavior', 'behavior', 'scope_constraint', 'test_delivery'], message.splitlines()), 1)]}
        task['requirement_refs'] = [ref for point in task['acceptance_points'] for ref in point['requirement_refs']]
        row = {'task_id': 'T1', 'supported': True, 'reason': '用户明确提出四个不同义务。',
            'summary_checks': summary_support_for(task),
            'acceptance_points': [{'acceptance_id': p['id'], 'supported': True,
                'source_class': 'explicit_request', 'source_refs': p['requirement_refs'],
                'duplicate_of': '', 'reason': '不同输入边界、范围限制或测试交付。'}
                for p in task['acceptance_points']], 'missing_requirements': []}
        validated = self.validate({'tasks': [row]}, [task], package)
        engine.validate_requirement_support(validated, [task], package)
        self.assertTrue(all(p['supported'] for p in validated['tasks'][0]['acceptance_points']))

    def test_same_obligation_can_be_deduplicated_without_diagnosis_class(self):
        point = self.review['tasks'][0]['acceptance_points'][1]
        point.update(source_class='reported_problem', reason='相同输入同一TABLE正确完成目标，重复表述。')
        self.validate()

    def test_duplicate_cannot_suppress_scope_constraint_or_test_delivery(self):
        for kind in ('scope_constraint', 'test_delivery'):
            with self.subTest(kind=kind):
                tasks = copy.deepcopy(self.tasks)
                tasks[0]['acceptance_points'][1]['kind'] = kind
                with self.assertRaisesRegex(ValueError, '跨kind'):
                    self.validate(tasks=tasks)

    def test_duplicate_requires_same_task_non_duplicate_supported_canonical(self):
        mutations = [lambda points: points[1].update(duplicate_of='R2'),
            lambda points: points[1].update(duplicate_of='another-task-R1'),
            lambda points: points[1].update(supported=True, source_class='reported_problem'),
            lambda points: points[0].update(supported=False),
            lambda points: points[0].update(duplicate_of='R3'),
            lambda points: points[0].update(source_class=[])]
        for mutate in mutations:
            value = copy.deepcopy(self.review)
            mutate(value['tasks'][0]['acceptance_points'])
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(value)

    def test_diagnostic_keyword_does_not_override_explicit_user_instruction(self):
        # Both classifications use semantics supplied by review, no project/string rules.
        text = 'I think the cache is stale.\nUse a dictionary internally because callers must access named fields.'
        payload = synthetic_payload()
        payload['trace']['messages'] = [{'role': 'user', 'content': text}]
        package = engine.normalize(payload, RULES)
        user = next(e for e in package['evidence'] if e['kind'] == 'user_requirement')
        task = {'id': 'T1', 'title': '按用户要求使用字典', 'goal': text.splitlines()[1],
            'requirement_refs': [reference(user, 2)],
            'acceptance_points': [{'id': 'R1', 'kind': 'behavior',
            'requirement': text.splitlines()[1], 'requirement_refs': [reference(user, 2)]}]}
        row = {'task_id': 'T1', 'supported': True, 'reason': '用户明确指定实现约束。',
            'summary_checks': summary_support_for(task),
            'acceptance_points': [{'acceptance_id': 'R1', 'supported': True,
                'reason': '第二句是明确指令，与第一句诊断假设不同。', 'source_class': 'explicit_request',
                'source_refs': [reference(user, 2)], 'duplicate_of': ''}], 'missing_requirements': []}
        row['summary_checks'][1]['fragments'] = [
            {'text': unit['text'], 'source_class': 'explicit_request', 'presentation': 'requirement',
             'source_refs': [reference(user, 2)]}
            for unit in summary_review_units([task])[1]['units']]
        self.validate({'tasks': [row]}, [task], package)

    def test_missing_requirement_cannot_reintroduce_an_observation(self):
        self.review['tasks'][0]['missing_requirements'] = [{'requirement': 'Keep JSON unchanged',
            'source_class': 'observation',
            'requirement_refs': self.review['tasks'][0]['acceptance_points'][2]['source_refs']}]
        with self.assertRaisesRegex(ValueError, '遗漏的硬性要求'):
            self.validate()

    def test_valid_missing_explicit_requirement_still_blocks_old_freeze_validator(self):
        self.review['tasks'][0]['missing_requirements'] = [{'requirement': 'Complete the reported operation',
            'source_class': 'reported_problem',
            'requirement_refs': self.review['tasks'][0]['acceptance_points'][0]['source_refs']}]
        result = self.validate()
        with self.assertRaises(engine.RequirementSupportError):
            engine.validate_requirement_support(result, self.tasks, self.package)

    def test_patch_assistant_and_tool_cannot_support_even_explicit_request_class(self):
        for kind in ('source', 'commit_diff', 'assistant', 'tool'):
            with self.subTest(kind=kind):
                package = copy.deepcopy(self.package)
                package['evidence'].append({'id': 'OTHER', 'kind': kind, 'content': 'Keep JSON unchanged'})
                value = copy.deepcopy(self.review)
                value['tasks'][0]['acceptance_points'][0]['source_refs'] = [
                    {'evidence_id': 'OTHER', 'start_line': 1, 'end_line': 1, 'quote': 'Keep JSON unchanged'}]
                with self.assertRaisesRegex(ValueError, '用户原话'):
                    self.validate(value, package=package)

    def test_cross_task_user_reference_cannot_change_this_task(self):
        package = copy.deepcopy(self.package)
        package['evidence'][0]['target_ids'] = ['OTHER-TASK']
        with self.assertRaisesRegex(ValueError, '其它任务'):
            self.validate(package=package)

    def test_quote_id_uses_shared_exact_reference_contract(self):
        value = copy.deepcopy(self.review)
        choices = _quote_choices(self.package)
        for point in value['tasks'][0]['acceptance_points']:
            point['source_refs'] = [{'quote_id': next(oid for oid, ref in choices.items()
                if ref == point['source_refs'][0])}]
        with self.assertRaises(ValueError):
            self.validate(value)
        repaired, _ = repair_references(value, self.package)
        self.validate(repaired)
        self.assertIn('{"quote_id":"Q-', REQUIREMENT_REVIEW_SYSTEM)

    def test_strict_schema_rejects_omission_duplicates_unknown_fields_and_malformed_values(self):
        mutations = [lambda v: v.update(status='passed'),
            lambda v: v['tasks'][0].pop('missing_requirements'),
            lambda v: v['tasks'][0]['acceptance_points'].pop(),
            lambda v: v['tasks'][0]['acceptance_points'][1].update(acceptance_id='R1'),
            lambda v: v['tasks'][0]['acceptance_points'][0].pop('source_class'),
            lambda v: v['tasks'][0]['acceptance_points'][0].update(source_class='guaranteed'),
            lambda v: v['tasks'][0]['acceptance_points'][0].update(source_refs=[]),
            lambda v: v['tasks'][0]['acceptance_points'][0].update(supported='true'),
            lambda v: v['tasks'][0]['acceptance_points'][0].update(reason=''),
            lambda v: v['tasks'][0]['acceptance_points'][0].update(duplicate_of=[]),
            lambda v: v['tasks'][0]['acceptance_points'][0]['source_refs'][0].update(evidence_id=[]),
            lambda v: v['tasks'][0]['acceptance_points'][0]['source_refs'][0].update(quote='not present')]
        for mutate in mutations:
            value = copy.deepcopy(self.review)
            mutate(value)
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.validate(value)

    def test_legacy_schema_only_works_with_explicit_non_strict_compatibility(self):
        value = {'tasks': [{'task_id': 'T1', 'supported': True, 'reason': 'legacy',
            'acceptance_points': [{'acceptance_id': p['id'], 'supported': True, 'reason': 'legacy'}
                                  for p in self.tasks[0]['acceptance_points']], 'missing_requirements': []}]}
        with self.assertRaises(ValueError):
            self.validate(value)
        self.assertEqual(validate_requirement_review(value, self.tasks, self.package, strict=False), value)


if __name__ == '__main__':
    unittest.main()

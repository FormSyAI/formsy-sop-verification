"""Offline source-closure recovery, including an initially under-cited review."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from .test_engine import RULES, reference, scripted_result, synthetic_payload
from .test_requirement_isolation import baseline_for, support_for


class RequirementSourceClosureTests(unittest.TestCase):
    def run_closure(self, omit_identity):
        payload = synthetic_payload()
        lines = ["Please correct this example's scoring.",
                 "Example object: def measure_cost(item):",
                 "For item=0, return 6 instead of 8.",
                 "Count each sequence once without a nesting multiplier."]
        payload['trace']['messages'][0]['content'] = '\n'.join(lines)
        package = engine.normalize(payload, RULES)
        user = next(item for item in package['evidence'] if item['kind'] == 'user_requirement')
        candidate = baseline_for(package, [
            {'id': 'example-result', 'kind': 'behavior',
             'requirement': 'For measure_cost(0), return 6 instead of 8.',
             'requirement_refs': [reference(user, 2), reference(user, 3)]},
            {'id': 'sequence-result', 'kind': 'behavior', 'requirement': lines[3],
             'requirement_refs': [reference(user, 4)]},
            {'id': 'unrequested-tests', 'kind': 'test_delivery',
             'requirement': 'Deliver regression assertions for measure_cost(0).',
             'requirement_refs': [reference(user, 2), reference(user, 3)]}])
        candidate['tasks'][0].update(title='Correct measure_cost scoring',
            goal='For measure_cost(0), return 6 instead of 8; count each sequence once without a nesting multiplier.',
            requirement_refs=[reference(user, i) for i in (1, 3, 4)])
        before = copy.deepcopy((package, candidate))
        calls, records = [], {}
        owner = self

        class Client:
            def complete(self, system, request, directory, stage):
                calls.append(stage)
                if stage.startswith('task-extraction'):
                    owner.assertIn('task.requirement_refs须覆盖title/goal全部陈述', system)
                    owner.assertIn('只引期望值不能证明其所属对象', system)
                    owner.assertIn('最小充分依据', system)
                    owner.assertEqual(request['evidence'][0]['content'], '\n'.join(lines))
                    value = copy.deepcopy(candidate)
                    if '-recheck-' in stage:
                        owner.assertIn('不能只修已报告缺口或照抄旧引用', request['reextraction_instruction'])
                        owner.assertIn('复核未指出缺口也不代表来源已齐全', request['reextraction_instruction'])
                        owner.assertIn('具体对象/标识符、触发条件、预期结果', request['reextraction_instruction'])
                        owner.assertEqual(request['requirement_review_feedback'], records['requirement-review-1'])
                        owner.assertIn('No request to deliver test source.', request['requirement_support_feedback'][0])
                        previous = request['previous_unfrozen_candidate'][0]
                        owner.assertEqual([ref['start_line'] for ref in previous['requirement_refs']], [1, 3, 4])
                        owner.assertEqual(previous['goal'], candidate['tasks'][0]['goal'])
                        value['tasks'][0]['acceptance_points'].pop()
                        if not omit_identity:
                            value['tasks'][0]['requirement_refs'].insert(1, reference(user, 2))
                elif stage.startswith('requirement-review'):
                    value = support_for(request['candidate_tasks'])
                    if '-recheck-' not in stage:
                        # Reproduce an initial review that rejects delivery but misses the name's source gap.
                        value['tasks'][0]['acceptance_points'][-1].update(supported=False,
                            source_class='reported_problem', reason='No request to deliver test source.')
                    else:
                        for summary in value['tasks'][0]['summary_checks']:
                            selected = (2,) if summary['field'] == 'title' else (2, 3, 4)
                            summary['fragments'][0]['source_refs'] = [reference(user, i) for i in selected]
                else:
                    value = scripted_result(request)
                records[stage] = copy.deepcopy(value)
                (Path(directory) / (stage + '.original.json')).write_text(json.dumps(value))
                return value

        with tempfile.TemporaryDirectory() as directory:
            if omit_identity:
                with self.assertRaisesRegex(ValueError, '无法建立受用户原话支持'):
                    engine.analyze(package, Client(), directory)
                self.assertFalse((Path(directory) / 'frozen-tasks.json').exists())
                self.assertNotIn('analysis-1', calls)
                receipt = json.loads((Path(directory) / 'requirement-review-recheck.reextraction.json').read_text())
                self.assertEqual(receipt['action'], 'stop_unfrozen')
                self.assertEqual({change['summary_field'] for change in receipt['changes']}, {'title', 'goal'})
                for change in receipt['changes']:
                    self.assertIn(reference(user, 2), change['source_refs'])
                self.assertEqual(len(calls), 4)
            else:
                result = engine.analyze(package, Client(), directory)
                frozen = json.loads((Path(directory) / 'frozen-tasks.json').read_text())
                self.assertEqual(frozen['tasks'], result['tasks'])
                task = frozen['tasks'][0]
                self.assertEqual(task['title'], candidate['tasks'][0]['title'])
                self.assertEqual(task['goal'], candidate['tasks'][0]['goal'])
                self.assertEqual([ref['start_line'] for ref in task['requirement_refs']], [1, 2, 3, 4])
                self.assertEqual([point['kind'] for point in task['acceptance_points']], ['behavior', 'behavior'])
                self.assertEqual(frozen['support_review'], records['requirement-review-recheck-1'])
                self.assertEqual(calls[-2:], ['analysis-1', 'counter-review-1'])
            self.assertEqual(calls[:4], ['task-extraction-1', 'requirement-review-1',
                'task-extraction-recheck-1', 'requirement-review-recheck-1'])
            self.assertEqual(sum(stage.startswith('task-extraction') for stage in calls), 2)
            self.assertFalse(any('-filtered-' in stage for stage in calls))
            self.assertTrue((Path(directory) / 'requirement-review.validation.json').exists())
            self.assertFalse((Path(directory) / 'requirement-review.reextraction.json').exists(),
                             'The first review only reported unsupported delivery, not the later identity gap.')
            for stage, record in records.items():
                self.assertEqual(json.loads((Path(directory) / (stage + '.original.json')).read_text()), record)
        self.assertEqual((package, candidate), before)

    def test_reextraction_closes_named_summary_sources_after_delivery_rejection(self):
        self.run_closure(omit_identity=False)

    def test_still_missing_named_summary_source_stops_unfrozen_after_two_extractions(self):
        self.run_closure(omit_identity=True)

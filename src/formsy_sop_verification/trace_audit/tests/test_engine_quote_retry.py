"""Actual engine retry entry points share strict citation grammar; no network calls."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from .. import audit_engine as engine
from ..reference_repair import CITATION_RETRY_PROMPT, attach_quote_ids
from .test_engine import FakeClient, RULES, scripted_result, synthetic_payload
from .test_execution_mapping_stage import LocalClient, mapping_fixture, mapping_response
from .test_requirement_isolation import CONTAMINANTS, package_with_attempt


def qid(payload, evidence_id, line=1):
    item = next(item for item in payload['evidence'] if item['id'] == evidence_id)
    return {'quote_id': item['numbered_lines'][line - 1]['quote_id']}


def select_refs(value, payload, *, frozen_tasks=False):
    value = copy.deepcopy(value)
    def walk(node):
        if isinstance(node, list):
            return [walk(item) for item in node]
        if isinstance(node, dict):
            if {'evidence_id', 'start_line', 'end_line', 'quote'} <= node.keys():
                return qid(payload, node['evidence_id'], node['start_line'])
            return {key: item if frozen_tasks and key == 'tasks' else walk(item)
                    for key, item in node.items()}
        return node
    return walk(value)


class ScriptedClient(FakeClient):
    def __init__(self, mutate):
        super().__init__()
        self.mutate = mutate
        self.systems = {}

    def complete(self, system, payload, directory, stage):
        self.systems[stage] = system
        value = super().complete(system, payload, directory, stage)
        return self.mutate(value, payload, stage)


class EngineQuoteRetryTests(unittest.TestCase):
    def setUp(self):
        self.package = engine.normalize(synthetic_payload(), RULES)
        baseline = scripted_result({**engine.model_input(self.package, task_only=True), "rules": []})
        self.tasks = engine.validate_result(baseline, self.package, task_only=True)['tasks']
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def analyze(self, client, *, extract=False, package=None):
        return engine.analyze(package or self.package, client, self.directory,
                              fixed_tasks=None if extract else copy.deepcopy(self.tasks))

    def test_analysis_repeated_bare_material_id_fails_after_two_calls(self):
        evidence_id = next(e['id'] for e in self.package['evidence'] if e['kind'] == 'source')
        def mutate(value, payload, stage):
            if stage.startswith('analysis-'):
                if stage.endswith('-2'):
                    self.assertEqual(payload['citation_retry']['mode'], 'exact_visible_citations')
                    value = select_refs(value, payload, frozen_tasks=True)
                value['acceptance_checks'][0]['run_refs'] = [evidence_id]
            return value
        client = ScriptedClient(mutate)
        with self.assertRaisesRegex(ValueError, '模型输出未通过'):
            self.analyze(client)
        self.assertEqual([c['stage'] for c in client.calls], ['analysis-1', 'analysis-2'])
        self.assertIn(CITATION_RETRY_PROMPT, client.systems['analysis-2'])
        self.assertFalse(list(self.directory.glob('revision-*.json')))

    def test_analysis_valid_qid_recovers_while_echoed_frozen_tasks_remain_exact(self):
        evidence_id = next(e['id'] for e in self.package['evidence'] if e['kind'] == 'source')
        original = copy.deepcopy(self.tasks)
        def mutate(value, payload, stage):
            if stage == 'analysis-1':
                value['acceptance_checks'][0]['run_refs'] = [evidence_id]
            elif stage == 'analysis-2':
                value = select_refs(value, payload, frozen_tasks=True)
                value['acceptance_checks'][0]['run_refs'] = [qid(payload, evidence_id)]
                self.assertEqual(value['tasks'], original)
            return value
        client = ScriptedClient(mutate)
        result = self.analyze(client)
        self.assertEqual(result['tasks'], original)
        self.assertEqual([c['stage'] for c in client.calls], ['analysis-1', 'analysis-2', 'counter-review-1'])
        repairs = json.loads((self.directory / 'analysis-2.reference-repairs.json').read_text())['repairs']
        self.assertTrue(any('run_refs' in r['path'] for r in repairs))

    def test_analysis_retry_cannot_mutate_echoed_frozen_tasks(self):
        def mutate(value, payload, stage):
            if stage == 'analysis-1':
                value['checks'][0]['evidence_refs'] = ['E-not-a-quote']
            elif stage == 'analysis-2':
                value = select_refs(value, payload, frozen_tasks=True)
                value['tasks'][0]['goal'] = 'changed frozen goal'
            return value
        with self.assertRaisesRegex(ValueError, '不能改写已冻结'):
            self.analyze(ScriptedClient(mutate))

    def test_assertion_retry_identifies_valid_quote_from_wrong_source(self):
        original = synthetic_payload()
        original['materials'].append({'name': 'tests/test_limit.py', 'kind': 'source',
            'version_id': self.tasks[0]['target_commit_ids'][0], 'content': 'assert resolve_limit(0) == 0'})
        self.package = engine.normalize(original, RULES)
        historical = next(e for e in self.package['evidence'] if e['kind'] == 'assistant')
        def mutate(value, payload, stage):
            if stage == 'analysis-1':
                value['acceptance_checks'][0]['assertion_refs'].append(qid(payload, historical['id']))
            elif stage == 'analysis-2':
                feedback = [f for f in payload['reference_feedback']
                            if f.get('problem') == 'assertion_source_mismatch']
                self.assertEqual(len(feedback), 1)
                self.assertTrue(feedback[0]['path'].startswith('$.acceptance_checks[0].assertion_refs['))
                self.assertEqual(feedback[0]['rejected_reference']['evidence_id'], historical['id'])
                self.assertTrue(feedback[0]['target_evidence'])
                by_id = {e['id']: e for e in self.package['evidence']}
                for choice in feedback[0]['target_evidence']:
                    self.assertEqual(by_id[choice['evidence_id']]['kind'], 'source')
                    self.assertIn(choice['version_id'], self.tasks[0]['target_commit_ids'])
                value = select_refs(value, payload, frozen_tasks=True)
            return value
        client = ScriptedClient(mutate)
        result = self.analyze(client)
        self.assertEqual(result['tasks'], self.tasks)
        self.assertEqual([c['stage'] for c in client.calls], ['analysis-1', 'analysis-2', 'counter-review-1'])

    def test_counter_review_uses_same_retry_and_can_rejudge_unknown_with_no_refs(self):
        def mutate(value, payload, stage):
            if stage == 'counter-review-1':
                value['findings'][0]['evidence_refs'] = ['E-not-a-quote']
            elif stage == 'counter-review-2':
                value = select_refs(value, payload, frozen_tasks=True)
                value['findings'][0].update(evidence_refs=[], summary='Reassessed as evidence missing.')
                for row in value['checks']:
                    row.update(result='未核查', evidence_refs=[], counter_refs=[])
            return value
        client = ScriptedClient(mutate)
        result = self.analyze(client)
        self.assertEqual(result['tasks'], self.tasks)
        self.assertIn(CITATION_RETRY_PROMPT, client.systems['counter-review-2'])
        self.assertEqual([c['stage'] for c in client.calls].count('counter-review-2'), 1)

    def test_task_extraction_retry_is_user_only_and_valid_visible_qid_recovers(self):
        package = package_with_attempt()
        def mutate(value, payload, stage):
            if stage == 'task-extraction-1':
                value['tasks'][0]['requirement_refs'][0]['evidence_id'] = 'UNKNOWN-USER'
            elif stage == 'task-extraction-2':
                self.assertEqual(payload['citation_retry']['mode'], 'exact_visible_citations')
                self.assertEqual({e['kind'] for e in payload['evidence']}, {'user_requirement'})
                serialized = json.dumps(payload['reference_feedback'], ensure_ascii=False)
                for marker in CONTAMINANTS:
                    self.assertNotIn(marker, serialized)
                value = select_refs(value, payload)
            return value
        client = ScriptedClient(mutate)
        result = self.analyze(client, extract=True, package=package)
        self.assertEqual(len(result['tasks']), 1)
        self.assertIn(CITATION_RETRY_PROMPT, client.systems['task-extraction-2'])

    def test_requirement_review_retry_rejects_invalid_manual_or_hidden_and_accepts_user_qid(self):
        for correction in ('manual', 'hidden', 'qid'):
            with self.subTest(correction=correction):
                package = package_with_attempt()
                hidden = next(e for e in package['evidence'] if e['kind'] == 'source')
                hidden_selector = attach_quote_ids({'evidence': [hidden]}, package)['evidence'][0]['numbered_lines'][0]['quote_id']
                def mutate(value, payload, stage):
                    if stage == 'requirement-review-1':
                        value['tasks'][0]['acceptance_points'][0]['source_refs'][0]['quote'] = 'invented quote'
                    elif stage == 'requirement-review-2':
                        self.assertEqual({e['kind'] for e in payload['evidence']}, {'user_requirement'})
                        self.assertEqual(payload['citation_retry']['mode'], 'exact_visible_citations')
                        serialized = json.dumps(payload['reference_feedback'], ensure_ascii=False)
                        self.assertNotIn(hidden['id'], serialized)
                        if correction == 'qid':
                            value = select_refs(value, payload)
                        elif correction == 'manual':
                            value['tasks'][0]['acceptance_points'][0]['source_refs'][0]['quote'] = 'still invented'
                        elif correction == 'hidden':
                            value['tasks'][0]['acceptance_points'][0]['source_refs'] = [{'quote_id': hidden_selector}]
                    return value
                client = ScriptedClient(mutate)
                if correction == 'qid':
                    result = self.analyze(client, extract=True, package=package)
                    self.assertEqual(len(result['tasks']), 1)
                else:
                    with self.assertRaisesRegex(ValueError, '需求语义复核输出无效'):
                        self.analyze(client, extract=True, package=package)
                self.assertIn(CITATION_RETRY_PROMPT, client.systems['requirement-review-2'])
                self.assertEqual(sum(c['stage'].startswith('requirement-review-') for c in client.calls), 2)

    def test_execution_mapping_qid_retry_recovers_exact_assertions_and_baseline(self):
        result, package = mapping_fixture()
        original = copy.deepcopy(result)
        def respond(payload, attempt):
            value = mapping_response(payload, quote_ids=attempt == 2)
            if attempt == 1:
                value['acceptance_execution_reviews'][0]['execution_run_reviews'][0]['assertion_refs'] = ['RUN']
            else:
                self.assertEqual(payload['citation_retry']['mode'], 'exact_visible_citations')
            return value
        client = LocalClient(respond)
        updated = engine.bind_execution_runs(result, package, client, self.directory)
        self.assertEqual(len(client.calls), 2)
        self.assertIn(CITATION_RETRY_PROMPT, client.calls[1]['system'])
        self.assertEqual(result, original)
        self.assertEqual(updated['tasks'], result['tasks'])
        self.assertEqual(updated['acceptance_checks'][1]['execution_assertion_refs'][0]['start_line'], 2)

    def test_execution_mapping_retry_keeps_task_version_and_receipt_selector_boundaries(self):
        for defect in ('manual', 'task', 'old_version', 'other_receipt'):
            with self.subTest(defect=defect):
                result, package = mapping_fixture()
                old = next(e for e in package['evidence'] if e['id'] == 'OLD')
                hidden = attach_quote_ids({'evidence': [old]}, package)['evidence'][0]['numbered_lines'][0]['quote_id']
                def respond(payload, attempt):
                    value = mapping_response(payload, quote_ids=attempt == 2 and defect != 'manual')
                    row = value['acceptance_execution_reviews'][0]
                    if attempt == 1:
                        row['execution_run_reviews'][0]['assertion_refs'] = ['RUN']
                    elif defect == 'manual':
                        row['execution_run_reviews'][0]['assertion_refs'][0]['quote'] = 'still invented'
                    elif defect == 'task':
                        row['task_id'] = 'OTHER_TASK'
                    elif defect == 'old_version':
                        row['execution_run_reviews'][0]['assertion_refs'] = [{'quote_id': hidden}]
                    elif defect == 'other_receipt':
                        row['execution_run_reviews'][0]['assertion_refs'] = [payload['candidate_runs'][1]['assertion_choices'][0]['selector']]
                    return value
                client = LocalClient(respond)
                before = copy.deepcopy(result)
                with self.assertRaisesRegex(ValueError, '实际运行与验收点映射未通过校验'):
                    engine.bind_execution_runs(result, package, client, self.directory)
                self.assertEqual(len(client.calls), 2)
                self.assertEqual(result, before)


if __name__ == '__main__':
    unittest.main()

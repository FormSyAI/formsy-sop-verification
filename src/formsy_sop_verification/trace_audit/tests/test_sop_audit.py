"""Synthetic offline checks for original-SOP selection, coverage and trust boundaries."""
import copy
import tempfile
import unittest
from pathlib import Path

from ..model_client import ModelOutputError
from ..sop_audit import audit_sop, reaggregate_sop
from ..sop_catalog import load_catalog


SHA, PARENT = 'a' * 40, 'b' * 40


def ref(eid, quote):
    return {'evidence_id': eid, 'start_line': 1, 'end_line': 1, 'quote': quote}


def fixtures():
    source = {'document_id': 'fix', 'start_line': 1, 'end_line': 1, 'quote': 'check'}
    rules = [{'id': rid, 'document_id': 'fix', 'title': rid, 'version': 'v1',
              'applicability': '代码修复任务', 'source_ref': source,
              'conditions': [{'id': rid + '.C01', 'text': text, 'kind': kind, 'source_ref': source}]}
             for rid, kind, text in [('FIX03', 'semantic', '最终代码保留零值'),
                                     ('FIX05', 'execution', '目标版本断言实际执行通过'),
                                     ('FIX06', 'human', '独立人员签署')]]
    package = {'title': 'Synthetic limit repair', 'rules': [], 'changes': [],
               'sop_selection': {'mode': 'auto'},
               'commits': [{'sha': SHA, 'parent': PARENT, 'evidence_id': 'D'}],
               'evidence': [{'id': 'U', 'kind': 'user_requirement', 'content': '保留零值，仅修复limit函数'},
                            {'id': 'S', 'kind': 'source', 'version_id': SHA, 'path': 'limit.py',
                             'content': 'return 25 if value is None else value'},
                            {'id': 'OLD', 'kind': 'source', 'version_id': PARENT, 'path': 'limit.py',
                             'content': 'return value or 25'},
                            {'id': 'TEST', 'kind': 'source', 'version_id': SHA, 'path': 'tests/test_limit.py',
                             'content': 'assert resolve_limit(0) == 0'},
                            {'id': 'RUN', 'kind': 'run_record', 'version_id': SHA, 'content': '{}'},
                            {'id': 'LOG', 'kind': 'test_log', 'version_id': SHA, 'content': '1 passed'},
                            {'id': 'ASSISTANT', 'kind': 'assistant', 'content': '已全部完成'}],
               'run_verification': []}
    task = {'id': 'T1', 'title': '保留零值', 'goal': '保留零值', 'commit_ids': [SHA],
            'target_commit_ids': [SHA], 'requirement_refs': [ref('U', '保留零值')],
            'acceptance_points': [{'id': 'A1', 'kind': 'behavior', 'requirement': '保留零值',
                                   'requirement_refs': [ref('U', '保留零值')]}]}
    result = {'tasks': [task], 'checks': [{'task_id': 'T1', 'rule_id': rule['id'], 'result': '未核查',
                                         'local_result': '满足', 'automated_result': '满足'} for rule in rules],
              'acceptance_checks': [{'task_id': 'T1', 'acceptance_id': 'A1', 'execution_result': '满足',
                                     'execution_run_ids': ['RUN'], 'source_context_evidence_ids': ['S'],
                                     'assertion_refs': [ref('TEST', 'assert resolve_limit(0) == 0')]}]}
    catalog = {'sha256': 'frozen', 'documents': [{'id': 'fix', 'title': 'Synthetic rules',
                                                'version': 'v1', 'sha256': 'hash', 'content': 'check'}],
               'rules': rules}
    return result, package, catalog


def default_response(payload):
    if 'candidates' in payload:
        return {'reviews': [{'id': row['id'], 'audit_object': row['audit_object'],
                             'dimension': row['dimension'], 'relation': 'evidence_insufficient',
                             'reason': '本条款尚无同维度直接反例。',
                             'obligation_refs': [], 'counterexample_refs': []}
                            for row in payload['candidates']], 'root_causes': []}
    if 'candidate_rules' in payload:
        return {'rules': [{'rule_id': row['id'], 'selection': 'selected', 'reason': '代码修复涉及该条件',
                           'evidence_refs': [ref('U', '保留零值')]} for row in payload['candidate_rules']]}
    return {'conditions': [{'condition_id': row['id'], 'result': '满足', 'reason': '目标代码保留零值',
                            'gap_type': '', 'evidence_refs': [ref('S', 'return 25 if value is None else value')],
                            'acceptance_ids': ['A1'], 'improvement': '', 'verification': ''}
                           for row in payload['conditions']]}


class Client:
    def __init__(self, respond=default_response):
        self.respond = respond
        self.calls = []

    def complete(self, system, payload, directory, stage):
        self.calls.append((stage, copy.deepcopy(payload)))
        return self.respond(payload)


class SopAuditTests(unittest.TestCase):
    def setUp(self):
        self.result, self.package, self.catalog = fixtures()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def audit(self, client=None, **options):
        self.client = client or Client()
        return audit_sop(self.result, self.package, self.catalog, self.client, self.directory, **options)

    def trusted_run(self):
        self.package['run_verification'] = [{'evidence_id': 'RUN', 'log_evidence_id': 'LOG',
            'verified': True, 'commit_sha': SHA, 'outcome': 'pass', 'source_evidence_ids': ['S'],
            'test_evidence_ids': ['TEST'], 'assertion_results': [
                {'path': 'tests/test_limit.py', 'line': 1, 'outcome': 'pass'}]}]

    def test_native_uncertain_selection_keeps_registered_atomic_statuses(self):
        self.catalog = load_catalog(Path(__file__).resolve().parents[1])
        self.catalog['rules'] = [rule for rule in self.catalog['rules'] if rule['id'] == 'SEC02']
        self.package['audit_context'] = {'profile': 'full_sop'}
        def respond(payload):
            return {'rules': [{'rule_id': row['id'], 'audit_object': row['audit_scope']['audit_object'],
                               'selection': 'uncertain', 'reason': '材料不足以核定本条范围。',
                               'evidence_refs': [ref('U', '保留零值')]}
                              for row in payload['candidate_rules']]}
        report = self.audit(Client(respond))
        rows = report['sop_condition_checks']
        expected = {item['id'] for rule in self.catalog['rules'] for condition in rule['conditions']
                    for item in condition['contract']['items']}
        atoms = [item for row in rows for item in row['atomic_checks']]
        self.assertEqual(len(rows), len(self.catalog['rules'][0]['conditions']))
        self.assertTrue(expected)
        self.assertEqual(len(atoms), len(expected))
        self.assertEqual({item['id'] for item in atoms}, expected)
        self.assertTrue(all(item['result'] == '未核查' and
                            item['gap_type'] == 'applicability_uncertain' for item in atoms))
        self.assertTrue(report['sop_coverage']['analysis_complete'])

    def test_native_human_conditions_keep_unknown_atoms_without_model_signoff(self):
        from ..sop_audit import HUMAN
        self.catalog = load_catalog(Path(__file__).resolve().parents[1])
        self.catalog['rules'] = [dict(rule, conditions=[condition for condition in rule['conditions']
                                  if condition['kind'] == 'human' or HUMAN.search(condition['text'])])
                                for rule in self.catalog['rules']]
        self.catalog['rules'] = [rule for rule in self.catalog['rules'] if rule['conditions']]
        self.catalog['rules'] = [rule for rule in self.catalog['rules'] if rule['id'] != 'FIX06']
        self.package['audit_context'] = {'profile': 'full_sop'}
        def respond(payload):
            self.assertIn('candidate_rules', payload)
            return {'rules': [{'rule_id': row['id'], 'audit_object': row['audit_scope']['audit_object'],
                               'selection': 'selected', 'reason': '本条流程范围适用。',
                               'evidence_refs': [ref('U', '保留零值')]}
                              for row in payload['candidate_rules']]}
        report = self.audit(Client(respond))
        rows = report['sop_condition_checks']
        self.assertTrue(rows)
        for row in rows:
            self.assertEqual({item['id'] for item in row['atomic_checks']},
                             {item['id'] for item in row['contract']['items']})
            self.assertTrue(all(item['result'] == '未核查' and item['gap_type'] == 'rule_scope_difference'
                                for item in row['atomic_checks']))
        self.assertFalse(report['original_sop']['formal_closed'])

    def test_selected_full_matrix_and_human_condition_is_not_signed_by_model(self):
        report = self.audit()
        self.assertEqual(len(report['sop_condition_checks']), 3)
        self.assertEqual([row['result'] for row in report['sop_condition_checks']], ['满足', '未核查', '未核查'])
        human = report['sop_condition_checks'][-1]
        self.assertEqual(human['gap_type'], 'rule_scope_difference')
        self.assertFalse(report['original_sop']['formal_closed'])
        self.assertEqual(len(self.client.calls), 2)
        self.assertTrue(report['sop_coverage']['matrix_complete'])
        self.assertTrue(report['sop_coverage']['analysis_complete'])
        self.assertNotIn('FIX06.C01', [row['id'] for row in self.client.calls[-1][1]['conditions']])

    def test_signature_plus_matching_specific_assertions_allows_execution(self):
        self.trusted_run()
        report = self.audit()
        row = report['sop_condition_checks'][1]
        self.assertEqual(row['result'], '满足')
        self.assertTrue(row['program_gates'][0]['met'])

    def test_file_level_signature_does_not_prove_assertion_execution(self):
        self.trusted_run()
        self.package['run_verification'][0]['assertion_results'] = []
        row = self.audit()['sop_condition_checks'][1]
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['gap_type'], 'evidence_missing')

    def test_failed_signed_assertion_is_a_confirmed_failure(self):
        self.trusted_run()
        run = self.package['run_verification'][0]
        run.update(outcome='fail')
        run['assertion_results'][0]['outcome'] = 'fail'
        self.assertEqual(self.audit()['sop_condition_checks'][1]['result'], '不满足')

    def test_wrong_version_scope_and_context_cannot_pass_execution(self):
        for mutate in [lambda run: run.update(commit_sha=PARENT),
                       lambda run: self.package['evidence'][4].update(target_ids=['T2']),
                       lambda run: run.update(source_evidence_ids=[])]:
            self.setUp()
            self.trusted_run()
            mutate(self.package['run_verification'][0])
            self.assertEqual(self.audit()['sop_condition_checks'][1]['result'], '未核查')

    def test_unrelated_suite_failure_does_not_override_selected_passed_assertion(self):
        self.trusted_run()
        self.package['run_verification'][0]['outcome'] = 'fail'
        self.assertEqual(self.audit()['sop_condition_checks'][1]['result'], '满足')

    def test_unverified_uploaded_success_is_not_execution_failure_or_success(self):
        self.trusted_run()
        self.package['run_verification'][0]['verified'] = False
        row = self.audit()['sop_condition_checks'][1]
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['model_result'], '满足')

    def test_selection_requires_every_candidate_rule(self):
        def response(payload):
            value = default_response(payload)
            if 'candidate_rules' in payload:
                value['rules'].pop()
            return value
        report = self.audit(Client(response))
        self.assertEqual(len(self.client.calls), 2)
        self.assertEqual(report['sop_coverage']['gap_types'], {'analysis_failed': 3})
        self.assertFalse(report['sop_coverage']['analysis_complete'])

    def test_missing_logs_cannot_be_used_to_exclude_a_rule(self):
        for rule in self.catalog['rules']:
            rule['applicability'] = '部署安装场景'
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row.update(selection='not_applicable', reason='没有日志所以不适用')
            return value
        report = self.audit(Client(response))
        self.assertTrue(all(row['result'] == '未核查' for row in report['sop_condition_checks']))
        self.assertEqual(report['sop_coverage']['gap_types'], {'applicability_uncertain': 3})
        self.assertEqual(len(self.client.calls), 1)
        selections = report['sop_selection']['task_selections'][0]['rules']
        self.assertTrue(all(row['selection'] == 'uncertain' for row in selections))
        self.assertTrue(all(row['model_selection'] == 'not_applicable' for row in selections))
        self.assertTrue(all(row['model_reason'] == '没有日志所以不适用' for row in selections))

    def test_scope_evidence_can_exclude_rules_without_model_condition_calls(self):
        for rule in self.catalog['rules']:
            rule['applicability'] = '部署安装场景'
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row.update(selection='not_applicable', reason='用户明确仅修复limit纯函数，本条涉及的部署场景不属于任务范围')
            return value
        report = self.audit(Client(response))
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(report['sop_coverage']['results'], {'不适用': 3})

    def test_uncertain_scope_is_not_not_applicable(self):
        for rule in self.catalog['rules']:
            rule['applicability'] = '部署安装场景'
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row.update(selection='uncertain', reason='任务是否涉及部署场景尚无法判断')
            return value
        report = self.audit(Client(response))
        self.assertEqual(report['sop_coverage']['gap_types'], {'applicability_uncertain': 3})

    def test_condition_matrix_cannot_omit_or_duplicate_ids(self):
        def response(payload):
            value = default_response(payload)
            if 'conditions' in value:
                value['conditions'][-1] = copy.deepcopy(value['conditions'][0])
            return value
        report = self.audit(Client(response))
        self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 2)
        self.assertEqual(len(self.client.calls), 3)

    def test_wrong_quote_old_version_or_other_task_acceptance_rejected(self):
        for mutate in [lambda row: row['evidence_refs'][0].update(quote='not present'),
                       lambda row: row.update(evidence_refs=[ref('OLD', 'return value or 25')]),
                       lambda row: row.update(acceptance_ids=['OTHER'])]:
            self.setUp()
            def response(payload):
                value = default_response(payload)
                for row in value.get('conditions', []):
                    mutate(row)
                return value
            report = self.audit(Client(response))
            self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 2)

    def test_assistant_only_conclusion_is_unknown_without_losing_candidate(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(evidence_refs=[ref('ASSISTANT', '已全部完成')])
            return value
        report = self.audit(Client(response))
        self.assertEqual(report['sop_coverage']['gap_types']['evidence_missing'], 2)
        self.assertTrue(report['sop_coverage']['analysis_complete'])
        for row in report['sop_condition_checks'][:2]:
            self.assertEqual(row['result'], '未核查')
            self.assertEqual(row['model_candidate']['result'], '满足')

    def test_condition_missing_evidence_cannot_be_not_applicable(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(result='不适用', reason='未提供测试材料', gap_type='')
            return value
        report = self.audit(Client(response))
        self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 2)

    def test_unknown_condition_requires_specific_gap_category(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(result='未核查', reason='尚未核查', gap_type='')
            return value
        self.assertEqual(self.audit(Client(response))['sop_coverage']['gap_types']['analysis_failed'], 2)

    def test_format_error_can_retry_once_and_feedback_is_preserved(self):
        count = 0
        def response(payload):
            nonlocal count
            count += 1
            if count == 1:
                raise ModelOutputError('synthetic malformed JSON')
            return default_response(payload)
        self.audit(Client(response))
        self.assertEqual(len(self.client.calls), 3)
        self.assertIn('synthetic malformed JSON', self.client.calls[1][1]['validation_feedback'][0])

    def test_provider_failure_has_no_format_retry_and_stops_later_tasks(self):
        task2 = copy.deepcopy(self.result['tasks'][0])
        task2['id'] = 'T2'
        self.result['tasks'].append(task2)
        def response(payload):
            raise ValueError('synthetic HTTP 401')
        report = self.audit(Client(response))
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(len(report['sop_condition_checks']), 6)
        self.assertFalse(report['sop_coverage']['analysis_complete'])

    def test_budget_counts_retries_and_preserves_remaining_unknown_matrix(self):
        report = self.audit(max_calls=1)
        self.assertEqual(len(self.client.calls), 1)
        self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 2)
        self.assertIn('预算上限', report['sop_condition_checks'][0]['reason'])
        report = self.audit(max_calls=0)
        self.assertEqual(report['sop_coverage']['request_count'], 0)
        self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 3)

    def test_batches_have_fixed_upper_bound_and_unique_stage_names(self):
        conditions = self.catalog['rules'][0]['conditions']
        conditions[:] = [{**conditions[0], 'id': 'FIX03.C' + str(i)} for i in range(49)]
        report = self.audit()
        self.assertEqual(len(self.client.calls), 6)
        batches = [payload for _, payload in self.client.calls if 'conditions' in payload]
        self.assertEqual([len(payload['conditions']) for payload in batches], [12, 12, 12, 12, 2])
        self.assertEqual(len({stage for stage, _ in self.client.calls}), 6)
        self.assertTrue(report['sop_coverage']['matrix_complete'])

    def test_original_defect_is_not_erased_by_new_semantic_pass(self):
        self.result['checks'][0]['automated_result'] = '不满足'
        report = self.audit()
        self.assertEqual(report['checks'][0]['sop_result'], '不满足')
        self.assertEqual(report['checks'][0]['local_result'], '满足')
        self.assertEqual(report['original_sop']['status'], '不满足')

    def test_all_new_conditions_pass_cannot_erase_confirmed_basic_failure(self):
        self.catalog['rules'] = self.catalog['rules'][:1]
        self.result['checks'][0]['automated_result'] = '不满足'
        report = self.audit()
        self.assertTrue(all(row['result'] == '满足' for row in report['sop_condition_checks']))
        self.assertEqual(report['original_sop']['status'], '不满足')
        self.assertEqual(report['sop_coverage']['outcome'], '不满足')
        report['sop_coverage']['unsupported_sections'] = [{'title': '尚未编译的治理章节'}]
        self.assertEqual(reaggregate_sop(report)['original_sop']['status'], '不满足')

    def test_mandatory_rules_are_selected_and_candidate_exclusions_are_preserved(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row.update(selection='not_applicable', reason='范围仅为limit纯函数')
            return value
        report = self.audit(Client(response))
        selections = report['sop_selection']['task_selections'][0]['rules']
        self.assertTrue(all(row['selection'] == 'selected' for row in selections))
        self.assertTrue(all(row['model_selection'] == 'not_applicable' for row in selections))
        self.assertTrue(all(row['model_reason'] == '范围仅为limit纯函数' for row in selections))
        self.assertEqual(len(self.client.calls), 2)
        self.assertTrue(all(rule['mandatory_review'] for rule in self.client.calls[0][1]['candidate_rules']))
        self.assertEqual(report['sop_coverage']['analysis_complete'], True)

    def test_mandatory_rule_with_missing_logs_is_checked_instead_of_excluded(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row.update(selection='uncertain', reason='没有日志所以无法确定是否需要检查')
            return value
        report = self.audit(Client(response))
        self.assertTrue(all(row['selection'] == 'selected' for row in report['sop_selection']['task_selections'][0]['rules']))
        self.assertEqual(report['sop_condition_checks'][1]['result'], '未核查')
        self.assertEqual(report['sop_condition_checks'][1]['gap_type'], 'evidence_missing')

    def test_optional_missing_evidence_exclusion_is_uncertain_with_original_scope(self):
        self.catalog['rules'][0]['applicability'] = '文件读写场景'
        def response(payload):
            value = default_response(payload)
            if 'rules' in value:
                value['rules'][0].update(selection='not_applicable', reason='缺少文件证据所以不检查')
            return value
        report = self.audit(Client(response))
        selection = report['sop_selection']['task_selections'][0]['rules'][0]
        self.assertEqual(selection['selection'], 'uncertain')
        self.assertEqual(selection['model_selection'], 'not_applicable')
        self.assertIn('不能以缺证据排除', selection['reason'])
        self.assertIn('文件读写场景', selection['reason'])
        self.assertEqual(report['sop_condition_checks'][0]['gap_type'], 'applicability_uncertain')

    def test_uncertain_downgrade_does_not_accept_invalid_exclusion_quote(self):
        self.catalog['rules'][0]['applicability'] = '文件读写场景'
        def response(payload):
            value = default_response(payload)
            if 'rules' in value:
                value['rules'][0].update(selection='not_applicable', reason='缺少文件证据所以不检查',
                                         evidence_refs=[ref('U', '不存在的引用')])
            return value
        report = self.audit(Client(response))
        self.assertEqual(len(self.client.calls), 3)
        self.assertEqual(report['sop_condition_checks'][0]['gap_type'], 'analysis_failed')
        self.assertNotEqual(report['sop_condition_checks'][1]['gap_type'], 'analysis_failed')
        self.assertEqual(self.client.calls[1][1]['candidate_rules'][0]['id'], 'FIX03')
        self.assertEqual(len(self.client.calls[1][1]['candidate_rules']), 1)

    def add_security_execution_condition(self):
        rule = copy.deepcopy(self.catalog['rules'][1])
        rule.update(id='SEC04', title='不可信输入', applicability='存在不可信输入时')
        rule['conditions'][0].update(id='SEC04.C06', text='拒绝伪造批准和越权执行', stage='L3')
        self.catalog['rules'].append(rule)

    def test_functional_run_does_not_prove_a_security_condition_passed(self):
        self.add_security_execution_condition()
        self.trusted_run()
        report = self.audit()
        execution = report['sop_condition_checks'][-1]
        self.assertEqual(execution['rule_id'], 'SEC04')
        self.assertEqual(execution['result'], '未核查')
        self.assertEqual(execution['model_result'], '满足')
        self.assertEqual(execution['gap_type'], 'automatic_check_unsupported')
        self.assertEqual(execution['program_gates'][-1]['id'], 'condition_specific_execution_mapping')
        self.assertEqual(report['sop_condition_checks'][1]['result'], '满足')

    def test_functional_failure_does_not_prove_a_security_failure(self):
        self.add_security_execution_condition()
        self.trusted_run()
        self.package['run_verification'][0]['assertion_results'][0]['outcome'] = 'fail'
        self.package['run_verification'][0]['outcome'] = 'fail'
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(result='不满足')
            return value
        row = self.audit(Client(response))['sop_condition_checks'][-1]
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['model_result'], '不满足')
        self.assertEqual(row['gap_type'], 'automatic_check_unsupported')

    def test_security_execution_scope_exemption_still_needs_positive_evidence(self):
        self.add_security_execution_condition()
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                if row['condition_id'] == 'SEC04.C06':
                    row.update(result='不适用', reason='用户明确只修复字符串纯函数，本条件的执行批准入口不属于任务范围',
                               evidence_refs=[ref('U', '仅修复limit函数')])
            return value
        row = self.audit(Client(response))['sop_condition_checks'][-1]
        self.assertEqual(row['result'], '不适用')
        self.assertEqual(row['gap_type'], '')

    def test_selection_without_task_scope_reference_is_not_accepted(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('rules', []):
                row['evidence_refs'] = []
            return value
        self.assertEqual(self.audit(Client(response))['sop_coverage']['gap_types']['analysis_failed'], 3)

    def test_requirement_quote_alone_cannot_prove_code_correct(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(evidence_refs=[ref('U', '保留零值')])
            return value
        row = self.audit(Client(response))['sop_condition_checks'][0]
        self.assertEqual(row['result'], '未核查')
        self.assertEqual(row['model_result'], '满足')
        self.assertEqual(row['gap_type'], 'evidence_missing')
        self.assertFalse(next(gate for gate in row['program_gates'] if gate['id'] == 'target_code_proof')['met'])

    def test_uncompiled_document_sections_limit_whole_document_claim(self):
        self.catalog['rules'] = self.catalog['rules'][:1]
        self.catalog['coverage_manifest'] = {'documents': [{'document_id': 'fix', 'uncompiled_sections': [
            {'title': '治理章节', 'source_ref': {}}]}]}
        report = self.audit()
        self.assertEqual(report['sop_condition_checks'][0]['result'], '满足')
        self.assertEqual(report['checks'][0]['sop_result'], '满足')
        self.assertEqual(report['original_sop']['status'], '未核查')
        self.assertEqual(len(report['original_sop']['unsupported_sections']), 1)

    def test_excluded_time_check_cannot_become_an_evidence_gap(self):
        def response(payload):
            value = default_response(payload)
            for row in value.get('conditions', []):
                row.update(result='未核查', reason='历史适用性未确认', gap_type='evidence_missing')
            return value
        report = self.audit(Client(response))
        self.assertEqual(report['sop_coverage']['gap_types']['analysis_failed'], 2)
        self.assertEqual(len(self.client.calls), 3)

    def test_semantic_condition_containing_independent_review_is_not_auto_passed(self):
        self.catalog['rules'][0]['conditions'][0]['text'] += '，独立复核齐全'
        row = self.audit()['sop_condition_checks'][0]
        self.assertEqual(row['kind'], 'human')
        self.assertEqual(row['result'], '未核查')

    def test_no_users_or_tasks_does_not_claim_original_sop_pass(self):
        self.result.update(tasks=[], checks=[], acceptance_checks=[])
        report = self.audit()
        self.assertEqual(len(self.client.calls), 0)
        self.assertEqual(report['original_sop']['status'], '未核查')

    def test_supplementation_preserves_unselected_task_rows_and_replaces_target(self):
        original = copy.deepcopy(self.audit())
        task2 = copy.deepcopy(self.result['tasks'][0])
        task2['id'] = 'T2'
        self.result['tasks'].append(task2)
        previous = copy.deepcopy(original)
        saved = {'task_id': 'T2', 'rule_id': 'FIX03', 'condition_id': 'FIX03.C01', 'document_id': 'fix',
                 'text': '保持未选任务记录', 'result': '满足', 'reason': '先前已检查', 'gap_type': ''}
        previous['sop_condition_checks'].append(saved)
        previous['sop_selection']['task_selections'].append({'task_id': 'T2', 'rules': []})
        report = self.audit(previous=previous, task_ids=['T1'])
        self.assertEqual([row for row in report['sop_condition_checks'] if row['task_id'] == 'T2'], [saved])
        self.assertEqual(len(self.client.calls), 2)

    def test_reaggregation_keeps_existing_native_closure_contract_and_rechecks_its_prerequisites(self):
        self.catalog = load_catalog(Path(__file__).resolve().parents[1])
        self.catalog['rules'] = [r for r in self.catalog['rules'] if r['id'] == 'FIX06']
        self.catalog['rules'][0]['conditions'] = [c for c in self.catalog['rules'][0]['conditions']
                                                if c['id'] in {'FIX06.C01', 'FIX06.C04'}]
        report = self.audit()
        for row in report['sop_condition_checks']:
            row['contract']['version'] = '1.6'
            row['contract']['frozen_marker'] = 'original interpretation'
        frozen = [copy.deepcopy(row['contract']) for row in report['sop_condition_checks']]
        report['checks'][0].update(automated_result='不满足', target_commit_ids=[SHA])
        derived = reaggregate_sop(report)
        self.assertEqual([row['contract'] for row in derived['sop_condition_checks']], frozen)
        self.assertTrue(all(row['result'] == '不满足' for row in derived['sop_condition_checks']))
        self.assertEqual(derived['original_sop']['status'], '不满足')

    def test_native_closure_supplement_preserves_unselected_old_rows_and_global_failure(self):
        self.catalog = load_catalog(Path(__file__).resolve().parents[1])
        self.catalog['rules'] = [r for r in self.catalog['rules'] if r['id'] == 'FIX06']
        self.catalog['rules'][0]['conditions'] = [c for c in self.catalog['rules'][0]['conditions']
                                                if c['id'] in {'FIX06.C01', 'FIX06.C04'}]
        self.package['audit_context'] = {'profile': 'full_sop'}
        self.result['checks'][0].update(automated_result='不满足', target_commit_ids=[SHA])
        original = copy.deepcopy(self.audit())
        task2 = copy.deepcopy(self.result['tasks'][0])
        task2['id'] = 'T2'
        self.result['tasks'].append(task2)
        self.result['checks'][0]['automated_result'] = '满足'
        saved_checks = [{**copy.deepcopy(check), 'task_id': 'T2'} for check in original['checks']]
        self.result['checks'].extend(saved_checks)
        for has_metadata in (True, False):
            with self.subTest(frozen_closure_metadata=has_metadata):
                previous = copy.deepcopy(original)
                saved_rows = []
                for prior in original['sop_condition_checks']:
                    row = copy.deepcopy(prior)
                    row['task_id'] = 'T2'
                    row['contract']['version'] = '1.6'
                    if not has_metadata:
                        row['contract'] = {'version': '1.1', 'items': []}
                        row['atomic_checks'] = []
                    saved_rows.append(row)
                previous['sop_condition_checks'].extend(saved_rows)
                previous['sop_selection']['task_selections'].append({'task_id': 'T2', 'rules': []})
                frozen_previous = copy.deepcopy(previous)
                report = self.audit(previous=previous, task_ids=['T1'])
                self.assertEqual([r for r in report['sop_condition_checks'] if r['task_id'] == 'T2'], saved_rows)
                self.assertEqual([c for c in report['checks'] if c['task_id'] == 'T2'], saved_checks)
                self.assertEqual(previous, frozen_previous)
                self.assertTrue(all(r['result'] == '未核查' for r in report['sop_condition_checks']
                                    if r['task_id'] == 'T1'))
                self.assertEqual(report['original_sop']['status'], '不满足')
                self.assertEqual(report['sop_coverage']['current_scope']['outcome'], '不满足')

    def test_input_catalog_and_materials_are_not_mutated(self):
        catalog, package = copy.deepcopy(self.catalog), copy.deepcopy(self.package)
        self.audit()
        self.assertEqual(self.catalog, catalog)
        self.assertEqual(self.package, package)

    def test_invalid_task_or_budget_rejected_before_network(self):
        for arguments in [{'task_ids': ['other']}, {'max_calls': -1}, {'max_calls': True}]:
            with self.assertRaises(ValueError):
                self.audit(**arguments)
            self.assertEqual(self.client.calls, [])


if __name__ == '__main__':
    unittest.main()

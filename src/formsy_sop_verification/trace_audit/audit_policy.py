"""Deterministic gates for scoped automatic review, separate from full SOP closure."""
import ast
import re
from .run_evidence import external_test_path

PASS, FAIL, UNKNOWN, NA = '满足', '不满足', '未核查', '不适用'
HUMAN = re.compile(r'人工(?:进行|执行|完成|提供)?(?:审核|复核|评审|审查|签署|签字|确认|审批|验收)|人审|'
                   r'独立(?:关闭)?(?:复核|审核|评审|审查)|确认记录|human\s+(?:review|approval|signoff)|'
                   r'manual\s+(?:review|approval)|independent\s+review', re.I)
CLOSURE = re.compile(r'正式关闭|(?:独立|本轮|本次)(?:\s*SOP\s*)?关闭(?:复核|审核|确认|记录|材料|证据|条件|门槛)')


def _formal_condition(value):
    return bool(HUMAN.search(str(value)) or CLOSURE.search(str(value)))


def _path(item):
    return item.get('path') or item.get('name', '')


def _test_path(path):
    return bool(re.search(r'(^|[/\\])(?:tests?|specs?|__tests__|audit-tests)([/\\]|$)|(^|[/\\])test_|_test\.|\.(?:test|spec)\.', path, re.I))


def target_source_index(task, package):
    """Index visible Python syntax; a locator never proves trust, flow or coverage."""
    result = []
    for source in package.get('evidence', []):
        path = _path(source)
        if (source.get('kind') != 'source' or not path.endswith('.py')
                or source.get('version_id') not in task.get('target_commit_ids', [])
                or not _allowed(source, task)):
            continue
        try:
            tree = ast.parse(source.get('content', ''))
        except (SyntaxError, ValueError):
            continue
        lines = source['content'].splitlines(keepends=True)
        sites = []
        for node in ast.walk(tree):
            test = _test_path(path) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
            call = isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and (
                node.func.attr == 'json' or any(isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                and (arg.value.startswith(('https://', 'http://', '/'))) for arg in node.args))
            if test or call:
                sites.append({'kind': 'test_function' if test else 'call_syntax',
                    'name': node.name if test else ast.get_source_segment(source['content'], node.func),
                    'reference': {'evidence_id': source['id'], 'start_line': node.lineno,
                                  'end_line': node.end_lineno,
                                  'quote': ''.join(lines[node.lineno - 1:node.end_lineno]).rstrip('\r\n')}})
        if sites:
            result.append({'evidence_id': source['id'], 'path': path, 'version_id': source['version_id'],
                           'line_count': len(lines), 'sites': sites})
    return result


def _allowed(item, task):
    return not item.get('target_ids') or task['id'] in item['target_ids']


def _ids(refs):
    return {ref.get('evidence_id') for ref in refs if isinstance(ref, dict)}


def _full_sha(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{40}', value) is not None


def _aggregate(values):
    if FAIL in values:
        return FAIL
    relevant = [v for v in values if v != NA]
    if values and not relevant:
        return NA
    return PASS if relevant and all(v == PASS for v in relevant) else UNKNOWN


def apply_policy(result, package):
    evidence = {e['id']: e for e in package.get('evidence', [])}
    changes = {c['id']: c for c in package.get('changes', [])}
    rules = {r['id']: r for r in package.get('rules', [])}
    runs = package.get('run_verification', [])
    acceptance_checks = result.get('acceptance_checks', [])
    constraints, coverage = [], []
    tasks = {t['id']: t for t in result.get('tasks', [])}
    globally_mapped = {cid for row in acceptance_checks if row.get('task_id') in tasks
                       and row.get('acceptance_id') in {p['id'] for p in tasks[row['task_id']].get('acceptance_points', [])}
                       for cid in row.get('change_ids', []) if cid in changes
                       and changes[cid].get('commit_id') in tasks[row['task_id']].get('commit_ids', [])}
    globally_mapped.update(relation['change_id'] for row in acceptance_checks
        if row.get('task_id') in tasks for relation in row.get('change_relations', [])
        if relation.get('relation') == 'supporting' and relation.get('change_id') in changes
        and changes[relation['change_id']].get('commit_id') in tasks[row['task_id']].get('commit_ids', []))

    def constraint(rule_id, condition, source='original_rule'):
        if not any(c['rule_id'] == rule_id and c['condition'] == condition for c in constraints):
            constraints.append({'rule_id': rule_id, 'condition': condition, 'source': source,
                                'status': '未确认', 'automatic_action_required': False,
                                'reason': '保留原 SOP 的人工或独立复核条件；当前无人流程不生成签署或人工补证步骤。'
                                if HUMAN.search(str(condition)) else
                                '保留原 SOP 正式关闭条件；当前自动审计完成不等待正式关闭补件。'
                                if CLOSURE.search(str(condition)) else
                                '保留原条款尚未核实的材料要求；自动子集满足不能外推完整条款满足。'})

    def automatic_action(value, rule_id, source):
        if not isinstance(value, str) or not _formal_condition(value):
            return value
        constraint(rule_id, value, source)
        kept = [clause.strip() for clause in re.split(r'[，,。；;\n]', value)
                if clause.strip() and not _formal_condition(clause)]
        return '；'.join(kept) or '按验收点补齐目标源码、断言、受信运行及自动复检证据。'
    for rule in rules.values():
        text = rule.get('criterion', '') + '\n' + '\n'.join(rule.get('required_evidence', []))
        if rule['id'] == 'FIX06':
            text += '\n' + rule.get('closure_policy', '')
        if _formal_condition(text):
            constraint(rule['id'], text.strip())
    constrained_rules = {c['rule_id'] for c in constraints}

    for task in result.get('tasks', []):
        target = set(task.get('target_commit_ids', []))
        related = set(task.get('commit_ids', []))
        points = task.get('acceptance_points', [])
        rows = [a for a in acceptance_checks if a.get('task_id') == task['id']]
        point_rows = {a.get('acceptance_id'): a for a in rows}
        complete = bool(points) and {p['id'] for p in points} == set(point_rows)
        points_by_id = {p['id']: p for p in points}
        scoped_changes = {cid: c for cid, c in changes.items() if c.get('commit_id') in related}
        unmapped = sorted(set(scoped_changes) - globally_mapped)

        def target_source(refs):
            return [evidence[eid] for eid in _ids(refs) if eid in evidence
                    and evidence[eid].get('kind') == 'source'
                    and not external_test_path(_path(evidence[eid]))
                    and evidence[eid].get('content', '').strip()
                    and evidence[eid].get('version_id') in target and _allowed(evidence[eid], task)]

        def assertion_sources(row):
            return [item for item in target_source(row.get('assertion_refs', [])) if _test_path(_path(item))]

        def execution_refs(row):
            return (row.get('execution_assertion_refs', []) if 'execution_run_reviews' in row
                    else row.get('execution_assertion_refs') or row.get('assertion_refs', []))

        def execution_assertions(row):
            refs = execution_refs(row)
            return [evidence[eid] for eid in _ids(refs) if eid in evidence
                    and evidence[eid].get('version_id') in target and _allowed(evidence[eid], task)
                    and (evidence[eid].get('kind') == 'source' and _test_path(_path(evidence[eid]))
                         or evidence[eid].get('kind') == 'context' and _path(evidence[eid]).startswith('audit-tests/'))]

        def exempt_test(row):
            point = points_by_id.get(row.get('acceptance_id'), {})
            refs = point.get('requirement_refs', [])
            return point.get('kind', 'behavior') == 'scope_constraint' \
                and row.get('test_design_result') == NA and bool(refs) and bool(row.get('reason', '').strip()) \
                and all(evidence.get(eid, {}).get('kind') == 'user_requirement' for eid in _ids(refs))

        def final_proof(row):
            refs = row.get('change_refs', []) + row.get('no_change_refs', []) + row.get('source_refs', [])
            if target_source(refs):
                return True
            return any(cid in changes and changes[cid].get('commit_id') in target
                       for cid in row.get('change_ids', []))

        def source_context(row):
            refs = row.get('change_refs', []) + row.get('no_change_refs', []) + row.get('source_refs', [])
            source = target_source(refs)
            paths = {_path(c) for cid in row.get('change_ids', []) if (c := changes.get(cid))
                     and not _test_path(_path(c))}
            # A full target file on the changed path supplies context around the quoted hunk.
            for item in evidence.values():
                if item.get('kind') == 'source' and item.get('version_id') in target \
                        and item.get('content', '').strip() and _allowed(item, task) and _path(item) in paths:
                    source.append(item)
            return [item for item in source if not _test_path(_path(item))]

        def matching_runs(row):
            assertions = {item['id'] for item in execution_assertions(row)}
            contexts = source_context(row)
            source_paths = {_path(item) for item in contexts}
            source_paths.update(changes[cid]['path'] for cid in row.get('change_ids', [])
                                if cid in changes and not _test_path(changes[cid].get('path', '')))
            matches = []
            if not assertions or not source_paths:
                return matches
            for run in runs:
                if not run.get('verified') or run.get('commit_sha') not in target:
                    continue
                if 'execution_run_reviews' in row and not any(
                        review.get('run_evidence_id') == run['evidence_id']
                        and review.get('relation') == 'required' for review in row['execution_run_reviews']):
                    continue
                bound = [run.get('evidence_id'), run.get('log_evidence_id')]
                bound += run.get('source_evidence_ids', []) + run.get('test_evidence_ids', [])
                if any(eid not in evidence or not _allowed(evidence[eid], task) for eid in bound):
                    continue
                if evidence[run['evidence_id']].get('kind') != 'run_record' \
                        or evidence[run['log_evidence_id']].get('kind') != 'test_log' \
                        or any(evidence[eid].get('version_id') != run['commit_sha'] for eid in bound):
                    continue
                files_bound = True
                for kind in ['source', 'test']:
                    ids = run.get(kind + '_evidence_ids', [])
                    files = [evidence[eid] for eid in ids]
                    expected_kind = 'context' if kind == 'test' and run.get('test_origin') == 'external_audit' else 'source'
                    if not files or any(e.get('kind') != expected_kind for e in files) \
                            or {_path(e) for e in files} != set(run.get(kind + '_paths', [])):
                        files_bound = False
                if not files_bound:
                    continue
                if not assertions.intersection(run.get('test_evidence_ids', [])) \
                        or not source_paths <= set(run.get('source_paths', [])):
                    continue
                matches.append(run)
            return matches

        for row in rows:
            row['source_context_evidence_ids'] = sorted({item['id'] for item in source_context(row)})
            row['assertion_evidence_ids'] = sorted({item['id'] for item in assertion_sources(row)})
            row['execution_assertion_evidence_ids'] = sorted({item['id'] for item in execution_assertions(row)})
            bound = matching_runs(row)
            row['execution_run_ids'] = [run['evidence_id'] for run in bound]
            required = set()
            mapped_refs = ([(review['run_evidence_id'], ref) for review in row['execution_run_reviews']
                            if review.get('relation') == 'required' for ref in review.get('assertion_refs', [])]
                           if 'execution_run_reviews' in row else [(None, ref) for ref in execution_refs(row)])
            for run_id, ref in mapped_refs:
                item = evidence.get(ref.get('evidence_id'), {})
                if item.get('id') not in row['execution_assertion_evidence_ids']:
                    continue
                lines = item.get('content', '').splitlines()
                for line in range(ref.get('start_line', 0), ref.get('end_line', -1) + 1):
                    if 1 <= line <= len(lines) and lines[line - 1].strip():
                        required.add((run_id, _path(item), line))
            recorded = {(run['evidence_id'] if 'execution_run_reviews' in row else None,
                         a.get('path'), a.get('line'), a.get('outcome'))
                        for run in bound for a in run.get('assertion_results', [])}
            passed = {(run_id, path, line) for run_id, path, line, outcome in recorded if outcome == 'pass'}
            failed = {(run_id, path, line) for run_id, path, line, outcome in recorded if outcome == 'fail'}
            skipped = {(run_id, path, line) for run_id, path, line, outcome in recorded if outcome == 'skipped'}
            if exempt_test(row):
                execution = NA
            elif required & failed:
                execution = FAIL
            elif row.get('test_design_result') == PASS and required and required <= passed \
                    and not required & skipped and not any(review.get('relation') == 'unknown'
                        for review in row.get('execution_run_reviews', [])):
                execution = PASS
            else:
                execution = UNKNOWN
            row['execution_result'] = execution
            row['execution_scope'] = '配置认可 runner 对被测目标代码和具体测试断言行的签名记录；外部审计测试独立于原提交交付，文件级记录不能证明验收点执行。'
            row['target_commit_ids'] = sorted(target)
            row['overall_result'] = _aggregate([row.get('result', UNKNOWN),
                NA if exempt_test(row) else row.get('test_design_result', UNKNOWN), execution])

        outcomes = [point_rows[p['id']].get('result', UNKNOWN) for p in points if p['id'] in point_rows]
        designs = [NA if exempt_test(a) else UNKNOWN if a.get('test_design_result') == NA else
                   a.get('test_design_result', UNKNOWN) for a in rows]
        implementations = _aggregate(outcomes + ([] if complete else [UNKNOWN]))
        code_points = [p for p in points if p.get('kind', 'behavior') != 'test_delivery']
        code_rows = [point_rows[p['id']] for p in code_points if p['id'] in point_rows]
        code_complete = bool(code_points) and len(code_rows) == len(code_points)
        code_implementation = _aggregate([a.get('result', UNKNOWN) for a in code_rows] +
                                         ([] if code_complete else [UNKNOWN]))
        test_design = _aggregate(designs + ([] if complete else [UNKNOWN]))
        execution = _aggregate([a['execution_result'] for a in rows] + ([] if complete else [UNKNOWN]))
        auto = {}
        task_checks = sorted([c for c in result.get('checks', []) if c.get('task_id') == task['id']],
                             key=lambda c: c.get('rule_id', ''))
        for check in task_checks:
            rid, rule = check['rule_id'], rules.get(check['rule_id'], {})
            local = check.get('local_result', check.get('result', UNKNOWN))
            details, gates = [], []

            def gate(name, met, reason):
                gates.append({'id': rid + '-' + name, 'met': bool(met), 'reason': reason})

            outcome = UNKNOWN
            if check.get('applicability') == '不适用' and local == NA:
                outcome = NA
                details.append('范围依据支持不适用；缺证据不会自动排除条款。')
                gate('scope-exemption', True, details[-1])
            elif check.get('applicability') == '待确认':
                details.append('条款适用性待确认。')
                gate('applicability', False, details[-1])
            elif rid == 'FIX01':
                refs_valid = complete and all(p.get('requirement_refs') and all(
                    evidence.get(eid, {}).get('kind') == 'user_requirement'
                    for eid in _ids(p['requirement_refs'])) for p in points)
                version_valid = target and all(_full_sha(sha) for sha in target)
                gate('requirements', refs_valid, '每个验收点均定位用户明确原话，且检查点完整。')
                gate('target-version', version_valid, '最终目标版本提供完整 SHA。')
                gate('rule-version', rule.get('version'), '规则提供固定版本。')
                gate('semantic-baseline', local == PASS, '模型须明确确认需求基准；字段齐全不能证明没有遗漏用户要求。')
                if refs_valid and version_valid and rule.get('version') and local == PASS:
                    outcome = PASS
                else:
                    details.append('需要每个验收点的用户原话、完整最终目标 SHA 和规则版本。')
            elif rid == 'FIX02':
                outcome = implementations
                proof = complete and all(final_proof(a) and (a.get('change_ids') or
                            (a.get('no_change_reason') and a.get('no_change_refs'))) for a in rows)
                gate('acceptance-coverage', complete and implementations == PASS,
                     '全部明确验收点具备语义实现候选，不能忽略漏实现或已定位反例。')
                gate('final-proof', proof, '每点关联最终目标改动或目标源码依据；中间版本单独不足。')
                gate('hunk-coverage', not unmapped, '关联 Commit 的每个 hunk 均有有效任务验收点映射；同 Commit 的其他任务可以覆盖各自 hunk。' +
                     (' 尚未映射：' + ', '.join(unmapped) if unmapped else ''))
                if outcome == PASS and (unmapped or not proof):
                    outcome = UNKNOWN
                if unmapped:
                    details.append('关联 Commit 仍有未映射 hunk：' + ', '.join(unmapped))
                if outcome == UNKNOWN:
                    details.append('每个验收点需要实现证据或目标版本无需改动依据；中间版本不能单独证明最终实现。')
            elif rid == 'FIX03':
                outcome = code_implementation
                contexts = code_complete and all(source_context(a) for a in code_rows)
                gate('implementation', code_complete and code_implementation == PASS,
                     '行为与范围约束的实现候选成立，无已定位代码反例；测试交付缺口单独评价。')
                gate('target-context', contexts, '每个验收点具有最终目标版本对应路径的非空源码上下文。')
                if outcome == PASS and not contexts:
                    outcome = UNKNOWN
                    details.append('缺少覆盖各验收点的最终目标源码上下文；局部 diff 不能证明完整表达式与调用行为。')
            elif rid == 'FIX04':
                outcome = test_design
                assertions = complete and all(exempt_test(a) or assertion_sources(a) for a in rows)
                gate('test-design', complete and test_design in [PASS, NA], '每点断言设计成立；仅明确范围约束可依据原话豁免。')
                gate('assertions', assertions, '需测试的每点断言均引用目标版本测试源码。')
                if outcome == PASS and not assertions:
                    outcome = UNKNOWN
                    details.append('每个验收点的断言必须绑定目标版本的测试源码。')
            elif rid == 'FIX05':
                outcome = execution
                required_rows = [a for a in rows if not exempt_test(a)]
                trusted = any(run.get('verified') and run.get('commit_sha') in target for run in runs)
                bindings = complete and all(matching_runs(a) for a in required_rows)
                gate('trusted-source', not required_rows or trusted, '运行回执来源在服务器私有信任配置中且签名通过。')
                gate('artifact-binding', bindings, '回执及全部绑定源码、测试、日志均属目标版本并允许该任务使用。')
                gate('assertion-execution', complete and execution in [PASS, NA],
                     '所有必需断言引用行均有签名 pass；仅文件哈希、未覆盖行或跳过不能证明执行通过。')
                if local == FAIL and outcome == PASS:
                    outcome = UNKNOWN
                    details.append('模型局部反例与受信运行声明矛盾，不能直接提升为满足。')
                if outcome != PASS:
                    details.append('运行需受信来源、目标身份、源码/测试/日志绑定及逐断言签名结果；未知设计或验收断言跳过不能通过。')
            elif rid == 'FIX06':
                prior = [auto.get('FIX0' + str(i), UNKNOWN) for i in range(1, 6)]
                readiness = _aggregate(prior)
                check['closure_readiness'] = FAIL if local == FAIL else readiness
                check['recheck_execution_result'] = auto.get('FIX05', UNKNOWN)
                outcome = readiness
                if local == FAIL and outcome == PASS:
                    outcome = UNKNOWN
                gate('prior-checks', all(v in [PASS, NA] for v in prior),
                     '前五项自动门槛均满足，或有明确原话范围支持不适用豁免。')
                gate('recheck-execution', auto.get('FIX05') in [PASS, FAIL, NA],
                     '复检结论需要本轮必验运行结果；未就绪不等于已经执行复检失败。')
                details.append('必需项已确认不满足时整体不满足；本轮复检执行结果单列，缺运行证据仍保留未核查。')
            else:
                details.append('尚未定义该条款的机器证据门槛，保留未知。')
                gate('defined-policy', False, details[-1])
            if local == FAIL and rid in {'FIX01', 'FIX02', 'FIX03', 'FIX04'}:
                outcome = FAIL
                gate('local-counterexample', False, '保留模型已定位的反例；机器门槛不会把不满足提升为满足。')
            elif local == FAIL and rid not in {'FIX05', 'FIX06'}:
                details.append('保留原模型局部失败；该扩展条款须经完整条件及同范围证据门槛后判定，不直接传播为机器失败。')
            auto[rid] = outcome
            sop = UNKNOWN if outcome == PASS and (rid in constrained_rules or rid == 'FIX06') else outcome
            if details:
                check['policy_notes'] = details
            for field in ['improvement', 'verification']:
                check[field] = automatic_action(check.get(field, ''), rid, 'check.' + field)
            missing = check.get('missing_materials', [])
            check['missing_materials'] = [value for value in missing if not _formal_condition(value)]
            for value in missing:
                constraint(rid, value, 'check.missing_materials')
            original_gaps = list(missing)
            known_requirements = {
                'FIX01': {'用户原话/有效决定引用', '任务与验收清单', '规则版本摘要'},
                'FIX02': {'验收点ID', '双向关系及孤立清单'},
                'FIX03': set(), 'FIX04': {'验收点到断言映射'},
                'FIX05': {'实际命令和完整输出', '受测版本/补丁/测试设计'},
                'FIX06': set(),
            }
            for required in rule.get('required_evidence', []):
                if required in known_requirements.get(rid, set()) or _formal_condition(required):
                    continue
                covered = False
                if rid == 'FIX01' and required == '目标源码与环境身份':
                    covered = bool(rows) and all(matching_runs(a) for a in rows if not exempt_test(a)) \
                        and any(matching_runs(a) for a in rows)
                elif rid == 'FIX02' and required == '固定版本实质diff及必要上下文':
                    covered = complete and all(source_context(a) for a in rows)
                elif rid == 'FIX03' and required == '变更前后代码':
                    before = True
                    for a in code_rows:
                        for cid in a.get('change_ids', []):
                            change = changes.get(cid, {})
                            if _test_path(change.get('path', '')):
                                continue
                            diff = evidence.get(change.get('evidence_id'), {}).get('content', '')
                            replaced = any(line.startswith('-') and not line.startswith('---') for line in diff.splitlines()) \
                                and any(line.startswith('+') and not line.startswith('+++') for line in diff.splitlines())
                            parent_source = any(e.get('kind') == 'source' and _path(e) == change.get('path')
                                                and e.get('version_id') in {c.get('parent') for c in package.get('commits', [])
                                                                          if c.get('sha') in target}
                                                and e.get('content', '').strip() for e in evidence.values())
                            before = before and (replaced or parent_source)
                    covered = code_complete and before and all(source_context(a) for a in code_rows)
                if not covered:
                    gap = '原条款必需证据尚无完整机器覆盖：' + required
                    original_gaps.append(gap)
                    constraint(rid, gap, 'original_required_evidence')
            if outcome == PASS and original_gaps:
                sop = UNKNOWN
            check.update(local_result=local, automated_result=outcome, sop_result=sop,
                         result=sop, gate_details=gates,
                         target_commit_ids=sorted(target),
                         assessment_scope='仅所列材料、目标版本与自动可验证子集；语义判断仍为模型候选。')

        for cid, change in scoped_changes.items():
            linked = [a['acceptance_id'] for a in rows if cid in a.get('change_ids', [])]
            relations = [{**relation, 'task_id': task['id'], 'acceptance_id': a['acceptance_id']}
                         for a in rows for relation in a.get('change_relations', [])
                         if relation.get('change_id') == cid]
            coverage.append({'task_id': task['id'], 'change_id': cid, 'path': change.get('path'),
                             'commit_id': change.get('commit_id'), 'acceptance_ids': linked,
                             'relations': relations, 'mapped': bool(linked)})
    mapped_any = {row['change_id'] for row in coverage if row['mapped']}
    result['change_coverage'] = []
    for cid, change in changes.items():
        rows = [row for row in coverage if row['change_id'] == cid]
        relations = [relation for row in rows for relation in row['relations']]
        kinds = {relation['relation'] for relation in relations}
        relationship = ('implementation' if cid in mapped_any and 'implementation' in kinds else
                        next(iter(kinds)) if len(kinds) == 1 else 'unknown')
        result['change_coverage'].append({**change,
            'acceptance_ids': sorted({aid for row in rows for aid in row['acceptance_ids']}),
            'task_ids': sorted({row['task_id'] for row in rows if row['mapped']}),
            'relations': relations, 'relationship_status': relationship,
            'purpose_covered': cid in globally_mapped,
            'status': 'mapped' if cid in mapped_any else 'unmapped'})
    result['unmapped_changes'] = [c for cid, c in changes.items() if cid not in globally_mapped]
    result['run_verification'] = runs
    result['schema_version'] = '2.0'
    result['original_sop'] = {'formal_closed': False, 'unassessed_conditions': constraints,
                              'status': '未确认', 'reason': '自动审计完成与原 SOP 正式关闭分别记录。'}
    result['formal_closed'] = False
    automatic = _aggregate([c['automated_result'] for c in result.get('checks', [])
                            if c.get('automated_result') != NA])
    if automatic == PASS and result['unmapped_changes']:
        automatic = UNKNOWN
    result['automatic_review'] = {'status': 'completed', 'analysis_complete': True,
                                  'outcome': automatic,
                                  'scope': '需求、实现、断言与受信运行的自动可验证子集；不声明真实业务验收或正式 SOP 关闭。'}
    for finding in result.get('findings', []):
        if finding.get('category') == 'evidence_gap' and _formal_condition(' '.join(str(finding.get(k, ''))
                for k in ['summary', 'improvement', 'verification'])):
            finding['original_sop_limitation'] = {k: finding.get(k, '') for k in ['summary', 'improvement', 'verification']}
            for field in ['summary', 'improvement', 'verification']:
                if _formal_condition(finding.get(field, '')):
                    constraint('', finding[field], 'finding.' + field)
            for field in ['improvement', 'verification']:
                finding[field] = automatic_action(finding.get(field, ''), '', 'finding.' + field)
            if _formal_condition(finding.get('summary', '')):
                finding['summary'] = '原 SOP 的正式关闭条件尚未确认；当前无人流程不等待人工动作。'
    return result

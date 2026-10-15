"""Fixed atomic obligations and same-scope gates for SOP candidates."""
import copy
import hashlib
import re

PASS, FAIL, UNKNOWN, NA = '满足', '不满足', '未核查', '不适用'
SEMANTIC_REF_FIELDS = ('evidence_refs', 'mapping_refs', 'control_refs', 'statement_refs',
                       'counterexample_refs', 'contract_refs', 'action_refs', 'requirement_refs', 'design_refs', 'purpose_refs')
CLAIM_TYPES = {'fact', 'diagnosis', 'prediction', 'plan', 'actual_state'}
DESIGN_BASES = {'user_expectation', 'plan_expectation', 'delivered_assertion', 'missing_delivery', 'unknown'}
PURPOSE_KINDS = {'diagnostic_attempt', 'implementation', 'delivery_support', 'unrelated'}


def own_version_matches(kind, value, proof, evidence, code_versions):
    if not isinstance(value, str) or not value.strip() or not proof:
        return False
    if kind == 'external':
        return value not in code_versions and any(value in ref['quote'] for ref in proof)
    return any(value in {evidence[ref['evidence_id']].get('version_id'),
                         hashlib.sha256(evidence[ref['evidence_id']]['content'].encode()).hexdigest(),
                         'sha256:' + hashlib.sha256(evidence[ref['evidence_id']]['content'].encode()).hexdigest()}
               for ref in proof)


def _native_baseline(condition):
    contract = condition.get('contract', {})
    return (condition.get('condition_id', condition.get('id')) == 'TC01.C01'
            and contract.get('origin') == 'library_interpretation'
            and contract.get('version') == '1.9' and contract.get('audit_object') == 'task_delivery'
            and contract.get('rule_context', {}).get('id') == 'TC01')


def _baseline_version_gate(check, condition, task, package, evidence):
    if not _native_baseline(condition) or check['result'] != PASS:
        return
    from .sop_audit import _task_user_ids
    baseline = check.get('semantic_basis', {}).get('rule_baseline', {})
    own = evidence.get(baseline.get('evidence_id'), {})
    proof = baseline.get('evidence_refs', [])
    selection = baseline.get('selection_refs', [])
    kind, version = baseline.get('kind'), baseline.get('version', '')
    identity = baseline.get('identity', '')
    code_versions = {value for commit in package.get('commits', [])
                     for value in (commit.get('sha'), commit.get('parent')) if value}
    users = _task_user_ids(task)
    eligible = (own.get('kind') == 'user_requirement' and own.get('id') in users if kind == 'direct_requirement'
                else own.get('kind') == 'context' and bool(selection)
                and all(ref['evidence_id'] in users and evidence[ref['evidence_id']]['kind'] == 'user_requirement'
                        for ref in selection)
                and any(identity and identity in ref['quote'] for ref in selection))
    met = (kind in {'direct_requirement', 'local', 'external'} and eligible and bool(proof)
           and bool(identity.strip()) and bool(version)
           and all(ref['evidence_id'] == own.get('id') for ref in proof)
           and (identity in {own.get('id'), own.get('name'), own.get('path')}
                or any(identity in ref['quote'] for ref in proof))
           and own_version_matches(kind, version, proof, evidence, code_versions))
    check.setdefault('rule_baseline_candidate', {key: copy.deepcopy(check.get(key))
                     for key in ('result', 'reason', 'evidence_refs', 'semantic_basis')})
    identity_version_met = bool(met)
    met = identity_version_met and kind == 'direct_requirement'
    reason = ('已定位模型声明的原用户规则基准及其自身版本；不认证外部规范或项目历史生效。' if met else
              '已定位候选规则身份与自身版本，但选择引用的有效采用含义未独立核实；不能由规则名子串判满足。'
              if identity_version_met else
              '对象代码版本不能代替规则基准版本；尚无明确同一规则基准及其自身版本的有效引用。')
    gate(check, {'id': 'task_rule_baseline_version', 'met': bool(met),
                 'identity_version_met': identity_version_met,
                 'selection_semantics': 'original_user_requirement' if kind == 'direct_requirement' else 'unverified',
                 'reason': reason})
    if met:
        set_judgment(check, PASS, reason)
    else:
        set_judgment(check, UNKNOWN, reason, 'evidence_missing')


def _expanded_semantics(item):
    return item.get('semantic_schema_version') in {'1.6', '1.7', '1.8', '1.9'}


def statement_review_inventory(task, package):
    """Candidate original Agent sources, not a semantic claim extractor or authenticated record."""
    return [{'evidence_id': item['id'], 'kind': 'assistant', 'start_line': 1,
             'end_line': max(1, len(item.get('content', '').splitlines())),
             'version_id': item.get('version_id') or '', 'target_ids': list(item.get('target_ids') or []),
             'task_binding': 'explicit' if item.get('target_ids') else 'unscoped'}
            for item in package.get('evidence', []) if item.get('kind') == 'assistant'
            and (not item.get('target_ids') or task['id'] in item['target_ids'])]


def _basis_schema_missing(item, status, basis):
    name = item.get('semantic_gate')
    review_unknown = name == 'claim_scope' and item.get('semantic_schema_version') and status == UNKNOWN
    if (not name or status not in {PASS, FAIL} and not review_unknown
            or name == 'design_failure' and status != FAIL):
        return []
    if not isinstance(basis, dict):
        return ['semantic_basis']
    fields = {'audit_object': str, 'dimension': str, 'basis_type': str}
    expected = 'direct_counterexample' if name == 'design_failure' else name
    # A different proof kind is a semantic mismatch, not an invitation to fabricate a chain.
    if basis.get('basis_type') == expected:
        required = {
            'design_failure': {'evidence_refs': list, 'counterexample_refs': list},
            'design_alignment': {'alignment': str, 'requirement_refs': list, 'design_refs': list},
            'security_chain': {'security_chain': dict, 'mapping_refs': list, 'control_refs': list},
            'actual_claim': {'claim_kind': str, 'claimant': str, 'target_commit_ids': list, 'statement_refs': list},
            'evidence_alignment': {'evidence_refs': list},
            'authorization_contract': {'authorization': dict, 'contract_refs': list, 'action_refs': list},
            'environment_record': {'environment': dict, 'evidence_refs': list},
            'claim_scope': {'claims': list},
            'presence_substitution': {'statement_kind': str, 'statement_refs': list,
                                      'evidence_refs': list, 'relation': str},
            'purpose_alignment': {'purpose_kind': str, 'relation': str,
                                  'purpose_refs': list, 'requirement_refs': list},
        }
        fields.update(required.get(name, {}))
        if status == FAIL and name not in {'design_failure', 'design_alignment', 'claim_scope', 'presence_substitution'}:
            fields['counterexample_refs'] = list
        if name == 'claim_scope' and status == PASS:
            fields['coverage'] = str
            if item.get('semantic_schema_version'):
                fields.update(covered_source_ids=list, source_reviews=list)
        if name == 'design_alignment' and item.get('semantic_schema_version'):
            fields['design_basis'] = str
    if review_unknown:
        fields.update(covered_source_ids=list, source_reviews=list)
    missing = [key for key, kind in fields.items() if not isinstance(basis.get(key), kind)
               or kind is str and not basis[key].strip()]
    for key, names in {'security_chain': ('asset', 'threat', 'control', 'scenario'),
                       'authorization': ('subject', 'destination', 'action', 'boundary'),
                       'environment': ('platform', 'runtime', 'configuration')}.items():
        if key in fields and isinstance(basis.get(key), dict):
            missing.extend(key + '.' + field for field in names if not isinstance(basis[key].get(field), str)
                           or not basis[key][field].strip())
    if 'claims' in fields and isinstance(basis.get('claims'), list):
        for index, claim in enumerate(basis['claims']):
            if isinstance(claim, dict):
                missing.extend('claims[' + str(index) + '].' + key for key, kind in
                               {'statement_refs': list, 'source_refs': list, 'relation': str}.items()
                               if not isinstance(claim.get(key), kind))
                if item.get('semantic_schema_version') and not isinstance(claim.get('claim_type'), str):
                    missing.append('claims[' + str(index) + '].claim_type')
                if _expanded_semantics(item):
                    missing.extend('claims[' + str(index) + '].' + key for key, kind in
                                   {'proposition': str, 'comparison_type': str, 'comparison_scope': str,
                                    'observation_commit_ids': list}.items()
                                   if not isinstance(claim.get(key), kind) or kind is str and not claim[key].strip())
    return missing


def aggregate(values):
    if FAIL in values:
        return FAIL
    actual = [value for value in values if value != NA]
    if values and not actual:
        return NA
    return PASS if actual and all(value == PASS for value in actual) else UNKNOWN



def _original_trigger_parent_refs(condition, item, task, package, refs):
    # Only the original-error obligation describes the direct parent, not target behavior.
    contract = condition.get('contract', {})
    if (condition.get('id', condition.get('condition_id')) != 'FIX03.C03'
            or contract.get('origin') != 'library_interpretation'
            or contract.get('version') != '1.9'
            or contract.get('rule_context', {}).get('id') != 'FIX03'
            or item.get('id') != 'FIX03.C03.I01' or item.get('text') != '原错误触发'
            or item.get('judgment_dimension') != 'implementation'):
        return False
    targets = set(task.get('target_commit_ids', []))
    parents = {c['parent'] for c in package.get('commits', [])
               if c.get('sha') in targets and c.get('parent')}
    evidence = {e['id']: e for e in package['evidence']}
    code = [evidence.get(ref.get('evidence_id'), {}) for ref in refs if isinstance(ref, dict)
            and evidence.get(ref.get('evidence_id'), {}).get('kind') in {'source', 'commit_diff'}]
    return (bool(parents) and any(e.get('version_id') in parents for e in code)
            and all(e.get('version_id') in parents | targets for e in code))


def atomic_response(row, condition, task, package, *, strict_basis=False):
    from .sop_audit import _validate_refs, InsufficientEvidence, GAPS, HISTORY
    items = condition.get('contract', {}).get('items', [])
    if not items:
        return []
    checks = row.get('atomic_checks')
    if checks is None and len(items) == 1:
        checks = [{**row, 'id': item['id']} for item in items]
    if (not isinstance(checks, list) or len(checks) != len(items) or
            any(not isinstance(check, dict) for check in checks) or
            {check.get('id') for check in checks} != {item['id'] for item in items}):
        raise ValueError('多项条件必须逐项返回全部固定原子子项，不能遗漏、重复或自行豁免。')
    point_ids = {point['id'] for point in task.get('acceptance_points', [])}
    by_id = {}
    for check in checks:
        item = next(item for item in items if item['id'] == check['id'])
        status, reason = check.get('result'), check.get('reason')
        refs, ids = check.get('evidence_refs', []), check.get('acceptance_ids', [])
        if status not in {PASS, FAIL, UNKNOWN, NA} or not isinstance(reason, str) or not reason.strip():
            raise ValueError('原子子项缺少有效四态结果或理由。')
        if HISTORY.search(reason):
            raise ValueError('原子子项不能重新引入已排除的历史时间适用性核查。')
        if (not isinstance(ids, list) or any(not isinstance(pid, str) for pid in ids) or
                len(ids) != len(set(ids)) or not set(ids) <= point_ids):
            raise ValueError('原子子项验收点不属于当前固定任务。')
        historical_comparison = (item.get('semantic_gate') == 'claim_scope' and _expanded_semantics(item)
                                 or _original_trigger_parent_refs(condition, item, task, package, refs))
        insufficient = None
        try:
            _validate_refs(refs, task, package, definite=status != UNKNOWN and not historical_comparison)
        except InsufficientEvidence as exc:
            if condition.get('contract', {}).get('origin') != 'library_interpretation':
                raise
            insufficient = str(exc)
        gap = check.get('gap_type', '')
        if status == UNKNOWN and gap not in GAPS - {'analysis_failed'}:
            raise ValueError('原子子项未核查须说明具体原因。')
        if status != UNKNOWN and gap:
            raise ValueError('原子子项确定结论不能携带未核查原因。')
        by_id[check['id']] = {'id': check['id'], 'result': status, 'reason': reason,
                              'gap_type': gap, 'evidence_refs': copy.deepcopy(refs),
                              'acceptance_ids': list(ids), 'program_gates': []}
        if insufficient:
            by_id[check['id']].update(result=UNKNOWN, reason=insufficient, gap_type='evidence_missing',
                                    model_candidate={'result': status, 'reason': reason})
            status = UNKNOWN
        basis = check.get('semantic_basis')
        if strict_basis:
            missing = _basis_schema_missing(item, status, basis)
            if missing:
                guidance = ('请补齐逐源清单，可标uncertain、claims为空且不编造支持引文；未核查也不能省略来源复核。'
                            if item.get('semantic_schema_version') and item.get('semantic_gate') == 'claim_scope'
                            and status in {PASS, UNKNOWN} else
                            '请引用现有材料补齐semantic_basis，无依据则改为未核查，不编造证明。')
                raise ValueError(check['id'] + '核查响应缺少结构化字段：' + '、'.join(missing) +
                                 '；' + guidance)
        if basis is not None:
            if not isinstance(basis, dict):
                raise ValueError('semantic_basis必须为对象，不能用自然语言替代结构化判断依据。')
            if _native_baseline(condition) and 'rule_baseline' in basis:
                baseline = basis['rule_baseline']
                if (not isinstance(baseline, dict) or set(baseline) -
                        {'kind', 'identity', 'version', 'evidence_id', 'evidence_refs', 'selection_refs'}
                        or any(key in baseline and not isinstance(baseline[key], str)
                               for key in ('kind', 'identity', 'version', 'evidence_id'))):
                    raise ValueError('TC01.C01规则基准须声明kind、identity、自身version、evidence_id及evidence_refs；缺证据请未核查。')
                if 'evidence_refs' in baseline:
                    _validate_refs(baseline['evidence_refs'], task, package, definite=False)
                if 'selection_refs' in baseline:
                    _validate_refs(baseline['selection_refs'], task, package, definite=False)
            if 'alignment' in basis and (not isinstance(basis['alignment'], str)
                                        or basis['alignment'] not in {'supported', 'contradicts', 'unknown'}):
                raise ValueError('design_alignment.alignment必须为supported、contradicts或unknown。')
            if 'design_basis' in basis and (not isinstance(basis['design_basis'], str)
                                             or basis['design_basis'] not in DESIGN_BASES):
                raise ValueError('design_basis必须区分user_expectation、plan_expectation、delivered_assertion、missing_delivery或unknown。')
            if (strict_basis and item.get('semantic_gate') == 'design_alignment'
                    and (status == PASS and basis.get('alignment') == 'contradicts'
                         or status == FAIL and basis.get('alignment') == 'supported')):
                raise ValueError(check['id'] + '的result与design_alignment.alignment相互矛盾；'
                                 '请对照冻结要求与设计引用重判，无依据则未核查。')
            for key in SEMANTIC_REF_FIELDS:
                if key in basis:
                    _validate_refs(basis[key], task, package, definite=False)
            if 'covered_source_ids' in basis and (not isinstance(basis['covered_source_ids'], list)
                    or any(not isinstance(eid, str) for eid in basis['covered_source_ids'])
                    or len(basis['covered_source_ids']) != len(set(basis['covered_source_ids']))):
                raise ValueError('covered_source_ids必须为不重复的原Agent来源ID列表。')
            if 'source_reviews' in basis:
                reviews = basis['source_reviews']
                if (not isinstance(reviews, list) or any(not isinstance(review, dict)
                        or not isinstance(review.get('evidence_id'), str)
                        or not isinstance(review.get('classification'), str)
                        or review['classification'] not in {'claims', 'no_claim', 'uncertain'} for review in reviews)
                        or len(reviews) != len({review['evidence_id'] for review in reviews})):
                    raise ValueError('source_reviews须逐一列出不重复来源ID及claims、no_claim或uncertain分类。')
            if (strict_basis and item.get('semantic_schema_version')
                    and item.get('semantic_gate') == 'claim_scope' and status in {PASS, UNKNOWN}):
                expected_sources = {source['evidence_id'] for source in statement_review_inventory(task, package)}
                covered = set(basis.get('covered_source_ids', []))
                reviewed = {review['evidence_id'] for review in basis.get('source_reviews', [])}
                if covered != expected_sources or reviewed != expected_sources:
                    missing = sorted(expected_sources - (covered & reviewed))
                    extra = sorted((covered | reviewed) - expected_sources)
                    raise ValueError(check['id'] + '须逐源覆盖原Agent陈述清单；遗漏：' + ','.join(missing) +
                                     '；清单外：' + ','.join(extra) + '。可标uncertain而不编造主张依据。')
            if item.get('semantic_gate') == 'presence_substitution':
                if 'statement_kind' in basis and (not isinstance(basis['statement_kind'], str)
                        or basis['statement_kind'] not in {'agent_statement', 'acceptance_decision'}):
                    raise ValueError('presence_substitution.statement_kind须为agent_statement或acceptance_decision。')
                if 'relation' in basis and (not isinstance(basis['relation'], str)
                        or basis['relation'] not in {'existence_as_completion', 'behavior_verified', 'unknown'}):
                    raise ValueError('presence_substitution.relation须为existence_as_completion、behavior_verified或unknown。')
            if item.get('semantic_gate') == 'purpose_alignment':
                if 'purpose_kind' in basis and (not isinstance(basis['purpose_kind'], str)
                                               or basis['purpose_kind'] not in PURPOSE_KINDS):
                    raise ValueError('purpose_kind须区分diagnostic_attempt、implementation、delivery_support或unrelated。')
                if 'relation' in basis and (not isinstance(basis['relation'], str)
                                            or basis['relation'] not in {'supported', 'contradicts', 'unknown'}):
                    raise ValueError('purpose_alignment.relation须为supported、contradicts或unknown。')
            claims = basis.get('claims', [])
            if not isinstance(claims, list) or any(not isinstance(claim, dict) for claim in claims):
                raise ValueError('claims必须逐项列出主张与原始来源。')
            for claim in claims:
                if 'claim_type' in claim and (not isinstance(claim['claim_type'], str)
                                                or claim['claim_type'] not in CLAIM_TYPES):
                    raise ValueError('claim_type须为fact、diagnosis、prediction、plan或actual_state。')
                if 'relation' in claim and (not isinstance(claim['relation'], str)
                                            or claim['relation'] not in {'supported', 'exceeds_source', 'uncertain'}):
                    raise ValueError('claim_scope.relation必须为supported、exceeds_source或uncertain。')
                if _expanded_semantics(item):
                    if 'comparison_type' in claim and (not isinstance(claim['comparison_type'], str)
                                                        or claim['comparison_type'] not in CLAIM_TYPES):
                        raise ValueError('comparison_type与claim_type使用相同的事实、诊断、预测、计划、实际状态枚举。')
                    if 'comparison_scope' in claim and (not isinstance(claim['comparison_scope'], str)
                            or claim['comparison_scope'] not in {'same_property', 'different_property', 'unknown'}):
                        raise ValueError('comparison_scope须为same_property、different_property或unknown。')
                    if 'observation_commit_ids' in claim and (not isinstance(claim['observation_commit_ids'], list)
                            or any(not isinstance(oid, str) for oid in claim['observation_commit_ids'])
                            or len(claim['observation_commit_ids']) != len(set(claim['observation_commit_ids']))):
                        raise ValueError('observation_commit_ids须为不重复的被比较源码版本ID列表。')
                    proposition = claim.get('proposition')
                    if proposition is not None and (not isinstance(proposition, str) or not proposition.strip()
                            or not isinstance(claim.get('statement_refs'), list)
                            or not any(proposition in ref.get('quote', '') for ref in claim['statement_refs']
                                       if isinstance(ref, dict) and isinstance(ref.get('quote'), str))):
                        raise ValueError('proposition须为statement_refs中逐字连续的单一命题；不得改写语气或扩大主张。')
                _validate_refs(claim.get('statement_refs', []), task, package, definite=False)
                _validate_refs(claim.get('source_refs', []), task, package, definite=False)
            if strict_basis and _expanded_semantics(item) and item.get('semantic_gate') == 'claim_scope':
                claimed_sources = {ref['evidence_id'] for claim in claims for ref in claim.get('statement_refs', [])}
                for review in basis.get('source_reviews', []):
                    if review['classification'] == 'claims' and review['evidence_id'] not in claimed_sources:
                        raise ValueError('source_reviews中claims来源须有对应claim比较链；未核时标uncertain：' + review['evidence_id'])
                    if review['classification'] == 'no_claim' and (not isinstance(review.get('reason'), str)
                                                                  or not review['reason'].strip()):
                        raise ValueError('source_reviews中no_claim须说明已复核而无可审主张的具体reason：' + review['evidence_id'])
            by_id[check['id']]['semantic_basis'] = copy.deepcopy(basis)
            proof_refs = [ref for key in SEMANTIC_REF_FIELDS for ref in basis.get(key, [])]
            proof_refs += [ref for claim in claims for key in ('statement_refs', 'source_refs')
                           for ref in claim.get(key, [])]
            for ref in proof_refs:
                if ref not in by_id[check['id']]['evidence_refs']:
                    by_id[check['id']]['evidence_refs'].append(copy.deepcopy(ref))
    return [{**by_id[item['id']], 'text': item['text']} for item in items]


def set_judgment(row, status, reason, gap=''):
    if row['result'] != status:
        row.setdefault('model_result', row['result'])
        row.setdefault('model_reason', row['reason'])
    row.update(result=status, reason=reason, gap_type=gap if status == UNKNOWN else '')


def gate(row, value):
    gates = row.setdefault('program_gates', [])
    gates[:] = [item for item in gates if item['id'] != value['id']]
    gates.append(value)


def documentation_ref(item):
    path = (item.get('path') or item.get('name', '')).lower().replace('\\', '/')
    basename = path.rsplit('/', 1)[-1]
    return (item.get('kind') in {'context', 'user_requirement'} or
            item.get('kind') == 'source' and
            (basename in {'pyproject.toml', 'pytest.ini', 'tox.ini', 'setup.cfg', 'setup.py',
                          'package.json', 'dockerfile', 'makefile', 'pipfile', 'environment.yml'} or
             basename.startswith(('requirements', 'readme')) or
             path.startswith(('.github/workflows/', 'docs/')) or basename.endswith(('.md', '.yaml', '.yml'))))


def process_scope_exempt(check, item, evidence):
    actions = ('复检', '复核', '重开', '关闭', '暂停', '取消', '轮次', '旧失败', '历史失败', '新反例')
    relevant = [action for action in actions if action in item['text']]
    if item.get('trigger', {}).get('mode') != 'conditional' or not relevant:
        return False
    if '重开' in relevant:
        required = {'重开'}
    elif '复检' in relevant:
        required = {'复检'} | ({'关闭'} if '关闭' in relevant else set())
    elif '复核' in relevant:
        required = {'复核'} | ({'关闭'} if '关闭' in relevant else set())
    else:
        required = set(relevant)
    excluded = set()
    for ref in check.get('evidence_refs', []):
        if evidence[ref['evidence_id']]['kind'] != 'user_requirement':
            continue
        quote = ref['quote']
        for match in re.finditer(r'(?:不(?:执行|进行|判断|宣称|涉及|包含|启动|需要|要求|做)|无需)[^。；，,;\n]{0,50}', quote):
            if any(word in quote[max(0, match.start() - 3):match.start()] for word in ('不是', '并非')):
                continue
            statement = re.split(r'但|而|却', match.group())[0]
            excluded.update(action for action in required if action in statement)
    return required <= excluded


def _semantic_gate(check, item, task, evidence, commits=()):
    """Check proof shape and scope, never infer semantic entailment from keywords."""
    name = item.get('semantic_gate')
    if not name or check['result'] not in {PASS, FAIL} or name == 'design_failure' and check['result'] != FAIL:
        return
    basis = check.get('semantic_basis', {})
    classified_sources = bool(item.get('semantic_schema_version'))
    target = set(task.get('target_commit_ids', []))
    matching_scope = (basis.get('audit_object') == item.get('audit_object') and
                      basis.get('dimension') == item.get('judgment_dimension'))

    def refs(key, allowed, source=None, versions=None):
        values = (basis if source is None else source).get(key, [])
        return isinstance(values, list) and bool(values) and all(isinstance(ref, dict)
                    and evidence.get(ref.get('evidence_id'), {}).get('kind') in allowed
                    and (evidence[ref['evidence_id']]['kind'] not in {'source', 'commit_diff'}
                         or evidence[ref['evidence_id']].get('version_id') in (target if versions is None else versions)) for ref in values)

    def fields(key, names):
        value = basis.get(key, {})
        return isinstance(value, dict) and all(isinstance(value.get(field), str) and value[field].strip()
                                               for field in names)

    documents = {'user_requirement', 'context'}
    code = {'source', 'commit_diff'}
    declarations = {'assistant', 'context', 'run_record', 'test_log'}
    counterexamples = code | documents | {'run_record', 'test_log'}
    met = matching_scope
    if name == 'design_failure':
        design_refs, contrary_refs = basis.get('evidence_refs', []), basis.get('counterexample_refs', [])
        met &= (basis.get('basis_type') == 'direct_counterexample' and refs('evidence_refs', documents)
                and refs('counterexample_refs', documents)
                and {(ref['evidence_id'], ref['quote']) for ref in contrary_refs}
                    != {(ref['evidence_id'], ref['quote']) for ref in design_refs})
        reason = '设计失败须引用同范围需求/计划中的直接矛盾；缺交付测试、断言或运行记录只能保留设计证据缺口。'
    elif name == 'design_alignment':
        relation = basis.get('alignment')
        active_requirements = {ref['evidence_id'] for ref in task.get('requirement_refs', [])}
        active_requirements.update(ref['evidence_id'] for point in task.get('acceptance_points', [])
                                   for ref in point.get('requirement_refs', []))
        met &= (basis.get('basis_type') == name and refs('requirement_refs', {'user_requirement'})
                and all(ref['evidence_id'] in active_requirements for ref in basis.get('requirement_refs', []))
                and refs('design_refs', documents)
                and (check['result'] == PASS and relation == 'supported'
                     or check['result'] == FAIL and relation == 'contradicts'
                     and {(ref['evidence_id'], ref['quote']) for ref in basis.get('requirement_refs', [])}
                         != {(ref['evidence_id'], ref['quote']) for ref in basis.get('design_refs', [])}))
        if classified_sources:
            origin = basis.get('design_basis')
            met &= (origin in {'user_expectation', 'plan_expectation'}
                    and (origin != 'user_expectation' or refs('design_refs', {'user_requirement'}))
                    and (origin != 'plan_expectation' or any(
                        evidence[ref['evidence_id']]['kind'] == 'context' for ref in basis.get('design_refs', []))))
        reason = ('设计断言须与冻结用户输入/期望逐项对照且结论一致；可判定但违背原要求的成功标准不算满足；'
                  '用户明确输入/期望本身可构成设计，无需强加独立计划文件。')
    elif name == 'security_chain':
        met &= (basis.get('basis_type') == name and fields('security_chain', ('asset', 'threat', 'control', 'scenario'))
                and refs('mapping_refs', documents) and refs('control_refs', code))
        reason = '安全条件须先有同对象的资产、威胁、控制与场景映射；普通功能反例不能自动传播为安全失败。'
    elif name == 'actual_claim':
        met &= (basis.get('basis_type') == name and basis.get('claim_kind') == 'actual_state'
                and isinstance(basis.get('claimant'), str) and bool(basis['claimant'].strip())
                and refs('statement_refs', declarations)
                and isinstance(basis.get('target_commit_ids'), list)
                and all(isinstance(value, str) for value in basis['target_commit_ids'])
                and set(basis['target_commit_ids']) == target and bool(target)
                and all(evidence[ref['evidence_id']].get('version_id') in target
                        or any(oid in ref['quote'] for oid in target) for ref in basis.get('statement_refs', [])))
        if classified_sources:
            met &= refs('statement_refs', {'assistant'})
        reason = '状态真实性须定位原Agent对该目标版本的实际声明；用户期望、计划或验收条件不能当已完成声明。'
    elif name == 'evidence_alignment':
        met &= basis.get('basis_type') == name and refs('evidence_refs', counterexamples)
        reason = '证据适用性须有该证据本身的比对依据；缺截图或普通功能失败不能证明证据对象错误。'
    elif name == 'authorization_contract':
        met &= (basis.get('basis_type') == name and fields('authorization', ('subject', 'destination', 'action', 'boundary'))
                and refs('contract_refs', documents) and refs('action_refs', code | {'context'}))
        reason = '授权结论须定位主体、目的地、动作及有效边界，并与实际动作比较；未要求该实现不等于明示禁止或已发生越权。'
    elif name == 'environment_record':
        met &= (basis.get('basis_type') == name and fields('environment', ('platform', 'runtime', 'configuration'))
                and refs('evidence_refs', documents | code)
                and any(documentation_ref(evidence[ref['evidence_id']]) for ref in basis.get('evidence_refs', [])))
        reason = '平台身份须有运行平台、运行时和配置记录；功能场景、服务名称或源码版本不能代替运行前提。'
    elif name == 'claim_scope':
        claims = basis.get('claims', [])
        inventory_ids = {source['evidence_id'] for source in statement_review_inventory(task, {'evidence': list(evidence.values())})}
        reviews = {review['evidence_id']: review['classification'] for review in basis.get('source_reviews', [])}
        statements = {'assistant'} if classified_sources else declarations
        sources = documents | code | ({'tool', 'run_record', 'test_log'} if classified_sources else set())
        related = set(task.get('commit_ids', [])) | target
        related.update(commit['parent'] for commit in commits if commit['sha'] in related and commit.get('parent'))

        def valid_claim(claim):
            versions = target
            if _expanded_semantics(item):
                ids = claim.get('observation_commit_ids')
                if (not isinstance(ids, list) or any(not isinstance(oid, str) for oid in ids)
                        or not set(ids) <= related or claim.get('comparison_type') != claim.get('claim_type')
                        or claim.get('comparison_scope') != 'same_property'):
                    return False
                proposition = claim.get('proposition')
                if (not isinstance(proposition, str) or not proposition.strip()
                        or not any(proposition in ref['quote'] for ref in claim.get('statement_refs', []))):
                    return False
                versions = set(ids)
                if claim.get('claim_type') == 'actual_state':
                    if (versions != target or not target or not all(
                            evidence[ref['evidence_id']].get('version_id') in target
                            or any(oid in ref['quote'] for oid in target) for ref in claim.get('statement_refs', []))):
                        return False
            return (refs('statement_refs', statements, claim) and refs('source_refs', sources, claim, versions)
                    and (not classified_sources or claim.get('claim_type') in CLAIM_TYPES)
                    and claim.get('relation') in {'supported', 'exceeds_source', 'uncertain'})

        valid = [claim for claim in claims if valid_claim(claim)]
        met &= basis.get('basis_type') == name and (bool(claims) or classified_sources and bool(inventory_ids))
        if check['result'] == PASS:
            met &= (basis.get('coverage') == 'all_in_scope' and len(valid) == len(claims)
                    and all(claim.get('relation') == 'supported' for claim in claims))
            if classified_sources:
                claimed = {ref['evidence_id'] for claim in claims for ref in claim.get('statement_refs', [])}
                met &= (set(basis.get('covered_source_ids', [])) == inventory_ids == set(reviews)
                        and set(reviews.values()) <= {'claims', 'no_claim'}
                        and claimed == {eid for eid, classification in reviews.items() if classification == 'claims'})
                if _expanded_semantics(item):
                    met &= all(review['classification'] != 'no_claim' or isinstance(review.get('reason'), str)
                               and bool(review['reason'].strip()) for review in basis.get('source_reviews', []))
        else:
            met &= any(claim.get('relation') == 'exceeds_source' for claim in valid)
        reason = '主张范围须逐项定位原Agent声明、原始来源和推论关系；有引用或审计器自述不能证明所有主张均未超出资料。'
        if classified_sources:
            reason += '一般诊断不要求字面SHA；满足需逐源复核陈述清单，不能只核计划便覆盖遗漏诊断；覆盖声明仍非语义穷尽证明。'
        if _expanded_semantics(item):
            reason += '逐字命题须保留原语气，同属性及所指版本比较；计划不能以完成维度反驳，实际完成声明仍需自身目标绑定。'
    elif name == 'purpose_alignment':
        active = {ref['evidence_id'] for ref in task.get('requirement_refs', [])}
        active.update(ref['evidence_id'] for point in task.get('acceptance_points', [])
                      for ref in point.get('requirement_refs', []))
        met &= (basis.get('basis_type') == name and basis.get('purpose_kind') in PURPOSE_KINDS
                and refs('purpose_refs', documents | {'assistant'}) and refs('requirement_refs', {'user_requirement'})
                and all(ref['evidence_id'] in active for ref in basis.get('requirement_refs', []))
                and (check['result'] == PASS and basis.get('relation') == 'supported'
                     and basis.get('purpose_kind') != 'unrelated'
                     or check['result'] == FAIL and basis.get('relation') == 'contradicts'
                     and refs('counterexample_refs', documents)))
        reason = '反向目的须对照需求/有效决定与诊断、实现或交付支持的实际目的；尝试无效或功能未修复不证明没有目的。'
    elif name == 'presence_substitution':
        statement_kinds = {'assistant'} if basis.get('statement_kind') == 'agent_statement' else {'context'}
        met &= (basis.get('basis_type') == name
                and basis.get('statement_kind') in {'agent_statement', 'acceptance_decision'}
                and refs('statement_refs', statement_kinds) and refs('evidence_refs', documents | code)
                and (check['result'] == FAIL and basis.get('relation') == 'existence_as_completion'
                     or check['result'] == PASS and basis.get('relation') == 'behavior_verified'))
        reason = '以产物存在代替完成须定位原Agent声明或有效验收决定及其依据；缺测试或脚本未覆盖功能不能证明发生该行为。'
    else:
        return
    if check['result'] == FAIL and name not in {'design_failure', 'design_alignment', 'claim_scope', 'presence_substitution'}:
        met &= refs('counterexample_refs', counterexamples)
    gate(check, {'id': 'semantic_scope_' + name, 'met': bool(met),
                 'audit_object': item.get('audit_object'), 'dimension': item.get('judgment_dimension'),
                 'reason': '结构化依据同对象、同判断层且引用可定位；内容关联仍需语义复核。' if met else reason})
    if not met:
        set_judgment(check, UNKNOWN, reason, 'evidence_missing' if matching_scope else 'applicability_uncertain')


def apply_atomic_gates(row, task, package):
    from .sop_audit import MISSING
    contract = row.get('contract', {})
    items = {item['id']: item for item in contract.get('items', [])}
    evidence = {item['id']: item for item in package['evidence']}
    for check in row.get('atomic_checks', []):
        item = items[check['id']]
        if (check.get('assessment_scope') == 'deferred'
                and check['id'] in row.get('review_scope', {}).get('deferred_item_ids', [])):
            continue
        policy = item.get('proof_policy', contract.get('proof_policy', 'semantic'))
        if policy == 'human':
            reason = '原子子项要求独立人员动作，当前无人流程不能确认；保留规则差异，不生成签署或人工待办。'
            gate(check, {'id': 'human_condition_unsupported', 'met': False, 'reason': reason})
            set_judgment(check, UNKNOWN, reason, 'rule_scope_difference')
            continue
        if policy == 'closure_prerequisites':
            continue  # Rebuilt from same-task, same-version program checks after all rows merge.
        if policy == 'process_history':
            if check['result'] == NA and not MISSING.search(check['reason']) and process_scope_exempt(check, item, evidence):
                gate(check, {'id': 'explicit_process_scope', 'met': True,
                             'reason': '用户原话明确排除本子项对应的本轮动作；不外推历史事件不存在。'})
                continue
            reason = '该子项要求已发生的流程事件；当前未接入可校验的流程事件记录，源码、需求和普通上传声明不能代替。'
            gate(check, {'id': 'process_event_proof', 'met': False, 'reason': reason})
            set_judgment(check, UNKNOWN, reason, 'automatic_check_unsupported')
            continue
        if check['result'] == NA and item.get('trigger', {}).get('mode') == 'always':
            reason = '此子项按固定契约必查，不能由纯函数、小任务或缺材料豁免。'
            gate(check, {'id': 'mandatory_atomic_scope', 'met': False, 'reason': reason})
            set_judgment(check, UNKNOWN, reason, 'applicability_uncertain')
        if check['result'] == NA:
            if MISSING.search(check['reason']):
                set_judgment(check, UNKNOWN, '缺材料不能证明该子项场景不适用。', 'applicability_uncertain')
            continue
        if row.get('kind') == 'execution':
            # Signed assertion binding is checked by the existing execution gate, not upload kind.
            continue
        if check['result'] not in {PASS, FAIL}:
            continue
        _baseline_version_gate(check, row, task, package, evidence)
        _semantic_gate(check, item, task, evidence, package.get('commits', []))
        if check['result'] not in {PASS, FAIL}:
            continue
        refs = [evidence[ref['evidence_id']] for ref in check['evidence_refs']]
        allowed = set(item.get('allowed_evidence_kinds', contract.get('allowed_evidence_kinds', [])))
        if allowed and not any(ref['kind'] in allowed for ref in refs):
            reason = '引用材料类型不能证明本子项；需要：' + '、'.join(sorted(allowed)) + '。'
            gate(check, {'id': 'atomic_evidence_type', 'met': False, 'reason': reason})
            set_judgment(check, UNKNOWN, reason, 'evidence_missing')
        elif policy in {'environment', 'evidence_plan'} and not any(documentation_ref(ref) for ref in refs):
            reason = '普通测试函数不能单独证明环境前提或证据采集计划；须引用明确配置或计划记录。'
            gate(check, {'id': 'explicit_documentation', 'met': False, 'reason': reason})
            set_judgment(check, UNKNOWN, reason, 'evidence_missing')
    checks = row.get('atomic_checks', [])
    if checks:
        status = aggregate([check['result'] for check in checks])
        conflict = row['result'] == FAIL and status in {PASS, NA}
        if conflict:
            status = UNKNOWN
            gate(row, {'id': 'parent_atomic_conflict', 'met': False,
                       'reason': '父模型失败与全部子项结论矛盾，不能把任一模型说法当独立事实。'})
        gate(row, {'id': 'all_required_atomic_checks', 'met': status == PASS, 'result': status,
                   'item_ids': [check['id'] for check in checks],
                   'reason': '全部固定子项按四态汇总；部分满足或缺证据不能代替全部满足。'})
        if status != row['result'] or contract.get('origin') == 'library_interpretation':
            details = [check['text'] + '：' + check['reason'] for check in checks if check['result'] == status]
            if conflict:
                details = ['父模型失败与全部子项满足或不适用相互矛盾，需要明确同范围证据。']
            gap = next((check['gap_type'] for check in checks if check['result'] == UNKNOWN), 'evidence_missing')
            if row['reason'] != '；'.join(details):
                row.setdefault('model_reason', row['reason'])
            set_judgment(row, status, '；'.join(details), gap)


def _change_purpose_consistency(row, task, result):
    from .sop_contracts import SPECIAL, ensure_contracts
    contract = row.get('contract', {})
    target = set(task.get('target_commit_ids', []))
    if (row.get('condition_id') != 'FIX02.C01' or row.get('rule_id') != 'FIX02'
            or row.get('document_id') != 'code-fix-0.1'
            or contract.get('origin') != 'library_interpretation'
            or row.get('text') != SPECIAL['FIX02.C01'][1]
            or row.get('task_id') != task['id'] or not target
            or set(row.get('target_commit_ids', [])) != target):
        return
    native = ensure_contracts({'rules': [rule for rule in result.get('sop_rules', [])
        if rule.get('id') == 'FIX02' and rule.get('document_id') == 'code-fix-0.1'
        and rule.get('version') == '0.1' and rule.get('source_kind') != 'uploaded_rule']})
    conditions = [condition for rule in native['rules'] for condition in rule.get('conditions', [])
                  if condition.get('id') == 'FIX02.C01']
    if (len(conditions) != 1 or row.get('source_ref') != conditions[0].get('source_ref')
            or contract != conditions[0].get('contract')):
        return
    unresolved = sorted({change['id'] for change in result.get('change_coverage', [])
        if change.get('commit_id') in target
        and (not change.get('task_ids') or task['id'] in change['task_ids'])
        and (change.get('purpose_covered') is False or change.get('unparsed') is True)})
    check = next((check for check in row.get('atomic_checks', [])
                  if check['id'] == 'FIX02.C01.I02'), None)
    if (not unresolved or not check or check['result'] != PASS
            and not (check['result'] == UNKNOWN and any(proof['id'] == 'same_target_change_purpose_consistency'
                                                       for proof in check.get('program_gates', [])))):
        return
    reason = '目标版本实质变更的任务依据尚未全部核定：' + '、'.join(unresolved) + '；未关联或未解析不能证明越界，也不能判全部有依据。'
    if check['result'] == PASS:
        check.setdefault('model_candidate', {'result': check['result'], 'reason': check['reason']})
    gate(check, {'id': 'same_target_change_purpose_consistency', 'met': False, 'result': UNKNOWN,
                 'change_ids': unresolved, 'target_commit_ids': sorted(target), 'reason': reason})
    set_judgment(check, UNKNOWN, reason, 'evidence_missing')
    checks = row['atomic_checks']
    atomic_status = aggregate([check['result'] for check in checks])
    gate(row, {'id': 'all_required_atomic_checks', 'met': atomic_status == PASS,
               'result': atomic_status, 'item_ids': [check['id'] for check in checks],
               'reason': '全部固定子项按四态汇总；反向依据未核定不抹去已确认失败。'})
    status = aggregate([row['result'], atomic_status])
    if status != row['result']:
        details = '；'.join(check['text'] + '：' + check['reason'] for check in checks
                          if check['result'] == status)
        set_judgment(row, status, details, 'evidence_missing')


def acceptance_consistency(row, task, result):
    contract = row.get('contract', {})
    dimension = contract.get('acceptance_dimension')
    if dimension not in {'implementation', 'test_design'}:
        return
    points = task.get('acceptance_points', [])
    if contract.get('acceptance_scope') in {'all_behavior_and_test_delivery', 'all_design_sufficient_only'}:
        points = [point for point in points if point.get('kind', 'behavior') != 'scope_constraint']
    required = {point['id'] for point in points}
    field = 'result' if dimension == 'implementation' else 'test_design_result'
    checks = {check['acceptance_id']: check for check in result.get('acceptance_checks', [])
              if check['task_id'] == task['id']}
    values = {pid: checks.get(pid, {}).get(field, UNKNOWN) for pid in sorted(required)}
    status = aggregate(list(values.values())) if required else UNKNOWN
    if contract.get('acceptance_scope') == 'all_design_sufficient_only' and status == FAIL:
        # A missing positive-case assertion does not prove a missing critical counterexample.
        status = UNKNOWN
    gate(row, {'id': 'same_scope_acceptance_consistency', 'met': status == PASS, 'result': status,
               'dimension': dimension, 'acceptance_ids': sorted(required), 'results': values,
               'reason': '程序取同任务、同判断维度的全部必要验收点，不能由模型选择已通过子集。'})
    if status == FAIL:
        failed = [pid for pid, value in values.items() if value == FAIL]
        for pid in failed:
            for name in ('change_refs', 'assertion_refs', 'no_change_refs'):
                for ref in checks[pid].get(name, []):
                    if ref not in row['evidence_refs']:
                        row['evidence_refs'].append(copy.deepcopy(ref))
        set_judgment(row, FAIL, '同范围必需验收已确认不满足：' + '、'.join(failed) +
                     '；记录缺口或其它验收通过不能豁免该项。')
    elif status == UNKNOWN and row['result'] in {PASS, NA}:
        set_judgment(row, UNKNOWN, '同范围必要验收尚未全部证实，不能判本条件满足。', 'evidence_missing')
    _change_purpose_consistency(row, task, result)


def closure_prerequisites(row, task, result):
    """A known unmet prerequisite blocks closure without claiming a recheck was run."""
    contract = row.get('contract', {})
    required = contract.get('closure_required_rules', [])
    target = set(task.get('target_commit_ids', []))
    if (not required or contract.get('origin') != 'library_interpretation'
            or row.get('document_id') != 'code-fix-0.1' or row.get('rule_id') != 'FIX06'
            or row.get('condition_id') not in {'FIX06.C01', 'FIX06.C04'}
            or not target or set(row.get('target_commit_ids', [])) != target):
        return
    items = contract.get('items', [])
    existing = {check['id']: check for check in row.get('atomic_checks', [])}
    checks = []
    for item in items:
        check = existing.get(item['id']) or {
            'id': item['id'], 'text': item['text'], 'result': UNKNOWN,
            'reason': '本子项尚无可核查的流程或人员动作证据。',
            'gap_type': 'rule_scope_difference' if item['proof_policy'] == 'human' else 'automatic_check_unsupported',
            'evidence_refs': [], 'acceptance_ids': [], 'program_gates': []}
        if item['proof_policy'] == 'closure_prerequisites':
            candidates = [check for check in result.get('checks', [])
                          if check.get('task_id') == task['id'] and check.get('rule_id') in required
                          and set(check.get('target_commit_ids', [])) == target]
            values = {rid: UNKNOWN for rid in required}
            for rid in required:
                matched = [check for check in candidates if check['rule_id'] == rid]
                if len(matched) == 1:
                    values[rid] = matched[0].get('automated_result', UNKNOWN)
            status = aggregate(list(values.values()))
            failed = [rid for rid, value in values.items() if value == FAIL]
            reason = ('同任务、同目标版本当前必验项已确认不满足：' + '、'.join(failed) +
                      '；其余未知子项继续保留，不能抵消已知失败。' if failed else
                      '同任务、同目标版本当前必验项均满足。' if status == PASS else
                      '当前必验清单尚未全部证实；缺证据不能推定复检执行失败。')
            check['evidence_refs'] = [copy.deepcopy(ref) for candidate in candidates
                                     if candidate['rule_id'] in failed
                                     for ref in candidate.get('evidence_refs', [])]
            check.update(result=status, reason=reason, gap_type='evidence_missing' if status == UNKNOWN else '')
            gate(check, {'id': 'same_target_closure_prerequisites', 'met': status == PASS,
                         'result': status, 'target_commit_ids': sorted(target), 'results': values,
                         'reason': reason})
        checks.append(check)
    row['atomic_checks'] = checks
    status = aggregate([check['result'] for check in checks])
    reason = '；'.join(check['text'] + '：' + check['reason'] for check in checks if check['result'] == status)
    row.update(result=status, reason=reason, gap_type=next((check['gap_type'] for check in checks
                    if check['result'] == UNKNOWN), 'evidence_missing') if status == UNKNOWN else '')
    gate(row, {'id': 'all_required_atomic_checks', 'met': status == PASS, 'result': status,
               'item_ids': [check['id'] for check in checks],
               'reason': '必需子项失败优先；未核查明细单独保留，不冒充已执行或人工复核。'})


def sync_execution_checks(row):
    dimension = row.get('contract', {}).get('execution_dimension')
    if dimension and dimension != 'behavior':
        return
    if row.get('kind') != 'execution' or row['result'] not in {UNKNOWN, FAIL}:
        return
    checks = row.get('atomic_checks', [])
    verified_row_failure = any(gate.get('id') == 'trusted_target_assertion_execution'
                               and gate.get('result') == FAIL and gate.get('evidence_ids')
                               for gate in row.get('program_gates', []))
    for check in checks:
        if check['result'] == NA:
            continue
        verified_item_failure = any(gate.get('id') == 'trusted_target_assertion_execution'
                                    and gate.get('result') == FAIL and gate.get('evidence_ids')
                                    for gate in check.get('program_gates', []))
        status = FAIL if verified_item_failure or (row['result'] == FAIL and len(checks) == 1
                                                  and verified_row_failure) else UNKNOWN
        reason = check['reason'] if verified_item_failure else row['reason']
        gate(check, {'id': 'condition_execution_binding', 'met': False, 'result': status,
                     'reason': reason})
        set_judgment(check, status, reason, row.get('gap_type') or 'evidence_missing')
    failed = [check for check in checks if check['result'] == FAIL]
    if failed and row['result'] != FAIL:
        reason = '已验证的必需运行子项不满足：' + '；'.join(check['reason'] for check in failed)
        set_judgment(row, FAIL, reason)

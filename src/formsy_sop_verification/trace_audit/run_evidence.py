"""Verify runner attestations and their uploaded artifacts; never execute a run."""
import hashlib
import hmac
import json
import posixpath
import re
from pathlib import Path


def external_test_path(path):
    normalized = posixpath.normpath('/' + str(path).replace('\\', '/'))
    return 'audit-tests' in normalized.split('/')


def execution_review_candidates(package, task):
    """Offer verified target runs and exact recorded assertion locations, never infer relevance."""
    evidence = {item['id']: item for item in package.get('evidence', [])}
    candidates = []
    for run in package.get('run_verification', []):
        if not run.get('verified') or run.get('commit_sha') not in task.get('target_commit_ids', []):
            continue
        bound = [run.get('evidence_id'), run.get('log_evidence_id')]
        bound += run.get('source_evidence_ids', []) + run.get('test_evidence_ids', [])
        if any(eid not in evidence or evidence[eid].get('version_id') != run['commit_sha']
               or evidence[eid].get('target_ids') and task['id'] not in evidence[eid]['target_ids']
               for eid in bound):
            continue
        choices = []
        for assertion in run.get('assertion_results', []):
            for eid in run.get('test_evidence_ids', []):
                item = evidence[eid]
                lines = item.get('content', '').splitlines()
                line = assertion.get('line', 0)
                if (item.get('path', item.get('name')) == assertion.get('path')
                        and 1 <= line <= len(lines)):
                    choices.append({'outcome': assertion['outcome'], 'ref': {
                        'evidence_id': eid, 'start_line': line, 'end_line': line,
                        'quote': lines[line - 1]}})
        candidates.append({'run_evidence_id': run['evidence_id'], 'commit_sha': run['commit_sha'],
                           'test_origin': run.get('test_origin', 'repository'),
                           'outcome': run.get('outcome'), 'assertion_choices': choices})
    return candidates


def _digest(value):
    try:
        return hashlib.sha256(value.encode('utf-8')).hexdigest()
    except UnicodeError:
        return None


def _hex(value, length):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-fA-F]{' + str(length) + '}', value) is not None


def _reject_constant(value):
    raise ValueError('Non-finite JSON number')


def _loads(value):
    return json.loads(value, parse_constant=_reject_constant)


def _verify(item, package, runners):
    result = {'evidence_id': item.get('id'), 'verified': False, 'outcome': 'unknown',
              'reason': '', 'commit_sha': '', 'repository': '',
              'source_paths': [], 'test_paths': [], 'source_evidence_ids': [],
              'test_evidence_ids': [], 'log_evidence_id': None}

    def unknown(reason):
        result['reason'] = reason + (' trusted/authenticated 是上传者自声明，不能赋予信任。'
                                    if result.get('uploader_claims_ignored') else '')
        return result

    try:
        receipt = _loads(item.get('content', ''))
    except (ValueError, TypeError, RecursionError):
        return unknown('运行回执不是有效 JSON。')
    if isinstance(receipt, dict):
        result['uploader_claims_ignored'] = [key for key in ['trusted', 'authenticated'] if key in receipt]
    if not isinstance(receipt, dict) or not isinstance(receipt.get('record'), dict):
        return unknown('运行回执缺少 record 对象。')
    runner_id, record = receipt.get('runner_id'), receipt['record']
    if not isinstance(runner_id, str) or runner_id not in runners:
        return unknown('运行来源未列入服务器私有信任配置。')
    secret = runners[runner_id]
    if not isinstance(secret, str) or not secret:
        return unknown('服务器运行来源配置无效。')
    signature = receipt.get('signature')
    if not _hex(signature, 64):
        return unknown('运行回执签名缺失或格式无效。')
    try:
        canonical = json.dumps(record, sort_keys=True, separators=(',', ':'),
                               ensure_ascii=False, allow_nan=False).encode('utf-8')
        expected = hmac.new(secret.encode('utf-8'), canonical, hashlib.sha256).hexdigest()
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return unknown('运行 record 不是可签名的 JSON。')
    if not hmac.compare_digest(expected, signature.lower()):
        return unknown('运行回执签名不匹配，无法认证来源或内容。')

    commit_sha, repository = record.get('commit_sha'), record.get('repository')
    if not _hex(commit_sha, 40) or not isinstance(repository, str) or not repository.strip():
        return unknown('运行回执缺少完整 Commit SHA 或仓库身份。')
    commit_sha = commit_sha.lower()
    commits = [c for c in package.get('commits', []) if c.get('sha') == commit_sha
               and c.get('repository') == repository]
    if not commits or repository == '未提供仓库':
        return unknown('运行仓库与完整 Commit 不匹配本次输入。')
    if item.get('version_id') != commit_sha:
        return unknown('运行回执材料未绑定同一目标 Commit。')
    result.update(commit_sha=commit_sha, repository=repository)
    if not isinstance(record.get('environment'), str) or not record['environment'].strip():
        return unknown('运行回执缺少环境标识。')
    command = record.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(x, str) and x.strip() for x in command):
        return unknown('运行回执缺少明确的命令参数列表。')
    exit_code, tests_run, skipped = (record.get(k) for k in ('exit_code', 'tests_run', 'skipped'))
    if any(type(x) is not int for x in [exit_code, tests_run, skipped]):
        return unknown('运行退出状态或测试统计格式无效。')
    if tests_run <= 0 or not 0 <= skipped < tests_run:
        return unknown('没有实际执行的测试，或测试全部跳过。')
    outcome = record.get('outcome')
    if outcome not in ['pass', 'fail'] or (outcome == 'pass') != (exit_code == 0):
        return unknown('运行结论与退出状态矛盾。')

    evidence = package.get('evidence', [])
    test_origin = record.get('test_origin', 'repository')
    if not isinstance(test_origin, str) or test_origin not in {'repository', 'external_audit'}:
        return unknown('测试产物来源必须为repository或external_audit。')
    result['test_origin'] = test_origin
    for field, output in [('source_hashes', 'source'), ('test_hashes', 'test')]:
        hashes = record.get(field)
        if not isinstance(hashes, dict) or not hashes or not all(
                isinstance(path, str) and path.strip() and _hex(digest, 64)
                for path, digest in hashes.items()):
            return unknown('运行回执缺少有效的源码或测试文件哈希表。')
        bound_ids = []
        for path, digest in hashes.items():
            kind = 'context' if output == 'test' and test_origin == 'external_audit' else 'source'
            if kind == 'context' and not path.startswith('audit-tests/'):
                return unknown('外部审计测试必须独立命名于audit-tests/，不能冒充目标仓库已交付测试。')
            files = [e for e in evidence if e.get('kind') == kind
                     and e.get('version_id') == commit_sha
                     and e.get('path', e.get('name')) == path]
            if not files or any(not isinstance(e.get('content'), str)
                                or _digest(e['content']) != digest.lower() for e in files):
                return unknown('运行源码或测试文件未提供、内容冲突，或哈希与目标版本不符。')
            bound_ids.extend(e.get('id') for e in files)
        result[output + '_paths'] = sorted(hashes)
        result[output + '_evidence_ids'] = sorted({eid for eid in bound_ids if isinstance(eid, str)})
    log_hash = record.get('log_sha256')
    logs = [e for e in evidence if e.get('kind') == 'test_log'
            and e.get('version_id') == commit_sha and isinstance(e.get('content'), str)
            and _hex(log_hash, 64) and _digest(e['content']) == log_hash.lower()]
    if not logs:
        return unknown('缺少与目标版本和签名回执哈希一致的测试日志。')

    assertions = record.get('assertion_results', [])
    if not isinstance(assertions, list):
        return unknown('逐断言运行记录必须为列表。')
    locations, assertion_results = set(), []
    for assertion in assertions:
        if not isinstance(assertion, dict):
            return unknown('逐断言运行记录格式无效。')
        path, line, assertion_outcome = (assertion.get(k) for k in ['path', 'line', 'outcome'])
        if not isinstance(path, str) or path not in record['test_hashes'] \
                or type(line) is not int or assertion_outcome not in ['pass', 'fail', 'skipped']:
            return unknown('逐断言运行记录必须指向受签名测试文件的明确行和有效结果。')
        files = [e for e in evidence if e.get('id') in result['test_evidence_ids']
                 and e.get('path', e.get('name')) == path]
        if not files or not 1 <= line <= len(files[0]['content'].splitlines()) \
                or not files[0]['content'].splitlines()[line - 1].strip() or (path, line) in locations:
            return unknown('逐断言运行行号无效、为空或重复，无法确定覆盖。')
        if outcome == 'pass' and assertion_outcome == 'fail':
            return unknown('运行通过声明与逐断言失败记录矛盾。')
        locations.add((path, line))
        assertion_results.append({'path': path, 'line': line, 'outcome': assertion_outcome})

    result.update(verified=True, outcome=outcome, log_evidence_id=logs[0].get('id'),
                  exit_code=exit_code, tests_run=tests_run, skipped=skipped,
                  assertion_results=assertion_results,
                  provenance='configured_runner_hmac',
                  reason='私有配置认可的运行来源签名及所列文件、日志、版本绑定已验证；结论仅覆盖该运行声明的范围。'
                         + ('测试为本轮外部审计产物，版本绑定只表示被测代码，不表示原提交已交付该测试。'
                            if test_origin == 'external_audit' else ''))
    return result


def verify_runs(package, root):
    """Untrusted/malformed receipts stay unknown; private signing secrets never leave here."""
    try:
        runners = _loads((Path(root) / '.trusted-runners.json').read_text(encoding='utf-8'))
        if not isinstance(runners, dict):
            runners = {}
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        runners = {}
    return [_verify(item, package, runners) for item in package.get('evidence', [])
            if item.get('kind') == 'run_record']

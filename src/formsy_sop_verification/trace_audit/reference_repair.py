"""Repair redundant reference coordinates, never evidence identity or claims."""
import ast
import copy
import hashlib
import json
import re


CITATION_SYSTEM_PROMPT = '''引用优先选择numbered_lines中程序提供的quote_id，单独返回{"quote_id":"Q-..."}，标准*_refs数组也可全部使用裸Q-ID字符串；程序将其展开为同一原文行的标准引用并继续校验任务、版本及证明范围。不要与手写quote/evidence_id/行号混用，不创造输入未提供的ID。需要多行时可列多条quote_id，也可保留原有逐字引用格式。
numbered_lines.line是证据的外层行号，text是完整原文；工具输出中的“51:”等内层行号也是原文的一部分，不得剥除或当成外层行号。空行无quote_id，空quote非法。reference_feedback中的choices只是可选原文，不保证支持当前主张；引用须自行匹配语义，无支持证据时保留未核查，不用任意引用凑通过。
E-开头的材料编号（含运行回执ID）只指整份材料，不能作为*_refs数组中的裸字符串引用；须选择支持相应事实的原文Q-ID或完整逐字引用。run_refs也遵守同一规则，不得用run_evidence_id代替原文引用。'''



CITATION_RETRY_PROMPT = ('本次引用重试优先从本阶段numbered_lines目录选取独立{"quote_id":"Q-..."}，'
    '标准*_refs数组也可全部使用裸Q-ID字符串、原样逐字且坐标准确的完整引用或为空；不同格式不得混用。'
    '完整引用必须属于本阶段可见材料，任何错字、换行或行号偏差都直接拒绝，不自动纠错。compact *_quote_ids仍可用。'
    '须重新判断相关reason中的事实，目录文本不支持旧主张时改为未核查并使用空refs；不得机械换引文保留旧reason。')


def validate_quote_id_retry(value, package, *, available_evidence_ids=None):
    """Restrict failed citation retries before expansion; never choose evidence for a claim."""
    evidence = {item['id']: item for item in package['evidence']
                if available_evidence_ids is None or item['id'] in available_evidence_ids}
    fields = {'evidence_id', 'start_line', 'end_line', 'quote'}

    def exact_reference(ref, path):
        if (set(ref) != fields or not isinstance(ref['evidence_id'], str)
                or ref['evidence_id'] not in evidence
                or _selected_text(ref, evidence[ref['evidence_id']]) is None):
            raise ValueError(path + ': 引用重试的完整引用须原样逐字且坐标精确，并在可见材料内；不自动纠错。')

    def walk(node, path):
        if isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f'{path}[{index}]')
        elif isinstance(node, dict):
            if 'quote_id' in node:
                if set(node) != {'quote_id'}:
                    raise ValueError(path + ': 引用重试只允许独立quote_id，不能混用手写字段。')
                resolve_quote_ids([node['quote_id']], package,
                                  available_evidence_ids=available_evidence_ids)
                return
            if {'start_line', 'end_line', 'quote'} & set(node):
                exact_reference(node, path)
                return
            for key, child in node.items():
                child_path = f'{path}.{key}'
                if isinstance(key, str) and key.endswith('_quote_ids'):
                    if key[:-len('_quote_ids')] + '_refs' in node:
                        raise ValueError(child_path + ': compact引用不能与手写refs混用。')
                    resolve_quote_ids(child, package, available_evidence_ids=available_evidence_ids)
                elif isinstance(key, str) and key.endswith('_refs'):
                    if isinstance(child, list) and all(isinstance(ref, str) for ref in child):
                        resolve_quote_ids(child, package, available_evidence_ids=available_evidence_ids)
                    elif isinstance(child, list) and all(
                            isinstance(ref, dict) and set(ref) == {'quote_id'} for ref in child):
                        walk(child, child_path)
                    elif isinstance(child, list) and all(
                            isinstance(ref, dict) and set(ref) == fields for ref in child):
                        walk(child, child_path)
                    else:
                        raise ValueError(child_path + ': 引用重试数组须全部为独立quote_id、裸Q-ID字符串、精确完整引用或空数组，不能混用。')
                else:
                    walk(child, child_path)
    walk(value, '$')


def _quote_choices(package):
    choices = {}
    for item in package['evidence']:
        content_hash = hashlib.sha256(item['content'].encode()).hexdigest()
        for number, line in enumerate(item['content'].splitlines(), 1):
            if not line.strip() or len(line) > 600:
                continue
            identity = json.dumps([item['id'], content_hash, item.get('version_id', ''), number],
                                  ensure_ascii=False, separators=(',', ':'))
            oid = 'Q-' + hashlib.sha256(identity.encode()).hexdigest()[:16]
            ref = {'evidence_id': item['id'], 'start_line': number, 'end_line': number, 'quote': line}
            if oid in choices and choices[oid] != ref:
                raise ValueError('精确引用ID冲突，不能解析该目录。')
            choices[oid] = ref
    return choices


def resolve_quote_ids(ids, package, *, available_evidence_ids=None):
    """Resolve explicit selections only; a compact citation never carries editable coordinates."""
    if (not isinstance(ids, list) or any(not isinstance(oid, str) for oid in ids)
            or len(ids) != len(set(ids))):
        raise ValueError('精确引用须为无重复的 quote_id 字符串列表。')
    choices = _quote_choices(package)
    if any(oid not in choices or available_evidence_ids is not None
           and choices[oid]['evidence_id'] not in available_evidence_ids for oid in ids):
        raise ValueError('精确引用ID未知或不在本阶段可见材料中，不能跨来源修复。')
    return [copy.deepcopy(choices[oid]) for oid in ids]


def attach_quote_ids(payload, package):
    """Annotate existing numbered evidence, without altering frozen content."""
    payload = copy.deepcopy(payload)
    choices = {(ref['evidence_id'], ref['start_line']): oid
               for oid, ref in _quote_choices(package).items()}
    evidence = {item['id']: item for item in package['evidence']}
    for item in payload.get('evidence', []):
        original = evidence.get(item.get('id'))
        if original is None:
            continue
        item['numbered_lines'] = [
            {'line': number, 'text': line,
             **({'quote_id': choices[(item['id'], number)]} if (item['id'], number) in choices else {})}
            for number, line in enumerate(original['content'].splitlines(), 1)]
    return payload


def _reason_fields(value, path='$'):
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = path + '.' + key
            if (key == 'reason' or key.endswith('_reason')) and isinstance(child, str):
                yield value, child_path, child
            else:
                yield from _reason_fields(child, child_path)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _reason_fields(child, f'{path}[{index}]')


def _contains_anchor(text, anchor):
    if re.fullmatch(r'[A-Za-z0-9_]+', anchor):
        return bool(re.search(r'(?<![A-Za-z0-9_])' + re.escape(anchor) + r'(?![A-Za-z0-9_])', text))
    return anchor in text


def _rejected_reason_anchors(quote, content, reasons):
    """Freeze only explicit old literals, not a semantic verdict about arbitrary prose."""
    candidates = []
    for match in re.finditer(r'''(?P<mark>['"`])(?P<literal>(?:\\.|(?!(?P=mark))[^\r\n])+)(?P=mark)''', quote):
        literal = match['literal']
        if match['mark'] != '`':
            try:
                literal = ast.literal_eval(match.group())
            except (ValueError, SyntaxError):
                pass
        candidates.append(literal)
    candidates.extend(word for word in re.findall(r'\b[A-Za-z_][A-Za-z0-9_]*\b', quote)
                      if '_' in word or any(letter.isupper() for letter in word))
    candidates.extend(re.findall(r'(?<![\w.])\d+(?:\.\d+)?(?![\w.])', quote))
    return list(dict.fromkeys(literal for literal in candidates
        if isinstance(literal, str) and literal.strip() and len(literal) <= 160
        and not _contains_anchor(content, literal)
        and any(_contains_anchor(reason, literal) for reason in reasons)))[:24]


def validate_retry_reason_consistency(value, diagnostics, package, *, available_evidence_ids=None):
    """A valid replacement citation cannot silently retain a rejected literal fact."""
    # shortcut: only frozen old literal anchors are checked; paraphrases and full claim semantics still need review.
    anchors = {anchor for diagnostic in diagnostics
               for anchor in diagnostic.get('rejected_reason_anchors', [])}
    if not anchors:
        return
    evidence = {item['id']: item for item in package['evidence']
                if available_evidence_ids is None or item['id'] in available_evidence_ids}

    def selected_quotes(node):
        if isinstance(node, list):
            for child in node:
                yield from selected_quotes(child)
        elif isinstance(node, dict):
            oid = node.get('evidence_id')
            item = evidence.get(oid) if isinstance(oid, str) else None
            if item is not None and _selected_text(node, item) is not None:
                yield node['quote']
            else:
                for child in node.values():
                    yield from selected_quotes(child)

    for owner, path, reason in _reason_fields(value):
        quotes = list(selected_quotes(owner))
        unsupported = sorted(anchor for anchor in anchors if _contains_anchor(reason, anchor)
                             and not any(_contains_anchor(quote, anchor) for quote in quotes))
        if unsupported:
            raise ValueError(path + ': 引用恢复仍保留被拒绝且未获本行逐字引用支持的旧字面事实：'
                             + ', '.join(unsupported) + '；撤回该事实并重判真正缺口，或引用实际支持它的可见原文。')


def reference_diagnostics(value, package, *, available_evidence_ids=None):
    """Explain invalid identities or quotes; never move a claim to another source."""
    available = [item for item in package['evidence']
                 if available_evidence_ids is None or item['id'] in available_evidence_ids]
    evidence = {item['id']: item for item in available}
    choices = _quote_choices({'evidence': available})
    by_line = {(ref['evidence_id'], ref['start_line']): {'quote_id': oid, **ref}
               for oid, ref in choices.items()}
    diagnostics = []
    catalog_path = None
    reasons = [reason for _, _, reason in _reason_fields(value)]

    def unknown_identity(path, reason):
        nonlocal catalog_path
        diagnostic = {'path': path, 'reason': reason,
            'instruction': '只从当前输入材料目录及numbered_lines显式重新选择；不得跨证据或版本自动迁移引用。重新核查相关reason中的事实，无支持证据可保留未核查并使用空evidence_refs。'}
        if catalog_path is None:
            diagnostic['available_evidence'] = [
                {'id': item['id'], 'name': item.get('name', item.get('path', ''))[:100],
                 'kind': item['kind'], 'version_id': item.get('version_id', '')}
                for item in available[:128]]
            diagnostic['available_evidence_count'] = len(available)
            diagnostic['available_evidence_omitted'] = max(0, len(available) - 128)
            catalog_path = path
        else:
            diagnostic['available_evidence_catalog_at'] = catalog_path
        diagnostics.append(diagnostic)

    def walk(node, path, reference_position=False):
        if len(diagnostics) >= 24:
            return
        if isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f'{path}[{index}]', reference_position)
        elif isinstance(node, dict):
            if 'quote_id' in node:
                oid = node['quote_id']
                if set(node) != {'quote_id'} or not isinstance(oid, str) or oid not in choices:
                    unknown_identity(path, '未知quote_id或与手写引用混用；仅选择输入目录中的独立quote_id。')
                return
            if 'evidence_id' in node and (reference_position or
                    {'start_line', 'end_line', 'quote'} & set(node)):
                oid = node['evidence_id']
                item = evidence.get(oid) if isinstance(oid, str) else None
                if item is None:
                    unknown_identity(path, '证据ID不存在或不在本阶段可见材料中，不跨证据猜测原文。')
                elif _selected_text(node, item) is None:
                    lines = item['content'].splitlines()
                    start, end = node.get('start_line'), node.get('end_line')
                    anchors = [n for n in (start, end) if type(n) is int and 1 <= n <= len(lines)]
                    numbers = sorted({max(1, min(len(lines), n + offset))
                                      for n in anchors or [1] for offset in (-1, 0, 1, 2)})
                    selected = [by_line[(oid, n)] for n in numbers if (oid, n) in by_line][:6]
                    quote = node.get('quote')
                    absent = isinstance(quote, str) and bool(quote.strip()) and quote not in item['content']
                    diagnostics.append({'path': path, 'evidence_id': oid,
                        'version_id': item.get('version_id', ''),
                        'error_kind': 'quote_absent_from_evidence' if absent else 'invalid_quote_coordinates',
                        'reason': '该quote在指定材料及版本全文中不存在，不是附近行号问题；可能混用了历史片段、其他材料或改写文本。'
                                  if absent else '原引用不是所选外层行的逐字非空原文；保留原文中的内层行号前缀，不拼接或改写。',
                        'choices': selected,
                        **({'rejected_quote': quote[:600], 'rejected_quote_truncated': len(quote) > 600,
                            'rejected_reason_anchors': _rejected_reason_anchors(quote, item['content'], reasons),
                            'recovery_options': [
                                {'action': 'rejudge_with_visible_support',
                                 'selectors': [{'quote_id': choice['quote_id']} for choice in selected],
                                 'instruction': '这些选择器只指向指定材料当前版本的真实原文；重新判断该原文实际支持的事实，不保留不存在的旧引文主张。'},
                                {'action': 'withdraw_unsupported_fact', 'result': '未核查', 'evidence_refs': [],
                                 'instruction': '没有支持原主张的可见原文时，撤回该事实并说明真正证据缺口；无需引用附近无关文本。'}]}
                           if absent else {}),
                        'instruction': '必须重新核查相关reason中的事实，不得仅换附近引文而保留旧主张；不跨证据或版本自动迁移引用。附近choices仅是实际原文，不能证明不存在的quote。无支持证据可保留未核查并使用空evidence_refs。'
                                       if absent else '仅当原文支持当前主张时选用独立quote_id；否则补充有效引用或保留未核查；空引用不能用任意附近文本填充。'})
                return
            for key, child in node.items():
                if len(diagnostics) >= 24:
                    return
                child_path = f'{path}.{key}'
                if isinstance(key, str) and key.endswith('_quote_ids'):
                    if not isinstance(child, list):
                        unknown_identity(child_path, '精确引用ID须为字符串数组；不从错误结构猜测或自动绑定原文。')
                    elif key[:-len('_quote_ids')] + '_refs' in node:
                        unknown_identity(child_path, '精确引用ID数组不能与手写refs混用；显式重新选择一种引用格式。')
                    else:
                        seen = set()
                        for index, oid in enumerate(child):
                            if len(diagnostics) >= 24:
                                return
                            if not isinstance(oid, str) or oid not in choices:
                                unknown_identity(f'{child_path}[{index}]',
                                    '未知quote_id、非字符串ID或不在本阶段可见材料中；仅从原目录显式选择。')
                            elif oid in seen:
                                unknown_identity(f'{child_path}[{index}]', '精确引用ID数组有重复项；不能用重复引用补齐证据。')
                            if isinstance(oid, str):
                                seen.add(oid)
                elif isinstance(key, str) and key.endswith('_refs') and isinstance(child, list) and any(
                        isinstance(ref, str) for ref in child):
                    if (all(isinstance(ref, str) and ref in choices for ref in child)
                            and len(child) == len(set(child))):
                        continue
                    unknown_identity(child_path, '标准引用数组含未知、隐藏或混用的裸ID；仅可全选当前目录Q-ID，不能猜测或混合手写引用。')
                    material_ids = list(dict.fromkeys(ref for ref in child
                        if isinstance(ref, str) and ref in evidence))[:6]
                    if material_ids:
                        diagnostics[-1]['material_ids_are_not_quotes'] = [
                            {'evidence_id': oid, 'choices': [by_line[(oid, number)]
                                for number in range(1, min(len(evidence[oid]['content'].splitlines()), 8) + 1)
                                if (oid, number) in by_line][:6]}
                            for oid in material_ids]
                        diagnostics[-1]['instruction'] += '材料编号只标识整份材料，不是引用。须显式选择支持当前主张的原文Q-ID；这些开头行仅用于定位，不能自动充当事实依据。'
                else:
                    walk(child, child_path, isinstance(key, str) and key.endswith('_refs'))

    walk(value, '$')
    return diagnostics


def _selected_text(ref, item):
    start, end, quote = (ref.get(key) for key in ('start_line', 'end_line', 'quote'))
    lines = item['content'].splitlines(keepends=True)
    if (type(start) is not int or type(end) is not int or
            not 1 <= start <= end <= len(lines) or
            not isinstance(quote, str) or not quote.strip()):
        return None
    selected = ''.join(lines[start - 1:end])
    return selected if quote in selected else None


def _unique_quote_lines(content, quote):
    offset = content.find(quote)
    if offset < 0 or content.find(quote, offset + 1) >= 0:
        return None
    end, cursor, covered = offset + len(quote), 0, []
    for number, line in enumerate(content.splitlines(keepends=True), 1):
        overlap = line[max(0, offset - cursor):min(len(line), end - cursor)]
        if cursor < end and cursor + len(line) > offset and overlap:
            covered.append(number)
        cursor += len(line)
        if cursor >= end:
            break
    return (covered[0], covered[-1]) if covered else None


def _restore_quote_endings(content, quote):
    parts = re.split(r'\r\n|\r|\n', quote)
    if len(parts) < 2:
        return None
    # A CRLF is one separator; never match only its CR or LF half.
    pattern = re.compile(r'(?:\r\n|\r(?!\n)|(?<!\r)\n)'.join(map(re.escape, parts)))
    match = pattern.search(content)
    if match is None or pattern.search(content, match.start() + 1) is not None:
        return None
    return match.group()


def _quoted_changed_lines(ref, item):
    selected = _selected_text(ref, item)
    if selected is None:
        return set()
    offset = selected.find(ref['quote'])
    if selected.find(ref['quote'], offset + 1) >= 0:
        return set()
    end, cursor, changed = offset + len(ref['quote']), 0, set()
    for number, line in enumerate(selected.splitlines(keepends=True), ref['start_line']):
        overlap = line[max(0, offset - cursor):min(len(line), end - cursor)]
        if (cursor < end and cursor + len(line) > offset and
                line.startswith(('+', '-')) and not line.startswith(('+++ ', '--- ')) and
                overlap.strip('+- \t\r\n')):
            changed.add(number)
        cursor += len(line)
        if cursor >= end:
            break
    return changed


def ref_hits_hunk(ref, hunk, item):
    """Only quoted changed text proves a hunk; a broad range is insufficient."""
    return (isinstance(ref, dict) and item.get('kind') == 'commit_diff' and
            ref.get('evidence_id') == item.get('id') == hunk.get('evidence_id') and
            item.get('version_id') == hunk.get('commit_id') and not hunk.get('unparsed') and
            bool(_quoted_changed_lines(ref, item).intersection(hunk['changed_line_numbers'])))


def repair_references(value, package, tasks=None, *, available_evidence_ids=None):
    """Return a copy and repair log; ambiguous or invalid identities stay rejected."""
    repaired, repairs = copy.deepcopy(value), []
    available = [item for item in package['evidence']
                 if available_evidence_ids is None or item['id'] in available_evidence_ids]
    evidence = {item['id']: item for item in available}
    choices = _quote_choices({'evidence': available})

    def walk(node, path):
        if isinstance(node, list):
            for index, child in enumerate(node):
                walk(child, f'{path}[{index}]')
        elif isinstance(node, dict):
            if 'quote_id' in node:
                oid = node['quote_id']
                if set(node) == {'quote_id'} and isinstance(oid, str) and oid in choices:
                    node.clear()
                    node.update(choices[oid])
                    repairs.append({'kind': 'quote_id', 'path': path, 'before': {'quote_id': oid},
                                    'after': copy.deepcopy(node)})
                return
            oid = node.get('evidence_id')
            item = evidence.get(oid) if isinstance(oid, str) else None
            if (item and isinstance(node.get('quote'), str) and node['quote'].strip() and
                    type(node.get('start_line')) is int and type(node.get('end_line')) is int and
                    _selected_text(node, item) is None):
                quote = node['quote']
                restored = _restore_quote_endings(item['content'], quote) if quote not in item['content'] else None
                span = _unique_quote_lines(item['content'], restored if restored is not None else quote)
                if span:
                    before = {key: node[key] for key in ('start_line', 'end_line')}
                    node.update(start_line=span[0], end_line=span[1])
                    after = {'start_line': span[0], 'end_line': span[1]}
                    if restored is not None:
                        before['quote'], after['quote'] = quote, restored
                        node['quote'] = restored
                    repairs.append({'kind': 'quote_line_endings' if restored is not None else 'quote_lines', 'path': path,
                                    'evidence_id': item['id'], 'before': before,
                                    'after': after})
            for key, child in node.items():
                # Frozen requirements are immutable even if their coordinates are bad.
                if key != 'tasks' or tasks is None:
                    child_path = f'{path}.{key}'
                    if (isinstance(key, str) and key.endswith('_refs') and isinstance(child, list)
                            and child and all(isinstance(oid, str) and oid in choices for oid in child)
                            and len(child) == len(set(child))):
                        for index, oid in enumerate(child):
                            child[index] = copy.deepcopy(choices[oid])
                            repairs.append({'kind': 'quote_id_string', 'path': f'{child_path}[{index}]',
                                            'before': oid, 'after': copy.deepcopy(child[index])})
                    else:
                        walk(child, child_path)

    walk(repaired, '$')
    if not isinstance(repaired, dict):
        return repaired, repairs
    task_rows = tasks if tasks is not None else repaired.get('tasks', [])
    by_task = {task['id']: task for task in task_rows if isinstance(task, dict) and
               isinstance(task.get('id'), str)} if isinstance(task_rows, list) else {}
    changes = {hunk['id']: hunk for hunk in package.get('changes', [])}
    rows = repaired.get('acceptance_checks', [])
    for index, row in enumerate(rows if isinstance(rows, list) else []):
        if not isinstance(row, dict):
            continue
        task_id = row.get('task_id')
        task = by_task.get(task_id) if isinstance(task_id, str) else None
        ids, refs = row.get('change_ids'), row.get('change_refs')
        if (not task or not isinstance(ids, list) or not ids or
                not all(isinstance(oid, str) and oid in changes for oid in ids) or
                len(ids) != len(set(ids)) or not isinstance(refs, list)):
            continue
        if not isinstance(task.get('commit_ids'), list) or not all(isinstance(oid, str) for oid in task['commit_ids']):
            continue
        related = set(task['commit_ids'])
        if any(changes[oid]['commit_id'] not in related for oid in ids):
            continue
        derived, ambiguous = set(), False
        for ref in refs:
            if not isinstance(ref, dict):
                continue
            oid = ref.get('evidence_id')
            item = evidence.get(oid, {}) if isinstance(oid, str) else {}
            if (item.get('kind') != 'commit_diff' or item.get('version_id') not in related or
                    item.get('target_ids') and task['id'] not in item['target_ids']):
                continue
            matches = {hunk['id'] for hunk in changes.values()
                       if ref_hits_hunk(ref, hunk, item)}
            if len(matches) > 1:
                ambiguous = True
                break
            derived.update(matches)
        if (ambiguous or not derived or
                {changes[oid]['evidence_id'] for oid in ids} !=
                {changes[oid]['evidence_id'] for oid in derived}):
            continue
        after = [hunk['id'] for hunk in package['changes'] if hunk['id'] in derived]
        if set(ids) != derived:
            row['change_ids'] = after
            repairs.append({'kind': 'change_ids', 'path': f'$.acceptance_checks[{index}].change_ids',
                            'before': ids, 'after': after})
    return repaired, repairs

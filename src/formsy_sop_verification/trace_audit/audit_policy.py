"""Deterministic gates for scoped automatic review, separate from full SOP closure."""
import ast
import copy
import hashlib
import io
import json
import math
import re
import tokenize
from .run_evidence import external_test_path
from .sop_contracts import VERSION

PASS, FAIL, UNKNOWN, NA = '满足', '不满足', '未核查', '不适用'
LOCAL_FAILURE_ITEMS = {'FIX02': 'FIX02.C01.I02', 'FIX03': 'FIX03.C01.I01'}
HUMAN = re.compile(r'人工(?:进行|执行|完成|提供)?(?:审核|复核|评审|审查|签署|签字|确认|审批|验收)|人审|'
                   r'独立(?:关闭)?(?:复核|审核|评审|审查)|确认记录|human\s+(?:review|approval|signoff)|'
                   r'manual\s+(?:review|approval)|independent\s+review', re.I)
CLOSURE = re.compile(r'正式关闭|(?:独立|本轮|本次)(?:\s*SOP\s*)?关闭(?:复核|审核|确认|记录|材料|证据|条件|门槛)')

SOURCE_SYNTAX_PROMPT = '''target_source_syntax_index只提供同任务、同目标可见源码的词法定位，须回读对应原文；location的行从1起、列为从0起的UTF-8字节位置。syntax_facts中的lambda形参、同词法作用域的Name绑定、调用参数、字符串selector、raises和assert须分别核对；不推断别名、动态绑定或跨函数数据流。相同形参名与不同形参名、默认入口与显式selector、预期异常与预期成功是不同场景。存在同名且预期异常的测试，不证明同名成功行为已覆盖，也不能写成没有任何同名测试；显式selector的成功测试不自动覆盖未传selector的真实入口。注释中的示例不是活动测试。只写已定位的具体缺口，不能由一个遗漏推导现有测试全都使用另一输入。
局部helper新增守卫只证明该helper对应分支的性质，不能据此断言缺少完整目标调用链的公开入口也不会抛错。入口、分派、参数变换及其它可能失败步骤未闭合时，公开入口的无异常性质仍未核查；不得悄悄缩成helper局部性质再判整个验收满足。完整静态路径或匹配对象、输入、目标版本的受信实际观察均可支持，不额外强制执行、输出大小写或容器合同。
组合/归约链中的输入元素、每步乘积和最终组边界分别求值；中间乘积丢失边界不等于最终组边界必错。最终恰回默认值时仍可能正确，须按实际输入的首尾端点核对，不能要求所有阶段均非默认。baseline或反例混淆这些阶段时明确保留范围缺口，不用候选描述代替源码与原用户示例。
测试函数名仅作定位，不是测试行为或布局事实。lambda_physical_line_groups按lambda实际起始物理行分组；explicit_line_continuation_lines只列源码中实际续行符，已排除字符串/注释。物理行与逻辑行不同，不能按测试名或用户另一个多行示例猜测当前断言跨行。helper与产品入口、显式selector与默认调用须分别核合同；未证明同合同前，不能要求删除或反转helper已有预期异常断言，补目标入口覆盖即可。复检建议按产品公开返回类型及return语句核期望；链式对象返回与其内部AST属性不同，不能把内部结构写成公开表达式的直接返回值。
short_circuit_syntax列布尔操作数的源码顺序；判断属性访问、类型守卫和失败路径须按完整表达式短路语义推导。沿调用链先核下层实际收到的实参，区分外层方法调用、lambda节点和lambda body，不能用外层参数数量解释下层AST检查。递归遍历中的层级或状态参数须逐层列出父节点更新、子调用实参和返回值；不能用默认值或父节点更新前的旧值直接代入深层节点，源码注释也不能替代实际状态传播。比较两版时沿同一输入分别展开完整路径，局部表达式相同或不同都不能独自证明完整输出相同或不同。历史tool/assistant中的异常只证明历史观察；目标已增加守卫或改变路径时须重新检查目标调用链，不能把已恢复的历史异常作为当前版本的直接反例或根因。静态推导与受信实际运行仍分开。全部reason、observed、根因mechanism、findings.summary须保留同一范围限定，不能只修正详细验收理由却在摘要声称没有任何同类测试。
adjacent_return_syntax只列同一语句列表里相邻return的原文顺序及表达式AST是否相同，不证明执行或全路径等价。先对照diff的新增/删除/保留行与目标源码，不能把后一条保留语句的不可达属性写到前一条新增语句上。实质范围越出须给同范围有效义务与已确认的实质影响，不能把任意新增行自动等同越界；冗余清理可以建议，若违反独立质量义务须另给对应依据，不补造用户禁止或豁免真实质量要求。
注册表、处理器分派及重复键须分别沿父版和目标版的完整注册顺序核最终绑定；某类声明了键不等于该输入最终命中此类。后续覆盖、导入顺序或调用前提未明确时保留未知；父版未实际可达的处理器字段不能被写成本次改动丢失的原有正常行为。
class_definition_syntax按源码词法顺序列类、bases和类体直接赋值；literal_value仅为直接字面量，动态表达式不求值。module_top_level=false的声明不证明会执行。parent_class_definitions仅附精确Commit父版本、同路径同任务的类定位，version_role=parent不能作为目标证明；这些定位不执行metaclass，也不计算注册结果。
duplicate_class_list_literals仅聚合同一源码版本中不同顶层类的同名属性、相同字符串列表值，保留原声明顺序和引用；last_lexical_declaration仅指最后一个词法声明，runtime_binding_verified=false。类体重新赋值、动态修改、decorator/metaclass及实际执行均未验证，不能由该聚合直接推出最终注册、可达路径或兼容反例。
证据齐全与被审实现满足是不同判断维度：条款核查原错误、代码、调用路径或合同材料是否齐全时，业务反例可能正是完整证据，不能仅因实现违反合同就将证据齐全判失败；业务正确性在对应条件另判。始终核固定audit_object和judgment_dimension，不偷换对象或维度。
反例须在该验收实际观察的时点沿完整有效路径求值；前置异常后尚未发生的状态不能虚构，中间值错误也不能自动推出最终观察值错误。全任务、兼容边界和范围条款须核对全部实质hunk及用户范围，局部验收正例不能代替完整条款满足。候选矩阵或发现中的矛盾只作为重核线索，须回对应目标源码逐字核对，不把另一份候选当独立事实或直接传播其结论。
config_reference_syntax的reference_only只定位显式配置引用；凭据引用存在不等于明文秘密、泄漏或保护已验证。缺少生命周期/保护/实际验证证据可保留未核查，不能写成材料中没有任何凭据引用，也不能由缺证据证明目标中不存在秘密。'''


def _formal_condition(value):
    return bool(HUMAN.search(str(value)) or CLOSURE.search(str(value)))


def _path(item):
    return item.get('path') or item.get('name', '')


def _test_path(path):
    return bool(re.search(r'(^|[/\\])(?:tests?|specs?|__tests__|audit-tests)([/\\]|$)|(^|[/\\])test_|_test\.|\.(?:test|spec)\.', path, re.I))


def _syntax_location(node):
    """[start line, start column, end line, end column]; columns are UTF-8 byte offsets."""
    return [node.lineno, node.col_offset, node.end_lineno, node.end_col_offset]


def _syntax_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _syntax_name(node.value)
        return (parent or '<' + type(node.value).__name__ + '>') + '.' + node.attr
    return None


def _explicit_line_continuation_lines(content):
    continuations = {number: len(line.rstrip('\n')) - 1
        for number, line in enumerate(io.StringIO(content, newline=None), 1)
        if line.rstrip('\n').endswith('\\')}
    # Explicit joins have no token; backslashes inside strings/comments belong to tokens.
    if continuations:
        for token in tokenize.generate_tokens(io.StringIO(content, newline=None).readline):
            for number in range(token.start[0], token.end[0] + 1):
                if (number in continuations
                        and token.start <= (number, continuations[number]) < token.end):
                    del continuations[number]
    return list(continuations)


def _test_syntax_facts(function, continuation_lines):
    """Record lexical facts only: do not resolve names, execute or infer coverage."""
    nodes, scopes = [], {}
    pending = [(node, function) for node in reversed(function.body)]
    while pending:
        node, scope = pending.pop()
        nodes.append(node)
        scopes[node] = scope
        body = getattr(node, 'body', [])
        body = body if isinstance(body, list) else [body]
        children = [(child, node if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef,
                     ast.ClassDef, ast.Lambda)) and child in body else scope)
                    for child in ast.iter_child_nodes(node)]
        pending.extend(reversed(children))
    nodes.sort(key=lambda node: (getattr(node, 'lineno', 0), getattr(node, 'col_offset', 0),
                                getattr(node, 'end_lineno', 0), getattr(node, 'end_col_offset', 0)))

    def located(node):
        fact = {'location': _syntax_location(node)}
        if scopes[node] is not function:
            fact['scope_location'] = _syntax_location(scopes[node])
            fact['scope_name'] = getattr(scopes[node], 'name', '<lambda>')
        return fact

    facts = {'scope': 'lexical_only'}
    lambdas = [node for node in nodes if isinstance(node, ast.Lambda)]
    if lambdas:
        facts['lambdas'] = [{**located(node), 'parameters':
            [arg.arg for arg in node.args.posonlyargs + node.args.args]
            + (['*' + node.args.vararg.arg] if node.args.vararg else [])
            + [arg.arg for arg in node.args.kwonlyargs]
            + (['**' + node.args.kwarg.arg] if node.args.kwarg else [])} for node in lambdas]
    line_groups = {}
    for node in lambdas:
        line_groups.setdefault(node.lineno, []).append(_syntax_location(node))
    groups = [{'line': line, 'lambda_locations': locations}
              for line, locations in line_groups.items() if len(locations) >= 2]
    if groups:
        facts['lambda_physical_line_groups'] = groups
    continuations = [line for line in continuation_lines if function.lineno <= line <= function.end_lineno]
    if continuations:
        facts['explicit_line_continuation_lines'] = continuations
    bindings, bound_names = [], set()
    for node in nodes:
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.NamedExpr)) and isinstance(node.value, ast.Lambda):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name):
                    bindings.append({**located(node), 'name': target.id,
                                     'lambda_location': _syntax_location(node.value)})
                    bound_names.add((target.id, scopes[node]))
    if bindings:
        facts['lambda_bindings'] = bindings
    calls, raises, assertions = [], [], []
    for node in nodes:
        if isinstance(node, ast.Call):
            arguments, strings, names = [], [], []
            for key, arg in ([({'position': i}, arg) for i, arg in enumerate(node.args)]
                             + [({'keyword': kw.arg}, kw.value) for kw in node.keywords]):
                if isinstance(arg, ast.Lambda):
                    arguments.append({**key, 'lambda_location': _syntax_location(arg)})
                elif isinstance(arg, ast.Name):
                    names.append({**key, 'name': arg.id})
                    if (arg.id, scopes[node]) in bound_names:
                        arguments.append({**key, 'lexical_name': arg.id})
                elif isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    strings.append({**key, 'value': arg.value})
            lambda_callee = isinstance(node.func, ast.Lambda)
            if arguments or lambda_callee or strings and names:
                call = {**located(node), 'callee': _syntax_name(node.func) or type(node.func).__name__}
                if arguments:
                    call['lambda_arguments'] = arguments
                elif names:
                    call['name_arguments'] = names
                if lambda_callee:
                    call['lambda_callee_location'] = _syntax_location(node.func)
                if strings:
                    call['string_arguments'] = strings
                calls.append(call)
        elif isinstance(node, (ast.With, ast.AsyncWith)):
            for item in node.items:
                context = item.context_expr
                if isinstance(context, ast.Call) and _syntax_name(context.func) == 'pytest.raises':
                    exception = context.args[0] if context.args else next(
                        (kw.value for kw in context.keywords if kw.arg == 'expected_exception'), None)
                    raised = {**located(node), 'body_location':
                              [*_syntax_location(node.body[0])[:2], *_syntax_location(node.body[-1])[2:]]}
                    if exception is not None:
                        raised['exception_location'] = _syntax_location(exception)
                        names = exception.elts if isinstance(exception, ast.Tuple) else [exception]
                        raised['exception_names'] = [_syntax_name(name) or type(name).__name__ for name in names]
                    raises.append(raised)
        elif isinstance(node, ast.Assert):
            assertions.append(_syntax_location(node))
    for key, value in [('calls', calls), ('raises', raises), ('asserts', assertions)]:
        if value:
            facts[key] = value
    return facts


def _class_definition_sites(tree, source):
    """Locate declarations and literal attributes; never execute class bodies."""
    content = source['content']
    lines = content.splitlines()
    sites = []
    classes = sorted((node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)),
                     key=lambda node: (node.lineno, node.col_offset))
    for order, node in enumerate(classes, 1):
        attributes = []
        for assignment in node.body:
            if not isinstance(assignment, (ast.Assign, ast.AnnAssign)):
                continue
            targets = assignment.targets if isinstance(assignment, ast.Assign) else [assignment.target]
            value = assignment.value
            values = value.elts if isinstance(value, (ast.List, ast.Tuple)) else [value]
            literal = all(isinstance(item, ast.Constant)
                          and type(item.value) in (str, int, float, bool, type(None))
                          and (not isinstance(item.value, float) or math.isfinite(item.value)) for item in values)
            for target in targets:
                if not isinstance(target, ast.Name):
                    continue
                attribute = {'name': target.id, 'location': _syntax_location(assignment),
                             'value_node_type': type(value).__name__,
                             'value_location': _syntax_location(value) if value else None,
                             'is_literal': literal}
                if literal:
                    attribute['literal_value'] = ([item.value for item in values]
                                                 if isinstance(value, (ast.List, ast.Tuple)) else value.value)
                attributes.append(attribute)
        header_end = max(node.lineno, node.body[0].lineno - 1)
        sites.append({'kind': 'class_definition_syntax', 'name': node.name,
            'syntax_facts': {'scope': 'lexical_only', 'lexical_order': order,
                'location': _syntax_location(node), 'module_top_level': node in tree.body,
                'bases': [{'source': ast.get_source_segment(content, base),
                           'location': _syntax_location(base)} for base in node.bases],
                'attributes': attributes},
            'reference': {'evidence_id': source['id'], 'start_line': node.lineno,
                          'end_line': header_end, 'quote': '\n'.join(lines[node.lineno - 1:header_end])}})
    return sites


def _duplicate_class_list_literals(sites):
    """Group existing lexical declarations, never infer effective class attributes."""
    groups = {}
    for site in sites:
        if site['kind'] != 'class_definition_syntax':
            continue
        facts = site['syntax_facts']
        if not facts['module_top_level']:
            continue
        for attribute in facts['attributes']:
            values = attribute.get('literal_value')
            if (attribute['value_node_type'] != 'List' or not attribute['is_literal']
                    or not all(isinstance(value, str) for value in values)):
                continue
            declaration = {'class_name': site['name'], 'lexical_order': facts['lexical_order'],
                'class_location': copy.deepcopy(facts['location']),
                'attribute_location': copy.deepcopy(attribute['location']),
                'class_reference': copy.deepcopy(site['reference'])}
            for value in dict.fromkeys(values):
                groups.setdefault((attribute['name'], value), []).append(copy.deepcopy(declaration))
    return [{'attribute_name': name, 'string_value': value, 'scope': 'lexical_only',
             'runtime_binding_verified': False, 'declarations': declarations,
             'last_lexical_declaration': copy.deepcopy(declarations[-1])}
            for (name, value), declarations in groups.items()
            if len({tuple(row['class_location']) for row in declarations}) > 1]


def _unittest_method_candidates(tree):
    """Locate TestCase-like declarations without resolving imports or collection."""
    if tree is None:
        return {}
    bases = {'unittest.TestCase'}
    for node in tree.body:
        if isinstance(node, ast.Import):
            bases.update((alias.asname or alias.name) + '.TestCase'
                         for alias in node.names if alias.name == 'unittest')
        elif isinstance(node, ast.ImportFrom) and node.module == 'unittest':
            bases.update(alias.asname or alias.name for alias in node.names if alias.name == 'TestCase')
        elif isinstance(node, ast.Assign) and _syntax_name(node.value) in bases:
            bases.update(target.id for target in node.targets if isinstance(target, ast.Name))
    classes = sorted((node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)),
                     key=lambda node: (node.lineno, node.col_offset))
    local_names = {node.name for node in classes}
    methods = {}
    for owner in classes:
        references = [_syntax_name(base) for base in owner.bases]
        candidates = [ref for ref in references if ref and (ref in bases or
                      ref.rsplit('.', 1)[-1].endswith('TestCase') and ref not in local_names)]
        if candidates:
            if owner in tree.body:
                bases.add(owner.name)
            methods.update({method: (owner.name, candidates) for method in owner.body
                            if isinstance(method, (ast.FunctionDef, ast.AsyncFunctionDef))
                            and method.name.startswith('test') and not method.name.startswith('test_')})
    return methods


def target_source_index(task, package):
    """Index scoped syntax; a locator never proves trust, flow or coverage."""
    result = []
    for source in package.get('evidence', []):
        path = _path(source)
        if (source.get('kind') != 'source'
                or source.get('version_id') not in task.get('target_commit_ids', [])
                or not _allowed(source, task)):
            continue
        content = source.get('content', '')
        lines = content.splitlines(keepends=True)
        sites = []
        for line_number, line in enumerate(lines, 1):
            for match in re.finditer(r'\$\{\{\s*secrets\.([A-Za-z_][A-Za-z0-9_]*)\s*\}\}', line):
                sites.append({'kind': 'config_reference_syntax', 'name': 'secrets.' + match.group(1),
                    'label': 'reference_only', 'reference': {'evidence_id': source['id'],
                    'start_line': line_number, 'end_line': line_number, 'quote': match.group(0)}})
        try:
            tree = ast.parse(content) if path.endswith('.py') else None
        except (SyntaxError, ValueError):
            tree = None
        parent_classes = []
        if tree is not None:
            sites.extend(_class_definition_sites(tree, source))
            parents = {commit.get('parent') for commit in package.get('commits', [])
                       if commit.get('sha') == source['version_id'] and commit.get('parent')}
            for parent in package.get('evidence', []):
                if (parent.get('kind') != 'source' or parent.get('version_id') not in parents
                        or _path(parent) != path or not _allowed(parent, task)):
                    continue
                try:
                    definitions = _class_definition_sites(ast.parse(parent.get('content', '')), parent)
                except (SyntaxError, ValueError):
                    continue
                if definitions:
                    parent_row = {'evidence_id': parent['id'], 'path': path,
                        'version_id': parent['version_id'], 'version_role': 'parent',
                        'sites': definitions}
                    duplicates = _duplicate_class_list_literals(definitions)
                    if duplicates:
                        parent_row['duplicate_class_list_literals'] = duplicates
                    parent_classes.append(parent_row)
        unittest_methods = _unittest_method_candidates(tree) if _test_path(path) else {}
        continuation_lines = (_explicit_line_continuation_lines(content)
                              if tree is not None and _test_path(path) else [])
        for node in ast.walk(tree) if tree is not None else []:
            for _, statements in ast.iter_fields(node):
                if not isinstance(statements, list):
                    continue
                for first, second in zip(statements, statements[1:]):
                    if isinstance(first, ast.Return) and isinstance(second, ast.Return):
                        sites.append({'kind': 'adjacent_return_syntax', 'label': 'lexical_order_only',
                            'same_return_expression_syntax': ast.dump(first) == ast.dump(second),
                            'returns': [{'location': _syntax_location(statement), 'reference': {
                                'evidence_id': source['id'], 'start_line': statement.lineno,
                                'end_line': statement.end_lineno,
                                'quote': ''.join(lines[statement.lineno - 1:statement.end_lineno]).rstrip('\r\n')}}
                                for statement in (first, second)]})
            test = _test_path(path) and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith('test_')
            call = isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and (
                node.func.attr == 'json' or any(isinstance(arg, ast.Constant) and isinstance(arg.value, str)
                and (arg.value.startswith(('https://', 'http://', '/'))) for arg in node.args))
            unittest_candidate = node in unittest_methods
            if test or unittest_candidate or call:
                site = {'kind': 'test_function' if test else 'unittest_method_candidate' if unittest_candidate else 'call_syntax',
                    'name': node.name if test or unittest_candidate else ast.get_source_segment(source['content'], node.func),
                    'reference': {'evidence_id': source['id'], 'start_line': node.lineno,
                                  'end_line': node.end_lineno,
                                  'quote': ''.join(lines[node.lineno - 1:node.end_lineno]).rstrip('\r\n')}}
                if test or unittest_candidate:
                    site['syntax_facts'] = _test_syntax_facts(node, continuation_lines)
                if unittest_candidate:
                    owner, references = unittest_methods[node]
                    site.update(label='lexical_candidate_only', owner_class=owner,
                                candidate_base_references=references, inheritance_verified=False,
                                collection_verified=False)
                sites.append(site)
            elif (not _test_path(path) and isinstance(node, ast.BoolOp)
                  and any(isinstance(child, ast.Attribute) or isinstance(child, ast.Call)
                          and _syntax_name(child.func) == 'isinstance' for child in ast.walk(node))):
                sites.append({'kind': 'short_circuit_syntax', 'name': type(node.op).__name__,
                    'label': 'evaluation_order_only',
                    'later_operands_require': 'all_previous_truthy' if isinstance(node.op, ast.And) else 'all_previous_falsy',
                    'operands': [{'node_type': type(value).__name__, 'location': _syntax_location(value),
                                  'source': ast.get_source_segment(content, value)}
                                 for value in node.values],
                    'reference': {'evidence_id': source['id'], 'start_line': node.lineno,
                                  'end_line': node.end_lineno,
                                  'quote': ''.join(lines[node.lineno - 1:node.end_lineno]).rstrip('\r\n')}})
        if sites or parent_classes:
            row = {'evidence_id': source['id'], 'path': path, 'version_id': source['version_id'],
                   'line_count': len(lines), 'sites': sites}
            duplicates = _duplicate_class_list_literals(sites)
            if duplicates:
                row['duplicate_class_list_literals'] = duplicates
            if parent_classes:
                row['parent_class_definitions'] = parent_classes
            result.append(row)
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


def _local_failure_item(check, package):
    iid = LOCAL_FAILURE_ITEMS.get(check['rule_id'])
    for rule in package.get('sop_catalog', {}).get('rules', []):
        for condition in rule.get('conditions', []):
            contract = condition.get('contract', {})
            if contract.get('origin') != 'library_interpretation' or contract.get('version') != VERSION:
                continue
            for item in contract.get('items', []):
                if item.get('id') == iid and item.get('failure_review', {}).get('version') == VERSION:
                    return {'item': item, 'source_ref': condition.get('source_ref')}
    return None


def local_failure_binding(check, task, package):
    """Bind a program-owned review to this candidate and its scoped original inputs."""
    def digest(value):
        return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                         separators=(',', ':')).encode()).hexdigest()
    versions = set(task.get('commit_ids', [])) | set(task.get('target_commit_ids', []))
    versions |= {c.get('parent') for c in package.get('commits', []) if c.get('sha') in versions}
    user_ids = _ids(task.get('requirement_refs', []))
    user_ids.update(eid for point in task.get('acceptance_points', []) for eid in _ids(point.get('requirement_refs', [])))
    sources = [{key: item.get(key) for key in ('id', 'kind', 'path', 'version_id', 'target_ids')}
               | {'content_sha256': hashlib.sha256(item.get('content', '').encode()).hexdigest()}
               for item in package.get('evidence', []) if _allowed(item, task)
               and (not item.get('version_id') or item.get('version_id') in versions)
               and (item.get('kind') != 'user_requirement' or item['id'] in user_ids)]
    frozen_task = {key: task.get(key) for key in ('id', 'title', 'goal', 'requirement_refs', 'commit_ids',
                   'target_commit_ids', 'acceptance_points', 'superseded_requirements')}
    return {'task_id': task['id'], 'rule_id': check['rule_id'],
            'target_commit_ids': sorted(task.get('target_commit_ids', [])),
            'atomic_item_id': LOCAL_FAILURE_ITEMS[check['rule_id']],
            'candidate_sha256': digest(check['local_failure_candidate']),
            'input_sha256': digest({'task': frozen_task, 'sources': sources,
                'changes': [c for c in package.get('changes', []) if c.get('commit_id') in versions],
                'rules': package.get('rules', []), 'rule_source': package.get('rule_source'),
                'fixed_item': _local_failure_item(check, package),
                'contract_sha256': package.get('sop_catalog', {}).get('contract_sha256'),
                'runs': [r for r in package.get('run_verification', []) if r.get('commit_sha') in versions]})}



def _local_failure_outcome(check, task, package):
    check.setdefault('local_failure_candidate', {key: copy.deepcopy(check.get(key)) for key in
        ('scope', 'reason', 'claim_kind', 'evidence_refs', 'counter_refs')})
    check['local_failure_candidate']['result'] = FAIL
    binding = local_failure_binding(check, task, package)
    review = check.get('local_failure_review', {})
    inconsistent = (review.get('binding') == binding and review.get('status') == 'completed' and
        (type(review.get('confirmed')) is not bool
         or review.get('effective_result') != (FAIL if review.get('confirmed') is True else UNKNOWN)
         or review.get('confirmed') is True and
            (review.get('relation') != 'direct_counterexample' or review.get('scope_consistency') != 'same_scope')))
    if inconsistent:
        review = {'status': 'pending', 'confirmed': False, 'effective_result': UNKNOWN, 'binding': binding,
                  'reason': '复核回执状态自相矛盾，须重新核对；原模型失败候选尚未获同范围支持。',
                  'invalidated_review': copy.deepcopy(review)}
        check['local_failure_review'] = review
    if review.get('binding') != binding or review.get('status') not in {'pending', 'completed', 'failed'}:
        review = {'status': 'pending', 'confirmed': False, 'effective_result': UNKNOWN,
                  'binding': binding, 'reason': '原模型不满足候选待同范围独立反例复核；尚未确认实际违约。'}
        check['local_failure_review'] = review
    confirmed = (review.get('status') == 'completed' and review.get('confirmed') is True
                 and review.get('effective_result') == FAIL
                 and review.get('relation') == 'direct_counterexample'
                 and review.get('scope_consistency') == 'same_scope')
    check['reason'] = review['reason']
    if review.get('status') == 'completed':
        answer = review.get('review', {})
        check['evidence_refs'] = copy.deepcopy(answer.get('obligation_refs', []) + answer.get('counterexample_refs', []))
        check['counter_refs'] = []
    return FAIL if confirmed else UNKNOWN


def _automatic_review(result):
    automatic = _aggregate([c['automated_result'] for c in result.get('checks', [])
                            if c.get('automated_result') != NA])
    if automatic == PASS and result.get('unmapped_changes'):
        automatic = UNKNOWN
    complete = all(c.get('local_failure_review', {}).get('status') not in {'pending', 'failed'}
                   for c in result.get('checks', []))
    result['automatic_review'] = {'status': 'completed' if complete else 'incomplete',
        'analysis_complete': complete, 'outcome': automatic,
        'scope': '需求、实现、断言与受信运行的自动可验证子集；不声明真实业务验收或正式 SOP 关闭。'}


def project_local_failures(result, package, task_ids):
    tasks = {task['id']: task for task in result['tasks'] if task['id'] in task_ids}
    changed = False
    for check in result.get('checks', []):
        if check.get('task_id') not in tasks or not check.get('local_failure_candidate'):
            continue
        if check.get('local_failure_base_result') == FAIL:
            continue
        outcome = _local_failure_outcome(check, tasks[check['task_id']], package)
        check.update(automated_result=outcome, sop_result=outcome, result=outcome)
        for proof in check.get('gate_details', []):
            if proof['id'] == check['rule_id'] + '-local-counterexample-review':
                proof.update(met=outcome == FAIL, reason=check['reason'])
        changed = True
    if changed:
        _automatic_review(result)
    return result

def apply_policy(result, package, *, task_ids=None):
    evidence = {e['id']: e for e in package.get('evidence', [])}
    changes = {c['id']: c for c in package.get('changes', [])}
    rules = {r['id']: r for r in package.get('rules', [])}
    runs = package.get('run_verification', [])
    acceptance_checks = result.get('acceptance_checks', [])
    chosen = None if task_ids is None else set(task_ids)
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
        if chosen is not None and task['id'] not in chosen:
            old_rows = [a for a in acceptance_checks if a.get('task_id') == task['id']]
            for cid, change in changes.items():
                if change.get('commit_id') not in task.get('commit_ids', []):
                    continue
                linked = [a['acceptance_id'] for a in old_rows if cid in a.get('change_ids', [])]
                relations = [{**relation, 'task_id': task['id'], 'acceptance_id': a['acceptance_id']}
                             for a in old_rows for relation in a.get('change_relations', [])
                             if relation.get('change_id') == cid]
                coverage.append({'task_id': task['id'], 'change_id': cid,
                                 'acceptance_ids': linked, 'relations': relations, 'mapped': bool(linked)})
            continue
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
            native_local_review = rid in LOCAL_FAILURE_ITEMS and _local_failure_item(check, package) is not None
            if rid in LOCAL_FAILURE_ITEMS and not native_local_review and check.get('local_failure_candidate'):
                candidate = check.pop('local_failure_candidate')
                check.update({key: copy.deepcopy(candidate[key]) for key in
                              ('scope', 'reason', 'claim_kind', 'evidence_refs', 'counter_refs')})
                check.pop('local_failure_review', None)
                check.pop('local_failure_base_result', None)
            if local == FAIL and native_local_review:
                check['local_failure_base_result'] = outcome
                if outcome == FAIL and check.get('local_failure_candidate'):
                    _local_failure_outcome(check, task, package)
                    check['reason'] = '验收点已有不满足；原自由反例是否成立另列复核。' + '；'.join(
                        a.get('reason', '') for a in rows if a.get('result') == FAIL)
            if local == FAIL and native_local_review and outcome != FAIL:
                outcome = _local_failure_outcome(check, task, package)
                gate('local-counterexample-review', outcome == FAIL, check['reason'])
            elif local == FAIL and rid in {'FIX01', 'FIX02', 'FIX03', 'FIX04'}:
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
    _automatic_review(result)
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

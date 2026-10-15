"""Offline syntax indexing tests; source strings are parsed, never executed."""
import copy
import json
import unittest

from ..audit_policy import target_source_index


TARGET, PARENT = 'a' * 40, 'b' * 40
TASK = {'id': 'T1', 'target_commit_ids': [TARGET]}


def source(content, path='tests/test_selector.py', **fields):
    return {'id': 'SOURCE', 'kind': 'source', 'version_id': TARGET,
            'path': path, 'content': content, **fields}


def index(*sources):
    return target_source_index(TASK, {'evidence': list(sources)})


def sites_of(rows, kind):
    return [site for row in rows for site in row['sites'] if site['kind'] == kind]


class TargetSourceSyntaxIndexTests(unittest.TestCase):
    def test_adjacent_returns_preserve_block_order_and_expression_syntax_only(self):
        content = ('def f():\n'
                   '    if enabled:\n'
                   '        return value, False\n'
                   '        # kept original return\n'
                   '        return (value, False)\n'
                   '    return other\n'
                   '    return changed\n')
        item = source(content, path='module.py')
        before = copy.deepcopy(item)
        sites = sites_of(index(item), 'adjacent_return_syntax')
        pairs = {tuple(r['reference']['start_line'] for r in site['returns']): site for site in sites}
        self.assertEqual(set(pairs), {(3, 5), (6, 7)})
        self.assertTrue(pairs[(3, 5)]['same_return_expression_syntax'])
        self.assertFalse(pairs[(6, 7)]['same_return_expression_syntax'])
        self.assertEqual(pairs[(3, 5)]['returns'][1]['reference']['quote'], '        return (value, False)')
        self.assertTrue(all(site['label'] == 'lexical_order_only' for site in sites))
        self.assertTrue(all('reachable' not in site and 'task_scope_met' not in site for site in sites))
        self.assertEqual(item, before)

    def test_return_pairs_do_not_bridge_blocks_statements_or_hidden_versions(self):
        content = ('def f():\n'
                   '    if enabled:\n'
                   '        return value\n'
                   '    else:\n'
                   '        return value\n'
                   '    return value\n'
                   '    changed = True\n'
                   '    return value\n')
        self.assertFalse(sites_of(index(source(content, path='module.py')), 'adjacent_return_syntax'))
        pair = 'def f():\n    return\n    return\n'
        self.assertTrue(sites_of(index(source(pair, path='module.py')), 'adjacent_return_syntax')[0]
                        ['same_return_expression_syntax'])
        for fields in ({'version_id': PARENT}, {'target_ids': ['other']}, {'kind': 'context'}):
            self.assertFalse(sites_of(index(source(pair, path='module.py', **fields)), 'adjacent_return_syntax'))

    def test_actual_lambda_parameter_names_and_calls_are_explicit(self):
        content = ('def test_different_names():\n'
                   '    first = parse_as_ast(lambda x: x + 1)\n'
                   '    second = parse_as_ast(lambda y: y + 1)\n'
                   '    assert first != second\n')
        site = sites_of(index(source(content)), 'test_function')[0]
        facts = site['syntax_facts']
        self.assertEqual([row['parameters'] for row in facts['lambdas']], [['x'], ['y']])
        self.assertEqual([row['callee'] for row in facts['calls']], ['parse_as_ast'] * 2)
        for call, function in zip(facts['calls'], facts['lambdas']):
            self.assertEqual(call['lambda_arguments'], [{'position': 0, 'lambda_location': function['location']}])
        self.assertEqual(facts['asserts'], [[4, 4, 4, 26]])
        self.assertEqual(site['reference']['quote'], content.rstrip('\n'))
        self.assertEqual(facts['scope'], 'lexical_only')

    def test_same_names_expected_exception_and_assertion_scope_stay_distinct(self):
        content = ('def test_same_names():\n'
                   '    with pytest.raises(ValueError):\n'
                   '        query().select(lambda x: x).select(lambda x: x)\n'
                   '    result = parse_as_ast(lambda y: y, "choose")\n'
                   '    assert result\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual([row['parameters'] for row in facts['lambdas']], [['x'], ['x'], ['y']])
        expected = facts['raises'][0]
        self.assertEqual(expected['exception_names'], ['ValueError'])
        self.assertEqual(expected['body_location'][:3], [3, 8, 3])
        self.assertEqual(facts['asserts'][0][0], 5)
        self.assertLess(expected['body_location'][2], facts['asserts'][0][0])
        self.assertEqual(facts['calls'][-1]['string_arguments'], [{'position': 1, 'value': 'choose'}])
        self.assertEqual(len(facts['calls']), 3)
        self.assertEqual([row['callee'] for row in facts['calls'][:2]], ['<Call>.select'] * 2)
        self.assertNotIn('coverage', facts)
        self.assertNotIn('execution', facts)

    def test_local_lambda_names_and_explicit_string_selectors_are_lexical(self):
        content = ('def test_selectors():\n'
                   '    f = lambda value: value\n'
                   '    g: object = lambda other: other\n'
                   '    parse_as_ast(f, "first", caller_name="second")\n'
                   '    parse_as_ast(g, selector="third")\n'
                   '    (lambda x, /, *args, key=None, **kw: x)("direct")\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual([row['name'] for row in facts['lambda_bindings']], ['f', 'g'])
        calls = facts['calls']
        self.assertEqual(calls[0]['lambda_arguments'], [{'position': 0, 'lexical_name': 'f'}])
        self.assertEqual(calls[0]['string_arguments'], [
            {'position': 1, 'value': 'first'}, {'keyword': 'caller_name', 'value': 'second'}])
        self.assertEqual(calls[1]['string_arguments'], [{'keyword': 'selector', 'value': 'third'}])
        self.assertEqual(calls[2]['lambda_callee_location'], facts['lambdas'][2]['location'])
        self.assertEqual(facts['lambdas'][2]['parameters'], ['x', '*args', 'key', '**kw'])

    def test_comments_and_strings_do_not_invent_lambdas_or_cross_nested_bindings(self):
        content = ('def test_text_only():\n'
                   '    # parse_as_ast(lambda comment: comment)\n'
                   '    text = "lambda text: text"\n'
                   '    parse_as_ast(text, caller_name="lambda fake: fake")\n'
                   '    def helper():\n'
                   '        local = lambda nested: nested\n'
                   '        parse_as_ast(local)\n'
                   '    parse_as_ast(local)\n'
                   '    assert text\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual([row['parameters'] for row in facts['lambdas']], [['nested']])
        self.assertEqual(facts['lambdas'][0]['scope_name'], 'helper')
        self.assertEqual(facts['lambda_bindings'][0]['scope_name'], 'helper')
        self.assertEqual(len(facts['calls']), 2)
        self.assertNotIn('lambda_arguments', facts['calls'][0])
        self.assertEqual(facts['calls'][0]['name_arguments'], [{'position': 0, 'name': 'text'}])
        self.assertEqual(facts['calls'][1]['scope_name'], 'helper')
        self.assertEqual(facts['asserts'][0][0], 9)

    def test_nested_helper_selector_is_visible_without_claiming_lambda_dataflow(self):
        content = ('def test_methods():\n'
                   '    class Query:\n'
                   '        def select_one(self, value):\n'
                   '            parse_as_ast(value, caller_name="select_one")\n'
                   '        def select_two(self, value):\n'
                   '            parse_as_ast(value, "select_two")\n'
                   '    Query().select_one(lambda x: x).select_two(lambda x: x)\n'
                   '    assert True\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual([row['parameters'] for row in facts['lambdas']], [['x'], ['x']])
        helpers = [row for row in facts['calls'] if 'scope_name' in row]
        self.assertEqual([row['scope_name'] for row in helpers], ['select_one', 'select_two'])
        self.assertEqual(helpers[0]['string_arguments'], [{'keyword': 'caller_name', 'value': 'select_one'}])
        self.assertEqual(helpers[1]['string_arguments'], [{'position': 1, 'value': 'select_two'}])
        for row in helpers:
            self.assertEqual(row['name_arguments'], [{'position': 0, 'name': 'value'}])
            self.assertNotIn('lambda_arguments', row)

    def test_target_version_task_and_source_kind_filter_every_site_kind(self):
        content = ('def test_target():\n'
                   '    parse_as_ast(lambda x: x)\n'
                   '    assert True\n'
                   '# ${{ secrets.CONFIG_TOKEN }}\n')
        rows = index(source(content), source(content, id='PARENT', version_id=PARENT),
                     source(content, id='OTHER', target_ids=['T2']),
                     source(content, id='CONTEXT', kind='context'))
        self.assertEqual([row['evidence_id'] for row in rows], ['SOURCE'])
        self.assertEqual({site['kind'] for site in rows[0]['sites']},
                         {'test_function', 'config_reference_syntax'})
        rows = index(source('return isinstance(a, ast.Call) and a.args', path='guard.py', version_id=PARENT),
                     source('return a or a.value', path='guard.py', target_ids=['T2']))
        self.assertEqual(rows, [])

    def test_class_declarations_keep_order_bases_and_literal_attributes(self):
        content = ('class Earlier(Base):\n'
                   '    destinations = ["SHARED", "ALIAS"]\n'
                   'class Later(Base, metaclass=Registry):\n'
                   '    destinations: tuple = ("SHARED", "ALIAS")\n'
                   '    enabled = True\n')
        rows = index(source(content, path='handlers.py'))
        sites = sites_of(rows, 'class_definition_syntax')
        self.assertEqual([site['name'] for site in sites], ['Earlier', 'Later'])
        self.assertEqual([site['syntax_facts']['lexical_order'] for site in sites], [1, 2])
        self.assertTrue(all(site['syntax_facts']['module_top_level'] for site in sites))
        self.assertEqual(sites[1]['syntax_facts']['bases'][0]['source'], 'Base')
        self.assertEqual(sites[1]['reference']['quote'], 'class Later(Base, metaclass=Registry):')
        attributes = sites[1]['syntax_facts']['attributes']
        self.assertEqual(attributes[0]['literal_value'], ['SHARED', 'ALIAS'])
        self.assertEqual(attributes[0]['value_node_type'], 'Tuple')
        self.assertIs(attributes[1]['literal_value'], True)
        self.assertNotIn('binding', json.dumps(rows))
        self.assertNotIn('executed', json.dumps(rows))

    def test_parent_class_metadata_requires_exact_parent_path_and_task(self):
        content = 'class Handler(Base):\n    destinations = ["SHARED"]\n'
        evidence = [source(content, path='handlers.py'),
                    source(content, id='PARENT', path='handlers.py', version_id=PARENT),
                    source(content, id='WRONG_VERSION', path='handlers.py', version_id='d' * 40),
                    source(content, id='WRONG_PATH', path='elsewhere.py', version_id=PARENT),
                    source(content, id='WRONG_TASK', path='handlers.py', version_id=PARENT, target_ids=['T2']),
                    source(content, id='CONTEXT', path='handlers.py', version_id=PARENT, kind='context')]
        rows = target_source_index(TASK, {'evidence': evidence,
            'commits': [{'sha': TARGET, 'parent': PARENT}, {'sha': 'c' * 40, 'parent': 'd' * 40}]})
        self.assertEqual([row['evidence_id'] for row in rows], ['SOURCE'])
        parents = rows[0]['parent_class_definitions']
        self.assertEqual([parent['evidence_id'] for parent in parents], ['PARENT'])
        self.assertEqual(parents[0]['version_id'], PARENT)
        self.assertEqual(parents[0]['version_role'], 'parent')
        self.assertEqual(parents[0]['sites'][0]['reference']['evidence_id'], 'PARENT')
        self.assertNotIn('parent_class_definitions', target_source_index(TASK, {'evidence': evidence})[0])

    def test_dynamic_and_annotation_only_class_attributes_are_not_evaluated(self):
        content = ('class Handler(Base):\n'
                   '    destinations = must_not_execute()\n'
                   '    annotated: str\n'
                   '    absent = None\n'
                   '    mixed = ["KEY", must_not_execute()]\n'
                   '    overflow = 1e400\n')
        attributes = sites_of(index(source(content, path='handlers.py')),
                              'class_definition_syntax')[0]['syntax_facts']['attributes']
        self.assertEqual([item['is_literal'] for item in attributes], [False, False, True, False, False])
        self.assertEqual(attributes[0]['value_location'], [2, 19, 2, 37])
        self.assertIsNone(attributes[1]['value_location'])
        self.assertNotIn('literal_value', attributes[1])
        self.assertIsNone(attributes[2]['literal_value'])
        self.assertNotIn('literal_value', attributes[3])
        json.dumps(attributes, allow_nan=False)

    def test_conditional_and_nested_class_locations_do_not_claim_module_execution(self):
        content = ('if unknown_condition:\n'
                   '    class Conditional(Base):\n'
                   '        token = "条件"\n'
                   'class Outer(Base):\n'
                   '    class Inner(Other):\n'
                   '        token = "嵌套"\n')
        sites = sites_of(index(source(content, path='handlers.py')), 'class_definition_syntax')
        self.assertEqual([site['name'] for site in sites], ['Conditional', 'Outer', 'Inner'])
        self.assertEqual([site['syntax_facts']['module_top_level'] for site in sites], [False, True, False])
        for site in sites:
            ref = site['reference']
            self.assertEqual(ref['quote'], '\n'.join(content.splitlines()[ref['start_line'] - 1:ref['end_line']]))
            self.assertEqual(site['syntax_facts']['scope'], 'lexical_only')
            self.assertNotIn('registered', site['syntax_facts'])

    def test_short_circuit_operands_keep_order_and_never_claim_execution(self):
        content = ('def guarded(a):\n'
                   '    return isinstance(a, ast.Call) and len(a.args) == 1 and a.args[0]\n'
                   'def fallback(a):\n'
                   '    return a is None or a.value\n'
                   'def unrelated(a, b):\n'
                   '    return a and b\n')
        rows = index(source(content, path='guard.py'))
        sites = sites_of(rows, 'short_circuit_syntax')
        self.assertEqual([site['name'] for site in sites], ['And', 'Or'])
        self.assertEqual([row['node_type'] for row in sites[0]['operands']], ['Call', 'Compare', 'Subscript'])
        self.assertEqual([row['location'][1] for row in sites[0]['operands']], [11, 39, 60])
        self.assertEqual([site['later_operands_require'] for site in sites],
                         ['all_previous_truthy', 'all_previous_falsy'])
        self.assertEqual([row['source'] for row in sites[0]['operands']],
                         ['isinstance(a, ast.Call)', 'len(a.args) == 1', 'a.args[0]'])
        self.assertEqual([row['source'] for row in sites[1]['operands']], ['a is None', 'a.value'])
        for site in sites:
            self.assertEqual(site['label'], 'evaluation_order_only')
            self.assertNotIn('result', site)
            self.assertNotIn('executed', site)
        self.assertEqual(sites_of(index(source(content)), 'short_circuit_syntax'), [])

    def test_existing_json_and_path_call_locators_are_preserved(self):
        content = ('def test_requests():\n'
                   '    data = response.json()\n'
                   '    response = client.get("https://example.test/path")\n'
                   '    response = client.post("/items")\n')
        sites = sites_of(index(source(content)), 'call_syntax')
        self.assertEqual([site['name'] for site in sites], ['response.json', 'client.get', 'client.post'])
        self.assertEqual([site['reference']['start_line'] for site in sites], [2, 3, 4])

    def test_config_expressions_are_references_even_in_non_python_source(self):
        content = ('env:\n'
                   '  TOKEN: ${{ secrets.CONFIG_TOKEN }}\n'
                   '  KEY: ${{secrets.OTHER_KEY}}\n'
                   '  TEXT: secrets.PLAIN_TEXT\n'
                   '  OTHER: ${{ vars.VALUE }}\n'
                   '  INVALID: ${{ secrets.HAS-DASH }}\n')
        rows = index(source(content, path='.github/workflows/ci.yml'),
                     source(content, id='PARENT', path='ci.yml', version_id=PARENT),
                     source(content, id='OTHER', path='ci.yml', target_ids=['T2']))
        sites = sites_of(rows, 'config_reference_syntax')
        self.assertEqual([site['name'] for site in sites], ['secrets.CONFIG_TOKEN', 'secrets.OTHER_KEY'])
        self.assertEqual([site['reference']['start_line'] for site in sites], [2, 3])
        self.assertEqual(sites[0]['reference']['quote'], '${{ secrets.CONFIG_TOKEN }}')
        self.assertTrue(all(site['label'] == 'reference_only' for site in sites))
        self.assertTrue(all('result' not in site and 'verified' not in site for site in sites))
        self.assertEqual(sites_of(rows, 'test_function'), [])

    def test_facts_reuse_the_function_reference_without_body_copies(self):
        content = ('def test_compact():\n'
                   '    f = lambda x: x\n'
                   '    with pytest.raises(ValueError):\n'
                   '        parse_as_ast(f, "select")\n'
                   '    assert f\n')
        rows = index(source(content))
        facts = sites_of(rows, 'test_function')[0]['syntax_facts']
        self.assertNotIn('quote', json.dumps(facts))
        original = copy.deepcopy(rows)
        del original[0]['sites'][0]['syntax_facts']
        self.assertLess(len(json.dumps(rows)), 4 * len(json.dumps(original)))

    def test_lambda_groups_use_physical_start_lines_despite_the_function_name(self):
        content = ('def test_continues_one_line():\n'
                   '    query().select(lambda x: x).select(lambda y: y) \\\n'
                   '        .finish()\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        locations = [row['location'] for row in facts['lambdas']]
        self.assertEqual([location[0] for location in locations], [2, 2])
        self.assertEqual(facts['lambda_physical_line_groups'],
                         [{'line': 2, 'lambda_locations': locations}])
        self.assertEqual(facts['explicit_line_continuation_lines'], [2])
        self.assertNotIn('coverage', facts)
        self.assertNotIn('execution', facts)

    def test_lambda_start_lines_do_not_merge_across_explicit_or_implicit_joins(self):
        content = ('def test_same_line_name():\n'
                   '    query().select(lambda x: x) \\\n'
                   '        .select(lambda y: y)\n'
                   '    query().select(\n'
                   '        lambda a: a\n'
                   '    ).select(lambda b: b)\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual([row['location'][0] for row in facts['lambdas']], [2, 3, 5, 6])
        self.assertNotIn('lambda_physical_line_groups', facts)
        self.assertEqual(facts['explicit_line_continuation_lines'], [2])

    def test_backslashes_in_comments_and_multiline_strings_are_not_code_joins(self):
        content = ('def test_token_layout():\n'
                   '    # fake comment \\\n'
                   '    text = """fake string \\\n'
                   'still inside string\n'
                   '"""\n'
                   '    formatted = f"""fake formatted string \\\n'
                   'still inside formatted string\n'
                   '"""\n'
                   '    assert text and formatted  # inline fake \\\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertNotIn('explicit_line_continuation_lines', facts)
        self.assertNotIn('lambda_physical_line_groups', facts)

    def test_continuation_lines_are_physical_and_limited_to_the_function(self):
        content = ('value = 1 + \\\n'
                   '    2\n'
                   'def test_unicode():\n'
                   '    text = "中文"\n'
                   '    query().select(lambda x: x).select(lambda x: x) \\\n'
                   '        .finish()\n'
                   'def helper():\n'
                   '    return 3 + \\\n'
                   '        4\n')
        for newline in ('\n', '\r\n', '\r'):
            with self.subTest(newline=repr(newline)):
                facts = sites_of(index(source(content.replace('\n', newline))),
                                 'test_function')[0]['syntax_facts']
                self.assertEqual(facts['explicit_line_continuation_lines'], [5])
                self.assertEqual(facts['lambda_physical_line_groups'][0]['line'], 5)

    def test_one_multiline_lambda_is_not_a_same_line_group(self):
        content = ('def test_multiline_lambda():\n'
                   '    parse_as_ast(lambda x: (\n'
                   '        x + 1\n'
                   '    ))\n')
        facts = sites_of(index(source(content)), 'test_function')[0]['syntax_facts']
        self.assertEqual(len(facts['lambdas']), 1)
        self.assertNotIn('lambda_physical_line_groups', facts)
        self.assertNotIn('explicit_line_continuation_lines', facts)


    def test_unittest_camel_case_method_is_a_locator_not_collection_proof(self):
        content = ('import unittest\n'
                   'class Case(unittest.TestCase):\n'
                   '    def testCamel(self):\n'
                   '        self.assertEqual(1, 1)\n'
                   '        raise RuntimeError("never execute source")\n')
        site = sites_of(index(source(content)), 'unittest_method_candidate')[0]
        self.assertEqual(site['name'], 'testCamel')
        self.assertEqual(site['owner_class'], 'Case')
        self.assertEqual(site['reference']['start_line'], 3)
        self.assertIn('self.assertEqual(1, 1)', site['reference']['quote'])
        self.assertEqual(site['label'], 'lexical_candidate_only')
        self.assertIs(site['inheritance_verified'], False)
        self.assertIs(site['collection_verified'], False)
        self.assertNotIn('result', site)

    def test_unittest_import_assignment_and_local_aliases_are_only_candidates(self):
        content = ('import unittest as unit\n'
                   'from unittest import TestCase as ImportedCase\n'
                   'Alias = ImportedCase\n'
                   'class First(unit.TestCase):\n'
                   '    def testFirst(self): pass\n'
                   'class Second(Alias):\n'
                   '    def testSecond(self): pass\n'
                   'class Third(Second):\n'
                   '    def testThird(self): pass\n')
        candidates = sites_of(index(source(content)), 'unittest_method_candidate')
        self.assertEqual([site['name'] for site in candidates], ['testFirst', 'testSecond', 'testThird'])
        self.assertEqual([site['candidate_base_references'] for site in candidates],
                         [['unit.TestCase'], ['Alias'], ['Second']])
        self.assertTrue(all(site['inheritance_verified'] is False for site in candidates))
        self.assertTrue(all(site['collection_verified'] is False for site in candidates))

    def test_ordinary_testimony_and_main_guard_function_are_not_promoted(self):
        content = ('class Plain:\n'
                   '    def testimony(self): pass\n'
                   'class FakeTestCase:\n'
                   '    def testimony(self): pass\n'
                   'class Derived(FakeTestCase):\n'
                   '    def testimony(self): pass\n'
                   'class Dynamic(factory_must_not_execute()):\n'
                   '    def testCamel(self): pass\n'
                   'if __name__ == "__main__":\n'
                   '    def testCamelOutside(self): pass\n'
                   'def test_legacy():\n'
                   '    assert True\n')
        rows = index(source(content))
        self.assertEqual(sites_of(rows, 'unittest_method_candidate'), [])
        self.assertEqual([site['name'] for site in sites_of(rows, 'test_function')], ['test_legacy'])

    def test_duplicate_class_lists_keep_order_exact_references_and_deduplicate_values(self):
        content = ('class First:\n'
                   '    labels = ["shared", "shared", "中文"]\n'
                   'class Second:\n'
                   '    labels = [\n'
                   '        "shared", "中文",\n'
                   '    ]\n'
                   '    another = ["shared"]\n')
        for newline in ('\n', '\r\n', '\r'):
            with self.subTest(newline=repr(newline)):
                original = source(content.replace('\n', newline), path='handlers.py')
                before = copy.deepcopy(original)
                row = index(original)[0]
                groups = row['duplicate_class_list_literals']
                self.assertEqual([(g['attribute_name'], g['string_value']) for g in groups],
                                 [('labels', 'shared'), ('labels', '中文')])
                for group in groups:
                    self.assertEqual([d['class_name'] for d in group['declarations']], ['First', 'Second'])
                    self.assertEqual([d['lexical_order'] for d in group['declarations']], [1, 2])
                    self.assertEqual(group['last_lexical_declaration'], group['declarations'][-1])
                    self.assertEqual(group['scope'], 'lexical_only')
                    self.assertIs(group['runtime_binding_verified'], False)
                    self.assertEqual(group['declarations'][1]['attribute_location'][:3], [4, 4, 6])
                    self.assertEqual(group['declarations'][0]['class_reference'], row['sites'][0]['reference'])
                    self.assertEqual(group['declarations'][1]['attribute_location'],
                                     row['sites'][1]['syntax_facts']['attributes'][0]['location'])
                    self.assertNotIn('attribute_reference', group['declarations'][1])
                self.assertEqual(original, before)

    def test_duplicate_class_lists_exclude_single_class_nested_and_nonliteral_values(self):
        content = ('class First:\n'
                   '    labels = ["shared", "shared"]\n'
                   '    scalar = "shared"\n'
                   '    tuple_value = ("shared",)\n'
                   '    mixed = ["shared", 1]\n'
                   '    dynamic = ["shared", must_not_execute()]\n'
                   'if flag:\n'
                   '    class Conditional:\n'
                   '        labels = ["shared"]\n'
                   'def factory():\n'
                   '    class Local:\n'
                   '        labels = ["shared"]\n'
                   'class Container:\n'
                   '    class Nested:\n'
                   '        labels = ["shared"]\n'
                   'class Second:\n'
                   '    scalar = "shared"\n'
                   '    tuple_value = ("shared",)\n'
                   '    mixed = ["shared", 1]\n'
                   '    dynamic = ["shared", must_not_execute()]\n')
        row = index(source(content, path='handlers.py'))[0]
        self.assertNotIn('duplicate_class_list_literals', row)
        self.assertEqual(len(sites_of([row], 'class_definition_syntax')), 6)

    def test_duplicate_class_lists_are_separate_for_parent_version_path_and_task(self):
        def pair(value):
            return f'class First:\n    markers = ["{value}"]\nclass Second:\n    markers = ["{value}"]\n'
        target = source(pair('new'), path='handlers.py')
        parent = source(pair('old'), path='handlers.py', id='PARENT', version_id=PARENT)
        wrongs = [source(pair('foreign'), path='handlers.py', id='WRONG_VERSION', version_id='c' * 40),
                  source(pair('foreign'), path='other.py', id='WRONG_PATH', version_id=PARENT),
                  source(pair('foreign'), path='handlers.py', id='WRONG_TASK', version_id=PARENT,
                         target_ids=['T2'])]
        package = {'evidence': [target, parent, *wrongs],
                   'commits': [{'sha': TARGET, 'parent': PARENT}]}
        rows = target_source_index(TASK, package)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]['duplicate_class_list_literals'][0]['string_value'], 'new')
        parents = rows[0]['parent_class_definitions']
        self.assertEqual([(p['evidence_id'], p['version_role']) for p in parents], [('PARENT', 'parent')])
        group = parents[0]['duplicate_class_list_literals'][0]
        self.assertEqual(group['string_value'], 'old')
        self.assertTrue(all(d['class_reference']['evidence_id'] == 'PARENT' for d in group['declarations']))
        single = 'class Only:\n    markers = ["cross"]\n'
        separated = index(source(single, path='one.py', id='ONE'), source(single, path='two.py', id='TWO'))
        self.assertTrue(all('duplicate_class_list_literals' not in row for row in separated))

    def test_duplicate_class_lists_do_not_resolve_reassignments_or_runtime_execution(self):
        content = ('@must_not_execute()\n'
                   'class First(metaclass=must_not_execute()):\n'
                   '    labels = ["shared"]\n'
                   '    labels = unresolved()\n'
                   'raise RuntimeError("source must never execute")\n'
                   'class Second:\n'
                   '    labels = ["shared"]\n'
                   'First.labels = ["changed"]\n')
        group = index(source(content, path='handlers.py'))[0]['duplicate_class_list_literals'][0]
        self.assertEqual([d['class_name'] for d in group['declarations']], ['First', 'Second'])
        self.assertEqual([d['attribute_location'][0] for d in group['declarations']], [3, 7])
        self.assertIs(group['runtime_binding_verified'], False)
        self.assertEqual(group['scope'], 'lexical_only')
        self.assertNotIn('winner', group)
        self.assertNotIn('result', group)

    def test_same_class_name_redeclarations_use_sites_not_names_or_effective_attributes(self):
        first = ('class Reused:\n'
                 '    labels = ["shared"]\n'
                 '    labels = ["shared"]\n')
        self.assertNotIn('duplicate_class_list_literals', index(source(first, path='handlers.py'))[0])
        content = first + 'class Reused:\n    labels = ["shared"]\n'
        group = index(source(content, path='handlers.py'))[0]['duplicate_class_list_literals'][0]
        declarations = group['declarations']
        self.assertEqual([d['class_name'] for d in declarations], ['Reused'] * 3)
        self.assertEqual([d['lexical_order'] for d in declarations], [1, 1, 2])
        self.assertEqual(declarations[0]['class_location'], declarations[1]['class_location'])
        self.assertNotEqual(declarations[0]['class_location'], declarations[2]['class_location'])
        self.assertEqual(group['last_lexical_declaration']['attribute_location'][0], 5)
        self.assertIs(group['runtime_binding_verified'], False)

    def test_qualified_case_reference_never_imports_or_certifies_inheritance(self):
        content = ('import module_that_is_not_installed as helpers\n'
                   'class Case(helpers.RaytracingTestCase):\n'
                   '    def testCamel(self):\n'
                   '        assert False\n')
        site = sites_of(index(source(content)), 'unittest_method_candidate')[0]
        self.assertEqual(site['candidate_base_references'], ['helpers.RaytracingTestCase'])
        self.assertIs(site['inheritance_verified'], False)
        self.assertIs(site['collection_verified'], False)
        self.assertNotIn('executed', site)


if __name__ == '__main__':
    unittest.main()

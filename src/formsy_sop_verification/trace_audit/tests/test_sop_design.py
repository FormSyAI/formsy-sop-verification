"""Synthetic offline checks for the complete original-design response contract."""
import copy
import unittest
from pathlib import Path

from ..sop_catalog import load_catalog
from ..sop_design import design_input, design_response
from .test_sop_audit import fixtures, ref


class DesignResponseContractTests(unittest.TestCase):
    def setUp(self):
        result, self.package, _ = fixtures()
        self.task = result['tasks'][0]
        rule = next(rule for rule in load_catalog(Path(__file__).resolve().parents[1])['rules']
                    if rule['id'] == 'TC12')
        self.conditions = [condition for condition in rule['conditions'] if condition['id'] == 'TC12.C01']
        self.payload = design_input(self.task, self.conditions, self.package)

    def unknown_response(self):
        value = copy.deepcopy(self.payload['response_contract']['structure_example'])
        for parent in value['conditions']:
            parent.update(result='未核查', reason='缺少完整原设计记录。', gap_type='evidence_missing')
            for child in parent['atomic_checks']:
                child.update(result='未核查', reason='此设计要素缺少直接依据。', gap_type='evidence_missing')
        return value

    def validate(self, value):
        return design_response(value, self.task, self.conditions, self.package, self.payload)

    def test_published_template_can_form_a_complete_valid_response(self):
        contract = self.payload['response_contract']
        value = self.unknown_response()
        parent = value['conditions'][0]
        self.assertEqual(set(parent), set(contract['required_fields']['condition']))
        self.assertEqual([child['id'] for child in parent['atomic_checks']],
                         [item['id'] for item in self.conditions[0]['contract']['items']])
        for child in parent['atomic_checks']:
            self.assertEqual(set(child), set(contract['required_fields']['atomic_check']))
        validated = self.validate(value)[0]
        self.assertEqual(validated['result'], '未核查')
        self.assertEqual(validated['reason'], parent['reason'])
        self.assertEqual(len(validated['atomic_checks']), len(parent['atomic_checks']))

    def test_complete_atomic_judgments_cannot_replace_missing_parent_judgment(self):
        value = self.unknown_response()
        parent = value['conditions'][0]
        parent = {'condition_id': parent['condition_id'], 'atomic_checks': parent['atomic_checks']}
        value['conditions'] = [parent]
        before = copy.deepcopy(value)
        with self.assertRaisesRegex(ValueError, 'SOP条件缺少有效四态结论或具体理由'):
            self.validate(value)
        self.assertEqual(value, before, 'Invalid output must not gain a program-inferred parent judgment.')

    def test_missing_parent_result_reason_or_unknown_gap_is_still_rejected(self):
        for field in ('result', 'reason', 'gap_type'):
            with self.subTest(field=field):
                value = self.unknown_response()
                del value['conditions'][0][field]
                with self.assertRaises(ValueError):
                    self.validate(value)

    def test_complete_parent_does_not_relax_atomic_semantic_basis(self):
        value = self.unknown_response()
        check = next(check for check in value['conditions'][0]['atomic_checks']
                     if check['id'] == 'TC12.C01.I05')
        check.update(result='满足', reason='用户明确期望保留零值。', gap_type='',
                     evidence_refs=[ref('U', '保留零值')], acceptance_ids=['A1'])
        with self.assertRaisesRegex(ValueError, 'semantic_basis'):
            self.validate(value)


if __name__ == '__main__':
    unittest.main()

"""Credential redaction must not erase the worker's typed authorization facts."""
import copy
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.full_audit import _ClientAdapter
from formsy_sop_verification.trace_audit.model_client import (
    DeepSeekClient, ModelOutputError, redact, redact_value, save_json)
from formsy_sop_verification.trace_audit.sop_audit import _condition_response
from formsy_sop_verification.trace_audit.sop_catalog import load_catalog
from formsy_sop_verification.trace_audit.tests.test_sop_audit import fixtures, ref


KEY = "synthetic-semantic-key"


def basis():
    return {'basis_type': 'authorization_contract', 'dimension': 'authorization',
        'audit_object': 'target_product', 'authorization': {
            'subject': 'requesting user', 'destination': 'repository limit.py',
            'action': 'change the return selection', 'boundary': 'only the named limit function'},
        'contract_refs': [ref('U', '仅修复limit函数')],
        'action_refs': [ref('S', 'return 25 if value is None else value')]}


def candidate(*, atomic=False, rows='conditions', prefixes=()):
    check = {'semantic_basis': basis()}
    if atomic:
        check = {'atomic_checks': [check]}
    value = {rows: [check]}
    for prefix in reversed(prefixes):
        value = {prefix: value}
    return value


class SemanticRedactionTests(unittest.TestCase):
    def test_secret_dictionary_keys_are_redacted_in_objects_and_encoded_json(self):
        generic = 'sk-' + 's' * 32
        value = {KEY: {'nested': {generic: 'ordinary'}}, 'safe': 'unchanged'}
        safe = redact_value(value, (KEY,))
        self.assertNotIn(KEY, json.dumps(safe))
        self.assertNotIn(generic, json.dumps(safe))
        self.assertEqual(safe['safe'], 'unchanged')
        for text in (json.dumps(value), json.dumps(json.dumps(value))):
            with self.subTest(text=text[:30]):
                result = json.loads(redact(text, (KEY,)))
                if isinstance(result, str):
                    result = json.loads(result)
                self.assertEqual(result, safe)
        with tempfile.TemporaryDirectory() as root, patch.dict('os.environ', {'DEEPSEEK_API_KEY': KEY}, clear=True):
            save_json(Path(root) / 'keys.json', value)
            retained = (Path(root) / 'keys.json').read_text()
            self.assertNotIn(KEY, retained)
            self.assertNotIn(generic, retained)

    def test_only_owned_condition_paths_preserve_exactly_typed_authorization(self):
        for rows in ('conditions', 'sop_condition_checks'):
            for atomic in (False, True):
                for prefixes in ((), ('payload',), ('previous_candidate',), ('report',), ('payload', 'previous_candidate')):
                    with self.subTest(rows=rows, atomic=atomic, prefixes=prefixes):
                        value = candidate(atomic=atomic, rows=rows, prefixes=prefixes)
                        before = copy.deepcopy(value)
                        self.assertEqual(redact_value(value, (KEY,)), value)
                        text = json.dumps(value, ensure_ascii=False)
                        self.assertEqual(json.loads(redact(text, (KEY,))), value)
                        escaped = json.dumps(text)
                        self.assertEqual(json.loads(json.loads(redact(escaped, (KEY,)))), value)
                        self.assertEqual(value, before)

    def test_wrong_path_shape_scope_or_headers_are_never_exempt(self):
        wrong_paths = [basis(), {'Headers': {'Authorization': basis()['authorization']}},
            {'metadata': candidate()}, {'conditions': {'semantic_basis': basis()}},
            {'conditions': {0: {'semantic_basis': basis()}}},
            {'conditions': [{'wrapper': {'semantic_basis': basis()}}]},
            {'conditions': [{'atomic_checks': {'semantic_basis': basis()}}]},
            {'conditions': [{'atomic_checks': {0: {'semantic_basis': basis()}}}]}]
        for name, wrong in [('basis_type', 'unknown'), ('dimension', 'credentials'),
                            ('audit_object', 'audit_runtime'), ('audit_object', {})]:
            value = candidate()
            value['conditions'][0]['semantic_basis'][name] = wrong
            wrong_paths.append(value)
        for contract in [KEY, {'subject': KEY}, {**basis()['authorization'], 'token': KEY},
                         {**basis()['authorization'], 'boundary': ''},
                         {**basis()['authorization'], 'subject': {'password': KEY}}]:
            value = candidate()
            value['conditions'][0]['semantic_basis']['authorization'] = contract
            wrong_paths.append(value)
        for value in wrong_paths:
            with self.subTest(value=value):
                safe = redact_value(value, (KEY,))
                encoded = json.dumps(safe)
                self.assertNotIn('requesting user', encoded)
                self.assertNotIn(KEY, encoded)
                self.assertIn('[REDACTED]', encoded)
                self.assertEqual(json.loads(redact(json.dumps(value), (KEY,))), json.loads(json.dumps(safe)))

    def test_valid_authorization_values_still_redact_keys_bearer_and_tokens(self):
        value = candidate()
        contract = value['conditions'][0]['semantic_basis']['authorization']
        contract.update(subject='user ' + KEY, destination='Bearer synthetic-bearer',
                        action='token=synthetic-token', boundary='access_token="synthetic-access"')
        before = copy.deepcopy(value)
        safe = redact_value(value, (KEY,))
        self.assertIsInstance(safe['conditions'][0]['semantic_basis']['authorization'], dict)
        for secret in (KEY, 'synthetic-bearer', 'synthetic-token', 'synthetic-access'):
            self.assertNotIn(secret, json.dumps(safe))
        self.assertEqual(value, before)
        self.assertEqual(json.loads(redact(json.dumps(value), (KEY,))), safe)

    def test_adapter_saved_payload_response_and_native_validator_keep_authorization_facts(self):
        result, package, _ = fixtures()
        task = result['tasks'][0]
        catalog = load_catalog(Path(__file__).resolve().parents[1] / 'src/formsy_sop_verification/trace_audit')
        rule = next(rule for rule in catalog['rules'] if rule['id'] == 'TC09')
        condition = next(row for row in rule['conditions'] if row['id'] == 'TC09.C02')
        row = {'condition_id': condition['id'], 'result': '满足', 'reason': 'The named change stays within the request.',
               'gap_type': '', 'evidence_refs': [ref('U', '仅修复limit函数'), ref('S', 'return 25 if value is None else value')],
               'acceptance_ids': ['A1'], 'improvement': '', 'verification': '', 'semantic_basis': basis()}
        response = {'conditions': [row]}

        class Client:
            key = KEY
            def complete(self, system, payload): return copy.deepcopy(response)

        before = copy.deepcopy(response)
        with tempfile.TemporaryDirectory() as root, patch.dict('os.environ', {'DEEPSEEK_API_KEY': KEY}, clear=True):
            returned = _ClientAdapter(Client(), 8, lambda _: None).complete(
                'Return conditions.', {'previous_candidate': response}, root, 'sop-condition-T1-1')
            checked = _condition_response(returned, task, [condition], package, strict_basis=True)
            self.assertEqual(checked[0]['atomic_checks'][0]['semantic_basis']['authorization'], basis()['authorization'])
            self.assertEqual(checked[0]['atomic_checks'][0]['result'], '满足')
            retained = json.loads((Path(root) / 'sop-condition-T1-1.call-001.response.json').read_text())
            self.assertEqual(retained, response)
            request = json.loads((Path(root) / 'sop-condition-T1-1.call-001.request.json').read_text())
            self.assertEqual(request['payload']['previous_candidate'], response)
            save_json(Path(root) / 'report.json', {'sop_condition_checks': [row]})
            self.assertIsInstance(json.loads((Path(root) / 'report.json').read_text())['sop_condition_checks'][0]['semantic_basis']['authorization'], dict)
        self.assertEqual(response, before)

    def test_legacy_parses_before_redaction_and_retains_safe_provider_wire(self):
        value = candidate()
        value['conditions'][0]['semantic_basis']['authorization']['subject'] += ' ' + KEY
        raw = json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content': json.dumps(value)}}]}).encode()
        with tempfile.TemporaryDirectory() as root, patch.dict('os.environ', {'DEEPSEEK_API_KEY': KEY}, clear=True), \
             patch('urllib.request.OpenerDirector.open', return_value=io.BytesIO(raw)) as wire:
            returned = DeepSeekClient(root).complete('Return conditions.', {}, root, 'analysis-1')
            self.assertIsInstance(returned['conditions'][0]['semantic_basis']['authorization'], dict)
            self.assertNotIn(KEY, json.dumps(returned))
            artifact = json.loads((Path(root) / 'analysis-1.provider-response.json').read_text())
            self.assertEqual(artifact['received_sha256'], 'sha256:' + hashlib.sha256(raw).hexdigest())
            self.assertNotIn(KEY, json.dumps(artifact))
            self.assertEqual(wire.call_count, 1)
            self.assertEqual(wire.call_args.kwargs['timeout'], 180)
            provider = json.loads(artifact['raw_text'])
            retained = json.loads(provider['choices'][0]['message']['content'])
            self.assertIsInstance(retained['conditions'][0]['semantic_basis']['authorization'], dict)

    def test_legacy_duplicate_json_is_rejected_before_redaction_can_hide_it(self):
        cases = [b'{"choices":[],"choices":[]}',
            json.dumps({'choices': [{'finish_reason': 'stop', 'message': {'content':
                '{"authorization":"sensitive-a","authorization":"sensitive-b"}'}}]}).encode()]
        for raw in cases:
            with self.subTest(raw=raw[:30]), tempfile.TemporaryDirectory() as root, \
                 patch.dict('os.environ', {'DEEPSEEK_API_KEY': KEY}, clear=True), \
                 patch('urllib.request.OpenerDirector.open', return_value=io.BytesIO(raw)) as wire:
                with self.assertRaises(ModelOutputError):
                    DeepSeekClient(root).complete('Return JSON.', {}, root, 'analysis-1')
                self.assertTrue((Path(root) / 'analysis-1.provider-response.json').exists())
                self.assertEqual(wire.call_count, 1)


if __name__ == '__main__':
    unittest.main()

"""Four-condition boundaries use only synthetic credentials and mocked transport."""
import copy
import importlib.util
import http.client
import tempfile
import threading
import io
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.core import _redact_tree, verify
from formsy_sop_verification.model_client import DeepSeekClient
from fixtures import request


class FourConditionKeyRedactionTests(unittest.TestCase):
    def test_core_tree_scrubs_nested_keys_and_keeps_other_metadata(self):
        key = "sk-" + "SYNTHETIC" * 4
        value = {"ordinary": {key: "instruction"}, "metadata": {"priority": 3, "enabled": True}}
        before = copy.deepcopy(value)
        result = _redact_tree(value)
        self.assertNotIn(key, json.dumps(result))
        self.assertEqual(result["metadata"], value["metadata"])
        self.assertEqual(result["ordinary"]["[REDACTED_KEY]"], "instruction")
        self.assertEqual(value, before)

    def test_core_normalized_sop_reaches_injected_client_with_redacted_keys(self):
        key = "sk-" + "SYNTHETIC" * 4
        payload = request()
        payload["mode"] = "model"
        payload["sop"]["instructions"] = {"ordinary": {key: "instruction"}}
        before = copy.deepcopy(payload)

        class Client:
            model = "offline-fixture"
            request_count = 0
            def complete(self, system, value):
                self.request_count += 1
                self.payload = value
                return {"checks": []}

        client = Client()
        report = verify(payload, client)
        self.assertNotIn(key, json.dumps(client.payload))
        self.assertNotIn(key, json.dumps(report))
        self.assertEqual(client.payload["sop"]["instructions"]["ordinary"]["[REDACTED_KEY]"], "instruction")
        self.assertEqual(client.request_count, 1)
        self.assertEqual(payload, before)

    def test_client_scrubs_configured_non_sk_keys_at_actual_serialization_boundary(self):
        key = "synthetic-configured-credential"
        value = {"ordinary": {key: "instruction"}, "metadata": {"priority": 3}}
        before = copy.deepcopy(value)
        raw = json.dumps({"choices": [{"finish_reason": "stop",
            "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as transport:
            result = DeepSeekClient().complete("Return JSON.", value)
        body = json.loads(transport.call_args.args[0].data)
        sent = json.loads(body["messages"][1]["content"])
        self.assertNotIn(key, json.dumps(body))
        self.assertEqual(sent["metadata"], value["metadata"])
        self.assertEqual(sent["ordinary"]["[REDACTED_KEY]"], "instruction")
        self.assertEqual(result, {"checks": []})
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(transport.call_args.kwargs["timeout"], 180)
        self.assertEqual(value, before)

    def test_normalized_request_verify_and_real_client_mock_keep_key_out_of_body_and_report(self):
        key = "sk-" + "SYNTHETIC" * 4
        payload = request()
        payload["mode"] = "model"
        payload["sop"]["instructions"] = {key: "ordinary instruction"}
        payload["sop"]["notes"]["engineering"] = "keep normal metadata"
        before = copy.deepcopy(payload)
        raw = json.dumps({"choices": [{"finish_reason": "stop",
            "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as transport:
            report = verify(payload)
        body = json.loads(transport.call_args.args[0].data)
        self.assertNotIn(key, json.dumps(body))
        self.assertNotIn(key, json.dumps(report))
        sent = json.loads(body["messages"][1]["content"])
        self.assertEqual(sent["sop"]["notes"], payload["sop"]["notes"])
        self.assertEqual(transport.call_count, 1)
        self.assertEqual(report["model"]["request_count"], 1)
        self.assertFalse(report["formal_closed"])
        self.assertEqual(payload, before)

    def test_known_credential_source_text_keeps_original_and_display_hashes_separate(self):
        from formsy_sop_verification.core import digest_bytes
        key = "synthetic-configured-credential"
        payload = request()
        payload["mode"] = "model"
        payload["sources"][0]["content"] += "\nreference " + key
        original = payload["sources"][0]["content"]
        raw = json.dumps({"choices": [{"finish_reason": "stop",
            "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)):
            report = verify(payload)
        source = report["source_index"]["user"]
        self.assertTrue(source["redacted"])
        self.assertEqual(source["original_sha256"], digest_bytes(original.encode()))
        self.assertEqual(source["sha256"], digest_bytes(original.replace(key, "[REDACTED_KEY]").encode()))
        self.assertNotIn(key, json.dumps(report))

    def test_credential_identities_are_rejected_before_model_without_rewriting_input(self):
        key = "sk-" + "SYNTHETIC" * 4
        changes = [
            lambda p: (p["context"].update(project_id=key), p["sop"].update(project_id=key)),
            lambda p: p["context"].update(task_id=key),
            lambda p: p["sop"].update(sop_id=key),
            lambda p: p["sources"][0].update(id=key),
            lambda p: p["sources"][0].update(version_id=key),
            lambda p: p["sources"][0]["locator"].update(session_id=key),
            lambda p: p["sources"][0]["locator"].update({key: "ordinary"}),
            lambda p: p["sources"][0]["locator"].update(password="synthetic-password"),
        ]
        for mutate in changes:
            payload = request()
            payload["mode"] = "model"
            mutate(payload)
            before = copy.deepcopy(payload)
            with self.subTest(mutation=changes.index(mutate)), \
                 patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
                 patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no model")) as transport:
                with self.assertRaisesRegex(ValueError, "^credential_in_evidence_identity$"):
                    verify(payload)
            transport.assert_not_called()
            self.assertEqual(payload, before)

    def test_new_local_storage_distinguishes_original_and_saved_hashes_without_changing_history(self):
        server = self.load_server()
        key = "synthetic-configured-credential"
        payload = request()
        payload["sop"]["instructions"] = {key: "ordinary", "password": "synthetic-password"}
        report = {"metadata": {key: "ordinary", "access_token": "synthetic-access"}}
        before = copy.deepcopy((payload, report))
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True):
            records = Path(root)
            old = records / "old-failure.json"
            old.write_bytes(b"prior failure sentinel")
            old_bytes = old.read_bytes()
            record = server.save_record(records, payload, report)
            saved_bytes = (records / (record["id"] + ".json")).read_bytes()
            saved = json.loads(saved_bytes)
            self.assertEqual(old.read_bytes(), old_bytes)
            for secret in (key, "synthetic-password", "synthetic-access"):
                self.assertNotIn(secret, saved_bytes.decode())
            self.assertTrue(record["input_storage_redacted"])
            self.assertTrue(record["report_storage_redacted"])
            self.assertEqual(record["input_sha256"], server.sha256(server.encoded(payload)))
            self.assertEqual(record["report_sha256"], server.sha256(server.encoded(report)))
            self.assertEqual(record["stored_input_sha256"], server.sha256(server.encoded(saved["request"])))
            self.assertEqual(record["stored_report_sha256"], server.sha256(server.encoded(saved["report"])))
            self.assertNotEqual(record["input_sha256"], record["stored_input_sha256"])
            self.assertEqual((records / (record["id"] + ".json")).stat().st_mode & 0o777, 0o600)
        self.assertEqual((payload, report), before)

    def test_http_four_condition_entry_scrubs_new_record_and_rejects_locator_identity(self):
        from fixtures import candidate
        server_module = self.load_server()
        key = "sk-" + "SYNTHETIC" * 4
        payload = request()
        payload["mode"] = "model"
        payload["sop"]["instructions"] = {key: "ordinary"}
        model_reply = candidate(payload)
        model_reply["checks"][0]["reason"] += " " + key
        raw = json.dumps({"choices": [{"finish_reason": "stop",
            "message": {"content": json.dumps(model_reply)}}]}).encode()
        with tempfile.TemporaryDirectory() as root, \
             patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as provider:
            records = Path(root)
            server = server_module.make_server(root=Path(__file__).resolve().parents[1], port=0, reports_dir=records)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/api/verify", json.dumps({"request": payload}).encode(),
                    {"Origin": "http://127.0.0.1:" + str(port), "Content-Type": "application/json"})
                response = connection.getresponse()
                response_bytes = response.read()
                self.assertEqual(response.status, 201)
                connection.close()
                body = json.loads(response_bytes)
                self.assertEqual(set(body), {"request", "report", "mode", "record"})
                self.assertNotIn(key, response_bytes.decode())
                self.assertTrue(body["record"]["input_storage_redacted"])
                self.assertNotIn(key, provider.call_args.args[0].data.decode())
                stored = records / (body["record"]["id"] + ".json")
                self.assertNotIn(key, stored.read_text())
                self.assertFalse(body["report"]["formal_closed"])
                self.assertTrue(body["report"]["analysis_complete"])

                invalid = copy.deepcopy(payload)
                invalid["sources"][0]["locator"].update(session_id=key)
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/api/verify", json.dumps({"request": invalid}).encode(),
                    {"Origin": "http://127.0.0.1:" + str(port), "Content-Type": "application/json"})
                rejected = connection.getresponse()
                self.assertEqual(rejected.status, 422)
                self.assertEqual(json.loads(rejected.read())["error"]["code"], "credential_in_evidence_identity")
                connection.close()
                self.assertEqual(provider.call_count, 1)
                self.assertEqual(len(list(records.glob("*.json"))), 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_full_transport_keeps_typed_authorization_and_never_calls_the_old_tree(self):
        from formsy_sop_verification.full_audit import _ClientAdapter, _EnvironmentFullClient
        value = {"conditions": [{"semantic_basis": {"basis_type": "authorization_contract",
            "dimension": "authorization", "audit_object": "target_product", "authorization": {
                "subject": "requesting user", "destination": "repository",
                "action": "repair named function", "boundary": "named function only"}}}]}
        event = {"choices": [{"index": 0, "delta": {"content": json.dumps(value)}, "finish_reason": "stop"}]}
        raw = ("data: " + json.dumps(event) + "\n\ndata: [DONE]\n\n").encode()
        response = io.BytesIO(raw)
        response.headers = {"Content-Type": "text/event-stream"}
        with tempfile.TemporaryDirectory() as root, \
             patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-current-key", "DEEPSEEK_THINKING": "enabled"}, clear=True), \
             patch("formsy_sop_verification.core._redact_tree", side_effect=AssertionError("old four-condition tree used")), \
             patch("urllib.request.OpenerDirector.open", return_value=response) as provider:
            client = _ClientAdapter(_EnvironmentFullClient(), 8, lambda _: None)
            result = client.complete("Return JSON.", value, root, "analysis-1")
            self.assertEqual(result, value)
            body = json.loads(provider.call_args.args[0].data)
            self.assertEqual(json.loads(body["messages"][1]["content"]), value)
            self.assertTrue(body["stream"])
            saved = json.loads((Path(root) / "analysis-1.call-001.response.json").read_text())
            self.assertEqual(saved, value)
            self.assertEqual(provider.call_count, 1)

    def test_cli_identity_error_is_fixed_and_precedes_any_provider_open(self):
        import subprocess
        key = "sk-" + "SYNTHETIC" * 4
        payload = request()
        payload["mode"] = "model"
        payload["sources"][0]["locator"].update(session_id=key)
        script = Path(__file__).resolve().parents[1] / "scripts/verify.py"
        guard = "import runpy, urllib.request\ndef blocked(*args, **kwargs):\n    raise AssertionError('unexpected provider call')\nurllib.request.OpenerDirector.open = blocked\nrunpy.run_path(" + repr(str(script)) + ", run_name='__main__')\n"
        result = subprocess.run([sys.executable, "-B", "-c", guard],
            input=json.dumps(payload).encode(), capture_output=True, timeout=10,
            env={"DEEPSEEK_API_KEY": key})
        self.assertEqual(result.returncode, 2, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout)["error"]["code"], "credential_in_evidence_identity")
        self.assertNotIn(key, (result.stdout + result.stderr).decode())
        self.assertFalse(result.stderr)


    def test_ordinary_source_ids_survive_verified_report_storage_and_http(self):
        from fixtures import ready_request

        def rename_refs(value, source_id):
            if isinstance(value, dict):
                return {key: source_id if key == "source_id" and child == "user" else rename_refs(child, source_id)
                        for key, child in value.items()}
            if isinstance(value, list):
                return [rename_refs(child, source_id) for child in value]
            return value

        server_module = self.load_server()
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {}, clear=True), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no model")) as provider:
            records = Path(root)
            server = server_module.make_server(root=Path(__file__).resolve().parents[1], port=0, reports_dir=records)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                for source_id in ("password", "authorization", "api_key", "password:foo", "authorization:review"):
                    with self.subTest(source_id=source_id):
                        payload = ready_request()
                        payload["sources"][0]["id"] = source_id
                        payload["sources"][0]["locator"]["message_ids"] = [source_id]
                        payload["candidate"] = rename_refs(payload["candidate"], source_id)
                        report = verify(payload)
                        entry = report["source_index"][source_id]
                        self.assertIsInstance(entry, dict)
                        self.assertTrue(report["analysis_complete"])
                        self.assertEqual(entry["locator"], payload["sources"][0]["locator"])
                        ref = report["checks"][0]["evidence_refs"][0]
                        self.assertEqual(ref["source_id"], source_id)
                        self.assertEqual(ref["source_sha256"], entry["sha256"])
                        record = server_module.save_record(records, payload, report)
                        stored = json.loads((records / (record["id"] + ".json")).read_bytes())
                        self.assertEqual(stored["report"]["source_index"][source_id], entry)
                        port = server.server_address[1]
                        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                        connection.request("POST", "/api/verify", json.dumps({"request": payload}).encode(),
                            {"Origin": "http://127.0.0.1:" + str(port), "Content-Type": "application/json"})
                        response = connection.getresponse()
                        self.assertEqual(response.status, 201)
                        body = json.loads(response.read())
                        connection.close()
                        self.assertEqual(body["report"]["source_index"][source_id], entry)
                        self.assertEqual(body["report"]["checks"][0]["evidence_refs"][0]["source_id"], source_id)
                provider.assert_not_called()
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_injected_and_environment_credentials_are_both_redacted_and_rejected_as_ids(self):
        injected = "synthetic-injected-credential"
        environment = "synthetic-environment-credential"
        payload = request()
        payload["mode"] = "model"
        payload["context"]["description"] = injected + " " + environment
        payload["sop"]["instructions"] = {injected: "ordinary", environment: "ordinary"}

        class Client:
            key = injected
            model = "offline-fixture"
            request_count = 0
            def complete(self, system, value):
                self.request_count += 1
                self.payload = value
                return {"checks": []}

        client = Client()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": environment}, clear=True):
            report = verify(payload, client)
            for secret in (injected, environment):
                self.assertNotIn(secret, json.dumps(client.payload))
                self.assertNotIn(secret, json.dumps(report))
            invalid = copy.deepcopy(payload)
            invalid["sources"][0]["id"] = environment
            with self.assertRaisesRegex(ValueError, "^credential_in_evidence_identity$"):
                verify(invalid, client)
            self.assertEqual(client.request_count, 1)

        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": injected}, clear=True):
            real_client = DeepSeekClient()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": environment}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as provider:
            real_client.complete("Return JSON.", {injected: "ordinary", environment: "ordinary"})
        for secret in (injected, environment):
            self.assertNotIn(secret, provider.call_args.args[0].data.decode())

    def test_redaction_is_idempotent_and_actual_model_lines_match_normalized_source_hash(self):
        from formsy_sop_verification.core import digest_bytes
        key = "sk-" + "SYNTHETIC" * 4
        for text in ("password=synthetic-password", "API_KEY=" + key,
                     'password="[REDACTED]"', "Authorization: Bearer synthetic-bearer"):
            with self.subTest(text=text[:20]):
                first = _redact_tree(text, (key,))
                self.assertEqual(_redact_tree(first, (key,)), first)
        payload = request()
        payload["mode"] = "model"
        payload["sources"][0]["content"] += "\npassword=synthetic-password\nAPI_KEY=" + key
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as provider:
            report = verify(payload)
        sent = json.loads(json.loads(provider.call_args.args[0].data)["messages"][1]["content"])
        text = "\n".join(line["text"] for source in sent["sources"] if source["id"] == "user"
                         for line in source["numbered_lines"])
        self.assertEqual(report["source_index"]["user"]["sha256"], digest_bytes(text.encode()))
        self.assertNotIn("[REDACTED]]", text)
        self.assertNotIn(key, text)

    def test_user_source_index_field_is_not_a_report_id_map_exemption(self):
        value = {"sop": {"instructions": {"source_index": {
            "password": "synthetic-password", "authorization": {"token": "synthetic-token"}}}}}
        safe = _redact_tree(value)
        self.assertEqual(safe["sop"]["instructions"]["source_index"]["password"], "[REDACTED]")
        self.assertEqual(safe["sop"]["instructions"]["source_index"]["authorization"], "[REDACTED]")
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-current-key"}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as provider:
            DeepSeekClient().complete("Return JSON.", value)
        self.assertNotIn("synthetic-password", provider.call_args.args[0].data.decode())
        self.assertNotIn("synthetic-token", provider.call_args.args[0].data.decode())


    def test_namespace_identities_survive_model_serialization_report_storage_and_http(self):
        from fixtures import candidate
        server_module = self.load_server()
        key = "synthetic-configured-credential"
        payload = request()
        reply = candidate(payload)
        reply = json.loads(json.dumps(reply).replace('"source_id": "user"', '"source_id": "authorization:review"'))
        payload["mode"] = "model"
        payload["context"].update(project_id="authorization:project", task_id="password:task")
        payload["sop"].update(project_id="authorization:project", sop_id="password:development")
        payload["sop"]["instructions"] = {"context": {"project_id": "authorization:ordinary"},
            "sources": [{"id": "password:ordinary"}], "source_index": {"password": "synthetic-password"}}
        payload["sources"][0].update(id="authorization:review", version_id="password:version")
        payload["sources"][0]["locator"].update(session_id="authorization:session", turn_id="password:turn",
            message_ids=["password:message"], call_ids=["authorization:call"])
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": json.dumps(reply)}}]}).encode()
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"DEEPSEEK_API_KEY": key}, clear=True), \
             patch("urllib.request.OpenerDirector.open", return_value=io.BytesIO(raw)) as provider:
            records = Path(root)
            server = server_module.make_server(root=Path(__file__).resolve().parents[1], port=0, reports_dir=records)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/api/verify", json.dumps({"request": payload}).encode(),
                    {"Origin": "http://127.0.0.1:" + str(port), "Content-Type": "application/json"})
                response = connection.getresponse()
                self.assertEqual(response.status, 201)
                body = json.loads(response.read())
                connection.close()
                sent = json.loads(json.loads(provider.call_args.args[0].data)["messages"][1]["content"])
                self.assertEqual(sent["context"]["project_id"], payload["context"]["project_id"])
                self.assertEqual(sent["context"]["task_id"], payload["context"]["task_id"])
                self.assertEqual(sent["sop"]["sop_id"], payload["sop"]["sop_id"])
                self.assertEqual(sent["sources"][0]["id"], "authorization:review")
                self.assertEqual(sent["sources"][0]["version_id"], "password:version")
                self.assertNotEqual(sent["sop"]["instructions"]["context"]["project_id"], "authorization:ordinary")
                self.assertNotEqual(sent["sop"]["instructions"]["sources"][0]["id"], "password:ordinary")
                self.assertNotIn("synthetic-password", provider.call_args.args[0].data.decode())
                report = body["report"]
                self.assertTrue(report["analysis_complete"])
                self.assertEqual(report["context"]["task_id"], "password:task")
                self.assertEqual(report["sop_pin"]["sop_id"], "password:development")
                entry = report["source_index"]["authorization:review"]
                self.assertEqual(entry["version_id"], "password:version")
                self.assertEqual(entry["locator"], payload["sources"][0]["locator"])
                ref = report["checks"][0]["evidence_refs"][0]
                self.assertEqual(ref["source_id"], "authorization:review")
                self.assertEqual(ref["locator"], entry["locator"])
                self.assertEqual(body["request"]["sources"][0]["id"], "authorization:review")
                stored = json.loads((records / (body["record"]["id"] + ".json")).read_bytes())
                self.assertEqual(stored["report"], report)
                self.assertEqual(stored["request"]["context"]["task_id"], "password:task")
                self.assertEqual(stored["request"]["sources"][0]["locator"], payload["sources"][0]["locator"])
                self.assertEqual(provider.call_count, 1)
                self.assertNotIn(key, json.dumps(body))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_supported_locator_identity_fields_are_opaque_and_plain_note_is_not(self):
        from fixtures import ready_request
        cases = [{"kind": "turn", "session_id": "authorization:session", "turn_id": "password:turn",
                  "message_ids": ["authorization:message"], "call_ids": ["password:call"]},
                 {"kind": "checkpoint", "checkpoint_id": "authorization:checkpoint"},
                 {"kind": "birdview", "artifact_id": "password:artifact", "part": "authorization:part",
                  "rule_id": "password:rule"},
                 {"kind": "manual", "note": "ordinary manual reference",
                  "url": "https://example.invalid/authorization:review"}]
        with patch.dict(os.environ, {}, clear=True):
            for locator in cases:
                with self.subTest(kind=locator["kind"]):
                    payload = ready_request()
                    payload["sources"][0]["locator"] = locator
                    report = verify(payload)
                    self.assertTrue(report["analysis_complete"])
                    self.assertEqual(report["source_index"]["user"]["locator"], locator)
                    self.assertEqual(report["checks"][0]["evidence_refs"][0]["locator"], locator)
            payload = ready_request()
            payload["sources"][0]["locator"] = {"kind": "manual", "note": "password:ordinary"}
            with self.assertRaisesRegex(ValueError, "^credential_in_evidence_identity$"):
                verify(payload)

    def test_namespaced_identities_containing_real_or_generic_keys_still_stop_before_model(self):
        configured, injected = "synthetic-configured-credential", "synthetic-injected-credential"
        generic = "sk-" + "UNCONFIGURED" * 3
        changes = [lambda p: p["context"].update(task_id="authorization:" + configured),
                   lambda p: p["sources"][0].update(id="password:" + injected),
                   lambda p: p["sources"][0].update(id="authorization:" + generic),
                   lambda p: p["sources"][0]["locator"].update(session_id="password:" + configured)]

        class Client:
            key = injected
            model = "offline-fixture"
            request_count = 0
            def complete(self, *args):
                raise AssertionError("no provider call")

        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": configured}, clear=True):
            for mutate in changes:
                payload = request()
                payload["mode"] = "model"
                mutate(payload)
                before = copy.deepcopy(payload)
                with self.subTest(mutation=changes.index(mutate)), self.assertRaisesRegex(
                        ValueError, "^credential_in_evidence_identity$"):
                    verify(payload, Client())
                self.assertEqual(payload, before)



    def test_manual_url_credentials_are_rejected_before_model_and_all_new_outputs(self):
        from formsy_sop_verification.core import _redact_input, _redact_report
        configured = "synthetic-configured-credential"
        escaped = "".join("%%%02x" % ord(char) for char in configured)
        urls = ["https://example.test/source?password=synthetic-sensitive-password",
                "https://example.test/source?%70assword=synthetic-sensitive-password",
                "https://example.test/source?label=" + escaped,
                "https://synthetic-user:synthetic-sensitive-password@example.test/source",
                "https://example.test/source#password=synthetic-sensitive-password",
                "https://example.test/password=synthetic-sensitive-password"]
        server_module = self.load_server()
        with tempfile.TemporaryDirectory() as root, \
             patch.dict(os.environ, {"DEEPSEEK_API_KEY": configured}, clear=True), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("unexpected model")) as provider:
            for url in urls:
                payload = request()
                payload["mode"] = "model"
                payload["sources"][0]["locator"] = {"kind": "manual", "url": url}
                report = {"source_index": {"user": {"locator": payload["sources"][0]["locator"]}}}
                before = copy.deepcopy(payload)
                with self.subTest(url=url[:60]):
                    for action in (lambda: verify(payload), lambda: _redact_input(payload, (configured,)),
                                   lambda: _redact_report(report, (configured,)),
                                   lambda: server_module.save_record(Path(root), payload, report),
                                   lambda: DeepSeekClient().complete("Return JSON.", payload)):
                        with self.assertRaisesRegex(ValueError, "^credential_in_evidence_identity$"):
                            action()
                    self.assertEqual(payload, before)
            provider.assert_not_called()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_manual_url_credential_error_http_does_not_echo_or_store_the_url(self):
        server_module = self.load_server()
        payload = request()
        payload["mode"] = "model"
        payload["sources"][0]["locator"] = {"kind": "manual",
            "url": "https://example.test/source?password=synthetic-sensitive-password"}
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {"DEEPSEEK_API_KEY": "synthetic-current-key"}, clear=True), \
             patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("unexpected model")) as provider:
            server = server_module.make_server(root=Path(__file__).resolve().parents[1], port=0, reports_dir=Path(root))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                connection.request("POST", "/api/verify", json.dumps({"request": payload}).encode(),
                    {"Origin": "http://127.0.0.1:" + str(port), "Content-Type": "application/json"})
                response = connection.getresponse()
                body = response.read()
                connection.close()
                self.assertEqual(response.status, 422)
                self.assertEqual(json.loads(body)["error"]["code"], "credential_in_evidence_identity")
                self.assertNotIn("synthetic-sensitive-password", body.decode())
                provider.assert_not_called()
                self.assertEqual(list(Path(root).glob("*.json")), [])
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)

    def test_manual_namespace_url_stays_unchanged_through_report_storage_and_cli(self):
        import subprocess
        from fixtures import ready_request
        from formsy_sop_verification.core import _redact_input, _redact_report
        server_module = self.load_server()
        urls = ["https://example.test/authorization:review?label=review#password:foo",
                "https://example.test/authorization%3Areview?label=review",
                "https://example.invalid/source?id=authorization:review&part=password:foo"]
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, {}, clear=True):
            for url in urls:
                payload = ready_request()
                payload["sources"][0]["locator"] = {"kind": "manual", "url": url}
                report = verify(payload)
                self.assertTrue(report["analysis_complete"])
                self.assertEqual(_redact_input(payload)["sources"][0]["locator"]["url"], url)
                self.assertEqual(_redact_report(report)["source_index"]["user"]["locator"]["url"], url)
                self.assertEqual(report["checks"][0]["evidence_refs"][0]["locator"]["url"], url)
                record = server_module.save_record(Path(root), payload, report)
                stored = json.loads((Path(root) / (record["id"] + ".json")).read_bytes())
                self.assertEqual(stored["request"]["sources"][0]["locator"]["url"], url)
                self.assertEqual(stored["report"]["source_index"]["user"]["locator"]["url"], url)
                result = subprocess.run([sys.executable, "-B",
                    str(Path(__file__).resolve().parents[1] / "scripts/verify.py")],
                    input=json.dumps(payload).encode(), capture_output=True, timeout=10, env={})
                self.assertEqual(result.returncode, 0, result.stderr.decode())
                self.assertEqual(json.loads(result.stdout)["source_index"]["user"]["locator"]["url"], url)
                self.assertFalse(result.stderr)

    def load_server(self):
        spec = importlib.util.spec_from_file_location("four_condition_credential_server",
            Path(__file__).resolve().parents[1] / "scripts/serve.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module


if __name__ == "__main__":
    unittest.main()

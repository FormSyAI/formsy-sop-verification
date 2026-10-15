import json
import importlib.util
import os
from pathlib import Path
import sys
import unittest
import tempfile
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from formsy_sop_verification.model_client import (DeepSeekClient, ProviderError,
    NoProviderRedirects, provider_configuration)
from formsy_sop_verification.full_audit import _EnvironmentFullClient
from formsy_sop_verification.trace_audit.model_client import DeepSeekClient as LegacyDeepSeekClient


class Response:
    def __init__(self, raw):
        self.raw = raw
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, size=-1):
        return self.raw if size < 0 else self.raw[:size]


class ModelClientTests(unittest.TestCase):
    def client(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fixture-secret-value", "DEEPSEEK_MODEL": "fixture-model"}, clear=True):
            return DeepSeekClient()

    def test_json_request_is_valid_and_key_never_enters_model_body(self):
        client = self.client()
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch("urllib.request.OpenerDirector.open", return_value=Response(raw)) as network:
            result = client.complete("fixed system", {"source": '{"password":"a,b","nested":"fixture-secret-value"}\nsecond line'})
        request = network.call_args.args[0]
        body = json.loads(request.data)
        payload = json.loads(body["messages"][1]["content"])
        self.assertNotIn("fixture-secret-value", json.dumps(body))
        self.assertIn("[REDACTED]", payload["source"])
        self.assertEqual(request.full_url, "https://api.deepseek.com/chat/completions")
        self.assertEqual(network.call_args.kwargs["timeout"], 180)
        self.assertEqual(result, {"checks": []})
        self.assertEqual(client.request_count, 1)

    def test_incomplete_duplicate_or_bad_model_json_is_not_accepted(self):
        cases = [
            (b'{"choices":[{"finish_reason":"length","message":{"content":"{}"}}]}', "provider_incomplete_output"),
            (b'{"choices":[],"choices":[]}', "provider_invalid_json"),
            (b'{"choices":[{"finish_reason":"stop","message":{"content":"{\\\"checks\\\":[],\\\"checks\\\":[]}"}}]}', "provider_invalid_candidate"),
            (b"x" * (1024 * 1024 + 1), "provider_response_too_large"),
        ]
        for raw, code in cases:
            with self.subTest(code=code), patch("urllib.request.OpenerDirector.open", return_value=Response(raw)):
                with self.assertRaises(ProviderError) as error:
                    self.client().complete("fixed", {})
                self.assertEqual(error.exception.code, code)

    def test_http_error_body_is_not_returned_and_not_retried(self):
        error = urllib.error.HTTPError("https://api.deepseek.com/chat/completions", 401, "sensitive provider detail", {}, None)
        client = self.client()
        with patch("urllib.request.OpenerDirector.open", side_effect=error) as network, self.assertRaises(ProviderError) as result:
            client.complete("fixed", {})
        self.assertEqual(result.exception.code, "provider_authentication_failed")
        self.assertEqual(network.call_count, 1)
        self.assertNotIn("sensitive", str(result.exception))

    def test_malformed_provider_envelope_is_bounded_error(self):
        cases = [None, [], {"choices": None}, {"choices": {}},
                 {"choices": [None]}, {"choices": ["sensitive body"]}, {"choices": [7]},
                 {"choices": [{"finish_reason": "stop", "message": None}]},
                 {"choices": [{"finish_reason": "stop", "message": {"content": 7}}]}]
        for envelope in cases:
            with self.subTest(envelope=envelope), patch("urllib.request.OpenerDirector.open", return_value=Response(json.dumps(envelope).encode())):
                with self.assertRaises(ProviderError) as result:
                    self.client().complete("fixed", {})
                self.assertEqual(result.exception.code, "provider_invalid_candidate")
                self.assertNotIn("sensitive", str(result.exception))

    def test_trusted_endpoint_configuration_and_actual_requests_are_shared(self):
        bases = [(None, "https://api.deepseek.com", "DeepSeek"),
                 ("https://api.deepseek.com/", "https://api.deepseek.com", "DeepSeek"),
                 ("https://api.deepseek.com/v1/", "https://api.deepseek.com/v1", "DeepSeek"),
                 ("https://tokenhub.tencentmaas.com/v1", "https://tokenhub.tencentmaas.com/v1", "Tencent TokenHub"),
                 ("https://tokenhub.tencentmaas.com/v1/", "https://tokenhub.tencentmaas.com/v1", "Tencent TokenHub")]
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"ok":true}'}}]}).encode()
        for base, endpoint, provider in bases:
            environment = {"DEEPSEEK_API_KEY": "fixture-secret-value", "DEEPSEEK_MODEL": "deepseek/deepseek-flash"}
            if base is not None:
                environment["DEEPSEEK_BASE_URL"] = base
            with self.subTest(base=base), patch.dict(os.environ, environment, clear=True), tempfile.TemporaryDirectory() as root:
                endpoint += "/chat/completions"
                self.assertEqual(provider_configuration(), {"provider": provider, "provider_endpoint": endpoint,
                    "model": "deepseek/deepseek-flash"})
                clients = [DeepSeekClient(), _EnvironmentFullClient(), LegacyDeepSeekClient(root)]
                for client in clients:
                    self.assertEqual((client.provider, client.provider_endpoint), (provider, endpoint))
                    self.assertTrue(any(isinstance(handler, NoProviderRedirects) for handler in client.opener.handlers))
                    with patch.object(client.opener, "open", return_value=Response(raw)) as network:
                        result = (client.complete("Follow the requested format.", {}) if isinstance(client, DeepSeekClient)
                                  else client.complete("Follow the requested format.", {}, root, "analysis-1"))
                    request = network.call_args.args[0]
                    self.assertEqual(request.full_url, endpoint)
                    self.assertEqual(request.get_header("Authorization"), "Bearer fixture-secret-value")
                    self.assertEqual(network.call_args.kwargs["timeout"], 180)
                    self.assertEqual(json.loads(request.data)["model"], "deepseek/deepseek-flash")
                    self.assertIn("JSON", json.loads(request.data)["messages"][0]["content"])
                    self.assertNotIn("fixture-secret-value", request.data.decode())
                    self.assertEqual(result, {"ok": True})

    def test_invalid_base_urls_are_rejected_before_all_provider_calls(self):
        invalid = ["", "http://api.deepseek.com", "https://user:private@api.deepseek.com",
            "https://api.deepseek.com?private=1", "https://api.deepseek.com?", "https://api.deepseek.com#private",
            "https://api.deepseek.com/chat/completions", "https://tokenhub.tencentmaas.com",
            "https://tokenhub.tencentmaas.com/v2", "https://api.deepseek.com.attacker.invalid",
            "https://attacker.invalid/v1", "https://api.deepseek.com:8080", "https://api.deepseek.com\n",
            "https://api.deepseek.com\\@attacker.invalid", "https://api.deepseek.com/v1/../v2",
            "\x1fhttps://api.deepseek.com", "https://api.deepseek.com:"]
        for base in invalid:
            with self.subTest(base=base), patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fixture-secret-value",
                    "DEEPSEEK_BASE_URL": base}, clear=True), \
                 patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no request")) as network:
                for build in (DeepSeekClient, _EnvironmentFullClient, lambda: LegacyDeepSeekClient("unused")):
                    with self.assertRaises(ProviderError) as raised:
                        build()
                    self.assertEqual(raised.exception.code, "provider_invalid_configuration")
                    self.assertEqual(raised.exception.failure_details["error_category"], "configuration")
                    self.assertNotIn("private", str(raised.exception))
                network.assert_not_called()

    def test_provider_redirects_are_never_followed_with_credentials(self):
        for location in ("https://attacker.invalid/", "http://tokenhub.tencentmaas.com/v1/chat/completions",
                         "https://tokenhub.tencentmaas.com/v1/chat/completions"):
            self.assertIsNone(NoProviderRedirects().redirect_request(None, None, 307, "redirect", {}, location))

    def test_read_only_configuration_exposes_only_validated_provider_metadata(self):
        spec = importlib.util.spec_from_file_location("endpoint_test_server", Path(__file__).resolve().parents[1] / "scripts/serve.py")
        server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server)
        for base in ("https://tokenhub.tencentmaas.com/v1", "https://private:secret@attacker.invalid/v1"):
            with self.subTest(base=base), patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fixture-secret-value",
                    "DEEPSEEK_BASE_URL": base, "DEEPSEEK_MODEL": "deepseek/deepseek-flash"}, clear=True), \
                 patch("formsy_sop_verification.full_audit.catalog_summary", return_value={"condition_count": 144}):
                for config in (server.configuration(), server.full_configuration()):
                    self.assertNotIn("fixture-secret-value", json.dumps(config))
                    self.assertNotIn("private", json.dumps(config))
                    if "attacker" in base:
                        self.assertFalse(config["model_configured"])
                        self.assertIsNone(config["provider_endpoint"])
                        self.assertEqual(config["configuration_error"], "provider_invalid_configuration")
                    else:
                        self.assertEqual(config["provider"], "Tencent TokenHub")
                        self.assertEqual(config["provider_endpoint"], base + "/chat/completions")

    def test_provider_defaults_and_explicit_blank_model_are_consistent(self):
        for base, expected in [("https://api.deepseek.com", "deepseek-flash"),
                               ("https://tokenhub.tencentmaas.com/v1", "deepseek/deepseek-flash")]:
            with self.subTest(base=base), patch.dict(os.environ, {"DEEPSEEK_BASE_URL": base}, clear=True):
                self.assertEqual(provider_configuration()["model"], expected)
                for client in (DeepSeekClient(), _EnvironmentFullClient(), LegacyDeepSeekClient("unused")):
                    self.assertEqual(client.model, expected)
            for blank in ("", "  "):
                with self.subTest(base=base, blank=blank), patch.dict(os.environ, {
                        "DEEPSEEK_BASE_URL": base, "DEEPSEEK_MODEL": blank}, clear=True):
                    with self.assertRaises(ProviderError):
                        provider_configuration()

    def test_full_thinking_precheck_rejects_without_reading_key_configuration(self):
        spec = importlib.util.spec_from_file_location("thinking_test_server", Path(__file__).resolve().parents[1] / "scripts/serve.py")
        server = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(server)
        for mode in ("", "invalid", "ENABLED", "enabled "):
            with self.subTest(mode=mode), patch.dict(os.environ, {"DEEPSEEK_THINKING": mode}, clear=True), \
                 patch.object(server, "configuration", side_effect=AssertionError("no key configuration read")), \
                 patch("formsy_sop_verification.full_audit.catalog_summary", side_effect=AssertionError("no catalog read")), \
                 patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("no provider request")):
                config = server.full_configuration()
                for field in ("available", "default_available", "model_configured"):
                    self.assertFalse(config[field])
                self.assertEqual(config["thinking_mode"], "invalid")
                self.assertEqual(config["configuration_error"], "provider_invalid_configuration")
        for mode in (None, "disabled", "enabled"):
            environment = {} if mode is None else {"DEEPSEEK_THINKING": mode}
            with self.subTest(mode=mode), patch.dict(os.environ, environment, clear=True), \
                 patch.object(server, "configuration", return_value={"model_configured": True}), \
                 patch("formsy_sop_verification.full_audit.catalog_summary", return_value={"condition_count": 144}):
                config = server.full_configuration()
                for field in ("available", "default_available", "model_configured"):
                    self.assertTrue(config[field])
                self.assertEqual(config["thinking_mode"], mode or "disabled")
                self.assertNotIn("configuration_error", config)


if __name__ == "__main__":
    unittest.main()

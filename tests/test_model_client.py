import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from formsy_sop_verification.model_client import DeepSeekClient, ProviderError


class Response:
    def __init__(self, raw):
        self.raw = raw
    def __enter__(self):
        return self
    def __exit__(self, *_):
        return False
    def read(self, size):
        return self.raw[:size]


class ModelClientTests(unittest.TestCase):
    def client(self):
        with patch.dict(os.environ, {"DEEPSEEK_API_KEY": "fixture-secret-value", "DEEPSEEK_MODEL": "fixture-model"}, clear=True):
            return DeepSeekClient()

    def test_json_request_is_valid_and_key_never_enters_model_body(self):
        client = self.client()
        raw = json.dumps({"choices": [{"finish_reason": "stop", "message": {"content": '{"checks":[]}'}}]}).encode()
        with patch("urllib.request.urlopen", return_value=Response(raw)) as network:
            result = client.complete("fixed system", {"source": '{"password":"a,b","nested":"fixture-secret-value"}\nsecond line'})
        request = network.call_args.args[0]
        body = json.loads(request.data)
        payload = json.loads(body["messages"][1]["content"])
        self.assertNotIn("fixture-secret-value", json.dumps(body))
        self.assertIn("[REDACTED]", payload["source"])
        self.assertEqual(request.full_url, "https://api.deepseek.com/chat/completions")
        self.assertEqual(network.call_args.kwargs["timeout"], 55)
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
            with self.subTest(code=code), patch("urllib.request.urlopen", return_value=Response(raw)):
                with self.assertRaises(ProviderError) as error:
                    self.client().complete("fixed", {})
                self.assertEqual(error.exception.code, code)

    def test_http_error_body_is_not_returned_and_not_retried(self):
        error = urllib.error.HTTPError("https://api.deepseek.com/chat/completions", 401, "sensitive provider detail", {}, None)
        client = self.client()
        with patch("urllib.request.urlopen", side_effect=error) as network, self.assertRaises(ProviderError) as result:
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
            with self.subTest(envelope=envelope), patch("urllib.request.urlopen", return_value=Response(json.dumps(envelope).encode())):
                with self.assertRaises(ProviderError) as result:
                    self.client().complete("fixed", {})
                self.assertEqual(result.exception.code, "provider_invalid_candidate")
                self.assertNotIn("sensitive", str(result.exception))


if __name__ == "__main__":
    unittest.main()

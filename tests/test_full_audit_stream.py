"""Offline SSE transport checks; no credentials, network or evidence execution."""
import hashlib
import http.client
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.full_audit import _ClientAdapter, _EnvironmentFullClient
from formsy_sop_verification.failure_reporting import AuditFailure
from formsy_sop_verification.trace_audit.model_client import ModelOutputError


KEY = "synthetic-stream-key"


def event(delta=None, *, finish=None, usage=None):
    value = {"choices": [] if delta is None else [{"index": 0, "delta": delta, "finish_reason": finish}]}
    if usage is not None:
        value["usage"] = usage
    return b"data: " + json.dumps(value, ensure_ascii=False).encode() + b"\r\n\r\n"


DONE = b"data: [DONE]\r\n\r\n"


class Response:
    headers = {"Content-Type": "text/event-stream; charset=utf-8"}

    def __init__(self, chunks):
        self.chunks = list(chunks)
        self.read_sizes = []

    def __enter__(self): return self
    def __exit__(self, *args): pass

    def read(self, size):
        raise AssertionError("SSE must read available chunks rather than wait to fill a buffer")

    def read1(self, size):
        self.read_sizes.append(size)
        if not self.chunks:
            return b""
        chunk = self.chunks.pop(0)
        if isinstance(chunk, Exception):
            raise chunk
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


class FullAuditStreamTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict("os.environ", {"DEEPSEEK_API_KEY": KEY,
            "DEEPSEEK_THINKING": "enabled", "DEEPSEEK_BASE_URL": "https://tokenhub.tencentmaas.com/v1",
            "DEEPSEEK_MODEL": "deepseek/deepseek-flash"}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def adapter(self):
        return _ClientAdapter(_EnvironmentFullClient(), 8, lambda stage: None)

    def retained(self, root):
        return json.loads((Path(root) / "analysis-1.call-001.provider-response.json").read_text())

    def test_split_utf8_frames_usage_and_exact_wire_hash_are_retained_without_key(self):
        usage = {"prompt_tokens": 5, "completion_tokens": 9, "completion_tokens_details": {"reasoning_tokens": 4}}
        raw = (b": keepalive\r\n\r\n" + event({"role": "assistant"}) +
               event({"role": None, "reasoning_content": "考虑 " + KEY}) + event({"content": '{"ok":"你'}) +
               event({"content": '好"}'}) + event({}, finish="stop") + event(usage=usage) + DONE)
        response = Response([raw[index:index+1] for index in range(len(raw))])
        with tempfile.TemporaryDirectory() as root, patch("urllib.request.OpenerDirector.open", return_value=response) as wire:
            adapter = self.adapter()
            self.assertEqual(adapter.complete("Return JSON.", {}, root, "analysis-1"), {"ok": "你好"})
            body = json.loads(wire.call_args.args[0].data)
            self.assertTrue(body["stream"])
            self.assertEqual(body["stream_options"], {"include_usage": True})
            self.assertEqual((body["max_tokens"], body["reasoning_effort"], wire.call_args.kwargs["timeout"]),
                             (32768, "high", 180))
            self.assertEqual((adapter.calls, adapter.client.request_count, wire.call_count), (1, 1, 1))
            retained = self.retained(root)
            self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
            self.assertEqual(retained["captured_bytes"], len(raw))
            self.assertFalse(retained["truncated"])
            self.assertTrue(retained["stream"]["done"])
            self.assertEqual(retained["stream"]["finish_reason"], "stop")
            self.assertEqual(retained["stream"]["usage"], usage)
            self.assertEqual(retained["envelope"]["usage"], usage)
            self.assertNotIn(KEY, json.dumps(retained))
            self.assertIn("[REDACTED_KEY]", retained["raw_text"])
            self.assertTrue(response.read_sizes)

    def test_multiline_data_crlf_and_comments_are_real_frames(self):
        raw = (b": heartbeat\r\n\r\nevent: message\r\ndata: {" +
            b'\r\ndata: "choices":[{"index":0,"delta":{"content":"{}"},"finish_reason":"stop"}]}' +
            b"\r\n\r\n" + DONE)
        with tempfile.TemporaryDirectory() as root, patch("urllib.request.OpenerDirector.open", return_value=Response([raw])):
            self.assertEqual(self.adapter().complete("Return JSON.", {}, root, "analysis-1"), {})

    def test_credential_split_between_events_or_json_escaped_cannot_be_reconstructed_from_artifacts(self):
        escaped = "".join("\\u%04x" % ord(character) for character in KEY)
        escaped_event = b'data: {"choices":[{"index":0,"delta":{"reasoning_content":"' + escaped.encode() + b'"},"finish_reason":null}]}\n\n'
        for prefix in (event({"reasoning_content": KEY[:7]}) + event({"reasoning_content": KEY[7:]}), escaped_event):
            with self.subTest(escaped=prefix == escaped_event), tempfile.TemporaryDirectory() as root, \
                 patch("urllib.request.OpenerDirector.open", return_value=Response([prefix + event({"content": "{}"}, finish="stop") + DONE])):
                self.assertEqual(self.adapter().complete("Return JSON.", {}, root, "analysis-1"), {})
                retained = self.retained(root)
                decoded = []
                for line in retained["raw_text"].splitlines():
                    if line.startswith("data: {"):
                        parsed = json.loads(line[6:])
                        decoded.extend(choice["delta"].get("reasoning_content", "") for choice in parsed["choices"])
                self.assertNotIn(KEY, "".join(decoded))
                self.assertNotIn(KEY, json.dumps(retained))
                self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(prefix + event({"content": "{}"}, finish="stop") + DONE).hexdigest())

    def test_escaped_field_names_and_other_split_credentials_cannot_be_reconstructed(self):
        generic = "sk-" + "x" * 32
        for secret in (KEY, generic, "access_token=synthetic-access"):
            with self.subTest(secret=secret[:10]), tempfile.TemporaryDirectory() as root:
                prefix = (event({"reasoning_content": secret[:7]}) +
                          event({"reasoning_content": secret[7:]})).replace(
                              b'"reasoning_content"', b'"\\u0072easoning_content"')
                raw = prefix + event({"content": "{}"}, finish="stop") + DONE
                with patch("urllib.request.OpenerDirector.open", return_value=Response([raw])):
                    self.assertEqual(self.adapter().complete("Return JSON.", {}, root, "analysis-1"), {})
                retained = self.retained(root)
                joined = "".join(choice["delta"].get("reasoning_content", "")
                    for line in retained["raw_text"].splitlines() if line.startswith("data: {")
                    for choice in json.loads(line[6:])["choices"])
                self.assertNotIn(secret, joined)
                self.assertNotIn(secret, json.dumps(retained))
                self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_partial_or_invalid_escaped_events_omit_opaque_wire_but_keep_receipt(self):
        escaped = "".join("\\u%04x" % ord(character) for character in KEY).encode()
        prefix = b'data: {"choices":[{"index":0,"delta":{"reasoning_content":"' + escaped
        cases = (prefix, prefix + b'"},bad-json}\n\n', b'data: "' + escaped + b'"\n\n')
        for raw in cases:
            with self.subTest(raw=raw[:30]), tempfile.TemporaryDirectory() as root, \
                 patch("urllib.request.OpenerDirector.open", return_value=Response([raw, TimeoutError("synthetic")])):
                with self.assertRaisesRegex(AuditFailure, "provider_network_or_timeout"):
                    self.adapter().complete("Return JSON.", {}, root, "analysis-1")
                retained = self.retained(root)
                self.assertIn("[REDACTED", retained["raw_text"])
                self.assertNotIn(escaped.decode(), retained["raw_text"])
                self.assertNotIn(KEY, json.dumps(retained))
                self.assertTrue(retained["transport_incomplete"])
                self.assertEqual(retained["captured_bytes"], len(raw))
                self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())

    def test_missing_done_finish_length_or_bad_frames_never_adopt_a_candidate(self):
        valid = event({"content": "{}"}) + event({}, finish="stop")
        cases = [
            (valid, "provider_incomplete_output", False),
            (event({"content": "{}"}, finish="length") + DONE, "provider_incomplete_output", True),
            (event({"content": "{}"}) + DONE, "provider_incomplete_output", False),
            (valid + DONE + event({"content": "{}"}), "provider_invalid_candidate", False),
            (valid + event({"content": "more"}) + DONE, "provider_invalid_candidate", False),
            (b'data: {bad-json}\n\n' + DONE, "provider_invalid_json", False),
            (valid + b"data: [DONE]", "provider_incomplete_output", False),
            (event({"content": '{"a":1,"a":2}'}, finish="stop") + DONE, "provider_invalid_candidate", False),
        ]
        for raw, code, truncated in cases:
            with self.subTest(code=code, raw=raw[:70]), tempfile.TemporaryDirectory() as root, \
                 patch("urllib.request.OpenerDirector.open", return_value=Response([raw])) as wire:
                adapter = self.adapter()
                with self.assertRaises(ModelOutputError) as raised:
                    adapter.complete("Return JSON.", {}, root, "analysis-1")
                self.assertEqual(str(raised.exception), code)
                self.assertEqual(raised.exception.truncated, truncated)
                retained = self.retained(root)
                self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(raw).hexdigest())
                self.assertEqual(retained["raw_text_format"], "redacted_normalized_sse")
                if truncated:
                    self.assertEqual(retained["stream"]["finish_reason"], "length")
                self.assertFalse((Path(root) / "analysis-1.call-001.response.json").exists())
                self.assertEqual(wire.call_count, 1)

    def test_json_mode_adds_explicit_json_system_requirement_without_changing_providers(self):
        for base, model in (("https://tokenhub.tencentmaas.com/v1", "deepseek/deepseek-flash"),
                            ("https://api.deepseek.com", "deepseek-flash")):
            with self.subTest(base=base), tempfile.TemporaryDirectory() as root, \
                 patch.dict("os.environ", {"DEEPSEEK_BASE_URL": base, "DEEPSEEK_MODEL": model}), \
                 patch("urllib.request.OpenerDirector.open", return_value=Response([
                     event({"content": "{}"}, finish="stop") + DONE])) as wire:
                self.assertEqual(self.adapter().complete("核对这条记录。", {}, root, "analysis-1"), {})
                body = json.loads(wire.call_args.args[0].data)
                self.assertIn("JSON", body["messages"][0]["content"])
                self.assertEqual(body["response_format"], {"type": "json_object"})
                self.assertEqual(body["model"], model)
                self.assertTrue(body["stream"])
                self.assertEqual(wire.call_count, 1)

    def test_wire_overhead_can_exceed_one_megabyte_but_has_its_own_bound(self):
        self.assertEqual(_EnvironmentFullClient.MAX_STREAM_BYTES, 16 * 1024 * 1024)
        raw = b":" + b"x" * _EnvironmentFullClient.MAX_RESPONSE_BYTES + b"\n\n" + event({"content": "{}"}, finish="stop") + DONE
        with tempfile.TemporaryDirectory() as root, patch("urllib.request.OpenerDirector.open", return_value=Response([raw])):
            self.assertEqual(self.adapter().complete("Return JSON.", {}, root, "analysis-1"), {})
            retained = self.retained(root)
            self.assertEqual(retained["captured_bytes"], len(raw))
            self.assertFalse(retained["truncated"])
        with tempfile.TemporaryDirectory() as root, patch.object(_EnvironmentFullClient, "MAX_STREAM_BYTES", 256), \
             patch("urllib.request.OpenerDirector.open", return_value=Response([raw])) as wire:
            with self.assertRaisesRegex(AuditFailure, "provider_response_too_large"):
                self.adapter().complete("Return JSON.", {}, root, "analysis-1")
            retained = self.retained(root)
            self.assertEqual(retained["captured_bytes"], 256)
            self.assertTrue(retained["truncated"])
            self.assertEqual(wire.call_count, 1)

    def test_content_and_reasoning_share_the_existing_one_megabyte_limit(self):
        usage = {"prompt_tokens": 4, "completion_tokens": 20}
        raw = event({"reasoning_content": "x" * (_EnvironmentFullClient.MAX_RESPONSE_BYTES - 1)}) + event({"content": "{}"}, finish="stop") + event(usage=usage) + DONE
        with tempfile.TemporaryDirectory() as root, patch("urllib.request.OpenerDirector.open", return_value=Response([raw])):
            with self.assertRaisesRegex(AuditFailure, "provider_response_too_large"):
                self.adapter().complete("Return JSON.", {}, root, "analysis-1")
            retained = self.retained(root)
            self.assertFalse(retained["truncated"])
            self.assertEqual(retained["stream_parse_error"], "provider_response_too_large")
            self.assertEqual(retained["stream"]["finish_reason"], "stop")
            self.assertEqual(retained["stream"]["usage"], usage)
            self.assertFalse((Path(root) / "analysis-1.call-001.response.json").exists())

    def test_timeout_disconnect_and_incomplete_read_keep_accumulated_partial_without_retry(self):
        prefix = event({"role": "assistant"}) + event({"reasoning_content": KEY})
        for error, issue, tail in [(TimeoutError(KEY), "timeout", b""),
                (http.client.RemoteDisconnected(KEY), "connection", b""),
                (http.client.IncompleteRead(b"data: {", 20), "read_incomplete", b"data: {")]:
            with self.subTest(issue=issue), tempfile.TemporaryDirectory() as root, \
                 patch("urllib.request.OpenerDirector.open", return_value=Response([prefix, error])) as wire:
                adapter = self.adapter()
                with self.assertRaisesRegex(AuditFailure, "provider_network_or_timeout") as raised:
                    adapter.complete("Return JSON.", {}, root, "analysis-1")
                details = raised.exception.failure_details
                self.assertEqual((details["phase"], details["transport_issue"]), ("read", issue))
                self.assertTrue(details["response_saved"])
                self.assertTrue(details["response_partial"])
                self.assertFalse(details["transport_retry"])
                retained = self.retained(root)
                self.assertTrue(retained["transport_incomplete"])
                self.assertEqual(retained["captured_bytes"], len(prefix + tail))
                self.assertEqual(retained["received_sha256"], "sha256:" + hashlib.sha256(prefix + tail).hexdigest())
                self.assertNotIn(KEY, json.dumps(retained))
                self.assertEqual(wire.call_args.kwargs["timeout"], 180)
                self.assertEqual((adapter.calls, adapter.client.request_count, wire.call_count), (1, 1, 1))
                self.assertFalse((Path(root) / "analysis-1.call-001.response.json").exists())

    def test_stream_requested_json_fallback_and_http_errors_keep_existing_classification(self):
        response = io.BytesIO(b'{"choices":[{"finish_reason":"stop","message":{"content":"{}"}}]}')
        response.headers = {"Content-Type": "application/json"}
        with tempfile.TemporaryDirectory() as root, patch("urllib.request.OpenerDirector.open", return_value=response) as wire:
            self.assertEqual(self.adapter().complete("Return JSON.", {}, root, "analysis-1"), {})
            self.assertTrue(json.loads(wire.call_args.args[0].data)["stream"])
            self.assertNotIn("wire_format", self.retained(root))
        for status, code in [(401, "provider_authentication_failed"), (402, "provider_quota_exhausted"),
                             (429, "provider_rate_limited"), (500, "provider_http_error")]:
            with self.subTest(status=status), tempfile.TemporaryDirectory() as root, \
                 patch("urllib.request.OpenerDirector.open", side_effect=urllib.error.HTTPError(
                     "https://tokenhub.tencentmaas.com/v1/chat/completions", status, KEY, {}, io.BytesIO(KEY.encode()))) as wire:
                with self.assertRaisesRegex(AuditFailure, code):
                    self.adapter().complete("Return JSON.", {}, root, "analysis-1")
                retained = self.retained(root)
                self.assertEqual(retained["http_status"], status)
                self.assertNotIn(KEY, json.dumps(retained))
                self.assertEqual(wire.call_count, 1)


if __name__ == "__main__":
    unittest.main()

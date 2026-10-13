"""Environment-only DeepSeek JSON client adapted from TraceAuditWeb/model_client.py."""

import json
import os
import urllib.error
import urllib.request

from .legacy_evidence import redact
from .failure_reporting import AuditFailure


class ProviderError(AuditFailure):
    pass


class DeepSeekClient:
    def __init__(self):
        self.key = os.environ.get("DEEPSEEK_API_KEY", "")
        self.model = os.environ.get("DEEPSEEK_MODEL", "deepseek-flash")
        self.request_count = 0

    def complete(self, system, payload):
        if not self.key:
            raise ProviderError("provider_not_configured")
        def scrub(value):
            if isinstance(value, str):
                return redact(value, (self.key,))
            if isinstance(value, list):
                return [scrub(item) for item in value]
            if isinstance(value, dict):
                return {key: scrub(item) for key, item in value.items()}
            return value

        body = {"model": self.model, "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": json.dumps(scrub(payload), ensure_ascii=False)}],
            "response_format": {"type": "json_object"}, "thinking": {"type": "disabled"},
            "temperature": 0, "max_tokens": 10000, "stream": False}
        # There is deliberately no private-config reader, disk log or endpoint override.
        serialized = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request("https://api.deepseek.com/chat/completions", data=serialized,
            headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
        self.request_count += 1
        try:
            with urllib.request.urlopen(request, timeout=55) as response:
                raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ProviderError("provider_response_too_large")
            from .core import decode_json
            value = decode_json(raw)
        except urllib.error.HTTPError as exc:
            raise ProviderError({401: "provider_authentication_failed", 402: "provider_quota_exhausted",
                                 429: "provider_rate_limited"}.get(exc.code, "provider_http_error")) from None
        except (urllib.error.URLError, TimeoutError, OSError):
            raise ProviderError("provider_network_or_timeout") from None
        except ProviderError:
            raise
        except (UnicodeError, ValueError, RecursionError):
            raise ProviderError("provider_invalid_json") from None
        try:
            if not isinstance(value, dict) or not isinstance(value.get("choices"), list):
                raise ProviderError("provider_invalid_candidate")
            choice = value["choices"][0]
            if not isinstance(choice, dict):
                raise ProviderError("provider_invalid_candidate")
            if choice.get("finish_reason") != "stop":
                raise ProviderError("provider_incomplete_output")
            message = choice.get("message")
            if not isinstance(message, dict) or not isinstance(message.get("content"), str):
                raise ProviderError("provider_invalid_candidate")
            # The core's strict decoder rejects duplicate keys and non-finite numbers.
            from .core import decode_json
            candidate = decode_json(choice["message"]["content"].encode("utf-8"))
            if not isinstance(candidate, dict):
                raise ProviderError("provider_invalid_candidate")
            return candidate
        except (KeyError, IndexError, TypeError, ValueError, UnicodeError, RecursionError) as exc:
            if isinstance(exc, ProviderError):
                raise
            raise ProviderError("provider_invalid_candidate") from None

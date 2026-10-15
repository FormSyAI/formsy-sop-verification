"""Environment-only DeepSeek JSON client adapted from TraceAuditWeb/model_client.py."""

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

from .failure_reporting import AuditFailure, PROVIDER_TIMEOUT_SECONDS

THINKING_MODES = frozenset({"enabled", "disabled"})


class ProviderError(AuditFailure):
    pass


def provider_configuration():
    """Resolve only trusted server configuration; never accept a request endpoint."""
    base = os.environ.get("DEEPSEEK_BASE_URL", "https://api.deepseek.com")
    try:
        url = urlsplit(base)
        paths = {"api.deepseek.com": {"", "/", "/v1", "/v1/"},
                 "tokenhub.tencentmaas.com": {"/v1", "/v1/"}}
        if (any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in base) or "\\" in base
                or "?" in base or "#" in base or url.scheme != "https"
                or url.username is not None or url.password is not None or url.port is not None
                or url.hostname not in paths or url.netloc.lower() != url.hostname
                or url.path not in paths[url.hostname]):
            raise ValueError
        provider = "Tencent TokenHub" if url.hostname == "tokenhub.tencentmaas.com" else "DeepSeek"
        model = os.environ.get("DEEPSEEK_MODEL", "deepseek/deepseek-flash" if provider == "Tencent TokenHub" else "deepseek-flash")
        if not model.strip():
            raise ValueError
    except ValueError:
        raise ProviderError("provider_invalid_configuration", failure_stage="prepare", phase="prepare") from None
    endpoint = "https://" + url.hostname + url.path.rstrip("/") + "/chat/completions"
    return {"provider": provider, "provider_endpoint": endpoint, "model": model}


class NoProviderRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        # One call sends credentials only to its configured endpoint.
        return None


class DeepSeekClient:
    def __init__(self):
        self.key = os.environ.get("DEEPSEEK_API_KEY", "")
        endpoint = provider_configuration()
        self.model, self.provider, self.provider_endpoint = endpoint["model"], endpoint["provider"], endpoint["provider_endpoint"]
        self.opener = urllib.request.build_opener(NoProviderRedirects())
        self.request_count = 0

    def complete(self, system, payload):
        if not self.key:
            raise ProviderError("provider_not_configured")
        from .core import _redact_input

        body = {"model": self.model, "messages": [
            {"role": "system", "content": system + "\nReturn only a strict JSON object."},
            {"role": "user", "content": json.dumps(_redact_input(payload, (self.key, os.environ.get("DEEPSEEK_API_KEY", ""))), ensure_ascii=False)}],
            "response_format": {"type": "json_object"}, "thinking": {"type": "disabled"},
            "temperature": 0, "max_tokens": 10000, "stream": False}
        # There is no private-config reader, disk log or request endpoint override.
        serialized = json.dumps(body, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(self.provider_endpoint, data=serialized,
            headers={"Authorization": "Bearer " + self.key, "Content-Type": "application/json"})
        self.request_count += 1
        try:
            with self.opener.open(request, timeout=PROVIDER_TIMEOUT_SECONDS) as response:
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

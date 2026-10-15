"""DeepSeek JSON calls. Keys stay in environment/private config, never in artifacts."""
import json
import hashlib
import os
import re
import urllib.error
import urllib.request
from pathlib import Path

from ..model_client import NoProviderRedirects, provider_configuration
from ..failure_reporting import PROVIDER_TIMEOUT_SECONDS
from ..core import decode_json


def private_config(root):
    # Local integration disables legacy dotenv access, including accidental service use.
    return {key: os.environ[key] for key in ('DEEPSEEK_API_KEY', 'DEEPSEEK_MODEL')
            if os.environ.get(key)}


SECRET_FIELD = r'(?:[A-Za-z0-9]+[_-])?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|authorization)'
SECRET_KEY = re.compile(SECRET_FIELD, re.IGNORECASE)
JSON_SECRET_FIELD = re.compile(r'(?i)("' + SECRET_FIELD + r'"\s*:\s*)')
SECRET_VALUE = r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|\[REDACTED(?:_KEY)?\]|[^\s,;}\]]+'
SECRET_ASSIGNMENT = re.compile(
    r'(?i)((?:"' + SECRET_FIELD + r'"|\'' + SECRET_FIELD + r'\'|\b' + SECRET_FIELD + r')\s*[=:]\s*)('
    + SECRET_VALUE + r')')


def _redact_text(text, secrets=()):
    text = str(text)
    for secret in secrets:
        if secret:
            text = text.replace(secret, '[REDACTED_KEY]')
    text = re.sub(r'\bsk-[A-Za-z0-9_-]{16,}', '[REDACTED_KEY]', text)

    # Decode each JSON value so objects, escapes and delimiters stay well formed.
    pieces, cursor = [], 0
    decoder = json.JSONDecoder()
    for match in JSON_SECRET_FIELD.finditer(text):
        if match.start() < cursor:
            continue
        try:
            _, length = decoder.raw_decode(text[match.end():])
        except (ValueError, RecursionError):
            continue
        original = text[match.end():match.end() + length]
        pieces.extend((text[cursor:match.end()], '"[REDACTED]"' + '\n' * original.count('\n')))
        cursor = match.end() + length
    text = ''.join(pieces) + text[cursor:]
    text = re.sub(r'(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;}"\']+', r'\1[REDACTED]', text)

    def replace_value(match):
        value = match[2]
        marker = value[0] + '[REDACTED]' + value[0] if value[0] in ('"', "'") else '[REDACTED]'
        return match[1] + marker

    return SECRET_ASSIGNMENT.sub(replace_value, text)


def _semantic_authorization(value, path):
    prefix = list(path)
    while prefix and prefix[0] in {'payload', 'previous_candidate', 'report'}:
        prefix.pop(0)
    if (len(prefix) not in (3, 5) or prefix[0] not in {'conditions', 'sop_condition_checks'}
            or type(prefix[1]) is not int or prefix[-1] != 'semantic_basis'
            or len(prefix) == 5 and (prefix[2] != 'atomic_checks' or type(prefix[3]) is not int)):
        return False
    contract = value.get('authorization')
    return (value.get('basis_type') == 'authorization_contract' and value.get('dimension') == 'authorization'
            and value.get('audit_object') in ('task_delivery', 'target_product')
            and isinstance(contract, dict) and set(contract) == {'subject', 'destination', 'action', 'boundary'}
            and all(isinstance(item, str) and item.strip() for item in contract.values()))


def redact(text, secrets=()):
    text = str(text)
    try:
        value = decode_json(text.encode('utf-8'))
    except (ValueError, UnicodeError, RecursionError):
        return _redact_text(text, secrets)
    if isinstance(value, (dict, list)):
        safe = redact_value(value, secrets)
    elif isinstance(value, str):
        safe = redact(value, secrets)
    else:
        return _redact_text(text, secrets)
    return json.dumps(safe, ensure_ascii=False) if safe != value else text


def redact_value(value, secrets=(), *, _path=()):
    if isinstance(value, dict):
        semantic = _semantic_authorization(value, _path)
        result = {}
        for key, item in value.items():
            safe_key = _redact_text(key, secrets) if isinstance(key, str) else key
            if key == 'authorization' and semantic:
                # This is an audit fact, but each field can still contain credentials.
                result[safe_key] = {field: re.sub(r'(?i)(\b(?:bearer|basic)\s+)[^\s,;}"\']+', r'\1[REDACTED]',
                    re.sub(r'(?i)(\btoken\s*[=:]\s*)(' + SECRET_VALUE + r')', r'\1"[REDACTED]"',
                           redact(text, secrets))) for field, text in item.items()}
            else:
                result[safe_key] = ('[REDACTED]' if SECRET_KEY.fullmatch(str(key))
                               else redact_value(item, secrets, _path=(*_path, key if isinstance(key, str) else None)))
        return result
    if isinstance(value, list):
        return [redact_value(item, secrets, _path=(*_path, index)) for index, item in enumerate(value)]
    if isinstance(value, str):
        return redact(value, secrets)
    return value


def save_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    data = (json.dumps(redact_value(value, (os.environ.get("DEEPSEEK_API_KEY", ""),)), ensure_ascii=False, indent=2) + '\n').encode()
    temporary = path.with_suffix(path.suffix + '.tmp')
    with temporary.open('wb') as stream:
        os.chmod(temporary, 0o600)
        stream.write(data)
    temporary.replace(path)


class DeepSeekClient:
    def __init__(self, root):
        config = private_config(root)
        self.key = config.get('DEEPSEEK_API_KEY', '')
        endpoint = provider_configuration()
        self.model, self.provider, self.provider_endpoint = endpoint['model'], endpoint['provider'], endpoint['provider_endpoint']
        self.opener = urllib.request.build_opener(NoProviderRedirects())
        self.configured = bool(self.key)

    def complete(self, system, payload, directory, stage):
        if not self.configured:
            raise ValueError('尚未配置 DeepSeek API；请在服务器本地配置 DEEPSEEK_API_KEY。')
        body = {'model': self.model, 'messages': [
            {'role': 'system', 'content': system + '\nReturn only a strict JSON object.'},
            {'role': 'user', 'content': json.dumps(payload, ensure_ascii=False)}],
            'response_format': {'type': 'json_object'}, 'thinking': {'type': 'disabled'},
            'temperature': 0, 'max_tokens': 10000, 'stream': False}
        body = redact_value(body, (self.key,))
        directory = Path(directory)
        save_json(directory / (stage + '.request.json'), body)
        request = urllib.request.Request(self.provider_endpoint,
            data=json.dumps(body, ensure_ascii=False).encode(),
            headers={'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=PROVIDER_TIMEOUT_SECONDS) as response:
                raw = response.read(1024 * 1024 + 1)
        except urllib.error.HTTPError as exc:
            save_json(directory / (stage + '.error.json'), {'http_status': exc.code, 'provider': self.provider,
                'provider_endpoint': self.provider_endpoint})
            labels = {401: '认证失败', 402: '余额不足', 429: '请求限流'}
            raise ValueError(self.provider + ' ' + labels.get(exc.code, '请求失败') + '（HTTP ' + str(exc.code) + '）') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            save_json(directory / (stage + '.error.json'), {'error': 'network_or_timeout'})
            raise ValueError(self.provider + ' 网络连接失败或超时；本次没有生成通过结论。') from None
        save_json(directory / (stage + '.provider-response.json'), {
            'raw_text': raw[:1024 * 1024].decode('utf-8', errors='replace'),
            'received_sha256': 'sha256:' + hashlib.sha256(raw).hexdigest(),
            'captured_bytes': min(len(raw), 1024 * 1024), 'truncated': len(raw) > 1024 * 1024})
        try:
            if len(raw) > 1024 * 1024:
                raise ModelOutputError('模型响应超过大小上限；保留脱敏原响应，不采用。')
            value = decode_json(raw)
            save_json(directory / (stage + '.response.json'), value)
            choice = value['choices'][0]
            if choice.get('finish_reason') != 'stop':
                raise ModelOutputError('模型输出未完整结束；保留响应，不采用截断结论。',
                                       truncated=choice.get('finish_reason') == 'length')
            result = decode_json(choice['message']['content'].encode('utf-8'))
            if not isinstance(result, dict):
                raise ModelOutputError('模型输出不是JSON对象。')
            return redact_value(result, (self.key,))
        except ModelOutputError:
            raise
        except (KeyError, IndexError, AttributeError, TypeError, ValueError, UnicodeError, RecursionError):
            raise ModelOutputError('模型未返回有效JSON；请严格返回单个JSON对象，顶层字段不能嵌套在tasks内；脱敏响应已保留。') from None


class ModelOutputError(ValueError):
    """Retryable output shape error, distinct from provider/auth/network failures."""

    def __init__(self, message, *, truncated=False):
        super().__init__(message)
        self.truncated = truncated

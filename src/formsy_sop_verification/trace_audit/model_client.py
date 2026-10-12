"""DeepSeek JSON calls. Keys stay in environment/private config, never in artifacts."""
import json
import os
import re
import urllib.error
import urllib.request
from pathlib import Path


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


def redact(text, secrets=()):
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
        except ValueError:
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


def redact_value(value, secrets=()):
    if isinstance(value, dict):
        return {key: '[REDACTED]' if SECRET_KEY.fullmatch(str(key)) else redact_value(item, secrets)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_value(item, secrets) for item in value]
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
        self.model = config.get('DEEPSEEK_MODEL', 'deepseek-flash')
        self.configured = bool(self.key)

    def complete(self, system, payload, directory, stage):
        if not self.configured:
            raise ValueError('尚未配置 DeepSeek API；请在服务器本地配置 DEEPSEEK_API_KEY。')
        body = {'model': self.model, 'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': json.dumps(payload, ensure_ascii=False)}],
            'response_format': {'type': 'json_object'}, 'thinking': {'type': 'disabled'},
            'temperature': 0, 'max_tokens': 10000, 'stream': False}
        body = redact_value(body, (self.key,))
        directory = Path(directory)
        save_json(directory / (stage + '.request.json'), body)
        request = urllib.request.Request('https://api.deepseek.com/chat/completions',
            data=json.dumps(body, ensure_ascii=False).encode(),
            headers={'Authorization': 'Bearer ' + self.key, 'Content-Type': 'application/json'})
        try:
            with urllib.request.urlopen(request, timeout=180) as response:
                value = redact_value(json.load(response), (self.key,))
        except urllib.error.HTTPError as exc:
            save_json(directory / (stage + '.error.json'), {'http_status': exc.code, 'provider': 'DeepSeek'})
            labels = {401: 'DeepSeek 认证失败', 402: 'DeepSeek 余额不足', 429: 'DeepSeek 请求限流'}
            raise ValueError(labels.get(exc.code, 'DeepSeek 请求失败') + '（HTTP ' + str(exc.code) + '）') from None
        except (urllib.error.URLError, TimeoutError, OSError):
            save_json(directory / (stage + '.error.json'), {'error': 'network_or_timeout'})
            raise ValueError('DeepSeek 网络连接失败或超时；本次没有生成通过结论。') from None
        save_json(directory / (stage + '.response.json'), value)
        try:
            choice = value['choices'][0]
            if choice.get('finish_reason') != 'stop':
                raise ModelOutputError('模型输出未完整结束；保留响应，不采用截断结论。',
                                       truncated=choice.get('finish_reason') == 'length')
            result = json.loads(choice['message']['content'])
            if not isinstance(result, dict):
                raise ModelOutputError('模型输出不是JSON对象。')
            return result
        except (KeyError, IndexError, TypeError, json.JSONDecodeError):
            raise ModelOutputError('模型未返回有效JSON；请严格返回单个JSON对象，顶层字段不能嵌套在tasks内；脱敏响应已保留。') from None


class ModelOutputError(ValueError):
    """Retryable output shape error, distinct from provider/auth/network failures."""

    def __init__(self, message, *, truncated=False):
        super().__init__(message)
        self.truncated = truncated

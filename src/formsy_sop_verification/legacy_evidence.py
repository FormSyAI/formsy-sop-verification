"""Small evidence primitives adapted from TraceAuditWeb; see profiles/provenance.json.

Exact-quote validation and failure-first aggregation retain the original boundaries.
They validate a candidate's references, never the semantic truth of its claims.
"""

import re


SECRET_FIELD = r"(?:[A-Za-z0-9]+[_-])?(?:api[_-]?key|access[_-]?token|refresh[_-]?token|password|secret|authorization)"
SECRET_ASSIGNMENT = re.compile(
    r"(?i)((?:\"" + SECRET_FIELD + r"\"|'" + SECRET_FIELD + r"'|\b" + SECRET_FIELD
    + r")\s*[=:]\s*)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*'|\[REDACTED(?:_KEY)?\]|[^\s,;}\]]+)"
)


def redact(value, secrets=()):
    text = value
    for secret in secrets:
        if secret:
            text = text.replace(secret, "[REDACTED_KEY]")
    text = re.sub(r"\bsk-[A-Za-z0-9_-]{16,}", "[REDACTED_KEY]", text)
    text = re.sub(r"(?i)(\bauthorization\s*:\s*(?:bearer|basic)\s+)[^\s,;}\"']+", r"\1[REDACTED]", text)

    def replace(match):
        if match[2].strip("\"'") in ("[REDACTED]", "[REDACTED_KEY]"):
            return match[0]
        # Keep the source line numbering even when a JSON/string value spans lines.
        return match[1] + "[REDACTED]" + "\n" * match[2].count("\n")

    return SECRET_ASSIGNMENT.sub(replace, text)


def check_refs(refs, evidence, *, user_only=False):
    """Adapted from audit_engine.check_refs; evidence_id is kept internally."""
    if not isinstance(refs, list):
        raise ValueError("模型引用不是列表。")
    for ref in refs:
        if not isinstance(ref, dict) or ref.get("evidence_id") not in evidence:
            raise ValueError("模型引用了不存在的材料。")
        item = evidence[ref["evidence_id"]]
        if user_only and item["kind"] != "user_requirement":
            raise ValueError("明确需求必须引用用户原话，不能引用助手声明。")
        start, end = ref.get("start_line"), ref.get("end_line")
        # Server uses LF-separated source coordinates; CR and Unicode separators
        # remain source characters rather than silently changing line identity.
        lines = item["content"].split("\n")
        if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(lines):
            raise ValueError("模型引用的行号超出原始材料。")
        quote = ref.get("quote")
        if not isinstance(quote, str) or not quote.strip() or quote not in "\n".join(lines[start - 1:end]):
            raise ValueError("引文与所选来源行原文不一致。")


def aggregate(values):
    if "unsatisfied" in values:
        return "unsatisfied"
    actual = [value for value in values if value != "not_applicable"]
    if values and not actual:
        return "not_applicable"
    return "satisfied" if actual and all(value == "satisfied" for value in actual) else "unverified"

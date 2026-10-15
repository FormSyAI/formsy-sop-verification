#!/usr/bin/env python3
"""One bounded JSON request in, one JSON report out; no filesystem writes."""

import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.core import MAX_INPUT_BYTES, decode_json, verify  # noqa: E402


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
        if len(raw) > MAX_INPUT_BYTES:
            raise ValueError("input_too_large")
        report = verify(decode_json(raw))
        output = json.dumps(report, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        if len(output) > 1024 * 1024:
            raise ValueError("output_too_large")
        sys.stdout.buffer.write(output + b"\n")
        return 0
    except (ValueError, UnicodeError, RecursionError) as exc:
        # Never echo untrusted input, provider output, credentials or exception text.
        if isinstance(exc, ValueError) and str(exc) == "credential_in_evidence_identity":
            sys.stdout.write('{"error":{"code":"credential_in_evidence_identity","message":"Remove credentials from project, SOP or source identity fields."}}\n')
        else:
            sys.stdout.write('{"error":{"code":"invalid_request","message":"Invalid or oversized verification request."}}\n')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

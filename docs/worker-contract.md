# Worker contract v1

The Server invokes an explicitly configured Python 3.10+ interpreter with `-I`
and the absolute `scripts/verify.py` path. The script resolves its own trusted
`src` directory; CWD, `PYTHONPATH`, local `.env` files and user credentials are
not used. Input is one UTF-8 JSON object on stdin; output is one JSON object on
stdout. The worker writes no files and executes no evidence or model commands.

## Request

```json
{
  "schema_version": 1,
  "mode": "model",
  "context": {
    "project_id": "project-id",
    "task_id": "task-id",
    "title": "Optional task title",
    "description": "Optional description; not a substitute for user evidence",
    "target_commit": "optional full 40-character commit SHA",
    "evidence_completeness": "complete"
  },
  "sop": {
    "project_id": "project-id",
    "sop_id": "development",
    "version": 1,
    "digest": "sha256:<64 lowercase hex characters>",
    "sections": ["the six original section objects, not these strings"],
    "other_original_bundle_fields": "preserved"
  },
  "sources": [{
    "id": "source-1",
    "kind": "user_message",
    "content": "Original source text",
    "locator": {
      "kind": "turn",
      "session_id": "session-id",
      "turn_id": "turn-id",
      "message_ids": ["message-id"],
      "call_ids": []
    }
  }]
}
```

The JSON above illustrates the envelope; the executable synthetic request is
`examples/offline-request.json`. `sop` is the complete **original** Server bundle,
including its six sections in `goal`, `behavior`, `constraints`, `impact`,
`preparation`, `acceptance` order. The worker preserves the original SOP pin.
The calling Server owns the RFC8785 digest and current authorization checks;
the worker does not substitute Python JSON sorting for that digest algorithm.

Sources accept `user_message`, `assistant_message`, `tool_call`, `tool_result`,
`commit_diff`, `source`, or `context`. Code/diff sources may carry `version_id`;
code facts require it to match `context.target_commit` as a full SHA. A complete
target diff is required for the bidirectional change check. Existing FormSy
SourceRef objects are preserved, including `turn` and `manual` variants.
Locators are never supplied or overridden by the model.

`evidence_completeness` is `complete` or `partial`, frozen from the Server's
capture metadata. Missing means unknown. Partial/unknown capture downgrades
positive candidates to `unverified`; valid, supported `unsatisfied` items remain
visible. `complete` describes the provided capture scope, not all real activity.

Production HTTP requests always use `mode: model` and reject a caller-supplied
`candidate`. `mode: offline` is for explicit fixtures/tests and never calls an
API. It optionally takes the same `candidate` JSON described below; without one,
all four checks remain `unverified` with `analysis_complete: false`.

## Frozen subset and model candidate

The packaged profile is `sixchapters-codefix-mvp-v1`, mapping revision `1`,
`draft_reference_subset`. It freezes existing TraceAuditWeb clauses and derived
atomic evidence contracts; it does not recreate their semantics with keywords.

| FormSy chapter | Existing condition | Atomic obligations |
| --- | --- | --- |
| goal | FIX01.C02 | 5 |
| behavior | FIX02.C01 | 2 |
| acceptance | FIX04.C02 | 5 |
| acceptance | FIX05.C04 | 4 |

The model must return exactly four conditions and all 16 fixed atomic items:

```json
{
  "checks": [{
    "condition_id": "FIX01.C02",
    "result": "unverified",
    "reason": "Specific candidate rationale",
    "sop_refs": [{"pointer": "/sections/0/items/0/1", "quote": "Exact published text"}],
    "evidence_refs": [{"source_id": "source-1", "start_line": 1, "end_line": 1, "quote": "Original source text"}],
    "items": [{
      "item_id": "FIX01.C02.I01",
      "result": "unverified",
      "reason": "Evidence or gap for this specific obligation",
      "evidence_refs": []
    }]
  }]
}
```

This is a shape illustration, not a complete valid candidate. The synthetic
example contains all required items. Results are `satisfied`, `unsatisfied`,
`unverified`, `not_applicable`. Unknowns and missing evidence are not exemptions.
Each definite item needs its own valid, allowed-kind evidence and an exact quote
from the mapped **current project** chapter. A reference clause absent from the
project chapter stays unknown; the draft mapping does not make it mandatory.

Source line numbers use `content.split("\n")`, starting at 1. CR and Unicode
separators remain original source characters. A quote must occur in the selected
lines joined with `\n`, without appending a new trailing newline. The worker
checks both the analyzed redacted text and the original input text. A redaction
placeholder cannot become an original-source citation.

The proof gates preserve user/assistant distinctions, full target version
binding, whole atomic-item sets, and failure-first aggregation. Incorrect quotes,
IDs, types or duplicate items produce an explicit validation error and unknown
condition; other valid conditions remain visible. A supported atomic failure is
retained even when another item is unknown or the model parent disagrees.

FIX05.C04 remains `unverified` because this MVP has no trusted-runner, specific
assertion or artifact binding adapter. Ordinary tool output is a runtime lead,
not an authenticated successful execution. Formal approval/closure is never
produced. Missing user-source text skips model calls and yields an incomplete
unknown report rather than inferring requirements from an assistant or title.

## Response

Stdout is the report directly, without a `report` wrapper. Main fields:

- `schema_version: 1`, `engine_version: "0.1.0"`.
- `context`: the frozen request context; `sop_pin` exactly contains
  `project_id`, `sop_id`, `version`, `digest` from the original bundle.
- `scope: "candidate"`, `review_state: "model_candidate"`,
  `human_review: "not_reviewed"`, `formal_closed: false`.
- `analysis_complete`: candidate structure/reference validation completion,
  separate from semantic correctness, evidence completeness or a passing result.
- `analysis_errors`: fixed provider/shape errors; never provider response bodies.
- `model`: `provider`, `model`, `invoked`, `request_count`,
  `status: completed | failed | offline`.
- `summary`: `result`, `review_state`, `counts`, with exactly the four result
  keys and integer counts summing to 4.
- `checks`: condition/rule/chapter IDs, title, criterion, `candidate_result`,
  gated `result`, reason, gaps, accepted evidence references, `sop_refs`, atomic
  items, validation errors, candidate and human-review state.
- Accepted `evidence_refs` add the trusted input locator, `source_sha256` and
  `redacted`. The Server independently resolves `source_id` against its own
  frozen input and validates quote/range again; it need not trust returned locators.
- `source_index`: input kind, locator, analyzed/original text SHA256, redaction
  marker and version. It excludes source body text.
- `coverage`: draft profile identity/revision/hash, four conditions, six chapter
  denominator, mapped/unmapped chapters, capture completeness, `complete_sop:
  false`, `execution_verification_supported: false`.
- `provenance` and `limitations`: frozen source/contract hashes and actual limits.

`profile_digest` is SHA256 of the raw packaged profile file bytes, explicitly
named `sha256_of_raw_profile_file_bytes`; it is not the SOP's RFC8785 digest.
The root `profiles/provenance.json` records reused functions and source hashes;
the immutable original rule snapshot is packaged next to the selected profile.

## Execution and limits

Only deployment `DEEPSEEK_API_KEY` and optional `DEEPSEEK_MODEL` are read for model
configuration. The default model follows the existing audit client,
`deepseek-flash`. Endpoint is fixed to the official DeepSeek JSON completions
endpoint. At most **one** request is made; there is no implicit format retry or
provider fallback. Network timeout is 55 seconds. A complete `finish_reason:
stop` and strict JSON object are required. Common credential fields/key formats
are redacted before sending; this is not a full personal-data detector.

Input: 2 MiB JSON; context 16 KiB; up to 400 sources and 320000 source characters;
locator at most 1024 UTF-8 JSON bytes. No silent truncation. JSON duplicate keys,
nonfinite values and lone surrogates are rejected. Provider response and worker
stdout each have a 1 MiB cap. Each item accepts at most eight quotes, each no more
than 1000 characters. Invalid input returns exit 2 and a bounded
`{"error":{"code":"invalid_request","message":"Invalid or oversized verification request."}}`.

Provider/network failures return exit 0 with a readable report whose four checks
are unknown, `model.status: failed`, and `analysis_complete: false`. The Server
persists it as a **failed analysis**, not a successful candidate run. Report
immutability, actor/project authorization and source availability rechecks are
Server responsibilities. The worker has no TaskCheck, Finish Gate, knowledge
enablement, task-completion or human-confirmation side effects.

## Offline verification

From the repository with a Python 3.10+ interpreter:

```sh
python3 -m unittest discover -s tests -v
python3 -I scripts/verify.py < examples/offline-request.json
```

The example is synthetic, explicitly uses `mode: offline`, and has a supplied
candidate. It proves deterministic request/report/reference gates, not real
DeepSeek quality, production deployment or business execution. Tests mock all
provider requests and do not read user credentials or `.env` files.

`examples/model-request.json` is a separate concrete synthetic semantic example:
it supplies None/zero/positive/negative acceptance cases, a complete two-file
diff, target-bound implementation/test assertions, and an explicit test plan.
It contains no supplied candidate or claimed test execution. Its full SHA is a
synthetic version-binding identifier, not a claimed real Git commit. This file
uses `mode: model`; invoking the worker on it makes the configured provider call.
The example generator only writes that input file and makes no API calls.

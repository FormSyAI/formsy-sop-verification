#!/usr/bin/env python3
"""Read an explicit native full-audit JSON request; no automatic model call."""
import argparse
import json
from pathlib import Path
import sys
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from formsy_sop_verification.core import MAX_INPUT_BYTES, decode_json
from formsy_sop_verification.full_audit import catalog_summary, prepare_full, run_full_audit


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request", type=Path, help="explicit request file; defaults to stdin")
    parser.add_argument("--run", action="store_true", help="send the selected materials to DeepSeek")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--max-sop-calls", type=int, default=64)
    parser.add_argument("--max-total-calls", type=int, default=80)
    parser.add_argument("--catalog", action="store_true")
    args = parser.parse_args()
    try:
        if args.catalog:
            result = catalog_summary()
        else:
            with args.request.open("rb") if args.request else sys.stdin.buffer as stream:
                raw = stream.read(MAX_INPUT_BYTES + 1)
            if len(raw) > MAX_INPUT_BYTES:
                raise ValueError("input_too_large")
            payload = decode_json(raw)
            if args.run:
                directory = args.output_dir or Path(__file__).resolve().parents[1] / "reports/local/full-audits" / uuid.uuid4().hex
                result = run_full_audit(payload, directory=directory, max_sop_calls=args.max_sop_calls,
                                        max_total_calls=args.max_total_calls)
            else:
                package = prepare_full(payload)
                catalog = package["sop_catalog"]
                inventory = {"source": package["rule_source"], "rule_count": len(catalog["rules"]),
                    "condition_count": sum(len(rule["conditions"]) for rule in catalog["rules"]),
                    "atomic_item_count": sum(len(condition["contract"]["items"])
                        for rule in catalog["rules"] for condition in rule["conditions"])}
                result = {"mode": "prepare_only", "model_invoked": False, "catalog": inventory,
                          "input_sha256": package["integration_input_sha256"],
                          "evidence_count": len(package["evidence"]), "audit_context": package["audit_context"]}
        json.dump(result, sys.stdout, ensure_ascii=False, allow_nan=False)
        sys.stdout.write("\n")
        return 0
    except Exception:
        # Do not print arbitrary source text or provider error bodies on stderr/stdout.
        json.dump({"error": {"code": "full_audit_failed", "message": "Full audit could not complete; check the selected input, configuration and private attempt directory."}}, sys.stdout)
        sys.stdout.write("\n")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

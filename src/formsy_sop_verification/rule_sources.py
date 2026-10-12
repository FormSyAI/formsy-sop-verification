"""Explicit, frozen rule sources: a verified FormSy SOP checkout or uploaded JSON."""

import copy
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import tempfile

from .core import MAX_INPUT_BYTES, decode_json
from .trace_audit import audit_engine, sop_catalog


REPOSITORY = "FormSyAI/formsy-sop"
RELEASE_ID = "traceaudit-r11"
DEFAULT_RULES_COMMIT = "617385cb54995287abeca8ccb5cb407b1e246994"
MAX_UPLOAD_RULES = 8  # Preserve the upstream normalizer's public upload contract.
MAX_UPLOAD_CONDITIONS = 512
MAX_UPLOAD_ATOMIC_ITEMS = 2048
RULE_FILES = {
    "rules/default_rules.json", "rules/语义审计判定规范.md", "rules/sop-library/catalog.json",
    "rules/sop-library/snapshots/code-fix-0.1.json",
    "rules/sop-library/snapshots/code-fix-guidance-0.1.md",
    "rules/sop-library/snapshots/security-0.1.md",
    "rules/sop-library/snapshots/technical-0.2.md",
}
RELEASE_FILES = RULE_FILES | {"compiled-catalog.json", "README.md"}


class RuleSourceError(ValueError):
    """A stable public error code, without local paths or file contents."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, allow_nan=False,
                      separators=(",", ":")).encode("utf-8")


def _read(base, name):
    relative = PurePosixPath(name)
    if (not isinstance(name, str) or relative.is_absolute() or "\\" in name
            or any(part in {"", ".", ".."} for part in name.split("/"))):
        raise RuleSourceError("invalid_sop_release_path")
    path = base
    for component in relative.parts:
        path = path / component
        if path.is_symlink():
            raise RuleSourceError("sop_release_symlink")
    if not path.is_file() or path.stat().st_size > sop_catalog.MAX_FILE_BYTES:
        raise RuleSourceError("sop_release_file_unavailable")
    with path.open("rb") as stream:
        raw = stream.read(sop_catalog.MAX_FILE_BYTES + 1)
    if len(raw) > sop_catalog.MAX_FILE_BYTES:
        raise RuleSourceError("sop_release_file_too_large")
    return raw


def _git(base, *arguments):
    try:
        result = subprocess.run(["git", "--no-replace-objects", "--no-optional-locks", "-C", str(base), *arguments],
                                capture_output=True, check=True, timeout=5)
        return result.stdout.decode("utf-8").strip()
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise RuleSourceError("sop_release_git_unavailable") from None


def _normalize_rules(rules):
    # Reuse precisely the native JSON upload normalization; no filesystem or model.
    payload = {"trace": {"messages": []}, "commits": [{"sha": "a" * 40, "diff": ""}],
               "rules": copy.deepcopy(rules)}
    return audit_engine.normalize(payload, [])["rules"]


def _summary(catalog, source):
    return {"source": source, "rule_count": len(catalog["rules"]),
            "condition_count": sum(len(rule["conditions"]) for rule in catalog["rules"]),
            "atomic_item_count": sum(len(condition["contract"]["items"])
                                     for rule in catalog["rules"] for condition in rule["conditions"]),
            "documents": sop_catalog.public_summary(catalog)["documents"],
            "selection": copy.deepcopy(catalog["selection"]),
            "max_upload_rules": MAX_UPLOAD_RULES,
            "max_upload_conditions": MAX_UPLOAD_CONDITIONS,
            "max_upload_atomic_items": MAX_UPLOAD_ATOMIC_ITEMS}


def default_catalog(selection=None):
    """Read only the configured checkout; reject drift and never use a bundled fallback."""
    try:
        configured = os.environ.get("FORMSY_SOP_RULES_ROOT")
        path = Path(configured) if configured else Path(__file__).resolve().parents[3] / "formsy-sop/audit/traceaudit-r11"
        if not path.is_absolute() or path.is_symlink() or not path.is_dir():
            raise RuleSourceError("sop_library_unavailable")
        base = path.resolve()
        release_raw = _read(base, "release.json")
        release = decode_json(release_raw)
        if (not isinstance(release, dict) or release.get("schema_version") != "1.0"
                or release.get("release_id") != RELEASE_ID or release.get("reference_only") is not True
                or release.get("source_authenticated") is not False):
            raise RuleSourceError("invalid_sop_release")
        files, metadata = release.get("files"), release.get("catalog")
        if not isinstance(files, list) or not isinstance(metadata, dict):
            raise RuleSourceError("invalid_sop_release")
        frozen, entries = {"release.json": release_raw}, {}
        for entry in files:
            if not isinstance(entry, dict) or entry.get("path") not in RELEASE_FILES or entry["path"] in entries:
                raise RuleSourceError("invalid_sop_release_files")
            name = entry["path"]
            expected_role = "rule_source" if name in RULE_FILES else "compiled_catalog" if name == "compiled-catalog.json" else "readme"
            if (entry.get("role") != expected_role or type(entry.get("bytes")) is not int
                    or not re.fullmatch(r"[0-9a-f]{64}", str(entry.get("sha256", "")))):
                raise RuleSourceError("invalid_sop_release_files")
            raw = _read(base, name)
            if len(raw) != entry["bytes"] or _sha(raw) != entry["sha256"]:
                raise RuleSourceError("sop_release_hash_mismatch")
            entries[name], frozen[name] = entry, raw
        if set(entries) != RELEASE_FILES or metadata.get("path") != "compiled-catalog.json":
            raise RuleSourceError("invalid_sop_release_files")
        if metadata.get("sha256") != entries["compiled-catalog.json"]["sha256"]:
            raise RuleSourceError("sop_release_catalog_mismatch")
        repository = Path(_git(base, "rev-parse", "--show-toplevel")).resolve()
        relative = base.relative_to(repository).as_posix()
        commit = _git(base, "rev-parse", "--verify", "HEAD")
        pin = os.environ.get("FORMSY_SOP_RULES_COMMIT", DEFAULT_RULES_COMMIT)
        if not re.fullmatch(r"[0-9a-f]{40}", commit) or (pin is not None and
                (not re.fullmatch(r"[0-9a-f]{40}", pin) or pin != commit)):
            raise RuleSourceError("sop_release_commit_mismatch")
        # Every adopted byte must be committed at the reported Git version.
        for name, raw in frozen.items():
            oid = _git(repository, "rev-parse", "--verify", f"HEAD:{relative}/{name}")
            actual_oid = hashlib.sha1(b"blob " + str(len(raw)).encode("ascii") + b"\0" + raw).hexdigest()
            if oid != actual_oid:
                raise RuleSourceError("sop_release_uncommitted_changes")
        compiled = decode_json(frozen["compiled-catalog.json"])
        # Compile from the exact verified bytes, so concurrent checkout edits cannot
        # replace a snapshot between hash verification and parsing.
        with tempfile.TemporaryDirectory(prefix="formsy-sop-rules-") as temporary:
            temporary = Path(temporary)
            for name in RULE_FILES:
                output = temporary / name
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(frozen[name])
            complete = sop_catalog.resolve_catalog(temporary)
            if compiled != complete:
                raise RuleSourceError("sop_release_compiler_mismatch")
            catalog = sop_catalog.resolve_catalog(temporary, selection)
        counts = _summary(complete, {})
        for key in ("rule_count", "condition_count", "atomic_item_count"):
            if metadata.get(key) != counts[key]:
                raise RuleSourceError("sop_release_catalog_mismatch")
        if (counts["rule_count"], counts["condition_count"], counts["atomic_item_count"]) != (33, 144, 184):
            raise RuleSourceError("sop_release_catalog_mismatch")
        selected_counts = _summary(catalog, {})
        if (selected_counts["rule_count"], selected_counts["condition_count"], selected_counts["atomic_item_count"]) != (33, 144, 184):
            raise RuleSourceError("default_sop_requires_complete_catalog")
        if (metadata.get("contract_sha256") != complete["contract_sha256"]
                or metadata.get("contract_version") != complete["contract_version"]):
            raise RuleSourceError("sop_release_contract_mismatch")
        source = {"kind": "formsy_sop", "repository": REPOSITORY, "path": relative,
                  "git_commit": commit, "release_id": RELEASE_ID, "release_sha256": _sha(release_raw),
                  "catalog_sha256": _sha(frozen["compiled-catalog.json"]),
                  "selected_catalog_sha256": _sha(_canonical(catalog)),
                  "contract_sha256": catalog["contract_sha256"], "contract_version": catalog["contract_version"],
                  "reference_only": True, "source_authenticated": False}
        rules = _normalize_rules(decode_json(frozen["rules/default_rules.json"]))
        return {"rules": rules, "catalog": catalog, "summary": _summary(catalog, source)}
    except RuleSourceError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise RuleSourceError("invalid_sop_library") from None


def validate_upload(payload):
    """Freeze the original rules-file JSON format; no arbitrary path/URL or LLM compiler."""
    try:
        if not isinstance(payload, dict) or set(payload) != {"rules"}:
            raise RuleSourceError("invalid_sop_upload")
        raw = _canonical(payload)
        if len(raw) > MAX_INPUT_BYTES:
            raise RuleSourceError("sop_upload_too_large")
        rules = _normalize_rules(payload["rules"])
        catalog = sop_catalog.uploaded_catalog(rules)
        summary = _summary(catalog, {})
        if (summary["condition_count"] > MAX_UPLOAD_CONDITIONS
                or summary["atomic_item_count"] > MAX_UPLOAD_ATOMIC_ITEMS):
            raise RuleSourceError("sop_upload_condition_limit")
        source = {"kind": "uploaded_rules", "input_sha256": _sha(raw),
                  "catalog_sha256": _sha(_canonical(catalog)), "contract_sha256": catalog["contract_sha256"],
                  "contract_version": catalog["contract_version"], "reference_only": True,
                  "source_authenticated": False}
        summary["source"] = source
        return {"rules": rules, "catalog": catalog, "summary": summary}
    except RuleSourceError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError):
        raise RuleSourceError("invalid_sop_upload") from None

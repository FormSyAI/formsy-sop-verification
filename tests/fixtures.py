"""Explicit synthetic fixtures; not project or model quality evidence."""

import copy
import hashlib
import json

from formsy_sop_verification.core import load_profile, SECTIONS


TARGET = "a" * 40


def request():
    profile = load_profile()
    titles = {"goal": "目标与范围", "behavior": "行为与边界", "constraints": "规则与约束", "impact": "技术影响", "preparation": "实现准备", "acceptance": "完成条件"}
    sop = {"schema_version": 1, "project_id": "fixture-project", "sop_id": "development", "version": 1,
           "published_at": "2026-10-12T00:00:00Z", "template_revision": "synthetic-fixture-v1",
           "workflow": {"profile": "development-v1", "stages": ["requirements", "plan", "implementation", "verification"]},
           "sections": [{"id": sid, "title": titles[sid], "domain": "synthetic-fixture", "description": "合成契约测试，不代表真实项目规范。",
                         "items": [["参考检查", "；".join(condition["text"] for condition in profile["conditions"] if condition["source_section_id"] == sid) or "本章未映射，保留未核查。"]],
                         "applicability": "本合成代码修复任务", "ready_criteria": "逐项保留证据与未知", "sources": "fixture", "gap_handling": "缺证据保留未知", "example": "synthetic fixture", "project_requirement": ""} for sid in SECTIONS],
           "notes": {"business": "", "engineering": "", "acceptance": ""}, "instructions": {}, "rules": [], "sources": []}
    sop["digest"] = "sha256:" + hashlib.sha256(json.dumps(sop, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()).hexdigest()

    def source(sid, kind, content, **extra):
        return {"id": sid, "kind": kind, "content": content, "locator": {"kind": "turn", "session_id": "fixture-session", "turn_id": "fixture-turn", "message_ids": [sid], "call_ids": ["fixture-call"] if kind.startswith("tool_") else []}, **extra}

    return {"schema_version": 1, "mode": "offline", "context": {"project_id": "fixture-project", "task_id": "fixture-task", "title": "合成零值修复", "description": "仅用于离线契约验证。", "target_commit": TARGET, "evidence_completeness": "complete"}, "sop": sop,
        "sources": [source("user", "user_message", "修复limit：None返回25，0保留0。补充None/0/负数断言并保留原负数拒绝行为。"),
                    source("diff", "commit_diff", "--- a/limit.py\n+++ b/limit.py\n-return value or 25\n+return 25 if value is None else value\n", version_id=TARGET),
                    source("test", "source", "def test_limit():\n    assert limit(None) == 25\n    assert limit(0) == 0\n    assert rejects_negative(-1)\n", version_id=TARGET),
                    source("context", "context", "本轮Python3.12；默认pytest配置；无mock、无skip；SOP " + sop["digest"]),
                    source("run", "tool_result", "pytest tests/test_limit.py\n3 passed\n") ]}


def ref(payload, sid):
    source = next(item for item in payload["sources"] if item["id"] == sid)
    return {"source_id": sid, "start_line": 1, "end_line": 1, "quote": source["content"].splitlines()[0]}


def candidate(payload):
    checks = []
    profile = load_profile()
    for condition in profile["conditions"]:
        index = SECTIONS.index(condition["source_section_id"])
        items = []
        for item in condition["contract"]["items"]:
            iid = item["id"]
            sid = "context"
            if iid in ("FIX01.C02.I01", "FIX01.C02.I02", "FIX02.C01.I02"):
                sid = "user"
            elif iid in ("FIX01.C02.I04", "FIX02.C01.I01"):
                sid = "diff"
            elif iid.startswith("FIX04"):
                sid = "test" if iid in ("FIX04.C02.I01", "FIX04.C02.I03", "FIX04.C02.I04") else "context"
            elif iid.startswith("FIX05"):
                sid = "run"
            items.append({"item_id": iid, "result": "satisfied", "reason": "合成候选，仅验证程序证据门槛。", "evidence_refs": [ref(payload, sid)]})
        checks.append({"condition_id": condition["id"], "result": "satisfied", "reason": "合成候选，非模型评测或业务通过。",
                       "sop_refs": [{"pointer": f"/sections/{index}/items/0/1", "quote": condition["text"]}],
                       "evidence_refs": [ref(payload, "user")], "items": items})
    return {"checks": checks}


def ready_request():
    payload = request()
    payload["candidate"] = candidate(payload)
    return copy.deepcopy(payload)

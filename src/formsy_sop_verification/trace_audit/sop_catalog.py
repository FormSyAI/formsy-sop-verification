"""Versioned, source-bound SOP candidates from the application's frozen local library."""
import copy
import hashlib
import json
import re
from pathlib import Path, PurePosixPath

from .sop_contracts import ensure_contracts

MAX_FILE_BYTES = 2_000_000
RULE_ID = re.compile(r"(?:FIX|TC|SEC)\d{2}\Z")
CONDITION_KINDS = {"semantic", "execution", "human"}


def _read(path):
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError("SOP 库文件不存在或超过大小限制")
    with path.open("rb") as stream:
        raw = stream.read(MAX_FILE_BYTES + 1)
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError("SOP 库文件超过大小限制")
    return raw


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("SOP 库包含重复 JSON 字段")
        result[key] = value
    return result


def _json(raw):
    try:
        return json.loads(raw, object_pairs_hook=_object,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError("非法 JSON 数值")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("SOP 库 JSON 格式无效") from exc


def _source_ref(ref, documents):
    if not isinstance(ref, dict) or ref.get("document_id") not in documents:
        raise ValueError("SOP 条件来源文档无效")
    document = documents[ref["document_id"]]
    start, end, quote = ref.get("start_line"), ref.get("end_line"), ref.get("quote")
    lines = document["content"].splitlines()
    if (type(start) is not int or type(end) is not int or
            not 1 <= start <= end <= len(lines) or not isinstance(quote, str) or
            not quote.strip() or quote not in "\n".join(lines[start - 1:end])):
        raise ValueError("SOP 条件来源行号或原文引用无效")
    return ref


def load_catalog(root):
    """Read only library-local snapshots, checking content hashes and exact citations."""
    base = Path(root).resolve()
    library = base / "rules" / "sop-library"
    if (base / "rules").is_symlink() or library.is_symlink():
        raise ValueError("SOP 库目录不能使用符号链接")
    manifest = library / "catalog.json"
    if manifest.is_symlink():
        raise ValueError("SOP 库清单不能是符号链接")
    catalog = _json(_read(manifest))
    if not isinstance(catalog, dict) or catalog.get("catalog_version") != "1.0":
        raise ValueError("不支持的 SOP 库版本")
    documents, rules = catalog.get("documents"), catalog.get("rules")
    if (not isinstance(documents, list) or not 1 <= len(documents) <= 16 or
            not isinstance(rules, list) or not 1 <= len(rules) <= 128):
        raise ValueError("SOP 库文档或规则集合无效")
    by_document = {}
    for document in documents:
        if not isinstance(document, dict):
            raise ValueError("SOP 库文档格式无效")
        doc_id = document.get("id")
        if not isinstance(doc_id, str) or not re.fullmatch(r"[a-z][a-z0-9._-]{1,79}", doc_id):
            raise ValueError("SOP 文档 ID 无效")
        if doc_id in by_document:
            raise ValueError("SOP 文档 ID 或版本冲突")
        if (not isinstance(document.get("title"), str) or not document["title"].strip() or
                not isinstance(document.get("version"), str) or not document["version"].strip() or
                type(document.get("current_reference")) is not bool or
                document.get("task_types") != ["code_fix"]):
            raise ValueError("SOP 文档版本或任务范围无效")
        relative = document.get("snapshot_path")
        if (not isinstance(relative, str) or "\\" in relative or
                not re.fullmatch(r"snapshots/[\w.-]+\.(?:md|json)", relative) or
                PurePosixPath(relative).is_absolute()):
            raise ValueError("SOP 快照路径必须位于库内 snapshots 目录")
        snapshot = library / relative
        if snapshot.is_symlink() or snapshot.parent.is_symlink() or snapshot.resolve().parent != library / "snapshots":
            raise ValueError("SOP 快照不能使用链接或越界路径")
        raw = _read(snapshot)
        if hashlib.sha256(raw).hexdigest() != document.get("sha256"):
            raise ValueError("SOP 来源快照哈希不匹配")
        try:
            document["content"] = raw.decode("utf-8")
        except UnicodeError as exc:
            raise ValueError("SOP 来源快照必须是 UTF-8") from exc
        by_document[doc_id] = document
    by_rule, condition_ids = {}, set()
    for rule in rules:
        if not isinstance(rule, dict) or not RULE_ID.fullmatch(str(rule.get("id", ""))):
            raise ValueError("SOP 规则 ID 无效")
        rule_id = rule["id"]
        if rule_id in by_rule:
            raise ValueError("SOP 规则 ID 或版本冲突")
        doc_id = rule.get("document_id")
        if doc_id not in by_document or rule.get("version") != by_document[doc_id]["version"]:
            raise ValueError("SOP 规则与来源版本不一致")
        if any(not isinstance(rule.get(field), str) or not rule[field].strip()
               for field in ("title", "applicability")):
            raise ValueError("SOP 规则标题或适用范围无效")
        if _source_ref(rule.get("source_ref"), by_document)["document_id"] != doc_id:
            raise ValueError("SOP 规则来源文档不一致")
        conditions = rule.get("conditions")
        if not isinstance(conditions, list) or not 1 <= len(conditions) <= 32:
            raise ValueError("SOP 具体条件集合无效")
        for condition in conditions:
            if not isinstance(condition, dict):
                raise ValueError("SOP 具体条件格式无效")
            condition_id = condition.get("id")
            if (not isinstance(condition_id, str) or
                    not re.fullmatch(re.escape(rule_id) + r"\.C\d{2}", condition_id) or
                    condition_id in condition_ids):
                raise ValueError("SOP 条件 ID 无效或重复")
            condition_ids.add(condition_id)
            if (not isinstance(condition.get("text"), str) or not condition["text"].strip() or
                    condition.get("kind") not in CONDITION_KINDS):
                raise ValueError("SOP 条件文字或类型无效")
            source = _source_ref(condition.get("source_ref"), by_document)
            if source["document_id"] != doc_id:
                raise ValueError("SOP 条件不能借用另一文档的来源")
            # A condition is an exact excerpt; interpretation belongs in the audit, not the library.
            source_items = condition.get("source_items")
            if source_items is not None:
                if (not isinstance(source_items, list) or not source_items or
                        any(not isinstance(item, str) or not item or item not in source["quote"] for item in source_items) or
                        condition["text"] != "；".join(source_items)):
                    raise ValueError("SOP 条件各项必须可追溯到引用原文")
            elif condition["text"] not in source["quote"]:
                raise ValueError("SOP 条件文字必须可追溯到引用原文")
        by_rule[rule_id] = rule
    if not by_rule or len(condition_ids) > 512:
        raise ValueError("SOP 库具体条件数量无效")
    coverage = catalog.get("coverage_manifest")
    if (not isinstance(coverage, dict) or coverage.get("scope") != "registered_rule_conditions" or
            not isinstance(coverage.get("scope_note"), str) or not coverage["scope_note"].strip() or
            not isinstance(coverage.get("documents"), list)):
        raise ValueError("SOP 库缺少明确的编译覆盖范围")
    covered_documents = set()
    for entry in coverage["documents"]:
        if (not isinstance(entry, dict) or entry.get("document_id") not in by_document or
                entry["document_id"] in covered_documents):
            raise ValueError("SOP 编译覆盖文档无效或重复")
        covered_documents.add(entry["document_id"])
        for field in ("compiled_sections", "uncompiled_sections"):
            sections = entry.get(field)
            if not isinstance(sections, list) or len(sections) > 64:
                raise ValueError("SOP 编译覆盖章节无效")
            for section in sections:
                if (not isinstance(section, dict) or
                        any(not isinstance(section.get(key), str) or not section[key].strip() for key in ("title", "reason")) or
                        _source_ref(section.get("source_ref"), by_document)["document_id"] != entry["document_id"]):
                    raise ValueError("SOP 编译覆盖章节来源无效")
    if covered_documents != set(by_document):
        raise ValueError("SOP 编译覆盖范围不能遗漏来源文档")
    return ensure_contracts(catalog)


def resolve_catalog(root, selection=None):
    """Select explicit document IDs/versions or the maintained current reference set.

    SOP issue dates and Trace timestamps do not participate in selection or judgment.
    """
    catalog = load_catalog(root)
    if selection is None:
        selection = {"mode": "auto"}
    if not isinstance(selection, dict) or selection.get("mode", "auto") not in {"auto", "pinned"}:
        raise ValueError("SOP 选择模式必须是 auto 或 pinned")
    mode = selection.get("mode", "auto")
    documents = {document["id"]: document for document in catalog["documents"]}
    requested = selection.get("document_ids", [])
    versions = selection.get("document_versions", {})
    hashes = selection.get("document_hashes", {})
    if (not isinstance(requested, list) or any(not isinstance(value, str) for value in requested) or
            len(set(requested)) != len(requested) or not isinstance(versions, dict) or
            any(not isinstance(key, str) or not isinstance(value, str) for key, value in versions.items()) or
            not isinstance(hashes, dict) or any(not isinstance(key, str) or not isinstance(value, str) for key, value in hashes.items())):
        raise ValueError("SOP 文档选择或版本限定无效")
    if mode == "pinned" and not requested:
        raise ValueError("固定 SOP 选择需要至少一个文档 ID")
    if mode == "auto" and requested:
        raise ValueError("自动选择不能混入固定文档 ID")
    selected = requested if mode == "pinned" else [key for key, document in documents.items()
                                                    if document["current_reference"] and document.get("has_rules")]
    if any(key not in documents for key in selected) or any(key not in selected for key in versions) or any(key not in selected for key in hashes):
        raise ValueError("所选 SOP 文档或版本限定不存在")
    if any(documents[key]["version"] != value for key, value in versions.items()):
        raise ValueError("所选 SOP 版本与冻结来源冲突")
    if any(documents[key]["sha256"] != value for key, value in hashes.items()):
        raise ValueError("所选 SOP 来源快照哈希冲突")
    selected_rules = [rule for rule in catalog["rules"] if rule["document_id"] in selected]
    if not selected_rules or any(not documents[key].get("has_rules") for key in selected):
        raise ValueError("所选文档没有可执行核查的具体条款")
    result = copy.deepcopy(catalog)
    result["documents"] = [document for document in result["documents"] if document["id"] in selected]
    result["rules"] = selected_rules
    result["coverage_manifest"]["documents"] = [entry for entry in result["coverage_manifest"]["documents"] if entry["document_id"] in selected]
    result["selection"] = {"mode": mode, "document_ids": selected,
                           "document_versions": {key: documents[key]["version"] for key in selected},
                           "document_hashes": {key: documents[key]["sha256"] for key in selected},
                           "rule_ids": [rule["id"] for rule in selected_rules]}
    return ensure_contracts(result)


def public_summary(catalog):
    """Browser inventory omits the full source bodies; reports keep the frozen bodies."""
    return {"catalog_version": catalog["catalog_version"],
            "documents": [{**{key: document[key] for key in
                                  ("id", "title", "version", "sha256", "source_path", "current_reference")},
                           "rule_count": sum(rule["document_id"] == document["id"] for rule in catalog["rules"])}
                          for document in catalog["documents"] if document.get("has_rules")],
            "total_rule_count": len(catalog["rules"]),
            "total_condition_count": sum(len(rule["conditions"]) for rule in catalog["rules"])}


def uploaded_catalog(normalized_rules):
    """Freeze normalized uploads as source text; their stated versions are not certified."""
    if not isinstance(normalized_rules, list) or not 1 <= len(normalized_rules) <= 128:
        raise ValueError("上传规则不能为空或超过数量限制")
    doc_id, lines, rules, seen = "uploaded-rules", ["# 上传的审计规则", ""], [], set()

    def field(label, value):
        # The source view uses LF for all input line separators, so line citations remain stable.
        value = "\n".join(value.splitlines())
        start = len(lines) + 1
        lines.extend((label + value).split("\n"))
        return value, {"document_id": doc_id, "start_line": start,
                       "end_line": len(lines), "quote": value}

    for original in normalized_rules:
        rule_id = original.get("id") if isinstance(original, dict) else None
        if (not isinstance(rule_id, str) or not re.fullmatch(r"[A-Za-z0-9:_-]{1,60}", rule_id) or
                rule_id in seen or any(not isinstance(original.get(key), str) or not original[key].strip()
                                      for key in ("criterion", "version")) or
                not isinstance(original.get("title", ""), str)):
            raise ValueError("上传规则 ID、版本或内容无效")
        seen.add(rule_id)
        start = len(lines) + 1
        field("## " + rule_id + " ", original.get("title", ""))
        version, _ = field("版本：", original["version"])
        field("适用范围：", "代码修复任务；具体适用性按本条与任务内容判断")
        criterion, criterion_ref = field("判定标准：", original["criterion"])
        match = re.search(r"(?:^|；)\s*满足条件：(.*?)(?=；\s*(?:不满足|未核查|不适用)条件：|$)", criterion, re.S)
        satisfied = match.group(1) if match else criterion
        if not match and re.search(r"(?:^|；)\s*(?:不满足|未核查|不适用)条件：", criterion):
            raise ValueError("上传规则含判定分支但未提供明确的满足条件")
        conditions = []

        def add(value, source, kind="semantic", stage="satisfaction"):
            conditions.append({"id": rule_id + ".C" + str(len(conditions) + 1).zfill(2),
                               "text": value, "kind": kind, "stage": stage,
                               "source_ref": {**source, "quote": value}})
        for piece in satisfied.split("；"):
            if piece.strip():
                add(piece.strip(), criterion_ref)
        evidence = original.get("required_evidence", [])
        if not isinstance(evidence, list) or any(not isinstance(item, str) for item in evidence):
            raise ValueError("上传规则所需证据必须为文本列表")
        for item in evidence:
            if item.strip():
                value, source = field("所需证据：", item)
                add(value, source, "human" if re.search(r"人工|复核人|独立.*复核", value) else "semantic", "required_evidence")
        for key, label in (("recheck", "复检："), ("closure_policy", "关闭条件：")):
            value = original.get(key, "")
            if not isinstance(value, str):
                raise ValueError("上传规则复检及关闭条件必须为文本")
            if value.strip():
                value, source = field(label, value)
                add(value, source, "human" if re.search(r"人工|复核人|独立.*复核", value) else "semantic", key)
        rules.append({"id": rule_id, "title": original.get("title") or rule_id,
                      "version": version, "document_id": doc_id,
                      "applicability": "代码修复任务；具体适用性按本条与任务内容判断",
                      "criterion": criterion, "conditions": conditions,
                      "required_evidence": copy.deepcopy(evidence),
                      "recheck": original.get("recheck", ""),
                      "closure_policy": original.get("closure_policy", ""),
                      "source_kind": "uploaded_rule", "source_ref": {"document_id": doc_id,
                      "start_line": start, "end_line": len(lines), "quote": "\n".join(lines[start - 1:])}})
        lines.append("")
    content = "\n".join(lines)
    if len(content.encode("utf-8")) > MAX_FILE_BYTES:
        raise ValueError("上传规则总长度超过限制")
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    versions = list(dict.fromkeys(rule["version"] for rule in rules))
    document = {"id": doc_id, "title": "用户上传的审计规则", "version": versions[0] if len(versions) == 1 else "包内逐条版本",
                "source_path": "uploaded_rules", "sha256": digest, "content": content,
                "source_kind": "uploaded_rule", "current_reference": False, "task_types": ["code_fix"], "has_rules": True}
    for rule in rules:
        _source_ref(rule["source_ref"], {doc_id: document})
        for condition in rule["conditions"]:
            _source_ref(condition["source_ref"], {doc_id: document})
    coverage = {"scope": "registered_rule_conditions",
                "scope_note": "完整结论覆盖上传包中已登记的规则条件，不代表任何未上传的 SOP 内容已核查。",
                "documents": [{"document_id": doc_id,
                               "compiled_sections": [{"title": rule["id"] + " " + rule["title"],
                                                      "source_ref": rule["source_ref"],
                                                      "reason": "登记上传标准的满足条件、所需证据及提供的复检/关闭要求；来源及版本为上传方声明"}
                                                     for rule in rules], "uncompiled_sections": []}]}
    return ensure_contracts({"catalog_version": "1.0", "documents": [document], "rules": rules, "coverage_manifest": coverage,
            "selection": {"mode": "uploaded", "document_ids": [doc_id], "document_versions": {doc_id: document["version"]},
                          "document_hashes": {doc_id: digest}, "rule_ids": [rule["id"] for rule in rules]}})

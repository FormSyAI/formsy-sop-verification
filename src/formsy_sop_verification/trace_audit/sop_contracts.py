"""Derived judging contracts; source clauses and their citation hashes stay unchanged."""
import copy
import hashlib
import json

VERSION = "1.9"
SEMANTIC = ["user_requirement", "source", "commit_diff", "context"]
PROCESS = ["context", "user_requirement"]
EXECUTION = ["run_record", "test_log"]
CLOSURE_CRITERION = ("满足条件：当前必验项与问题处置满足关闭门槛，原失败和影响范围复检、独立复核齐全；"
                     "不满足条件：已证实仍有阻塞反例或缺必要复检/确认却宣称关闭；"
                     "未核查条件：修复说明存在但复检、版本绑定、关键补证或独立复核不足")
EXECUTION_CRITERION = ("满足条件：每个必验行为有正确版本/环境的有效通过结果；跳过有有效替代；交付绑定足够；"
                       "不满足条件：实际必验断言失败，或可核实的必要交付条件不成立；"
                       "未核查条件：仅作者陈述、缺日志、版本/环境不匹配或用mock支持真实声明")
IMPLEMENTATION_CRITERION = ("满足条件：原错误因果链被修改，适用合同/负面/兼容边界无已知未处置反例；运行性结论另需实际证据；"
                            "不满足条件：固定对象和前提下存在可复现或静态可成立的错误路径；"
                            "未核查条件：只有局部diff、触发条件未知、关键上下文或必要实证缺失")
EXECUTION_DIMENSIONS = {
    "FIX05.C01": ("每个必验行为有正确版本/环境的有效通过结果", "behavior"),
    "FIX05.C02": ("跳过有有效替代", "skip_substitution"),
    "FIX05.C03": ("交付绑定足够", "artifact_binding"),
    "FIX05.C04": ("实际命令和完整输出；受测版本/补丁/测试设计；环境和真实/mock分类；必要产物与最终实例身份", "evidence_completeness"),
    "FIX05.C05": ("当前受测对象的原始执行与身份绑定，不继承旧版本同名结果", "current_identity"),
}


def _item(text, kinds=None, policy="semantic", mode="rule", trigger=""):
    return {"text": text, "allowed_evidence_kinds": list(kinds or SEMANTIC),
            "proof_policy": policy, "trigger": {"mode": mode, "text": trigger}}


# Interpret only these exact local excerpts, never an uploaded rule reusing their IDs.
SPECIAL = {
    "TC01.C02": ("technical-0.2", "有效决定、目标平台明确", [
        _item("有效决定明确；用户期望或建议不自动成为已批准的实现方案", PROCESS, mode="always"),
        _item("目标运行平台、解释器/运行时和配置前提明确；功能、服务名称或源码SHA不能代替环境身份",
              policy="environment", mode="always"),
    ]),
    "FIX01.C02": ("code-fix-0.1", "用户原话/有效决定引用；任务与验收清单；规则版本摘要；目标源码与环境身份", [
        _item("用户原话/有效决定引用"),
        _item("任务与验收清单"),
        _item("规则版本摘要"),
        _item("目标源码身份明确并绑定审计目标版本", ["source", "commit_diff"], mode="always"),
        _item("目标环境身份明确；源码SHA只能定位源码版本，不能证明平台、解释器、依赖或运行前提",
              policy="environment", mode="always"),
    ]),
    "FIX04.C02": ("code-fix-0.1", "测试源码及配置；验收点到断言映射；前置/负例/回归设计；mock与skip说明", [
        _item("目标版本测试源码可定位", ["source", "commit_diff"], mode="always"),
        _item("适用测试配置明确；可由配置、明确运行计划或明确采用默认配置的有效依据证明；不强制独立配置文件，证据不足记未核查",
              policy="evidence_plan", mode="always"),
        _item("验收点到断言映射"),
        _item("前置/负例/回归设计"),
        _item("mock与skip说明"),
    ]),
    "FIX02.C01": ("code-fix-0.1", "每个必要验收点有语义成立的改动或有效无需改动依据，每段实质变更有有效任务依据", [
        _item("每个必要验收点有语义成立的改动或有效无需改动依据", ["source", "commit_diff"], mode="always"),
        _item("每段实质变更有有效任务依据", mode="always"),
    ]),
    "TC12.C01": ("technical-0.2", "前置、环境、数据、操作、可判定断言、证据计划齐全", [
        _item("每条适用验收×平台组合的前置条件明确", mode="always"),
        _item("每条适用验收×平台组合的环境明确；需明确配置或运行前提，普通测试函数存在不证明环境齐全",
              policy="environment", mode="always"),
        _item("每条适用验收×平台组合的数据明确；用户给出的具体输入可证明数据设计，缺测试代码不等于缺数据设计", mode="always"),
        _item("每条适用验收×平台组合的操作明确；用户给出的具体命令可证明操作设计，未运行不等于无操作设计", mode="always"),
        _item("每条适用验收×平台组合有可判定且符合冻结用户要求的输入与期望结果设计；明确用户输入/期望本身可构成设计，不强制独立计划文件；故意把错误实现的输出作为期望不算满足。此处核设计，测试代码是否全部交付另由FIX02/TC13核查",
              ["user_requirement", "source", "context"], mode="always"),
        _item("每条适用验收×平台组合的证据计划明确；需说明采集对象、方式或保留位置，测试代码存在不证明已有证据计划",
              policy="evidence_plan", mode="always"),
    ]),
    "TC13.C02": ("technical-0.2", "关键反例按风险覆盖", [
        _item("逐一核对用户明确要求及任务定义中的必需反例均有能验证需求的断言；已登记缺口不能代替覆盖；无明确指定反例时说明依据，不自行添加要求",
              mode="always"),
        _item("适用的风险关键反例有验证设计；不把建议反例自动升级为必需要求", ["source", "context"],
              mode="conditional", trigger="任务存在原要求或实际能力/风险决定的关键反例"),
    ]),
    "FIX06.C01": ("code-fix-0.1", "当前必验项与问题处置满足关闭门槛，原失败和影响范围复检、独立复核齐全", [
        _item("当前必验清单全部满足关闭门槛", policy="closure_prerequisites", mode="always"),
        _item("问题处置满足关闭门槛", PROCESS, "process_history"),
        _item("原失败和影响范围完成有效复检", PROCESS, "process_history"),
        _item("独立复核齐全", PROCESS, "human"),
    ]),
    "FIX06.C04": ("code-fix-0.1", "满足当前必验清单、版本、复检及独立人工复核门槛；风险接受不能转满足", [
        _item("当前必验清单全部满足关闭门槛", policy="closure_prerequisites", mode="always"),
        _item("版本身份满足关闭门槛", PROCESS, "process_history"),
        _item("有效复检满足关闭门槛", PROCESS, "process_history"),
        _item("独立人工复核满足关闭门槛", PROCESS, "human"),
        _item("风险接受没有把未满足事项转为满足", PROCESS, "process_history"),
    ]),
    "FIX06.C03": ("code-fix-0.1", "追加新轮次并复核完整关闭清单；新反例重开，旧失败不删除", [
        _item("复检追加新轮次且关联原轮次", PROCESS, "process_history", "conditional", "发生修订后的复检"),
        _item("复检核对完整关闭清单", PROCESS, "process_history", "conditional", "发生复检或宣称关闭"),
        _item("新反例触发重开", PROCESS, "process_history", "conditional", "已关闭问题出现新反例"),
        _item("旧失败记录保留", PROCESS, "process_history", "conditional", "已有历史失败记录"),
    ]),
    "TC11.C01": ("technical-0.2", "各平台运行/交付前提明确", [
        _item("任务涉及的运行/交付平台与前提明确；纯函数仍需检查解释器、依赖或适用运行前提，不能据纯函数排除",
              policy="environment", mode="always"),
    ]),
    "TC11.C02": ("technical-0.2", "适用兼容、失败和恢复行为具体", [
        _item("适用兼容行为具体", mode="conditional", trigger="任务涉及兼容承诺、数据/版本变化或兼容风险"),
        _item("适用失败行为具体", mode="conditional", trigger="任务涉及安装、升级、交付或恢复失败场景"),
        _item("适用恢复行为具体", mode="conditional", trigger="任务承诺恢复、回退或存在需要处置的恢复风险"),
    ]),
    "TC11.C03": ("technical-0.2", "环境缺口保留", [
        _item("环境核查及其缺口如实记录，缺少环境材料不得记不适用", PROCESS, "environment", "always"),
    ]),
    "TC11.C04": ("technical-0.2", "首版未承诺升级需说明边界", [
        _item("首版未承诺升级时明确该边界", mode="conditional", trigger="首版交付且未承诺升级能力"),
    ]),
}

# Adjacent history checks use the same evidence boundary as FIX06, not code as process proof.
PROCESS_CONDITIONS = {"FIX01.C03", "TC02.C03", "TC15.C01", "TC15.C02", "TC15.C03", "TC15.C04", "SEC12.C05"}
PROCESS_TRIGGERS = {"FIX01.C03": "出现新增决定或对象差异，需要重新确认受影响基准和结论",
                    "TC15.C02": "问题被宣称关闭或已处于关闭状态",
                    "TC15.C03": "出现影响已有结论的变更、新反例或关闭判断错误",
                    "TC15.C04": "本轮或相关问题发生暂停或取消"}


def rule_audit_scope(rule):
    """Selection and condition evaluation use the same object, never the auditor's UI."""
    native = rule.get("source_kind") != "uploaded_rule" and rule.get("document_id") != "uploaded-rules"
    rid = rule.get("id")
    delivery = native and rid in {"TC01", "TC12", "TC14", "SEC10", "SEC12"}
    scope = {"audit_object": "task_delivery" if delivery else "target_product",
             "trigger_basis": "本任务承诺的产物、原Agent交付及其声明" if delivery else "被审产品的实际能力、合同和风险",
             "non_trigger": "审计器自己的界面和本轮生成结论不属于被审对象"}
    if native and rid == "SEC03":
        scope["non_trigger"] += "；Agent编辑仓库文件或运行工具本身不能证明目标产品具备文件/工具能力"
        scope["non_trigger"] += "；未定位到影响关联不等于已证明无影响，须有范围排除依据才能不适用"
    if native and rid == "SEC10":
        scope["non_trigger"] += "；仓库存在构建配置、setup.py或入口点不等于本任务承诺交付安装包或更新"
    return scope


def _semantic_boundary(rule, condition, item):
    rid, cid = rule.get("id"), condition["id"]
    dimension = "execution" if condition.get("kind") == "execution" else "rule_specific"
    if rid.startswith("SEC") and condition.get("kind") != "execution":
        dimension = "security_contract"
    boundary = "失败只在同任务、同对象、同版本与同判断维度内汇总；相邻条款不自动继承。"
    guard = ""
    if rid == "TC12":
        dimension, guard = "design", "design_failure"
        boundary += "需求/计划中的数据、命令、期望分别核设计；缺交付断言或运行记录不能直接判设计失败。"
        if item["id"] == "TC12.C01.I05":
            guard = "design_alignment"
            boundary += "可判定不等于符合需求；逐项对照冻结用户期望和设计断言，不沿用错误实现的输出作为成功标准。"
            boundary += "先核用户显式输入/操作/期望构成的设计；缺交付断言属于交付缺口，不是相反设计期望。"
        elif item["proof_policy"] == "environment":
            dimension, guard = "environment", "environment_record"
            boundary += "平台、运行时及必要配置须有具体记录；服务名称和输出模式不能单独代替环境。"
    elif rid in {"FIX02", "FIX03"}:
        dimension = "implementation"
    elif rid in {"FIX04", "TC13"}:
        dimension = "test_delivery"
    elif rid == "TC03":
        dimension = "module_contract"
    elif rid == "TC04":
        dimension = "interface_contract"
    elif rid == "TC05":
        dimension = "data_contract"
    elif rid == "TC06":
        dimension = {"TC06.C01": "scenario_design", "TC06.C02": "state_exit_contract",
                     "TC06.C03": "unsupported_boundary"}[cid]
    if cid == "TC02.C01":
        dimension = "requirement_traceability"
    elif cid in {"TC07.C03", "SEC09.C03"}:
        dimension = "resolution_claim"
    elif cid == 'SEC09.C05':
        dimension = 'dependency_evidence'
    elif cid == 'SEC11.C04':
        dimension = 'operation_state_contract'
    if cid in {"TC09.C02", "TC09.C03"}:
        dimension, guard = "authorization", "authorization_contract"
        boundary += "新增传输字段或任务范围偏移不自动证明未授权新权限，须核有效授权边界与实际动作。"
    if cid in {"SEC12.C01", "SEC12.C06"}:
        dimension, guard = "security_chain", "security_chain"
        boundary += "先建立资产、威胁、控制、场景映射；普通功能失败不自动成为安全保护失败。"
    elif cid in {"SEC12.C02", "SEC12.C04"}:
        dimension, guard = "actual_state", "actual_claim"
        boundary += "核原Agent实际状态声明；用户期望、计划、验收目标不是已完成声明。"
    elif cid == "SEC12.C03":
        dimension, guard = "evidence_integrity", "evidence_alignment"
        boundary += "先核材料适用性；缺截图或普通功能失败不能替代证据错误的反例。"
    elif cid == "TC01.C02" and item["proof_policy"] == "environment":
        dimension, guard = "environment", "environment_record"
    elif cid == "TC14.C02":
        dimension, guard = "claim_scope", "claim_scope"
        boundary += "逐项核原Agent主张与原始来源的推论边界；有引用不能证明所有主张均受支持。"
        boundary += "一般事实、诊断、预测和计划不要求字面目标SHA；逐源核可查陈述清单，语气与所指观察/版本分别保留。"
        boundary += "主张按逐字命题拆开，同一属性和观察版本比较；计划不改写成实际完成。一般诊断可核其所指父版本，不外推当前状态。"
    elif cid == "TC02.C02":
        dimension, guard = "purpose", "purpose_alignment"
        boundary += "诊断尝试、实现及交付支持分别核有效目的；尝试无效不证明没有需求目的，功能失败不是目的冲突反例。"
    elif cid == "TC13.C03":
        dimension, guard = "completion_reasoning", "presence_substitution"
        boundary += "核原Agent声明或有效验收决定是否用产物存在代替功能完成；缺必要测试不证明发生该行为。"
    item.update(audit_object=rule_audit_scope(rule)["audit_object"], judgment_dimension=dimension,
                judgment_boundary=boundary)
    if guard:
        item["semantic_gate"] = guard
        item["semantic_schema_version"] = VERSION
    item["failure_review"] = {"version": VERSION, "dimension": dimension,
        "boundary": "须定位本子项具体义务及直接反例；相邻条款失败、缺材料、普通崩溃不能代替。"}
    if cid in {"TC04.C01", "TC05.C01"}:
        item['direct_contract_source_review'] = True


def _rule_context(rule):
    fields = ("id", "title", "version", "document_id", "applicability", "criterion", "source_ref",
              "required_evidence", "recheck", "closure_policy")
    return {key: copy.deepcopy(rule[key]) for key in fields if key in rule}


def _contract(rule, condition):
    uploaded = rule.get("source_kind") == "uploaded_rule" or rule.get("document_id") == "uploaded-rules"
    mode = "conditional" if condition.get("stage") in {"recheck", "closure_policy"} else "rule"
    trigger_text = condition.get("applicability") or rule.get("applicability", "")
    policy, kinds = "semantic", SEMANTIC
    if condition.get("kind") == "execution":
        kinds = EXECUTION
    elif condition.get("stage") in {"recheck", "closure_policy"} or not uploaded and condition["id"] in PROCESS_CONDITIONS:
        policy, kinds = "process_history", PROCESS
    if not uploaded and condition["id"] in PROCESS_TRIGGERS:
        mode, trigger_text = "conditional", PROCESS_TRIGGERS[condition["id"]]
    texts = condition.get("source_items") or [condition["text"]]
    items = [_item(text, kinds, policy, mode, trigger_text) for text in texts]
    special = SPECIAL.get(condition["id"])
    if not uploaded and special and (rule.get("document_id"), condition["text"]) == special[:2]:
        items = copy.deepcopy(special[2])
    native_closure = (not uploaded and condition["id"] in {"FIX06.C01", "FIX06.C04"}
                      and special and (rule.get("document_id"), condition["text"]) == special[:2]
                      and rule.get("version") == "0.1" and rule.get("criterion") == CLOSURE_CRITERION
                      and CLOSURE_CRITERION in rule.get("source_ref", {}).get("quote", "")
                      and rule.get("source_ref", {}).get("document_id") == "code-fix-0.1"
                      and condition.get("source_ref", {}).get("quote") == condition["text"]
                      and '"id": "FIX06"' in rule.get("source_ref", {}).get("quote", ""))
    if condition["id"] in {"FIX06.C01", "FIX06.C04"} and not native_closure:
        items = [_item(text, kinds, policy, mode, trigger_text) for text in texts]
    for index, item in enumerate(items, 1):
        item["id"] = condition["id"] + ".I" + str(index).zfill(2)
        if not item["trigger"]["text"]:
            item["trigger"]["text"] = trigger_text
        if not uploaded:
            _semantic_boundary(rule, condition, item)
        else:
            item.update(audit_object=rule_audit_scope(rule)['audit_object'],
                        judgment_dimension='uploaded_rule_specific',
                        judgment_boundary='只核上传条款自己的义务；相同ID不继承本地判定、延期或执行豁免。',
                        failure_review={'version': VERSION, 'dimension': 'uploaded_rule_specific',
                                        'boundary': '上传条款须有自身直接反例，邻条款失败不传播。'})
    # A clause is unconditional only when all its atomic obligations are unconditional.
    modes = {item["trigger"]["mode"] for item in items}
    contract = {"version": VERSION,
                "origin": "uploaded_explicit" if uploaded else "library_interpretation",
                "aggregation": "all", "trigger": {"mode": next(iter(modes)) if len(modes) == 1 else "rule",
                                                        "text": trigger_text},
                "allowed_evidence_kinds": list(dict.fromkeys(kind for item in items for kind in item["allowed_evidence_kinds"])),
                "proof_policy": items[0]["proof_policy"] if len({item["proof_policy"] for item in items}) == 1 else "semantic",
                "items": items, "rule_context": _rule_context(rule)}
    if not uploaded:
        contract.update(audit_scope=rule_audit_scope(rule), audit_object=rule_audit_scope(rule)["audit_object"],
                        judgment_dimension=items[0]["judgment_dimension"] if len({item["judgment_dimension"] for item in items}) == 1 else "rule_specific")
    if not uploaded and condition["id"] == "FIX02.C01" and special and condition["text"] == special[1]:
        contract.update(acceptance_dimension="implementation", acceptance_scope="all_required")
    if not uploaded and condition["id"] in {"TC13.C01", "TC13.C02"} and rule.get("document_id") == "technical-0.2":
        contract.update(acceptance_dimension="test_design", acceptance_scope="all_behavior_and_test_delivery")
        if condition["id"] == "TC13.C02":
            contract["acceptance_scope"] = "all_design_sufficient_only"
    if native_closure:
        contract["closure_required_rules"] = ["FIX01", "FIX02", "FIX03", "FIX04", "FIX05"]
    if (not uploaded and rule.get("id") == "FIX03" and rule.get("document_id") == "code-fix-0.1"
            and rule.get("version") == "0.1" and rule.get("criterion") == IMPLEMENTATION_CRITERION
            and condition["id"] == "FIX03.C02" and condition["text"] == "运行性结论另需实际证据"
            and condition.get("source_ref", {}).get("quote") == condition["text"]
            and IMPLEMENTATION_CRITERION in rule.get("source_ref", {}).get("quote", "")
            and rule.get("source_ref", {}).get("document_id") == "code-fix-0.1"
            and '"id": "FIX03"' in rule.get("source_ref", {}).get("quote", "")):
        contract.update(execution_dimension="evidence_presence", allowed_evidence_kinds=EXECUTION.copy(),
                        judgment_dimension="execution_evidence")
        for item in items:
            item.update(allowed_evidence_kinds=EXECUTION.copy(), judgment_dimension="execution_evidence")
            item['failure_review']['dimension'] = 'execution_evidence'
    execution = EXECUTION_DIMENSIONS.get(condition["id"])
    if (not uploaded and execution and rule.get("id") == "FIX05" and rule.get("document_id") == "code-fix-0.1"
            and rule.get("version") == "0.1" and condition["text"] == execution[0]
            and rule.get("criterion") == EXECUTION_CRITERION
            and EXECUTION_CRITERION in rule.get("source_ref", {}).get("quote", "")
            and rule.get("source_ref", {}).get("document_id") == "code-fix-0.1"
            and condition.get("source_ref", {}).get("document_id") == "code-fix-0.1"
            and '"id": "FIX05"' in rule.get("source_ref", {}).get("quote", "")):
        contract["execution_dimension"] = execution[1]
        dimension = 'execution' if execution[1] == 'behavior' else execution[1]
        contract['judgment_dimension'] = dimension
        for item in items:
            item['judgment_dimension'] = dimension
            item['failure_review']['dimension'] = dimension
        if execution[1] != "behavior":
            for item in items:
                item["allowed_evidence_kinds"] = list(dict.fromkeys(item["allowed_evidence_kinds"] + EXECUTION))
            contract["allowed_evidence_kinds"] = list(dict.fromkeys(contract["allowed_evidence_kinds"] + EXECUTION))
        if execution[1] == "evidence_completeness":
            for item in items:
                if item["text"] == "环境和真实/mock分类":
                    item["allowed_evidence_kinds"] = list(dict.fromkeys(item["allowed_evidence_kinds"] + ["context"]))
            contract["allowed_evidence_kinds"] = list(dict.fromkeys(contract["allowed_evidence_kinds"] + ["context"]))
    return contract


def ensure_contracts(catalog):
    """Derive current contracts in a copy, including legacy frozen catalogs without contracts.

    Supplied contract fields are not a trust source. Original documents, clauses and source
    hashes are preserved; callers must keep existing saved reports immutable.
    """
    result = copy.deepcopy(catalog)
    contracts = []
    for rule in result.get("rules", []):
        for condition in rule.get("conditions", []):
            condition["contract"] = _contract(rule, condition)
            contracts.append({"condition_id": condition["id"], "contract": condition["contract"]})
    result["contract_version"] = VERSION
    result["contract_sha256"] = hashlib.sha256(json.dumps(contracts, sort_keys=True, ensure_ascii=False,
                                                         separators=(",", ":")).encode("utf-8")).hexdigest()
    return result

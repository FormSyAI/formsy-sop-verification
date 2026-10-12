// Local UI only. Report objects are retained unchanged; uploaded text is never executed.
const $ = (id) => document.getElementById(id);
const escapeHtml = (value) =>
  String(value ?? "").replace(
    /[&<>"']/g,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[character],
  );
const labels = {
  satisfied: "满足",
  unsatisfied: "不满足",
  unverified: "未核查",
  not_applicable: "不适用",
};
const sections = {
  goal: "目标与范围",
  constraints: "规则与约束",
  behavior: "行为与边界",
  impact: "技术影响",
  preparation: "实现准备",
  acceptance: "完成条件",
};
const kinds = {
  user_message: "用户要求",
  assistant_message: "助手记录",
  commit_diff: "代码改动",
  source: "源码 / 测试",
  context: "上下文",
  tool_call: "工具调用",
  tool_result: "工具输出",
};
const modeLabels = {
  synthetic_replay: "合成材料 · 模型回放",
  offline_fixture: "合成材料 · 离线示例",
  offline: "离线验证",
  model: "模型核查",
};
const validationLabels = {
  unsupported_evidence_kind: "证据来源不能证明本项要求。",
  invalid_evidence_refs: "证据引用格式不完整。",
  invalid_evidence_ref: "某条证据引用缺少有效的来源或行号。",
  redacted_quote_is_not_original_evidence: "引文已被脱敏，不能作为原始证据证明。",
  invalid_sop_refs: "规范引用格式不完整。",
  invalid_sop_ref: "某条规范引用缺少有效字段或引文。",
  sop_ref_wrong_chapter: "规范引用指向了不对应的章节。",
  invalid_sop_pointer: "规范字段指针不存在或无法读取。",
  noncanonical_array_index: "规范引用的数组位置格式不合法。",
  sop_quote_mismatch: "引文与所指规范原文不一致。",
  atomic_item_set_mismatch: "候选未包含本条件要求的完整原子项。",
  duplicate_atomic_item: "候选重复引用了同一个原子项。",
  parent_atomic_result_conflict: "条件结论与原子项结论冲突。",
  candidate_condition_set_mismatch: "候选条件缺失、重复或身份不一致。",
  missing_or_duplicate_condition: "该条件的候选缺失或重复。",
  invalid_result: "候选结论不属于允许的四种状态。",
  invalid_atomic_result: "原子项结论不属于允许的四种状态。",
  invalid_candidate_shape: "候选结构不完整，无法验证。",
  missing_user_requirement: "缺少可读取的用户要求原文。",
  provider_request_failed: "模型请求失败，未获得完整分析。",
  model_unconfigured: "本地未配置模型。",
};
const state = {
  config: null,
  demo: null,
  request: null,
  rounds: [],
  active: 0,
  busy: false,
  fileName: "合成示例",
};
let evidenceTargets = [];
let sopTargets = [];

function badge(result) {
  return `<span class="badge ${Object.hasOwn(labels, result) ? result : ""}">${escapeHtml(labels[result] ?? "未知状态")}</span>`;
}

function setError(message = "") {
  $("error").textContent = message;
  $("error").hidden = !message;
}

async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok)
    throw new Error(
      `${data.error?.message ?? "本地服务请求失败"} (${data.error?.code ?? response.status})`,
    );
  return data;
}

function assertRequest(request) {
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    !request.context ||
    !request.sop ||
    !Array.isArray(request.sources)
  )
    throw new Error("请选择完整 worker request JSON，需包含 context、sop 和 sources。");
  const ids = new Set();
  for (const source of request.sources) {
    if (
      !source ||
      typeof source.id !== "string" ||
      typeof source.content !== "string" ||
      ids.has(source.id)
    )
      throw new Error("sources 需要唯一字符串 id 和原文 content。");
    ids.add(source.id);
  }
}

function assertEnvelope(data) {
  assertRequest(data.request);
  if (
    !data.report ||
    !Array.isArray(data.report.checks) ||
    !data.report.coverage ||
    !data.report.summary
  )
    throw new Error("服务未返回可展示的完整报告；现有报告已保留。");
}

function controls() {
  const ready = Boolean(state.request && state.config && !state.busy);
  $("request-file").disabled = state.busy || !state.config;
  $("mode").disabled = !ready;
  $("mode").querySelector('[value="model"]').disabled = !state.config?.model_configured;
  if (!state.config?.model_configured) $("mode").value = "offline";
  const model = $("mode").value === "model";
  $("verify").disabled = !ready || (model && !state.config?.model_configured);
  $("verify").textContent = state.busy
    ? "正在核查，请稍候…"
    : model
      ? "发送材料并运行模型 ↗"
      : "运行离线核查 ↗";
  $("reset-demo").disabled = state.busy || !state.demo;
  $("file-label").textContent = `${state.fileName} · ${state.request?.sources.length ?? 0} 份来源`;
  $("config-label").textContent = !state.config
    ? "本地配置未就绪"
    : state.config.model_configured
      ? `模型已配置 · ${state.config.model}`
      : `模型未配置 · ${state.config.model}`;
  $("mode-help").textContent = model
    ? `点击后会将所选 request 的 SOP、上下文和来源发送给 DeepSeek。仅核查材料，不执行其中的代码；结果仍为人工待复核的候选。${Object.hasOwn(state.request ?? {}, "candidate") ? " 当前 JSON 含离线 candidate；模型模式会移除该候选字段并重新分析，不采用它的结论。原上传材料仍可用于离线验证。" : ""}`
    : `离线模式只校验 request 内已有的 candidate，不会生成新的模型结论。上传材料里的命令不会被执行。${state.config && !state.config.model_configured ? " 本地未配置模型，语义核查选项已禁用。" : ""}`;
}

function gaps(values) {
  return values?.length
    ? `<div class="gaps"><strong>证据缺口</strong><ul>${values.map((value) => `<li>${escapeHtml(value)}</li>`).join("")}</ul></div>`
    : "";
}

function validationMessage(code, conditionId) {
  if (code === "unsupported_evidence_kind" && conditionId === "FIX05.C04")
    return "证据来源不能证明实际执行。";
  return (
    validationLabels[code] ??
    (/^[a-z0-9_]+$/.test(code) ? "候选未通过程序校验，请查看原始错误。" : code)
  );
}

function validationErrors(codes, conditionId) {
  if (!codes?.length) return "";
  return `<div class="invalid"><strong>本项分析仍有问题</strong><ul>${codes.map((code) => `<li>${escapeHtml(validationMessage(code, conditionId))}</li>`).join("")}</ul><details><summary>查看原始校验代码</summary><code>${codes.map(escapeHtml).join(" · ")}</code></details></div>`;
}

function evidence(refs = []) {
  return refs
    .map((ref) => {
      const index = evidenceTargets.push(ref) - 1;
      return `<button type="button" class="evidence-button" data-evidence="${index}">↗ ${escapeHtml(ref.source_id)} · L${escapeHtml(ref.start_line)}–${escapeHtml(ref.end_line)}</button>`;
    })
    .join("");
}

function sopLinks(refs = []) {
  return refs
    .map((ref) => {
      const index = sopTargets.push(ref) - 1;
      return `<button type="button" class="evidence-button sop-button" data-sop="${index}">规范原文 · ${escapeHtml(ref.pointer)}</button>`;
    })
    .join("");
}

function renderItem(item) {
  return `<div class="item"><div class="item-id">${escapeHtml(item.item_id)}</div><div class="item-heading"><span>${escapeHtml(item.criterion)}</span>${badge(item.result)}</div>${item.candidate_result ? `<div class="candidate-label">模型候选：${escapeHtml(labels[item.candidate_result] ?? "未知状态")}</div>` : ""}<p class="reason">${escapeHtml(item.reason)}</p>${gaps(item.gaps)}<div class="evidence-links">${evidence(item.evidence_refs)}</div></div>`;
}

function renderCheck(check, index) {
  const items = check.items ?? [];
  return `<article class="card condition"><div class="condition-heading"><div><div class="condition-number">CONDITION 0${index + 1} &nbsp; / &nbsp; ${escapeHtml(check.condition_id)}</div><h3>${escapeHtml(check.title)}</h3></div><div class="condition-state">${badge(check.result)}<div class="candidate-label">模型候选：${escapeHtml(labels[check.candidate_result] ?? "未提供")}</div></div></div><p class="criterion">${escapeHtml(check.criterion)}</p><p class="reason">${escapeHtml(check.reason)}</p>${gaps(check.gaps)}${validationErrors(check.validation_errors, check.condition_id)}<div class="evidence-links">${evidence(check.evidence_refs)}${sopLinks(check.sop_refs)}</div><details class="atomic"><summary>逐个检查原子义务（${items.length}）<span>逐项验证后状态</span></summary>${items.length ? items.map(renderItem).join("") : '<p class="muted">本条件没有可展示的有效原子项；请先查看缺口和校验错误。</p>'}</details></article>`;
}

function render() {
  const round = state.rounds[state.active];
  if (!round) return;
  evidenceTargets = [];
  sopTargets = [];
  const { report, request, mode } = round;
  const coverage = report.coverage;
  const pin = report.sop_pin ?? request.sop;
  const model = report.model ?? {};
  const counts = report.summary.counts;
  const synthetic = mode === "synthetic_replay" || mode === "offline_fixture";
  const analysisErrors = report.analysis_errors ?? [];
  const status = report.analysis_complete
    ? "本轮分析已完成 · 候选待人工复核"
    : "本轮分析未完成 · 保留有效条件与缺口";
  const modelText = model.invoked
    ? `${escapeHtml(model.provider ?? "DeepSeek")} / ${escapeHtml(model.model ?? "—")}，记录调用 ${escapeHtml(model.request_count ?? "—")} 次，模型状态 ${escapeHtml(model.status ?? "—")}${mode === "synthetic_replay" ? "。本页仅回放已保存报告，没有再次调用模型" : ""}`
    : "本轮未调用模型；仅做离线候选与引用验证";
  $("report").innerHTML =
    `${synthetic ? `<div class="notice"><strong>${mode === "synthetic_replay" ? "合成材料 · 真实模型结果回放" : "合成材料 · 离线契约示例"}</strong>本例的需求、源码、diff、SOP 和目标 SHA 都是合成材料。${mode === "synthetic_replay" ? "报告来自已完成的一次 DeepSeek 调用，原样展示验证后结果。" : "结果来自离线测试候选，不代表模型执行。"}没有执行示例代码或测试，也不代表真实任务已落库。</div>` : ""}<div class="report-heading"><div><div class="step-label">CANDIDATE REPORT</div><h2>${escapeHtml(request.context.title ?? "SOP 核查报告")}</h2><p class="report-subtitle">${escapeHtml(modeLabels[mode] ?? mode)} · ${escapeHtml(round.createdLabel)} · 人工未复核 · 正式未关闭</p></div><label class="history"><select id="history" aria-label="选择报告轮次" ${state.busy ? "disabled" : ""}>${state.rounds.map((entry, index) => `<option value="${index}" ${index === state.active ? "selected" : ""}>第 ${state.rounds.length - index} 轮 · ${escapeHtml(modeLabels[entry.mode] ?? entry.mode)}</option>`).join("")}</select><small>当前页面共 ${state.rounds.length} 轮；刷新后重置，不覆盖旧轮次。</small></label></div><div class="notice ${report.analysis_complete ? "" : "warning"}"><strong>${escapeHtml(status)}</strong><p>${modelText}。</p>${analysisErrors.length ? `<p>分析错误：${analysisErrors.map(escapeHtml).join(" · ")}</p>` : ""}<p>程序校验保留四态，不证明语义正确。${report.formal_closed === true ? "报告存在异常的正式关闭标记，本工具仍不执行任何任务关闭。" : "任何满足结论都仍是候选，需人工检查。"}</p></div><div class="stats">${Object.entries(
      labels,
    )
      .map(
        ([key, label]) =>
          `<div class="card stat ${key}"><div class="stat-value">${escapeHtml(counts?.[key] ?? "—")}</div><div class="stat-label">${label}</div><i class="stat-dot"></i></div>`,
      )
      .join(
        "",
      )}</div><div class="card scope"><div><h3>局部参考映射 · ${escapeHtml(coverage.mapped_conditions)} 个条件 / ${escapeHtml(coverage.mapped_sections?.length ?? 0)} 章</h3><p>已映射：${(coverage.mapped_sections ?? []).map((id) => escapeHtml(sections[id] ?? id)).join("、")}。未覆盖：${(coverage.unmapped_sections ?? []).map((id) => escapeHtml(sections[id] ?? id)).join("、")}。</p><p>材料完整性：${coverage.evidence_completeness === "complete" ? "输入标为完整；仍需逐项核对证据" : "材料部分可用或完整性未知，不能声称完整审查"}。当前 ${escapeHtml(coverage.mapped_conditions)} 个参考条件不代表六章全文符合。</p></div><div class="version"><span class="badge">SOP v${escapeHtml(pin.version)}</span><button type="button" class="evidence-button sop-button" data-full-sop>查看规范</button></div><details><summary>固定版本、摘要与本轮身份</summary><dl><dt>项目 / 任务</dt><dd>${escapeHtml(request.context.project_id)} / ${escapeHtml(request.context.task_id)}</dd><dt>SOP 摘要</dt><dd><code>${escapeHtml(pin.digest)}</code></dd><dt>规范身份校验</dt><dd>${escapeHtml(report.sop_pin_validation ?? "未提供")}</dd><dt>目标 Commit</dt><dd><code>${escapeHtml(request.context.target_commit || "未选定；改动覆盖应保持未核查")}</code>${synthetic ? "（合成版本标识）" : ""}</dd><dt>映射修订</dt><dd>${escapeHtml(coverage.profile_id)} / ${escapeHtml(coverage.mapping_revision)}</dd>${round.record ? `<dt>本地轮次</dt><dd>${escapeHtml(round.record.id)}</dd><dt>输入摘要</dt><dd><code>${escapeHtml(round.record.input_sha256)}</code></dd><dt>报告摘要</dt><dd><code>${escapeHtml(round.record.report_sha256)}</code></dd>` : ""}</dl></details></div><div class="condition-list">${report.checks.map(renderCheck).join("")}</div><section class="card source-library"><h3>本轮原始材料 · ${request.sources.length} 份</h3><p>点击引用可按 source_id 和原始行号回看。这里只读取材料，不运行其中的命令。</p><div class="source-list">${request.sources.map((source, index) => `<button type="button" class="evidence-button" data-source="${index}">${escapeHtml(source.id)} <span class="muted">${escapeHtml(kinds[source.kind] ?? source.kind)}</span></button>`).join("")}</div></section>`;
}

function addRound(data, createdLabel) {
  assertEnvelope(data);
  state.rounds.unshift({ ...data, createdLabel });
  state.active = 0;
  render();
}

function showDialog(title, body) {
  $("source-title").textContent = title;
  $("source-body").innerHTML = body;
  $("source-dialog").showModal();
}

function showSource(source, ref) {
  if (!source)
    return showDialog(
      "原文未定位",
      '<div class="notice warning">此 source_id 不在本轮固定输入中，未显示替代材料。</div>',
    );
  const round = state.rounds[state.active];
  const lines = source.content.split("\n");
  const rangeValid =
    ref &&
    Number.isInteger(ref.start_line) &&
    Number.isInteger(ref.end_line) &&
    ref.start_line >= 1 &&
    ref.end_line >= ref.start_line &&
    ref.end_line <= lines.length;
  const quoteFound =
    rangeValid &&
    typeof ref.quote === "string" &&
    ref.quote.length > 0 &&
    lines
      .slice(ref.start_line - 1, ref.end_line)
      .join("\n")
      .includes(ref.quote);
  const metadata = round.report.source_index?.[source.id] ?? {};
  // Bound presentation only; the worker receives the complete, unchanged source.
  const quoteLine = quoteFound
    ? ref.start_line -
      1 +
      lines
        .slice(ref.start_line - 1, ref.end_line)
        .join("\n")
        .split(ref.quote)[0]
        .split("\n").length -
      1
    : 0;
  const start = quoteFound ? Math.max(0, quoteLine - 100) : 0;
  const end = Math.min(lines.length, start + (quoteFound ? 201 : 300));
  showDialog(
    `${source.id} · ${kinds[source.kind] ?? source.kind}`,
    `<p class="source-metadata">${escapeHtml(source.kind)} · ${lines.length} 行${ref ? ` · 引用 L${escapeHtml(ref.start_line)}–${escapeHtml(ref.end_line)}` : ""}<br />报告记录的原始文本摘要：<code>${escapeHtml(metadata.original_sha256 ?? "未提供")}</code>${metadata.redacted ? `<br />分析文本经过脱敏，分析文本摘要：<code>${escapeHtml(metadata.sha256 ?? "未提供")}</code>` : ""}</p>${ref ? `<blockquote>${escapeHtml(ref.quote)}</blockquote><div class="notice ${quoteFound ? "" : "warning"}">${quoteFound ? "已定位 source_id、行号及逐字引文；高亮为引用所在行。" : "引用行号或逐字文本与当前原始材料不一致，未声称定位成功。报告可能含脱敏文本，请继续人工核对。"}</div>` : ""}${start > 0 || end < lines.length ? `<div class="notice">为保持页面流畅，仅展示 L${start + 1}–${end} 的阅读窗口。完整材料仍保留在本轮输入中，核查输入未因此截断。</div>` : ""}<div class="source-lines">${lines
      .slice(start, end)
      .map((line, offset) => {
        const number = start + offset + 1;
        return `<div class="source-line ${quoteFound && number >= ref.start_line && number <= ref.end_line ? "highlight" : ""}"><span class="line-number">${number}</span><span class="line-content">${escapeHtml(line) || " "}</span></div>`;
      })
      .join(
        "",
      )}</div><details><summary>原始定位信息</summary><pre class="json">${escapeHtml(JSON.stringify(source.locator ?? {}, null, 2))}</pre></details>`,
  );
  if (quoteFound)
    requestAnimationFrame(() =>
      $("source-body").querySelector(".highlight")?.scrollIntoView({ block: "center" }),
    );
}

function pointerValue(value, pointer) {
  if (pointer === "") return value;
  if (typeof pointer !== "string" || !pointer.startsWith("/") || /~(?![01])/.test(pointer))
    return undefined;
  for (const token of pointer.slice(1).split("/")) {
    const key = token.replace(/~1/g, "/").replace(/~0/g, "~");
    if (Array.isArray(value) && !/^(0|[1-9][0-9]*)$/.test(key)) return undefined;
    if (!value || typeof value !== "object" || !Object.hasOwn(value, key)) return undefined;
    value = value[key];
  }
  return value;
}

function showSop(ref) {
  const sop = state.rounds[state.active].request.sop;
  const value = ref ? pointerValue(sop, ref.pointer) : sop;
  const valid =
    ref &&
    typeof value === "string" &&
    typeof ref.quote === "string" &&
    ref.quote.length > 0 &&
    value.includes(ref.quote);
  showDialog(
    ref ? `规范原文 · ${ref.pointer}` : `本轮固定 SOP · v${sop.version}`,
    `${ref ? `<blockquote>${escapeHtml(ref.quote)}</blockquote><div class="notice ${valid ? "" : "warning"}">${valid ? "已定位规范字段及逐字引文。" : "规范指针或逐字引文未匹配，保留未定位状态。"}</div>` : '<div class="notice">此处展示输入内固定的 SOP 原文。结构校验不代替 FormSy Server 的授权与 RFC8785 摘要验证。</div>'}<div class="sop-value">${escapeHtml(value === undefined ? "没有找到该规范字段。" : typeof value === "string" ? value : JSON.stringify(value, null, 2))}</div>`,
  );
}

$("report").addEventListener("click", (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  const round = state.rounds[state.active];
  if (button.hasAttribute("data-evidence")) {
    const ref = evidenceTargets[Number(button.dataset.evidence)];
    if (ref)
      showSource(
        round.request.sources.find((source) => source.id === ref.source_id),
        ref,
      );
  } else if (button.hasAttribute("data-source"))
    showSource(round.request.sources[Number(button.dataset.source)]);
  else if (button.hasAttribute("data-sop")) showSop(sopTargets[Number(button.dataset.sop)]);
  else if (button.hasAttribute("data-full-sop")) showSop();
});

$("report").addEventListener("change", (event) => {
  if (event.target.id !== "history") return;
  state.active = Number(event.target.value);
  render();
});
$("close-dialog").addEventListener("click", () => $("source-dialog").close());
$("mode").addEventListener("change", controls);
$("request-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file) return;
  try {
    if (file.size > 2 * 1024 * 1024)
      throw new Error("request JSON 超过 2 MiB，请缩小材料；不会自动截断来源。");
    const request = JSON.parse(await file.text());
    assertRequest(request);
    state.request = request;
    state.fileName = file.name;
    $("mode").value = "offline";
    setError();
    controls();
  } catch (error) {
    setError(`材料未载入：${error.message} 现有材料和报告已保留。`);
  }
  event.target.value = "";
});

$("verify").addEventListener("click", async () => {
  if (state.busy || !state.request || !state.config) return;
  const mode = $("mode").value;
  if (mode !== "offline" && mode !== "model") return;
  if (mode === "model" && !state.config.model_configured)
    return setError("本地未配置模型，未发送材料。");
  const request = { ...state.request, mode };
  if (mode === "model") delete request.candidate;
  state.busy = true;
  controls();
  render();
  setError();
  try {
    const data = await api("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request }),
    });
    addRound(
      data,
      new Date(data.record?.created_at ?? Date.now()).toLocaleString("zh-CN", { hour12: false }),
    );
    $("report").scrollIntoView({ behavior: "smooth", block: "start" });
  } catch (error) {
    setError(`本轮未确认生成结果：${error.message} 旧报告已保留；本页不会自动重试模型请求。`);
  } finally {
    state.busy = false;
    controls();
    render();
  }
});

$("reset-demo").addEventListener("click", () => {
  if (!state.demo || state.busy) return;
  state.request = state.demo.request;
  state.fileName = "合成示例";
  $("mode").value = "offline";
  const existing = state.rounds.findIndex((round) => round.report === state.demo.report);
  if (existing >= 0) {
    state.active = existing;
    render();
  } else addRound(state.demo, "已保存的示例");
  setError();
  controls();
});

async function start() {
  const results = await Promise.allSettled([api("/api/config"), api("/api/demo")]);
  const errors = [];
  if (results[0].status === "fulfilled") state.config = results[0].value;
  else errors.push(`本地配置不可用：${results[0].reason.message}`);
  if (results[1].status === "fulfilled") {
    try {
      assertEnvelope(results[1].value);
      state.demo = results[1].value;
      state.request = state.demo.request;
      addRound(state.demo, "已保存的示例");
    } catch (error) {
      errors.push(error.message);
    }
  } else errors.push(`示例不可用：${results[1].reason.message}`);
  if (!state.demo)
    $("report").innerHTML =
      '<div class="card loading">尚无可展示的报告。可上传完整 request JSON，再显式运行离线核查。</div>';
  setError(errors.join("；"));
  controls();
}

start();

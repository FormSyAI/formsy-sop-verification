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
const kinds = {
  user_message: "用户要求",
  assistant_message: "助手记录",
  commit_diff: "代码改动",
  source: "源码 / 测试",
  context: "上下文",
  tool_call: "工具调用",
  tool_result: "工具输出",
};
async function api(path, options) {
  const response = await fetch(path, options);
  const data = await response.json();
  if (!response.ok) {
    const error = new Error(
      `${data.error?.message ?? "本地服务请求失败"} (${data.error?.code ?? response.status})`,
    );
    error.code = data.error?.code;
    throw error;
  }
  return data;
}

function showDialog(title, body) {
  $("source-title").textContent = title;
  $("source-body").innerHTML = body;
  $("source-dialog").showModal();
}

function showFrozenSource(source, ref, metadata = {}) {
  if (!source)
    return showDialog(
      "原文未定位",
      '<div class="notice warning">此 source_id 不在本轮固定输入中，未显示替代材料。</div>',
    );
  /* eslint-disable no-control-regex -- Match Python splitlines boundaries used by the full engine. */
  const pythonBreak = /\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/g;
  const python = metadata.line_mode === "python";
  // The full engine uses Python splitlines(keepends=True); the four-check worker uses LF only.
  const segments = python
    ? (source.content.match(
        /[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]*(?:\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029])|[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]+$/g,
      ) ?? [])
    : source.content.split("\n");
  const lines = python
    ? segments.map((line) => line.replace(/(?:\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029])$/, ""))
    : segments;
  /* eslint-enable no-control-regex */
  const rangeValid =
    ref &&
    Number.isInteger(ref.start_line) &&
    Number.isInteger(ref.end_line) &&
    ref.start_line >= 1 &&
    ref.end_line >= ref.start_line &&
    ref.end_line <= lines.length;
  const selectedText = rangeValid
    ? segments.slice(ref.start_line - 1, ref.end_line).join(python ? "" : "\n")
    : "";
  const quoteFound =
    rangeValid &&
    typeof ref.quote === "string" &&
    ref.quote.length > 0 &&
    selectedText.includes(ref.quote);
  // Bound presentation only; the worker receives the complete, unchanged source.
  const quoteLine = quoteFound
    ? ref.start_line -
      1 +
      (python
        ? (selectedText.split(ref.quote)[0].match(pythonBreak)?.length ?? 0)
        : selectedText.split(ref.quote)[0].split("\n").length - 1)
    : 0;
  const start = quoteFound ? Math.max(0, quoteLine - 100) : 0;
  const end = Math.min(lines.length, start + (quoteFound ? 201 : 300));
  showDialog(
    `${source.id} · ${kinds[source.kind] ?? source.kind}`,
    `<p class="source-metadata">${escapeHtml(source.kind)} · ${lines.length} 行${ref ? ` · 引用 L${escapeHtml(ref.start_line)}–${escapeHtml(ref.end_line)}` : ""}<br />报告记录的上传原文摘要：<code>${escapeHtml(metadata.original_sha256 ?? (Array.isArray(metadata.original_sha256s) ? metadata.original_sha256s.join("、") : "未提供"))}</code>${metadata.redacted ? "<br />脱敏展示，与上传原文摘要不同。" : ""}${metadata.sha256 ? `<br />分析文本摘要：<code>${escapeHtml(metadata.sha256)}</code>` : ""}${metadata.display_sha256 ? `<br />当前展示文本摘要：<code>${escapeHtml(metadata.display_sha256)}</code>` : ""}</p>${ref ? `<blockquote>${escapeHtml(ref.quote)}</blockquote><div class="notice ${quoteFound ? "" : "warning"}">${quoteFound ? "已定位 source_id、行号及逐字引文；高亮为引用所在行。" : "引用行号或逐字文本与当前冻结材料不一致，未声称定位成功。报告可能含脱敏文本，请继续人工核对。"}</div>` : ""}${start > 0 || end < lines.length ? `<div class="notice">为保持页面流畅，仅展示 L${start + 1}–${end} 的阅读窗口。完整材料仍保留在本轮快照中，核查输入未因此截断。</div>` : ""}<div class="source-lines">${lines
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

$("close-dialog").addEventListener("click", () => $("source-dialog").close());
document.querySelectorAll('[data-view="full"]').forEach((button) =>
  button.addEventListener("click", () => $("full-view").scrollIntoView({ behavior: "smooth", block: "start" })),
);

const fullState = {
  config: null,
  library: null,
  uploaded: null,
  uploading: false,
  loading: false,
  demos: [],
  demo: null,
  request: null,
  fileName: "",
  rounds: [],
  active: 0,
  viewVersion: 0,
  submitting: false,
  polling: false,
  pollVersion: 0,
  timer: null,
  query: "",
  filter: "",
  providerBlocked: false,
};
const fullResults = {
  满足: "satisfied",
  不满足: "unsatisfied",
  未核查: "unverified",
  不适用: "not_applicable",
};
const jobLabels = {
  queued: "等待审计",
  running: "正在审计",
  cancelling: "正在停止旧审计",
  cancelled: "审计已停止",
  completed: "作业已返回",
  failed: "作业失败",
};
const failureCategoryNames = {
  configuration: "模型配置不可用",
  authentication: "模型认证失败",
  quota: "模型额度不足",
  rate_limit: "模型请求限流",
  http: "模型服务 HTTP 错误",
  timeout: "模型请求超时",
  connection: "模型连接失败",
  read_incomplete: "模型响应读取不完整",
  output: "模型输出不合要求",
  validation: "审计校验失败",
  budget: "审计调用预算耗尽",
  storage: "记录保存失败",
  internal_unknown: "程序内部错误，原因尚未确定",
  start: "后台任务启动失败",
};

function failureDetailsHtml(failure) {
  if (!failure || typeof failure !== "object" || Array.isArray(failure)) return "";
  const category = typeof failure.error_category === "string"
    ? (Object.hasOwn(failureCategoryNames, failure.error_category) ? failureCategoryNames[failure.error_category] : "未分类错误")
    : null;
  return [
    ["错误类别", category],
    ["失败阶段", failure.failure_stage],
    ["HTTP 状态", Number.isInteger(failure.http_status) && failure.http_status >= 100 && failure.http_status <= 599
      ? String(failure.http_status) : null],
    ["请求阶段", ["prepare", "connect", "read", "parse", "store", "engine", "job", "report"].includes(failure.phase) ? failure.phase : null],
    ["原始响应已保存", typeof failure.response_saved === "boolean" ? (failure.response_saved ? "是" : "否") : null],
    ["异常类型", failure.exception_type],
    ["模型服务代码", failure.provider_code],
  ].filter(([, value]) => typeof value === "string" && value)
    .map(([label, value]) => `<p>${label}：${escapeHtml(value)}</p>`).join("");
}

function setFullError(message = "") {
  $("full-error").textContent = message;
  $("full-error").hidden = !message;
}

function assertFullRequest(request) {
  if (
    !request ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    Object.keys(request).some(
      (key) =>
        ![
          "title",
          "trace",
          "commits",
          "materials",
          "audit_context",
          "sop_selection",
          "rules",
        ].includes(key),
    ) ||
    typeof request.title !== "string" ||
    !Array.isArray(request.trace?.messages) ||
    !Array.isArray(request.commits) ||
    !Array.isArray(request.materials)
  )
    throw new Error(
      "完整审计请求需包含 title、trace.messages、commits、materials；旧版四项 worker 请求与此格式不同。",
    );
  if (
    request.trace.messages.some(
      (message) =>
        !["user", "assistant", "tool"].includes(message?.role) ||
        typeof message.content !== "string",
    ) ||
    !request.trace.messages.some((message) => message.role === "user" && message.content.trim())
  )
    throw new Error("trace.messages 需要明确的用户要求原文，以及合法的 role/content。");
  if (
    request.commits.some(
      (commit) =>
        !/^[0-9a-f]{40}$/i.test(commit?.sha) ||
        (commit.diff !== undefined && typeof commit.diff !== "string"),
    ) ||
    request.materials.some(
      (material) =>
        !["source", "context", "test_log", "run_record"].includes(material?.kind) ||
        typeof material.name !== "string" ||
        typeof material.content !== "string",
    )
  )
    throw new Error("Commit 需要完整 40 位 SHA；materials 需要合法 kind、name 和 content。");
  if (
    request.audit_context?.profile &&
    !["code_fix", "full_sop"].includes(request.audit_context.profile)
  )
    throw new Error("audit_context.profile 只能是 code_fix 或 full_sop。");
  if (request.rules !== undefined && (!Array.isArray(request.rules) || !request.rules.length))
    throw new Error("自定义规则需包含非空 rules 数组。");
  if (request.sop_selection?.mode && !["auto", "uploaded"].includes(request.sop_selection.mode))
    throw new Error("请选择默认 FormSy SOP 或上传自定义规则。");
  if (new TextEncoder().encode(JSON.stringify(request)).length > 2 * 1024 * 1024)
    throw new Error("完整审计请求超过 2 MiB，未自动截断材料。");
}

function assertFullReport(report) {
  const validRefs = (refs) =>
    Array.isArray(refs) &&
    refs.every((ref) => ref && typeof ref === "object" && !Array.isArray(ref));
  const objectRows = (value) =>
    Array.isArray(value) &&
    value.every((row) => row && typeof row === "object" && !Array.isArray(row));
  if (
    report?.schema_version !== "2.1" ||
    !objectRows(report.tasks) ||
    [
      "checks",
      "findings",
      "rules",
      "sop_rules",
      "acceptance_checks",
      "change_coverage",
      "unmapped_changes",
      "sop_issue_groups",
    ].some((key) => report[key] !== undefined && !objectRows(report[key])) ||
    report.tasks.some(
      (task) => task.acceptance_points !== undefined && !objectRows(task.acceptance_points),
    ) ||
    (report.sop_selection?.task_selections !== undefined &&
      (!objectRows(report.sop_selection.task_selections) ||
        report.sop_selection.task_selections.some(
          (selection) => selection.rules !== undefined && !objectRows(selection.rules),
        ))) ||
    !Array.isArray(report.sop_condition_checks) ||
    !Array.isArray(report.evidence) ||
    !Array.isArray(report.sop_documents) ||
    !report.sop_coverage ||
    report.evidence.some(
      (entry) => typeof entry?.id !== "string" || typeof entry.content !== "string",
    ) ||
    report.sop_documents.some(
      (entry) => typeof entry?.id !== "string" || typeof entry.content !== "string",
    ) ||
    new Set(report.evidence.map((entry) => entry.id)).size !== report.evidence.length ||
    new Set(report.sop_documents.map((entry) => entry.id)).size !== report.sop_documents.length ||
    report.sop_condition_checks.some(
      (row) =>
        !row ||
        !Object.hasOwn(fullResults, row.result) ||
        !validRefs(row.evidence_refs) ||
        !Array.isArray(row.atomic_checks) ||
        row.atomic_checks.some(
          (item) =>
            !item || !Object.hasOwn(fullResults, item.result) || !validRefs(item.evidence_refs),
        ),
    ) ||
    (report.sop_coverage.unsupported_sections !== undefined &&
      (!Array.isArray(report.sop_coverage.unsupported_sections) ||
        report.sop_coverage.unsupported_sections.some(
          (section) => !section || typeof section !== "object",
        ))) ||
    (report.sop_coverage.failures !== undefined && !Array.isArray(report.sop_coverage.failures)) ||
    (report.integration?.known_limitations !== undefined &&
      !Array.isArray(report.integration.known_limitations)) ||
    report.formal_closed !== false
  )
    throw new Error("未找到完整审计 schema_version 2.1 报告、条件矩阵及冻结来源；现有报告保留。");
}

function selectedRuleSummary() {
  return $("full-sop-source").value === "uploaded"
    ? fullState.uploaded?.summary
    : fullState.library;
}
function ruleSummaryHtml(summary) {
  if (!summary) return "<p>规则信息尚未读取。</p>";
  const source = summary.source ?? {};
  const custom = source.kind === "uploaded_rules";
  const interpretation = [source.release_id == null ? "" : `规则发布 ${escapeHtml(source.release_id)}`,
    source.interpretation_revision == null ? "" : `判定口径 ${escapeHtml(source.interpretation_revision)}`].filter(Boolean).join(" · ");
  return `<strong>${custom ? "已冻结自定义规则 JSON" : source.kind === "formsy_sop" ? "FormSyAI/formsy-sop 冻结版本" : "本轮报告规则快照"}</strong><p>${escapeHtml(summary.rule_count ?? "未提供")} 条规则 · ${escapeHtml(summary.condition_count ?? "未提供")} 个条件${summary.atomic_item_count != null ? ` · ${escapeHtml(summary.atomic_item_count)} 个原子义务` : ""}</p><p>${custom ? "上传原文摘要" : "Git 版本"}：<code>${escapeHtml(custom ? source.input_sha256 : (source.git_commit ?? "未提供"))}</code></p>${interpretation ? `<p>${interpretation}</p>` : ""}<p>规则目录摘要：<code>${escapeHtml(source.catalog_sha256 ?? "未提供")}</code> · 机器契约 ${escapeHtml(source.contract_version ?? "未提供")}</p>${array(
    summary.documents,
  )
    .map(
      (document) =>
        `<p>${escapeHtml(document.title ?? document.id)} · ${escapeHtml(document.version ?? "未提供版本")} · <code>${escapeHtml(document.sha256 ?? "未提供摘要")}</code></p>`,
    )
    .join("")}<p>仅作为本轮参考规则；不代表项目已发布或历史生效的 SOP。切换不会替换旧报告。</p>`;
}
function renderRuleSummary() {
  const custom = $("full-sop-source").value === "uploaded";
  $("full-sop-upload").hidden = !custom;
  const summary = selectedRuleSummary();
  $("full-sop-summary").innerHTML = fullState.uploading
    ? "正在本机校验并冻结规则，不会调用模型…"
    : custom && !fullState.uploaded
      ? `<strong>请选择规则 JSON</strong><p>规则数组或 {"rules": […]}；最多 ${escapeHtml(fullState.library?.max_upload_rules ?? fullState.config?.max_upload_rules ?? 8)} 条规则。上传只校验和冻结，未运行审计。</p>`
      : !custom && !summary?.source
        ? `<strong>默认 FormSy SOP 不可用</strong><p>${escapeHtml(summary?.default_error ?? "默认规则版本尚未读取或校验失败。可切换并上传自定义规则，不会静默改用另一套规则。")}</p>`
        : ruleSummaryHtml(summary);
}
async function freezeRules(rules) {
  const maximum = fullState.library?.max_upload_rules ?? fullState.config?.max_upload_rules ?? 8;
  if (!Array.isArray(rules) || !rules.length || rules.length > maximum)
    throw new Error(`SOP JSON 需包含 1–${maximum} 条规则的数组，或 {"rules": […]}。`);
  if (new TextEncoder().encode(JSON.stringify({ rules })).length > 2 * 1024 * 1024)
    throw new Error("规则 JSON 超过 2 MiB，未自动截断。");
  fullState.uploading = true;
  $("full-consent").checked = false;
  fullControls();
  try {
    const data = await api("/api/sop-uploads", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ rules }),
    });
    if (
      typeof data.id !== "string" ||
      !Array.isArray(data.rules) ||
      !data.rules.length ||
      data.summary?.source?.kind !== "uploaded_rules" ||
      data.model_invoked !== false
    )
      throw new Error("未收到明确的离线规则冻结记录，原有规则保留。");
    fullState.uploaded = data;
    $("full-sop-source").value = "uploaded";
    $("full-consent").checked = false;
  } finally {
    fullState.uploading = false;
    fullControls();
  }
}
function buildFullRequest() {
  const request = structuredClone(fullState.request);
  if ($("full-sop-source").value === "uploaded") {
    if (!fullState.uploaded) throw new Error("请先上传并离线校验自定义规则。");
    request.rules = structuredClone(fullState.uploaded.rules);
    delete request.sop_selection;
  } else {
    if (!fullState.library?.source || fullState.library.default_available === false)
      throw new Error("默认 FormSy SOP 不可用；请选择并校验自定义规则，不会自动切换规则。");
    delete request.rules;
    request.sop_selection = { mode: "auto", document_ids: [] };
  }
  assertFullRequest(request);
  return request;
}
const activeFullStatuses = ["queued", "running", "cancelling"];
const terminalFullStatuses = ["completed", "failed", "cancelled"];
let auditObjectView;
function renderAuditObject() {
  const content = $("full-object-content"), request = fullState.request;
  const view = [request, fullState.fileName, fullState.demo];
  if (auditObjectView?.every((value, index) => value === view[index])) return;
  auditObjectView = view;
  content.replaceChildren();
  if (!request) {
    content.append(node("p", "", "尚未载入审计材料。"));
    return;
  }
  const declared = (value) => typeof value === "string" && value.trim() ? value : null;
  appendField(content, "文件 / 载入来源", fullState.fileName || "未提供");
  appendField(content, "输入标题", request.title);
  if (fullState.demo) {
    appendField(content, "公开示例 ID", fullState.demo.id);
    appendField(content, "公开示例原文件 SHA256", fullState.demo.input_sha256);
  }
  const traceId = [request.trace?.trace_id, request.trace?.id].find((value) =>
    declared(value) !== null || (typeof value === "number" && Number.isSafeInteger(value)));
  appendField(content, "材料声明的 Trace ID", traceId === undefined ? "未提供" : String(traceId));
  const repositories = [...new Set([declared(request.trace?.repository), ...request.commits.map((commit) => declared(commit.repository)),
    declared(fullState.demo?.repository)].filter(Boolean))];
  appendField(content, "材料声明的仓库", repositories.length ? repositories : "未提供");
  appendField(content, "输入 Commit SHA", request.commits.length ? request.commits.map((commit) => commit.sha) : "未提供");
  content.append(node("p", "", `${request.trace.messages.length} 条消息 · ${request.materials.length} 份材料 · ${request.commits.length} 个输入 Commit`));
  const users = request.trace.messages.filter((message) => message.role === "user"),
    original = users.map((message) => message.content).join("\n\n"),
    details = node("details");
  details.append(node("summary", "", `原用户请求 · ${users.length} 条`), node("pre", "", original.slice(0, 6000)));
  if (original.length > 6000) details.append(node("p", "help", "仅预览前 6000 字符；完整原文保留在输入材料中。"));
  content.append(details);
  const trace = node("details");
  trace.append(node("summary", "", `完整 Trace 消息正文 · ${request.trace.messages.length} 条`),
    node("p", "help", "逐条显示消息角色与完整正文；不含 Commit 差异和其他材料。"));
  request.trace.messages.forEach((message, index) => {
    trace.append(node("h4", "", `第 ${index + 1} 条 · ${message.role}`), node("pre", "", message.content));
  });
  content.append(trace);
}
function renderDemoChoices() {
  const select = $("full-demo-select");
  select.replaceChildren();
  const placeholder = node("option", "", fullState.demos.length ? "选择公开完整 Trace（仅载入）" : "暂无可载入的公开示例");
  placeholder.value = "";
  select.append(placeholder);
  for (const demo of fullState.demos) {
    const option = node("option", "", `${demo.title || demo.id} · ${demo.repository || "仓库未提供"}`);
    option.value = demo.id;
    select.append(option);
  }
  select.value = fullState.demo?.id || "";
  $("full-demo-status").textContent = fullState.demos.length
    ? `${fullState.demos.length} 份公开完整 Trace · 附许可证。选择仅载入材料，开始审计仍需单独确认。`
    : "暂无可载入的公开示例；仍可使用安全合成示例或导入 JSON。";
}
function retainFullJob(result, expectedId) {
  if (!result || typeof result.id !== "string" || !result.id || (expectedId && result.id !== expectedId) ||
      ![...activeFullStatuses, ...terminalFullStatuses].includes(result.status) ||
      (result.supersedes !== undefined && (!Array.isArray(result.supersedes) || result.supersedes.some((id) => typeof id !== "string" || !id || id === result.id))))
    throw new Error("作业响应身份或状态不匹配。");
  if (result.status === "completed") assertFullReport(result.report);
  let round = fullState.rounds.find((entry) => !entry.imported && entry.id === result.id);
  if (round && terminalFullStatuses.includes(round.status) && activeFullStatuses.includes(result.status)) return round;
  if (round) Object.assign(round, result);
  else {
    round = { ...result };
    fullState.rounds.push(round);
  }
  return round;
}
async function refreshSuperseded(round) {
  for (const id of array(round.supersedes)) {
    const previous = fullState.rounds.find((entry) => !entry.imported && entry.id === id);
    if (previous && terminalFullStatuses.includes(previous.status)) continue;
    try { retainFullJob(await api(`/api/full-audits/${encodeURIComponent(id)}`), id); }
    catch { /* The old snapshot remains visible; a later poll can read the stop metadata. */ }
  }
}
async function loadFullDemo(id) {
  if (fullState.loading || fullState.submitting || fullState.uploading) return;
  const selected = id ? fullState.demos.find((demo) => demo.id === id) : null;
  $("full-consent").checked = false;
  if (id && !selected) return setFullError("所选公开示例未列入已核验目录，原有材料保留。");
  fullState.loading = true;
  fullControls();
  try {
    const value = await api(id ? `/api/full-demo/${encodeURIComponent(id)}` : "/api/full-audit-demo"),
      request = id ? value.request : value;
    if (id && (value.demo?.id !== id || value.demo.input_sha256 !== selected.input_sha256))
      throw new Error("示例身份或输入摘要与目录不一致。");
    assertFullRequest(request);
    fullState.request = request;
    fullState.demo = id ? value.demo : null;
    fullState.fileName = id ? `公开示例：${selected.title || id}` : "完整审计安全合成示例";
    $("full-consent").checked = false;
    $("full-demo-select").value = id;
    setFullError();
  } catch (error) {
    $("full-demo-select").value = fullState.demo?.id || "";
    setFullError(`示例未载入：${error.message} 原有材料与报告保留。`);
  } finally {
    fullState.loading = false;
    fullControls();
  }
}
function fullControls() {
  const running = fullState.rounds.some((round) => activeFullStatuses.includes(round.status));
  const configured = fullState.config?.available && fullState.config?.model_configured;
  const provider = fullState.config?.provider ?? "DeepSeek";
  const modelName = fullState.config?.model ?? "deepseek-flash";
  const endpoint = fullState.config?.provider_endpoint;
  const fallback = !!fullState.config && (!configured || fullState.providerBlocked);
  const offlineOption = $("full-mode").querySelector("[value=offline]");
  offlineOption.hidden = !fallback;
  offlineOption.disabled = !fallback;
  if (fallback) $("full-mode").value = "offline";
  else $("full-mode").value = "model";
  const model = $("full-mode").value === "model";
  const rulesReady =
    $("full-sop-source").value === "uploaded"
      ? !!fullState.uploaded
      : !!fullState.library?.source && fullState.library.default_available !== false;
  const busy = fullState.submitting || fullState.uploading || fullState.loading;
  $("full-consent").disabled = busy;
  const modelOption = $("full-mode").querySelector("[value=model]");
  modelOption.disabled = !configured || fullState.providerBlocked;
  modelOption.textContent = `${provider} / ${modelName} 多轮语义审计`;
  $("full-consent-label").hidden = !model;
  $("full-consent-text").textContent = `我了解：完整审计会分多次将所选材料发送至 ${provider}，使用模型 ${modelName}，可能产生费用；结果仍需人工复核。`;
  $("full-mode").disabled = busy;
  $("full-sop-source").disabled = busy;
  $("full-sop-file").disabled = busy;
  $("full-request-file").disabled = busy;
  $("full-demo").disabled = busy;
  $("full-demo-select").disabled = busy || !fullState.demos.length;
  $("full-verify").disabled =
    !fullState.request ||
    !rulesReady ||
    busy ||
    (model && (!configured || !$("full-consent").checked));
  $("full-verify").textContent = fullState.submitting
    ? "正在提交…"
    : model
        ? running ? `停止旧任务并使用 ${provider} / ${modelName} 开始新审计` : `使用 ${provider} / ${modelName} 开始审计`
        : "运行本地结构检查";
  $("full-file-label").textContent = fullState.fileName || "先载入合成示例或选择 JSON";
  $("full-model-status").disabled = busy || running;
  $("full-model-status").textContent = !fullState.config
    ? "模型 API · 读取配置"
    : fullState.providerBlocked
      ? `${provider} API · 本轮请求未完成 · ${modelName}`
      : configured ? `${provider} API · 已配置 · ${modelName}` : `${provider} API · 不可用`;
  $("full-config-label").textContent = configured
    ? `${provider} / ${modelName}${endpoint ? ` · ${endpoint}` : ""} · 配置已读取，额度与连接以实际请求为准`
    : "本地备用仅检查结构；仍可回看已有报告";
  $("full-mode-help").textContent = model
    ? `点击后将分多次把所选对话、Commit diff、材料和本轮规则发送至 ${provider}，使用模型 ${modelName}，可能产生费用。${endpoint ? `服务端请求端点：${endpoint}。` : ""}总模型请求最多 ${fullState.config?.max_total_calls ?? 80} 次，其中 SOP 请求最多 ${fullState.config?.max_sop_calls ?? 64} 次；不运行材料里的业务代码。失败保留记录，不自动重新提交。`
    : `${provider} 当前不可用，本地备用只检查输入结构与已冻结规则清单，不生成语义结论，也不会自动重跑。恢复配置后可点击 ${provider} API 重新读取状态。`;
  renderRuleSummary();
  renderAuditObject();
  const active = fullState.rounds.find((round) => activeFullStatuses.includes(round.status));
  $("full-active-status").hidden = !active;
  $("full-active-status").textContent = active ? `活动任务记录：${active.id} · ${jobLabels[active.status]}${active.input_sha256 ? ` · 输入摘要 ${active.input_sha256}` : ""}` : "";
}
$("full-model-status").addEventListener("click", async () => {
  if (fullState.submitting || fullState.loading || fullState.uploading || fullState.rounds.some((round) => activeFullStatuses.includes(round.status))) return;
  try {
    fullState.config = await api("/api/full-audit-config");
    fullState.providerBlocked = false;
    $("full-consent").checked = false;
    const provider = fullState.config.provider ?? "DeepSeek";
    showDialog(`${provider} API`, `<p>${fullState.config.model_configured ? "服务端密钥已配置" : "服务端未配置密钥"} · ${escapeHtml(provider)} / ${escapeHtml(fullState.config.model ?? "deepseek-flash")}</p>${fullState.config.provider_endpoint ? `<p>服务端请求端点：<code>${escapeHtml(fullState.config.provider_endpoint)}</code></p>` : ""}<p>这里只读取本地服务配置，不调用模型，也不显示密钥。额度与连接状态以实际审计返回为准；失败记录不会被覆盖。</p>`);
  } catch (error) {
    fullState.config = { ...fullState.config, available: false, model_configured: false };
    setFullError(`无法读取模型配置：${error.message} 已显示本地结构检查备用入口。`);
  }
  fullControls();
});
$("full-sop-source").addEventListener("change", () => {
  $("full-consent").checked = false;
  setFullError();
  fullControls();
});
$("full-sop-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file || fullState.loading || fullState.submitting || fullState.uploading) return;
  fullState.loading = true;
  $("full-consent").checked = false;
  fullControls();
  try {
    if (file.size > 2 * 1024 * 1024) throw new Error("规则 JSON 超过 2 MiB，未自动截断。");
    const value = JSON.parse(await file.text());
    await freezeRules(Array.isArray(value) ? value : value?.rules);
    setFullError();
  } catch (error) {
    setFullError(`规则未载入：${error.message} 原有材料、规则和报告已保留。`);
  } finally {
    fullState.loading = false;
    fullControls();
  }
  event.target.value = "";
});

// Reused from TraceAuditWeb/static/app.js: native schema 2 report rendering.
const resultNames = {
  pass: "满足",
  passed: "满足",
  fail: "不满足",
  failed: "不满足",
  insufficient_evidence: "未核查",
  insufficient: "未核查",
  unknown: "未核查",
  not_checked: "未核查",
  not_applicable: "不适用",
};
const kindNames = {
  trace: "对话记录",
  user_requirement: "用户要求",
  assistant: "助手对话",
  tool: "工具记录",
  commit: "代码变更",
  commit_diff: "代码变更",
  diff: "代码变更",
  source: "源码材料",
  test_log: "测试日志",
  run_record: "运行记录",
  context: "上下文材料",
  rule: "审计规则",
};
const fieldNames = {
  summary: "摘要",
  overall: "整体判断",
  conclusion: "判断说明",
  scope: "审计范围",
  status: "状态",
  task_count: "任务数",
  check_count: "检查项数",
  finding_count: "问题记录数",
  evidence_count: "证据数",
  missing_materials: "缺失材料",
  limitations: "范围限制",
  warnings: "审计提醒",
  next_steps: "下一步",
  title: "标题",
  text: "内容",
  requirement: "要求",
  reason: "依据",
  rationale: "推断依据",
  description: "说明",
  criterion: "判断标准",
  required_evidence: "所需证据",
  version: "规则版本",
  applicability: "适用性",
  before: "原判断",
  after: "新判断",
  previous: "上一版本",
  current: "本次版本",
  changed: "判断变化",
  changed_checks: "变化的检查项",
  added_evidence: "新增证据",
  new_evidence: "新增证据",
  resolved_findings: "已改善问题",
  remaining_findings: "待处理问题",
  new_findings: "新增问题",
  result: "判断",
  check_id: "检查项",
  rule_id: "规则",
  task_id: "任务",
  improvement: "改进建议",
  verification: "验证方法",
  impact: "影响",
  formal_closed: "正式闭环",
  review_state: "审查状态",
};
Object.assign(fieldNames, {
  tasks: "任务数",
  checks: "检查项数",
  results: "原 SOP 条款分布",
  automated_results: "自动子集分布",
  findings: "问题记录数",
  previous_revision: "上一版本",
  current_revision: "本次版本",
  affected_task_ids: "涉及任务",
  unchanged: "未变化的检查项",
  requirement_refs: "原要求引用",
  superseded_by_refs: "后续替代引用",
  id: "检查项",
});
const categoryNames = {
  implementation_defect: "实现问题候选",
  suspected_issue: "疑似问题",
  evidence_gap: "证据缺口",
};
const changeRelationNames = {
  implementation: "实现关联",
  supporting: "配套改动",
  diagnostic: "诊断改动",
  unrelated: "与该要求无关",
  unknown: "关系未确定",
};
const sopSelectionNames = { selected: "已选用", not_applicable: "不适用", uncertain: "待确认" };
const sopGapNames = {
  evidence_missing: "缺少证据",
  automatic_check_unsupported: "自动检查尚未支持",
  rule_scope_difference: "规则范围差异",
  applicability_uncertain: "适用性待确认",
  analysis_failed: "分析失败",
  scope_not_requested: "未纳入本次阶段",
};
Object.assign(fieldNames, {
  total: "条件总数",
  selected: "已选用",
  complete: "矩阵完整",
  matrix_complete: "核查矩阵完整",
  call_count: "模型调用数",
  failed_batches: "分析失败批次",
  condition_count: "条件数",
  rule_count: "规则数",
  document_count: "文档数",
  conditions: "条件数",
  rules: "规则数",
  documents: "文档数",
  counts: "核查分布",
  task_id: "任务",
  rule_id: "规则",
  condition_id: "条件",
  text: "条件内容",
  acceptance_ids: "关联验收点",
  program_gates: "程序证据门槛",
  local_result: "模型候选事实",
  model_result: "模型候选事实",
  automated_result: "证据门槛后的判断",
  met: "已具备",
  selection: "选用状态",
  gap_type: "原因分类",
  pass: "满足",
  fail: "不满足",
  unknown: "未核查",
  not_applicable: "不适用",
});

function node(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined && text !== null) element.textContent = String(text);
  return element;
}
function array(value) {
  return (Array.isArray(value) ? value : value == null ? [] : [value]).filter(
    (item) => item != null,
  );
}
/* eslint-disable no-control-regex -- Preserve the native Python line boundary contract. */
function sourceLines(value) {
  const lines = String(value ?? "").split(/\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029]/);
  if (lines.at(-1) === "") lines.pop();
  return lines;
}
/* eslint-enable no-control-regex */
function display(value) {
  return value == null
    ? "未提供"
    : typeof value === "boolean"
      ? value
        ? "是"
        : "否"
      : String(value);
}
function applicabilityLabel(value) {
  return (
    { applicable: "适用", not_applicable: "不适用", uncertain: "待确认", unknown: "待确认" }[
      value
    ] || display(value)
  );
}

function resultLabel(result) {
  return resultNames[result] || display(result);
}
function conditionAnalysisIncomplete(check) {
  return (
    ["failed", "partial"].includes(check.analysis_status) || check.gap_type === "analysis_failed"
  );
}
function allRequiredResult(results) {
  const labels = results.map((result) => resultLabel(result || "未核查"));
  if (labels.includes("不满足")) return "不满足";
  if (!labels.length || labels.some((label) => !["满足", "不适用"].includes(label)))
    return "未核查";
  return labels.every((label) => label === "不适用") ? "不适用" : "满足";
}
function resultClass(result) {
  const label = resultLabel(result);
  return label === "不满足"
    ? "fail"
    : ["未核查", "证据不足"].includes(label)
      ? "insufficient"
      : label === "不适用"
        ? "na"
        : label === "满足"
          ? ""
          : "na";
}
function taskName(id, report = currentFullReport()) {
  const task = array(report?.tasks).find((item) => item.id === id);
  return task ? task.title || task.id : id || "未关联任务";
}
function versionTwo(report) {
  return String(report.schema_version || "").split(".")[0] === "2";
}
function resultBadge(result, prefix = "") {
  return node("span", `check-result ${resultClass(result)}`, `${prefix}${resultLabel(result)}`);
}
function appendAtomicChecks(parent, check) {
  const checks = array(check.atomic_checks).filter((item) => item && typeof item === "object");
  if (!checks.length) return;
  const details = node("details", "gate-details sop-atomic-checks");
  details.open = checks.some((item) => resultLabel(item.result) === "不满足");
  details.append(node("summary", "", `逐项核查 · ${checks.length} 个子项`));
  for (const item of checks) {
    const row = node("div", "condition-row sop-atomic-check"),
      heading = node("div", "sop-condition-head");
    heading.append(
      node("strong", "", `${item.id || "未标明子项"} · ${item.text || "未提供子项内容"}`),
      resultBadge(item.result || "未核查"),
    );
    if (array(check.review_scope?.deferred_item_ids).includes(item.id))
      heading.append(node("span", "tag neutral", "未纳入本次阶段"));
    row.append(heading);
    appendField(row, "核查依据", item.reason);
    appendRefs(row, item.evidence_refs, "子项证据");
    if (item.model_result) row.append(resultBadge(item.model_result, "模型候选："));
    if (array(item.program_gates).length) {
      const gates = node("details", "gate-details");
      gates.append(node("summary", "", "查看子项的程序证据门槛"));
      renderValue(gates, item.program_gates);
      row.append(gates);
    }
    details.append(row);
  }
  parent.append(details);
}

function renderValue(container, value, depth = 0) {
  if (depth > 12) {
    container.append(node("span", "inline-note", "嵌套内容过深，请核对本轮 JSON 快照。"));
    return;
  }
  if (value === undefined || value === null || value === "") {
    container.append(node("span", "inline-note", "未提供"));
    return;
  }
  if (Array.isArray(value)) {
    if (!value.length) {
      container.append(node("span", "inline-note", "无"));
      return;
    }
    const list = node("ul");
    for (const item of value) {
      const li = node("li");
      renderValue(li, item, depth + 1);
      list.append(li);
    }
    container.append(list);
  } else if (typeof value === "object") {
    if (value.evidence_id) {
      container.append(citationButton(value));
      return;
    }
    const dl = node("dl", "object-detail");
    for (const [key, content] of Object.entries(value)) {
      const dd = node("dd");
      renderValue(dd, content, depth + 1);
      dl.append(node("dt", "", fieldNames[key] || key), dd);
    }
    container.append(dl);
  } else container.append(node("span", "", display(value)));
}
function citationButton(reference) {
  if (!reference || typeof reference !== "object" || !reference.evidence_id)
    return node(
      "span",
      "inline-note",
      typeof reference === "object"
        ? reference?.text || reference?.id || "引用未提供定位信息"
        : reference,
    );
  const evidence = array(currentFullReport()?.evidence).find(
    (item) => item.id === reference.evidence_id,
  );
  const line = reference.start_line
    ? ` · L${reference.start_line}${reference.end_line && reference.end_line !== reference.start_line ? `–${reference.end_line}` : ""}`
    : "";
  const button = node(
    "button",
    `citation${evidence ? "" : " missing"}`,
    `${evidence?.name || reference.evidence_id}${line}`,
  );
  button.type = "button";
  button.title = evidence
    ? `查看 ${evidence.name || evidence.id} 原文${line}`
    : "此引用对应的原始证据未包含在报告中";
  button.addEventListener("click", () => openEvidence(reference.evidence_id, reference));
  return button;
}
function appendRefs(container, references, label) {
  const refs = array(references);
  if (!refs.length) return;
  if (label) container.append(node("h4", "", label));
  const wrap = node("div", "refs");
  for (const ref of refs) wrap.append(citationButton(ref));
  container.append(wrap);
}
function appendField(container, label, content) {
  if (
    content === undefined ||
    content === null ||
    content === "" ||
    (Array.isArray(content) && !content.length)
  )
    return;
  container.append(node("h4", "", label));
  const wrap = node("div");
  renderValue(wrap, content);
  container.append(wrap);
}
function empty(container, message) {
  container.append(node("div", "empty-state", message));
}
function card(id, title, badge) {
  const article = node("article", "report-card"),
    head = node("div", "card-head"),
    heading = node("h3", "card-title"),
    body = node("div", "card-body");
  if (id) heading.append(node("span", "card-id", id));
  heading.append(document.createTextNode(title || "未命名"));
  head.append(heading);
  if (badge) head.append(badge);
  article.append(head, body);
  return { article, heading, body };
}
function renderMetrics(report) {
  const checks = array(report.checks);
  const items = versionTwo(report)
    ? [
        ["提取任务", array(report.tasks).length, ""],
        [
          "明确验收点",
          array(report.tasks).reduce(
            (count, task) => count + array(task.acceptance_points).length,
            0,
          ),
          "",
        ],
        [
          "自动项未核查",
          checks.filter((check) => resultLabel(check.automated_result) === "未核查").length,
          "attention",
        ],
        ["未关联改动", array(report.unmapped_changes).length, "problem"],
      ]
    : [
        ["提取任务", array(report.tasks).length, ""],
        ["SOP 检查项", checks.length, ""],
        [
          "未核查",
          checks.filter((check) => ["未核查", "证据不足"].includes(resultLabel(check.result)))
            .length,
          "attention",
        ],
        ["问题记录", array(report.findings).length, "problem"],
      ];
  $("metrics").replaceChildren(
    ...items.map(([label, value, style]) => {
      const item = node("div", `metric ${style}`);
      item.append(node("div", "metric-label", label), node("div", "metric-value", value));
      return item;
    }),
  );
}
function renderCurrentScope(report) {
  const container = $("current-audit-scope"),
    current = report.sop_coverage?.current_scope;
  container.replaceChildren();
  container.hidden = !current;
  if (!current) return;
  const profile = current.profile || report.audit_context?.profile;
  container.append(
    node("h3", "", "本轮审计范围"),
    node(
      "p",
      "",
      { code_fix: "代码修复 · 本次变更及相关路径", full_sop: "原 SOP 完整要求" }[profile] ||
        profile ||
        "未提供范围",
    ),
    resultBadge(current.scope_result || current.outcome || "未核查", "本轮："),
  );
  container.append(
    node(
      "p",
      "",
      `本轮必需条件：${display(current.required_conditions ?? current.conditions)} · 未纳入本次阶段：${display(current.deferred_conditions)}`,
    ),
  );
  if (current.analysis_complete !== undefined)
    container.append(
      node(
        "p",
        "",
        current.analysis_complete ? "本轮所需条件分析已完成。" : "本轮所需条件分析未完成。",
      ),
    );
  container.append(
    node(
      "p",
      "inline-note",
      "未纳入本次阶段的条款保留原始判断，不作为不适用或已满足；条款完整要求仍在下方列出。",
    ),
  );
}
function renderReviewStatus(report) {
  renderCurrentScope(report);
  const modern = versionTwo(report),
    container = $("review-status");
  container.replaceChildren();
  container.hidden = !modern;
  $("legacy-banner").hidden = modern;
  $("schema-label").textContent = modern
    ? `规则结构 ${report.schema_version} · 自动审计候选`
    : "历史规则版本";
  const sopIncomplete = report.sop_coverage?.analysis_complete === false;
  $("candidate-banner").textContent = modern
    ? sopIncomplete
      ? "SOP 选择或条件分析未完成，相关结果保留为未核查。下方基础修复分析与 SOP 核查分别记录。"
      : "分析完成状态、自动检查结论与原 SOP 条款分别记录。局部事实成立仅覆盖列明范围。"
    : "历史审计候选；判断按当时规则展示，未按当前证据门槛重新计算。";
  if (!modern) return;
  const review = report.automatic_review || {},
    original = report.original_sop || {};
  const automatic = node("div", "panel review-state"),
    formal = node("div", "panel review-state");
  automatic.append(
    node("h3", "", report.sop_coverage ? "基础修复分析" : "自动审计"),
    node("p", "review-state-value", review.analysis_complete ? "分析已完成" : "分析未完成"),
    resultBadge(review.outcome || "未核查", "自动检查："),
    node(
      "p",
      "field-hint",
      report.sop_coverage
        ? "仅汇总基础代码修复检查；SOP 选择与条件分析状态单独呈现。"
        : "按当前材料与程序门槛汇总；有未知项也可以完成分析。",
    ),
  );
  formal.append(
    node("h3", "", "条款完整要求"),
    node(
      "p",
      "review-state-value",
      original.formal_closed ? "完整要求已确认" : original.status || "未确认",
    ),
    node(
      "p",
      "field-hint",
      sopIncomplete
        ? "SOP 选择或条件分析未完成；已有记录不能替代成功核查。具体失败原因见下方。"
        : report.sop_condition_checks
          ? "完整条件逐项核查结果见下方；分析完成不代表所有适用条件都满足。"
          : "原规则中未由自动证据覆盖的条件单独保留，不阻塞自动审计完成。",
    ),
  );
  const conditions = report.sop_condition_checks ? [] : array(original.unassessed_conditions);
  if (conditions.length) {
    const details = node("details", "unassessed-conditions");
    details.append(node("summary", "", `原规则范围限制 · ${conditions.length} 项条件尚未核定`));
    for (const item of conditions) {
      const row = node("div", "condition-row");
      row.append(node("strong", "", `${item.rule_id || ""} · ${item.condition || "未核定条件"}`));
      if (item.reason) row.append(node("p", "", item.reason));
      details.append(row);
    }
    formal.append(details);
  }
  container.append(automatic, formal);
}
function renderSummary(report) {
  const container = $("summary-content"),
    summary = report.summary;
  container.replaceChildren();
  if (versionTwo(report)) {
    container.append(node("h3", "", "自动检查分布"));
    const results = node("div", "summary-results"),
      counts = {};
    for (const check of array(report.checks)) {
      const result = check.automated_result || "未核查";
      counts[result] = (counts[result] || 0) + 1;
    }
    for (const [result, count] of Object.entries(counts))
      results.append(resultBadge(result, `${count} 项 · `));
    container.append(
      results,
      node(
        "p",
        "inline-note",
        "按任务 × 规则统计自动子集。验收点的实际改动、断言和执行情况见逐项映射；条款完整要求的核查见下方。",
      ),
    );
    return;
  }
  if (summary && typeof summary === "object" && !Array.isArray(summary) && summary.results) {
    container.append(node("h3", "", "本次候选判断"));
    const results = node("div", "summary-results");
    for (const [result, count] of Object.entries(summary.results))
      results.append(
        node("span", `check-result ${resultClass(result)}`, `${resultLabel(result)} ${count}`),
      );
    container.append(
      results,
      node("p", "inline-note", "每项判断仅覆盖所列范围，原文证据与缺失材料见下方。"),
    );
    const other = Object.fromEntries(
      Object.entries(summary).filter(
        ([key]) => !["tasks", "checks", "findings", "results"].includes(key),
      ),
    );
    if (Object.keys(other).length) renderValue(container, other);
  } else renderValue(container, summary || "审计候选报告已生成，请按任务逐项核对证据与范围。");
}
function renderDelta(delta) {
  const container = $("delta-content");
  container.replaceChildren();
  const show = delta && delta.previous_revision !== 0;
  container.hidden = !show;
  if (!show) return;
  container.append(
    node(
      "h3",
      "",
      `版本变化${delta.previous_revision ? ` · 第 ${delta.previous_revision} → ${delta.current_revision} 版` : ""}`,
    ),
  );
  if (!Array.isArray(delta.changed)) {
    renderValue(container, delta);
    return;
  }
  for (const change of delta.changed) {
    const row = node("div", "delta-row");
    row.append(
      node("strong", "", change.id || change.check_id || "检查项"),
      node(
        "span",
        "",
        `${change.before == null ? "新增" : resultLabel(change.before)} → ${resultLabel(change.after)}`,
      ),
    );
    if (change.automated_after)
      row.append(
        node(
          "span",
          "",
          `自动子集：${change.automated_before == null ? "新增" : resultLabel(change.automated_before)} → ${resultLabel(change.automated_after)}`,
        ),
      );
    if (change.reason) row.append(node("p", "", change.reason));
    container.append(row);
  }
  if (!delta.changed.length)
    container.append(node("p", "inline-note", "本次复审的检查项判断没有变化。"));
  if (array(delta.unchanged).length) {
    const details = node("details", "unchanged-details");
    details.append(node("summary", "", `${delta.unchanged.length} 项保持原判断`));
    renderValue(details, delta.unchanged);
    container.append(details);
  }
  if (array(delta.affected_task_ids).length)
    container.append(node("p", "inline-note", `涉及任务：${delta.affected_task_ids.join("、")}`));
}
function renderTasks(report) {
  const container = $("tasks-content");
  container.replaceChildren();
  for (const task of array(report.tasks)) {
    const { article, body } = card(
      task.id,
      task.title,
      node("span", "tag neutral", `${array(task.commit_ids).length} 条变更`),
    );
    appendField(body, "任务目标", task.goal);
    appendRefs(body, task.requirement_refs, "用户要求原文");
    appendField(body, "推断要求 · 需结合原文核对", task.inferred_requirements);
    if (versionTwo(report)) {
      const points = node("div", "acceptance-points");
      body.append(node("h4", "", "明确验收点"));
      for (const point of array(task.acceptance_points)) {
        const row = node("div", "acceptance-point");
        row.append(
          node("strong", "", point.id),
          node(
            "span",
            "tag neutral",
            { behavior: "行为", scope_constraint: "范围约束", test_delivery: "测试交付" }[
              point.kind
            ] || "行为",
          ),
          node("p", "", point.requirement),
        );
        appendRefs(row, point.requirement_refs);
        points.append(row);
      }
      if (!points.children.length)
        points.append(node("p", "inline-note", "未提取到明确验收点，不能据此确认任务已完整覆盖。"));
      body.append(points);
      appendField(body, "验收目标 Commit", task.target_commit_ids);
      appendField(body, "已被后续要求替代", task.superseded_requirements);
    }
    if (array(task.commit_ids).length) {
      body.append(node("h4", "", "关联代码变更"));
      const chips = node("div", "commit-chips");
      for (const id of array(task.commit_ids)) chips.append(node("span", "commit-chip", id));
      body.append(chips);
    }
    container.append(article);
  }
  if (!container.children.length) empty(container, "本次报告尚未提取出可展示的任务。");
}
function changeReference(change) {
  const evidence = array(currentFullReport()?.evidence).find(
    (item) => item.id === change.evidence_id,
  );
  return {
    evidence_id: change.evidence_id,
    start_line: change.start_line,
    end_line: change.end_line,
    quote: evidence
      ? pythonSegments(evidence.content)
          .slice(change.start_line - 1, change.end_line)
          .join("")
      : "",
  };
}
function appendChangeRelations(container, relations, report) {
  const rows = array(relations).filter((item) => item && typeof item === "object");
  if (!rows.length) return;
  const details = node("details", "gate-details change-relations");
  details.append(
    node("summary", "", `逐项改动关系 · ${rows.length} 条`),
    node("p", "inline-note", "仅明确的实现关联计入实现覆盖；配套、诊断和其他关系分别保留。"),
  );
  for (const relation of rows) {
    const row = node("div", "condition-row");
    row.append(
      node(
        "strong",
        "",
        `${relation.change_id || "改动"} · ${changeRelationNames[relation.relation] || "关系未确定"}`,
      ),
    );
    if (relation.task_id) appendField(row, "关联任务", taskName(relation.task_id, report));
    appendField(row, "关联验收点", relation.acceptance_id);
    appendField(row, "关系依据", relation.reason);
    appendRefs(row, relation.evidence_refs, "关系证据");
    details.append(row);
  }
  container.append(details);
}
function appendChange(container, change, report) {
  const label = change.relationship_status
    ? changeRelationNames[change.relationship_status] || "存在多类关联"
    : change.status === "mapped"
      ? "已关联 · 关系未分类"
      : "未关联";
  const { article, body } = card(
    change.id,
    change.path || "未识别文件路径",
    node("span", "tag neutral", label),
  );
  body.append(node("p", "commit-chip", change.commit_id || "未标明 Commit"));
  appendRefs(body, [changeReference(change)], "代码 diff 原文");
  if (array(change.acceptance_ids).length)
    appendField(
      body,
      "对应验收点",
      change.acceptance_ids.map((id) => {
        const task = array(report.tasks).find((item) =>
          array(item.acceptance_points).some((point) => point.id === id),
        );
        return `${id}${task ? ` · ${task.title || task.id}` : ""}`;
      }),
    );
  appendChangeRelations(body, change.relations, report);
  container.append(article);
}
function renderAcceptance(report) {
  const modern = versionTwo(report);
  $("acceptance-section").hidden = !modern;
  $("acceptance-nav").hidden = !modern;
  const container = $("acceptance-content");
  container.replaceChildren();
  $("change-coverage-content").replaceChildren();
  $("unmapped-content").replaceChildren();
  if (!modern) return;
  const coverage = new Map(
    array(report.acceptance_checks).map((check) => [
      `${check.task_id}:${check.acceptance_id}`,
      check,
    ]),
  );
  for (const task of array(report.tasks))
    for (const point of array(task.acceptance_points)) {
      const check = coverage.get(`${task.id}:${point.id}`);
      const { article, heading, body } = card(
        point.id,
        point.requirement,
        resultBadge(
          check?.overall_result || check?.result || "未核查",
          check?.overall_result ? "整体验收：" : "实现：",
        ),
      );
      heading.append(node("span", "check-context", task.title || task.id));
      appendRefs(body, point.requirement_refs, "用户要求");
      if (!check) {
        body.append(node("p", "missing-list", "本报告缺少此验收点的映射判断。"));
        container.append(article);
        continue;
      }
      const context = node("div", "check-scope");
      if (check.scope) context.append(node("span", "", `范围：${check.scope}`));
      for (const [label, result] of [
        ["实现：", check.result],
        ["断言：", check.test_design_result],
        ["执行：", check.execution_result],
      ])
        context.append(resultBadge(result || "未核查", label));
      body.append(context);
      appendField(body, "判断依据", check.reason);
      const stages = node("div", "acceptance-evidence");
      const changeLabel = Array.isArray(check.change_relations)
        ? "实现改动证据"
        : "关联改动证据 · 关系未分类";
      for (const [label, refs, missing] of [
        [changeLabel, check.change_refs, "未关联实现改动"],
        ["测试断言", check.assertion_refs, "缺少对应断言证据"],
        ["运行证据", check.run_refs, "缺少可核定运行证据"],
      ]) {
        const stage = node("div", "mapping-stage");
        stage.append(node("h4", "", label));
        if (label === "测试断言") {
          stage.append(resultBadge(check.test_design_result || "未核查"));
          if (check.test_design_reason)
            stage.append(node("p", "inline-note", check.test_design_reason));
        }
        if (label === "运行证据") stage.append(resultBadge(check.execution_result || "未核查"));
        appendRefs(stage, refs);
        if (label === "运行证据" && array(check.execution_run_ids).length)
          appendRefs(
            stage,
            check.execution_run_ids.map((id) => ({ evidence_id: id })),
            "程序匹配的运行回执",
          );
        if (label === "运行证据" && array(check.execution_assertion_refs).length)
          appendRefs(stage, check.execution_assertion_refs, "本轮运行断言 · 与原交付断言分别记录");
        if (label === "运行证据")
          for (const review of array(check.execution_run_reviews)) {
            const relation =
              {
                required: "直接验证本验收点",
                supporting: "兼容或配套检查",
                unrelated: "与本验收点无关",
                unknown: "运行关联待核查",
              }[review.relation] || "运行关联待核查";
            appendField(stage, relation, review.reason);
            appendRefs(stage, [{ evidence_id: review.run_evidence_id }]);
          }
        if (
          !array(refs).length &&
          !(label === "运行证据" && array(check.execution_run_ids).length)
        ) {
          const excluded =
            resultLabel(
              label === "运行证据"
                ? check.execution_result
                : label === "测试断言"
                  ? check.test_design_result
                  : check.result,
            ) === "不适用";
          stage.append(
            node(
              "p",
              "inline-note",
              excluded ? "该约束不需要此类验证，范围依据见本项说明。" : missing,
            ),
          );
        }
        stages.append(stage);
      }
      body.append(stages);
      appendField(
        body,
        Array.isArray(check.change_relations) ? "实现关联改动编号" : "关联改动编号 · 关系未分类",
        check.change_ids,
      );
      appendChangeRelations(body, check.change_relations, report);
      appendField(body, "无需改动的依据", check.no_change_reason);
      appendRefs(body, check.no_change_refs, "无需改动的原文证据");
      appendField(body, "反例 / 未满足情形", check.counterexample);
      const actions = node("div", "action-grid"),
        improvement = node("div"),
        verification = node("div");
      appendField(improvement, "改进动作", check.improvement);
      appendField(verification, "复检方法", check.verification);
      if (improvement.children.length || verification.children.length) {
        actions.append(improvement, verification);
        body.append(actions);
      }
      container.append(article);
    }
  if (!container.children.length)
    empty(container, "未提取到明确验收点，尚不能判断需求覆盖。请核对上传的用户原话是否完整。");
  else
    container.append(
      node(
        "p",
        "inline-note",
        "验收点可能描述同一行为的不同方面；不按失败验收点数推算独立缺陷数。",
      ),
    );
  const changes = array(report.change_coverage),
    unmapped = array(report.unmapped_changes);
  $("change-coverage-label").textContent = `查看全部 ${changes.length} 处代码变更归属`;
  for (const change of changes) appendChange($("change-coverage-content"), change, report);
  if (!changes.length)
    empty($("change-coverage-content"), "未识别出可定位的 diff 改动。请检查材料是否包含完整补丁。");
  for (const change of unmapped) appendChange($("unmapped-content"), change, report);
  if (!unmapped.length)
    empty(
      $("unmapped-content"),
      changes.length
        ? "已识别的改动均有验收点关联；关联关系仍需结合上方依据判断。"
        : "缺少可定位的改动，无法核对是否存在未关联内容。",
    );
}
function sopSourceButton(reference) {
  const document = array(currentFullReport()?.sop_documents).find(
    (item) => item.id === reference?.document_id,
  );
  const line = reference?.start_line
    ? ` · L${reference.start_line}${reference.end_line && reference.end_line !== reference.start_line ? `–${reference.end_line}` : ""}`
    : "";
  const button = node(
    "button",
    `citation${document ? "" : " missing"}`,
    `${document?.title || reference?.document_id || "SOP 来源未提供"}${line}`,
  );
  button.type = "button";
  button.title = document ? "查看本次使用的 SOP 原文快照" : "报告缺少此规则原文快照";
  button.addEventListener("click", () => openEvidence(reference?.document_id, reference, true));
  return button;
}
function appendSopSource(container, reference) {
  if (!reference?.document_id) return;
  container.append(node("h4", "", "SOP 原条款"));
  const refs = node("div", "refs");
  refs.append(sopSourceButton(reference));
  container.append(refs);
}
function renderSopCoverage(report) {
  const present = Boolean(
    report.sop_selection || report.sop_condition_checks || report.sop_coverage,
  );
  $("checks-nav").textContent = present ? "基础修复检查" : "SOP 判断";
  $("checks-heading").textContent = present ? "基础修复检查" : "SOP 逐项判断";
  $("sop-coverage-section").hidden = !present;
  $("sop-coverage-nav").hidden = !present;
  for (const id of [
    "sop-coverage-summary",
    "sop-selection-content",
    "sop-condition-content",
    "sop-sources-content",
  ])
    $(id).replaceChildren();
  if (!present) return;
  const summary = $("sop-coverage-summary"),
    mode = report.sop_selection?.mode;
  summary.append(
    node("h3", "", "已登记条款条件逐项核查"),
    node(
      "p",
      "",
      { auto: "自动从本地 SOP 库选择", pinned: "在指定 SOP 文档内选择", uploaded: "使用上传规则" }[
        mode
      ] || "本次 SOP 选择",
    ),
  );
  const coverage = report.sop_coverage || {},
    results = node("div", "summary-results");
  if (coverage.scope_description)
    summary.append(node("p", "inline-note", coverage.scope_description));
  for (const [result, count] of Object.entries(coverage.results || {}))
    results.append(resultBadge(result, `${count} 项 · `));
  if (results.children.length) summary.append(results);
  summary.append(
    node(
      "p",
      "inline-note",
      "以上为条件判定数，不是独立缺陷数。同一问题可能影响多个条件或验收点；候选根因归并与原始问题记录见“具体问题与改进”。",
    ),
  );
  if (Array.isArray(report.sop_issue_groups) || report.sop_issue_summary) {
    if (sopIssueSummaryText(report)) summary.append(node("p", "", sopIssueSummaryText(report)));
    summary.append(
      node(
        "p",
        "inline-note",
        "SOP 同根因归并只汇总有明确原因证据的失败条件，不等于独立缺陷准确率；原条件结果与证据仍逐项保留。",
      ),
    );
  }
  const counts = [];
  if (coverage.task_rule_pairs !== undefined)
    counts.push(`${coverage.task_rule_pairs} 组任务 × 规则`);
  if (coverage.selected_rule_pairs !== undefined)
    counts.push(`${coverage.selected_rule_pairs} 组选用`);
  if ((coverage.conditions ?? coverage.total) !== undefined)
    counts.push(`${coverage.conditions ?? coverage.total} 个条件`);
  if (counts.length) summary.append(node("p", "", counts.join(" · ")));
  if (coverage.matrix_complete !== undefined)
    summary.append(
      node(
        "p",
        "",
        coverage.matrix_complete
          ? "核查矩阵完整：所有任务 × 已登记规则 × 条件均有记录。分析失败的条件也保留记录，不代表分析成功或条件满足。"
          : "核查矩阵不完整：尚不能确认已登记条款的覆盖已完成。",
      ),
    );
  if (coverage.analysis_complete !== undefined)
    summary.append(
      node(
        "p",
        "",
        coverage.analysis_complete
          ? "条件分析已完成；未核查项仍需按原因处理。"
          : "部分条件分析失败，相关项保留为未核查。",
      ),
    );
  if (coverage.gap_types && Object.keys(coverage.gap_types).length) {
    const gaps = node("p", "sop-gap-type");
    gaps.textContent = Object.entries(coverage.gap_types)
      .map(([type, count]) => `${sopGapNames[type] || type} ${count} 项`)
      .join(" · ");
    summary.append(gaps);
  }
  if (array(coverage.failures).length) {
    const failures = node("details", "gate-details"),
      affected = array(report.sop_condition_checks).filter(conditionAnalysisIncomplete).length;
    failures.append(
      node("summary", "", `${coverage.failures.length} 条分析失败记录 · 影响 ${affected} 个条件`),
    );
    for (const failure of array(coverage.failures)) {
      const location = [["任务", failure.task_id], ["条件", failure.condition_id],
        ["子项", failure.atomic_item_id], ["失败阶段", failure.stage], ["类别", failure.kind]]
        .filter(([, value]) => typeof value === "string" && value)
        .map(([label, value]) => `${label}：${value}`).join(" · ");
      if (location) failures.append(node("p", "inline-note", location));
      failures.append(node("p", "", failure.reason || "未提供失败原因"));
    }
    summary.append(failures);
  }
  if (array(coverage.unsupported_sections).length) {
    const unsupported = node("details", "sop-unsupported");
    unsupported.append(
      node("summary", "", `尚未支持的原文章节 · ${coverage.unsupported_sections.length} 项`),
      node(
        "p",
        "inline-note",
        "以下章节尚未编译为自动核查条件，因此不能据已登记条件的结果认定整份 SOP 已核查。",
      ),
    );
    for (const section of array(coverage.unsupported_sections)) {
      const row = node("div", "condition-row");
      row.append(
        node("strong", "", section.title || "未标明章节"),
        node("p", "sop-gap-type", "自动检查尚未覆盖"),
      );
      appendField(row, "覆盖边界", section.reason);
      appendSopSource(row, section.source_ref);
      unsupported.append(row);
    }
    summary.append(unsupported);
  }
  summary.append(
    node(
      "p",
      "inline-note",
      "按任务记录选用依据，再逐条件核查。模型候选判断经证据门槛约束；静态核查不代表已经运行测试或完成产品验收。",
    ),
  );
  const ruleMap = new Map(
    [...array(report.rules), ...array(report.sop_rules)].map((rule) => [rule.id, rule]),
  );
  for (const taskSelection of array(report.sop_selection?.task_selections)) {
    const { article, body } = card(taskSelection.task_id, taskName(taskSelection.task_id, report));
    for (const selection of array(taskSelection.rules)) {
      const row = node("div", "sop-rule-selection"),
        status = selection.selection;
      const head = node("div", "sop-condition-head");
      head.append(
        node(
          "strong",
          "",
          `${selection.rule_id || "未标明规则"} · ${selection.title || ruleMap.get(selection.rule_id)?.title || "规则"}`,
        ),
        node(
          "span",
          `check-result ${selection.analysis_failed || status === "uncertain" ? "insufficient" : status === "not_applicable" ? "na" : ""}`,
          `${selection.analysis_failed ? "分析失败 · " : ""}${sopSelectionNames[status] || "待确认"}`,
        ),
      );
      row.append(head);
      appendField(row, "选用依据", selection.reason);
      appendRefs(row, selection.evidence_refs, "任务依据");
      appendSopSource(row, selection.source_ref);
      body.append(row);
    }
    if (!body.children.length) empty(body, "此任务没有选用记录，不能确认规则选择已完成。");
    $("sop-selection-content").append(article);
  }
  if (!$("sop-selection-content").children.length)
    empty($("sop-selection-content"), "本报告没有逐任务的 SOP 选用记录。");
  const conditionGroups = new Map();
  for (const check of array(report.sop_condition_checks)) {
    const key = JSON.stringify([check.task_id, check.rule_id]),
      checks = conditionGroups.get(key) || [];
    checks.push(check);
    conditionGroups.set(key, checks);
  }
  for (const checks of conditionGroups.values()) {
    const first = checks[0],
      group = node("details", "sop-condition-group"),
      header = node("summary"),
      counts = { 满足: 0, 不满足: 0, 未核查: 0, 不适用: 0 };
    for (const check of checks)
      counts[resultLabel(check.result || "未核查")] =
        (counts[resultLabel(check.result || "未核查")] || 0) + 1;
    group.open = counts["不满足"] > 0;
    header.append(
      node(
        "strong",
        "",
        `${first.rule_id || "未标明规则"} · ${ruleMap.get(first.rule_id)?.title || "规则"}`,
      ),
      node("span", "check-context", `${taskName(first.task_id, report)} · ${checks.length} 个条件`),
      resultBadge(allRequiredResult(checks.map((check) => check.result)), "本组："),
    );
    const badges = node("span", "summary-results");
    for (const [result, count] of Object.entries(counts))
      badges.append(resultBadge(result, `${count} 项 · `));
    header.append(badges);
    group.append(header);
    const failed = checks.filter(conditionAnalysisIncomplete).length;
    if (failed) badges.append(node("span", "check-result insufficient", `${failed} 项分析失败`));
    const content = node("div", "card-stack");
    group.append(content);
    $("sop-condition-content").append(group);
    for (const check of checks) {
      const { article, heading, body } = card(
        `${check.rule_id || ""} · ${check.condition_id || ""}`,
        check.text || "未提供条件内容",
        resultBadge(check.result || "未核查", coverage.current_scope ? "原条款：" : ""),
      );
      heading.append(node("span", "check-context", taskName(check.task_id, report)));
      const scope = node("div", "check-scope");
      scope.append(node("span", "", `适用性：${applicabilityLabel(check.applicability)}`));
      if (check.gap_type)
        scope.append(node("span", "sop-gap-type", sopGapNames[check.gap_type] || check.gap_type));
      body.append(scope);
      const stageScope = check.review_scope?.status || check.assessment_scope;
      if (stageScope === "deferred" && check.gap_type !== "scope_not_requested")
        scope.append(node("span", "tag neutral", "未纳入本次阶段"));
      else if (stageScope === "partial" || stageScope === "required")
        scope.append(
          node("span", "tag neutral", stageScope === "partial" ? "部分子项纳入本轮" : "本轮必需"),
        );
      if (
        check.scope_result &&
        stageScope !== "deferred" &&
        check.gap_type !== "scope_not_requested"
      )
        scope.append(resultBadge(check.scope_result, "本轮："));
      appendField(body, "本轮范围依据", check.review_scope?.reason);
      if (check.analysis_status === "failed" && check.gap_type !== "analysis_failed")
        scope.append(node("span", "sop-gap-type", "分析失败 · 已知判断与证据仍保留"));
      if (check.analysis_status === "partial")
        scope.append(node("span", "sop-gap-type", "部分分析失败 · 已知判断与证据仍保留"));
      appendField(body, "条件核查依据", check.reason);
      appendSopSource(body, check.source_ref);
      appendRefs(body, check.evidence_refs, "关联 Trace / Commit 证据");
      appendField(body, "关联验收点", check.acceptance_ids);
      if (check.model_result || check.local_result)
        body.append(resultBadge(check.model_result || check.local_result, "模型候选："));
      appendAtomicChecks(body, check);
      if (check.program_gates !== undefined) {
        const gates = node("details", "gate-details");
        gates.append(node("summary", "", "查看此条件的程序证据门槛"));
        renderValue(gates, check.program_gates);
        body.append(gates);
      }
      const actions = node("div", "action-grid"),
        improvement = node("div"),
        verification = node("div");
      appendField(improvement, "改进 / 补证动作", check.improvement);
      appendField(verification, "复检方法", check.verification);
      if (improvement.children.length || verification.children.length) {
        actions.append(improvement, verification);
        body.append(actions);
      }
      content.append(article);
    }
  }
  if (!$("sop-condition-content").children.length)
    empty($("sop-condition-content"), "未生成完整条件核查矩阵，不能确认条款完整要求已核实。");
  for (const document of array(report.sop_documents)) {
    const row = node("div", "verification-record");
    row.append(
      node("strong", "", document.title || document.id),
      node("p", "", `参考版本：${document.version || "未提供"}`),
      node("p", "source-hash", `SHA-256：${document.sha256 || "未提供"}`),
    );
    row.append(sopSourceButton({ document_id: document.id }));
    $("sop-sources-content").append(row);
  }
  if (!$("sop-sources-content").children.length)
    empty($("sop-sources-content"), "缺少本次 SOP 原文快照。");
}
function renderChecks(report) {
  const container = $("checks-content");
  container.replaceChildren();
  const ruleMap = new Map(array(report.rules).map((rule) => [rule.id, rule]));
  for (const check of array(report.checks)) {
    const rule = ruleMap.get(check.rule_id),
      modern = versionTwo(report),
      badge = resultBadge(
        modern ? check.automated_result || "未核查" : check.result,
        modern ? "自动子集：" : "",
      );
    const { article, heading, body } = card(
      check.id,
      `${check.rule_id || ""} ${rule?.title || check.title || "审计检查"}`.trim(),
      badge,
    );
    heading.append(node("span", "check-context", taskName(check.task_id, report)));
    const context = node("div", "check-scope");
    context.append(node("span", "", `适用性：${applicabilityLabel(check.applicability)}`));
    if (check.scope) context.append(node("span", "", `范围：${display(check.scope)}`));
    body.append(context);
    if (modern) {
      const levels = node("div", "result-levels");
      for (const [label, result] of [
        ["模型局部事实", check.local_result],
        ["程序证据门槛后的自动子集", check.automated_result],
        ["条款完整要求", check.sop_result ?? check.result],
      ]) {
        const level = node("div", "result-level");
        level.append(node("span", "", label), resultBadge(result || "未核查"));
        levels.append(level);
      }
      body.append(levels);
      if (check.closure_readiness)
        body.append(resultBadge(check.closure_readiness, "关闭就绪度："));
      if (check.recheck_execution_result)
        body.append(resultBadge(check.recheck_execution_result, "复检执行："));
      const gates = array(check.gate_details);
      if (gates.length) {
        const details = node("details", "gate-details");
        details.append(
          node(
            "summary",
            "",
            `证据门槛 · ${gates.filter((gate) => gate.met === true).length} / ${gates.length} 已具备`,
          ),
        );
        for (const gate of gates) {
          const row = node("div", `gate-row ${gate.met === true ? "met" : "unmet"}`);
          row.append(
            node(
              "strong",
              "",
              `${gate.met === true ? "已具备" : "未具备"} · ${gate.label || gate.id || "证据条件"}`,
            ),
          );
          if (gate.reason) row.append(node("p", "", gate.reason));
          details.append(row);
        }
        body.append(details);
      }
    }
    appendField(body, "判断依据", check.reason);
    const review = check.local_failure_review;
    if (modern && review && typeof review === "object" && !Array.isArray(review)) {
      const details = node("details", "gate-details local-failure-review"),
        completed = review.status === "completed",
        confirmed = completed && review.confirmed === true && review.effective_result === "不满足" &&
          review.relation === "direct_counterexample" && review.scope_consistency === "same_scope";
      details.append(node("summary", "", "模型反例复核"));
      appendField(details, "复核状态", {
        pending: "复核未完成", completed: "复核已完成", failed: "复核失败",
      }[review.status] || "复核状态未核定");
      appendField(details, "反例关系", completed ? {
        direct_counterexample: "直接反例候选",
        different_dimension: "属于其他判断维度",
        evidence_insufficient: "反例证据不足",
      }[review.relation] || "未核查" : "未核查");
      appendField(details, "范围一致性", completed ? {
        same_scope: "同一范围", different_scope: "不同范围", uncertain: "范围待确认",
      }[review.scope_consistency] || "范围待确认" : "范围待确认");
      appendField(details, "复核结论", confirmed ? "复核支持同范围反例" : "尚无复核支持的同范围反例");
      details.append(resultBadge(confirmed ? "不满足" : "未核查", "本次有效判断："));
      appendField(details, "复核说明", review.reason);
      const candidate = check.local_failure_candidate;
      if (candidate && typeof candidate === "object" && !Array.isArray(candidate)) {
        appendField(details, "原模型失败候选理由", candidate.reason);
        appendRefs(details, candidate.evidence_refs, "原候选支持证据");
        appendRefs(details, candidate.counter_refs, "原候选反向证据");
      }
      body.append(details);
    }
    appendRefs(body, check.evidence_refs, "支持证据");
    appendRefs(body, check.counter_refs, "反向证据");
    if (array(check.missing_materials).length) {
      const missing = node("div", "missing-list");
      missing.append(node("strong", "", "仍需补充"));
      renderValue(missing, check.missing_materials);
      body.append(missing);
    }
    const actions = node("div", "action-grid"),
      improvement = node("div"),
      verification = node("div");
    appendField(improvement, "建议动作", check.improvement);
    appendField(verification, "验证方法", check.verification);
    if (improvement.children.length || verification.children.length) {
      actions.append(improvement, verification);
      body.append(actions);
    }
    if (rule) {
      const details = node("details", "format-help");
      details.append(node("summary", "", "查看本项规则"));
      appendField(details, "判断标准", rule.criterion);
      appendField(details, "所需证据", rule.required_evidence);
      appendField(details, "规则版本", rule.version);
      body.append(details);
    }
    container.append(article);
  }
  if (!container.children.length) empty(container, "本次报告没有可展示的 SOP 判断。");
}
function findingGroups(report) {
  const groups = new Map();
  for (const [index, finding] of array(report.findings).entries()) {
    if (!finding || typeof finding !== "object") continue;
    const explicit = typeof finding.issue_key === "string" && finding.issue_key.trim() !== "";
    const key = explicit
      ? JSON.stringify([finding.task_id, finding.category, finding.issue_key])
      : `record:${index}`;
    if (!groups.has(key))
      groups.set(key, { issue_key: explicit ? finding.issue_key : null, findings: [] });
    groups.get(key).findings.push(finding);
  }
  return [...groups.values()];
}
function appendFinding(container, finding, report) {
  const { article, heading, body } = card(
    finding.id,
    finding.summary,
    node(
      "span",
      "finding-category",
      categoryNames[finding.category] || finding.category || "待核对问题",
    ),
  );
  heading.append(node("span", "check-context", taskName(finding.task_id, report)));
  appendRefs(body, finding.evidence_refs, "关联证据");
  appendField(body, "影响", finding.impact);
  appendField(body, "关联验收点", finding.acceptance_ids);
  appendField(body, "关联条件", finding.condition_ids);
  const actions = node("div", "action-grid"),
    improvement = node("div"),
    verification = node("div");
  appendField(improvement, "具体改进", finding.improvement);
  appendField(verification, "如何验证", finding.verification);
  actions.append(improvement, verification);
  body.append(actions);
  container.append(article);
}
function sopIssueSummaryText(report) {
  const summary = report.sop_issue_summary;
  if (!summary || typeof summary !== "object" || Array.isArray(summary)) return "";
  return `${display(summary.groups)} 个 SOP 同根因问题组 · ${display(summary.grouped_conditions)} 个受影响条件 · ${display(summary.ungrouped_conditions)} 个未归并条件 · 共 ${display(summary.failed_conditions)} 个不满足条件`;
}
function appendSopIssueGroups(container, report) {
  if (!Array.isArray(report.sop_issue_groups) && !report.sop_issue_summary) return false;
  const section = node("section", "sop-issue-groups");
  section.append(node("h3", "", "SOP 同根因问题组"));
  if (sopIssueSummaryText(report)) section.append(node("p", "", sopIssueSummaryText(report)));
  section.append(
    node(
      "p",
      "inline-note",
      "按独立反证复核提供的原因证据归组；归并不等于独立缺陷准确率，原条件结果和原始问题记录均保留。",
    ),
  );
  for (const group of array(report.sop_issue_groups)) {
    const details = node("details", "sop-condition-group sop-issue-group"),
      heading = node("summary"),
      body = node("div", "card-body");
    heading.append(
      node("strong", "", group.title || group.id || "未提供问题标题"),
      node(
        "span",
        "check-context",
        `${taskName(group.task_id, report)} · ${array(group.condition_ids).length} 个条件`,
      ),
    );
    details.append(heading, body);
    appendField(body, "涉及组件", group.component);
    appendField(body, "目标版本", group.target_commit_ids);
    appendField(body, "触发条件", group.trigger);
    appendField(body, "原因机制", group.mechanism);
    appendRefs(body, group.cause_refs, "同根因证据");
    appendField(body, "关联子项", group.atomic_item_ids);
    const versions = JSON.stringify(array(group.target_commit_ids).slice().sort());
    for (const id of array(group.condition_ids)) {
      const matches = array(report.sop_condition_checks).filter(
        (condition) =>
          condition.task_id === group.task_id &&
          condition.condition_id === id &&
          JSON.stringify(array(condition.target_commit_ids).slice().sort()) === versions,
      );
      if (matches.length !== 1) {
        body.append(
          node("p", "inline-note", `${id}：报告中无法唯一定位同任务、同目标版本的原条件。`),
        );
        continue;
      }
      const condition = matches[0],
        item = card(id, condition.text || "原条件", resultBadge(condition.result || "未核查"));
      appendField(item.body, "核查依据", condition.reason);
      appendRefs(item.body, condition.evidence_refs, "原条件证据");
      body.append(item.article);
    }
    section.append(details);
  }
  if (!array(report.sop_issue_groups).length)
    section.append(
      node("p", "inline-note", "尚无已确认的 SOP 同根因问题组；未归并条件仍按原条款逐项查看。"),
    );
  container.append(section);
  return true;
}
function renderFindings(report) {
  const container = $("findings-content");
  container.replaceChildren();
  const hasSopIssues = appendSopIssueGroups(container, report);
  const groups = findingGroups(report),
    records = groups.reduce((count, group) => count + group.findings.length, 0),
    explicit = groups.filter((group) => group.issue_key !== null);
  if (!records) {
    if (!hasSopIssues) empty(container, "本次报告未列出具体问题；结论仅覆盖已提供的证据范围。");
    return;
  }
  container.append(
    node(
      "p",
      "inline-note",
      `${records} 条原始问题记录${explicit.length ? ` · ${explicit.length} 个显式候选根因组 · ${groups.length - explicit.length} 条未分组记录` : " · 尚无显式根因归并"}。候选分组不代表已确认的独立缺陷数；条件结果与原始记录均保留。原始问题记录仍是未独立复核的模型候选；某检查的反例复核不自动认证这些记录。`,
    ),
  );
  for (const group of groups) {
    if (group.issue_key === null) {
      appendFinding(container, group.findings[0], report);
      continue;
    }
    const first = group.findings[0],
      details = node("details", "sop-condition-group finding-group"),
      heading = node("summary");
    heading.append(
      node("strong", "", `候选根因组 · ${first.summary || group.issue_key}`),
      node(
        "span",
        "check-context",
        `${taskName(first.task_id, report)} · ${group.findings.length} 条记录`,
      ),
      node("span", "finding-category", categoryNames[first.category] || "待核对问题"),
    );
    details.open = true;
    details.append(heading);
    const content = node("div", "card-stack");
    details.append(content);
    for (const finding of group.findings) appendFinding(content, finding, report);
    container.append(details);
  }
}
function renderEvidence(report) {
  const container = $("evidence-content");
  container.replaceChildren();
  for (const evidence of array(report.evidence)) {
    const button = node("button", "evidence-card"),
      content = node("span");
    button.type = "button";
    content.append(
      node("span", "evidence-name", evidence.name || evidence.id),
      node(
        "span",
        "evidence-meta",
        `${kindNames[evidence.kind] || evidence.kind || "材料"} · ${sourceLines(evidence.content).length} 行${evidence.version_id ? ` · ${evidence.version_id}` : ""}`,
      ),
    );
    button.append(node("span", "evidence-icon", "≡"), content, node("span", "evidence-arrow", "↗"));
    button.addEventListener("click", () => openEvidence(evidence.id));
    container.append(button);
  }
  if (!container.children.length) empty(container, "报告未包含可展示的原始材料。");
  const verification = report.run_verification,
    details = $("run-verification"),
    content = $("run-verification-content");
  content.replaceChildren();
  details.hidden =
    !versionTwo(report) || !verification || (Array.isArray(verification) && !verification.length);
  if (!details.hidden)
    for (const record of array(verification)) {
      if (!record || typeof record !== "object") continue;
      const row = node("div", "verification-record"),
        verified = record.verified === true;
      const outcome = verified
        ? { pass: "运行通过 · 限定范围", fail: "运行失败 · 限定范围" }[record.outcome] ||
          "运行结论未核查"
        : "运行结论未核查";
      row.append(
        node("h4", "", verified ? "运行来源与绑定材料已验证" : "运行来源或材料绑定未验证"),
        node("p", "", outcome),
      );
      appendRefs(row, record.evidence_id ? [{ evidence_id: record.evidence_id }] : [], "回执原文");
      appendField(row, "程序校验说明", record.reason);
      appendField(row, "回执记录的仓库", record.repository);
      appendField(row, "回执记录的 Commit", record.commit_sha);
      appendField(row, "所列源码路径", record.source_paths);
      appendField(row, "所列测试路径", record.test_paths);
      if (record.test_origin === "external_audit")
        appendField(
          row,
          "测试来源",
          "本轮新增外部审计测试；Commit 绑定表示被测代码，不表示原提交已交付该测试。",
        );
      if (record.exit_code !== undefined)
        appendField(
          row,
          "运行统计",
          `退出码 ${record.exit_code} · 执行 ${display(record.tests_run)} · 跳过 ${display(record.skipped)}`,
        );
      appendRefs(
        row,
        record.log_evidence_id ? [{ evidence_id: record.log_evidence_id }] : [],
        "对应日志",
      );
      if (record.assertion_results !== undefined) {
        row.append(
          node("h4", "", "按路径与行号记录的断言结果"),
          node("pre", "verification-assertions", JSON.stringify(record.assertion_results, null, 2)),
        );
      }
      content.append(row);
    }
}

function currentFullReport() {
  return fullState.rounds[fullState.active]?.report;
}
/* eslint-disable no-control-regex -- Python splitlines(keepends=True) is the report line coordinate system. */
function pythonSegments(text) {
  return (
    text.match(
      /[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]*(?:\r\n|[\n\r\v\f\x1c-\x1e\x85\u2028\u2029])|[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]+$/g,
    ) ?? []
  );
}
/* eslint-enable no-control-regex */
function openEvidence(id, reference, sopDocument = false) {
  const report = currentFullReport();
  const source = array(sopDocument ? report?.sop_documents : report?.evidence).find(
    (item) => item.id === id,
  );
  if (!source) return setFullError(`无法定位引用 ${id}：本轮报告未包含对应的冻结材料。`);
  showFrozenSource(
    {
      ...source,
      kind: sopDocument ? "参考规范" : source.kind,
      locator: sopDocument
        ? { source_path: source.source_path, version: source.version }
        : source.provenance,
    },
    reference?.start_line ? { ...reference, source_id: id } : undefined,
    {
      original_sha256: source.original_sha256,
      original_sha256s: source.original_sha256s,
      redacted: source.display_redacted,
      sha256: source.sha256,
      display_sha256: source.display_sha256,
      line_mode: "python",
    },
  );
}
function renderFullMatrix() {
  const report = currentFullReport();
  if (!report || !$("full-matrix")) return;
  const rows = report.sop_condition_checks.filter(
    (row) =>
      (!fullState.filter || fullResults[row.result] === fullState.filter) &&
      (!fullState.query ||
        [row.rule_id, row.condition_id, row.task_id, row.text, row.reason]
          .join(" ")
          .toLowerCase()
          .includes(fullState.query.toLowerCase())),
  );
  renderSopCoverage({ ...report, sop_condition_checks: rows });
  $("full-filter-count").textContent =
    `${rows.length} / ${report.sop_condition_checks.length} 条条件记录`;
}
function reportRuleSummary(report) {
  const rules = array(report.sop_rules);
  return {
    source: report.rule_source ?? {},
    rule_count: rules.length || new Set(report.sop_condition_checks.map((row) => row.rule_id)).size,
    condition_count: rules.length
      ? rules.reduce((n, rule) => n + array(rule.conditions).length, 0)
      : new Set(report.sop_condition_checks.map((row) => row.condition_id)).size,
    atomic_item_count: rules.length
      ? rules.reduce(
          (n, rule) =>
            n +
            array(rule.conditions).reduce(
              (m, condition) => m + array(condition.contract?.items).length,
              0,
            ),
          0,
        )
      : null,
    documents: report.sop_documents,
  };
}
function renderFull() {
  const round = fullState.rounds[fullState.active];
  if (!round) return;
  const history = `<label class="history"><select id="full-history" aria-label="选择完整审计轮次">${fullState.rounds.map((entry, index) => `<option value="${index}" ${index === fullState.active ? "selected" : ""}>第 ${fullState.rounds.length - index} 轮 · ${entry.imported ? "导入回放" : (jobLabels[entry.status] ?? escapeHtml(entry.status))}</option>`).join("")}</select><small>本页保留 ${fullState.rounds.length} 轮；刷新可恢复服务端活动任务，已保存记录仍保留在服务端。</small></label>`;
  const related = [...array(round.supersedes), ...(typeof round.superseded_by === "string" ? [round.superseded_by] : [])],
    links = related.length ? `<div class="job-actions">${related.map((id) => `<button type="button" class="button secondary" data-full-job="${escapeHtml(id)}">查看关联任务 ${escapeHtml(id)}</button>`).join("")}</div>` : "",
    stop = round.stop && typeof round.stop === "object" ? round.stop : {},
    stopped = ["cancelling", "cancelled"].includes(round.status),
    stopDetails = stopped ? `<div class="notice"><strong>${escapeHtml(jobLabels[round.status])}</strong><p>${round.status === "cancelling" ? "已请求停止旧任务；新审计等待旧请求退出后开始。" : "此轮已停止，已有响应与停止记录保留；未记为审计通过或分析失败。"}</p>${stop.stage ? `<p>停止阶段：${escapeHtml(stop.stage)}</p>` : ""}${round.cancelled_at ? `<p>停止时间：${escapeHtml(round.cancelled_at)}</p>` : ""}</div>` : "";
  const heading = `<div class="report-heading"><div><div class="step-label">完整审计 · 模型候选</div><h2>${escapeHtml(round.report?.title ?? round.request?.title ?? "完整审计")}</h2><p class="report-subtitle">人工未复核 · 正式未关闭 · ${round.imported ? "导入本地报告，不代表本次模型执行" : escapeHtml(round.id)}</p></div>${history}</div>${links}${stopDetails}`;
  if (!round.report) {
    $("full-report").innerHTML =
      `${heading}<div class="notice ${round.status === "failed" ? "error" : ""}"><strong>${escapeHtml(jobLabels[round.status] ?? "作业状态未知")}</strong><p>${escapeHtml(round.error?.message ?? round.progress ?? "")}</p>${round.error?.code ? `<p>错误代码：${escapeHtml(round.error.code)}</p>` : ""}${failureDetailsHtml(round.error)}${round.error?.recording_error ? `<div><p>失败记录保存异常；原始故障仍保留。</p>${failureDetailsHtml(round.error.recording_error)}</div>` : ""}${activeFullStatuses.includes(round.status) ? `<p>${round.status === "queued" && related.length ? "新审计已排队，等待旧请求退出后运行。" : "停止查看进度不会取消后台任务，也不会再次发送材料。"}</p><div class="job-actions"><button type="button" class="button secondary" data-full-poll>${fullState.polling ? "停止查看进度" : "继续查看进度"}</button></div>` : round.status === "cancelled" ? "<p>旧轮记录保留，可从历史轮次查看。</p>" : "<p>本轮失败已保留；不自动重试。旧报告可从历史轮次回看。</p>"}</div>`;
    return;
  }
  const report = round.report,
    model = report.model_snapshot ?? {};
  const diagnostics = array(model.failure_diagnostics).filter((item) => item && typeof item === "object" && !Array.isArray(item));
  const sections = [
    ["overview", "概览"],
    ["tasks", "任务与要求"],
    ["acceptance", "验收点映射"],
    ["sop-coverage", "SOP 选择与完整核查"],
    ["checks", "基础修复检查"],
    ["findings", "具体问题"],
    ["evidence", "证据材料"],
  ];
  $("full-report").innerHTML =
    `${heading}<nav class="report-nav" aria-label="完整报告章节">${sections.map(([id, label]) => `<a id="${id}-nav" href="#${id}-section">${label}</a>`).join("")}</nav>
    <section id="overview-section" class="full-report-section"><h2>概览</h2>
    ${model.execution_mode === "offline_fake" ? '<div class="notice"><strong>离线模拟结果</strong>完整引擎使用离线 fake client，没有向真实模型发送请求。</div>' : ""}
    <div class="notice warning"><strong>候选结果 · 人工未复核 · 正式未关闭</strong><p>${model.model_invoked ? `报告记录 ${escapeHtml(model.provider ?? "DeepSeek")} / ${escapeHtml(model.model)}，真实 HTTP 请求 ${escapeHtml(model.api_request_count)} 次。` : "报告未记录真实模型调用。"} 材料来源未经平台身份认证，业务测试未由本工具执行。</p><p id="candidate-banner"></p></div>
    ${diagnostics.length ? `<details class="notice warning"><summary>${diagnostics.length} 条调用异常记录（可能包含已恢复尝试）</summary>${diagnostics.map((item) => `<div>${failureDetailsHtml(item)}</div>`).join("")}</details>` : ""}
    <p id="schema-label" class="muted"></p><div id="legacy-banner" hidden></div><div id="metrics" class="metrics"></div><div id="current-audit-scope" class="card scope-panel"></div><div id="review-status" class="review-grid"></div><div id="summary-content" class="card scope-panel"></div><div id="report-warnings" class="notice warning" hidden></div><div id="delta-content" class="card scope-panel" hidden></div>
    <details class="card report-identity"><summary>本轮来源、规则版本与分析限制</summary>${ruleSummaryHtml(reportRuleSummary(report))}<p>审计 ID：${escapeHtml(report.audit_id ?? round.id)}</p><p>输入摘要：<code>${escapeHtml(report.integration?.input_sha256 ?? "未提供")}</code></p>${model.provider || model.model || model.provider_endpoint ? `<p>报告记录的模型配置：${escapeHtml(model.provider ?? "DeepSeek")} / ${escapeHtml(model.model ?? "未提供")}${model.provider_endpoint ? `；请求端点：<code>${escapeHtml(model.provider_endpoint)}</code>` : ""}。</p>` : ""}<p>真实 HTTP 请求：${escapeHtml(model.api_request_count ?? 0)}；总调用预算：${escapeHtml(model.max_total_calls ?? "未提供")}。</p><ul>${array(
      report.integration?.known_limitations,
    )
      .map((limit) => `<li>${escapeHtml(limit)}</li>`)
      .join("")}</ul></details></section>
    <section id="tasks-section" class="full-report-section"><h2>任务与要求</h2><div id="tasks-content" class="card-stack"></div></section>
    <section id="acceptance-section" class="full-report-section"><h2>验收点映射</h2><p class="help">实现、测试断言和实际执行分别核对，不以一种证据替代另一种。</p><div id="acceptance-content" class="card-stack"></div><details class="card scope-panel"><summary id="change-coverage-label">全部代码变更归属</summary><div id="change-coverage-content" class="card-stack"></div></details><div class="card scope-panel"><h3>未关联改动</h3><div id="unmapped-content" class="card-stack"></div></div></section>
    <section id="sop-coverage-section" class="full-report-section"><h2>SOP 选择与完整核查</h2><div id="sop-coverage-summary" class="card scope-panel"></div><details class="card scope-panel"><summary>逐任务规则选择依据</summary><div id="sop-selection-content"></div></details><div class="card full-toolbar"><input id="full-search" type="search" aria-label="搜索完整审计条件" placeholder="搜索规则、条件或依据" value="${escapeHtml(fullState.query)}"/><select id="full-filter" aria-label="筛选完整审计状态"><option value="">全部状态</option>${Object.entries(
      labels,
    )
      .map(
        ([key, label]) =>
          `<option value="${key}" ${fullState.filter === key ? "selected" : ""}>${label}</option>`,
      )
      .join(
        "",
      )}</select><span id="full-filter-count" class="muted"></span></div><div id="full-matrix"><div id="sop-condition-content"></div></div><details class="card scope-panel"><summary>本轮规范原文快照</summary><div id="sop-sources-content"></div></details></section>
    <section id="checks-section" class="full-report-section"><h2 id="checks-heading">基础修复检查</h2><div id="checks-content" class="card-stack"></div></section>
    <section id="findings-section" class="full-report-section"><h2>具体问题与改进</h2><div id="findings-content" class="card-stack"></div></section>
    <section id="evidence-section" class="full-report-section"><h2>证据材料</h2><p class="help">仅从所选历史报告读取冻结原文；更换本轮规则或上传材料不会替换历史证据。</p><div id="evidence-content" class="evidence-grid"></div><details id="run-verification" class="card scope-panel" hidden><summary>报告记录的运行来源与材料绑定</summary><p class="help">以下为报告内记录；上传者自报身份不等于 FormSy 平台授权或本工具实际执行。</p><div id="run-verification-content"></div></details></section>`;
  renderMetrics(report);
  renderReviewStatus(report);
  renderSummary(report);
  renderDelta(report.delta);
  if (array(report.warnings).length) {
    $("report-warnings").hidden = false;
    $("report-warnings").append(node("strong", "", "引用校验与范围提醒"));
    renderValue($("report-warnings"), report.warnings);
  }
  renderTasks(report);
  renderAcceptance(report);
  renderFullMatrix();
  renderChecks(report);
  renderFindings(report);
  renderEvidence(report);
}

async function pollFull(round) {
  const version = ++fullState.pollVersion;
  fullState.polling = true;
  setFullError();
  renderFull();
  const poll = async () => {
    if (!fullState.polling || version !== fullState.pollVersion) return;
    try {
      const result = await api(`/api/full-audits/${encodeURIComponent(round.id)}`);
      if (version !== fullState.pollVersion) return;
      retainFullJob(result, round.id);
      await refreshSuperseded(round);
      if (version !== fullState.pollVersion) return;
      if (result.error?.provider_code || result.report?.sop_coverage?.provider_failure) {
        fullState.providerBlocked = true;
        $("full-consent").checked = false;
      }
      if (terminalFullStatuses.includes(round.status)) fullState.polling = false;
      renderFull();
      fullControls();
      if (fullState.polling) fullState.timer = setTimeout(poll, 1500);
    } catch (error) {
      if (version !== fullState.pollVersion) return;
      fullState.polling = false;
      setFullError(
        `进度读取中断：${error.message} 后台可能继续运行；不会重复提交。可继续查看进度。`,
      );
      renderFull();
      fullControls();
    }
  };
  await poll();
}

$("full-mode").addEventListener("change", () => {
  $("full-consent").checked = false;
  fullControls();
});
$("full-consent").addEventListener("change", fullControls);
$("full-demo").addEventListener("click", () => loadFullDemo(""));
$("full-demo-select").addEventListener("change", (event) => {
  $("full-consent").checked = false;
  if (event.target.value) return loadFullDemo(event.target.value);
  fullControls();
});
$("full-request-file").addEventListener("change", async (event) => {
  const file = event.target.files[0];
  if (!file || fullState.loading || fullState.submitting || fullState.uploading) return;
  fullState.loading = true;
  $("full-consent").checked = false;
  fullControls();
  try {
    if (file.size > 16 * 1024 * 1024)
      throw new Error("JSON 超过 16 MiB；未自动截断。请求本身上限仍为 2 MiB。");
    const value = JSON.parse(await file.text());
    const report = value.report ?? value;
    if (report.schema_version === "2.1") {
      assertFullReport(report);
      fullState.rounds.unshift({
        id: `import-${Date.now()}`,
        status: "completed",
        report,
        imported: true,
      });
      fullState.active = 0;
      fullState.viewVersion++;
      renderFull();
    } else {
      assertFullRequest(value);
      if (value.rules !== undefined) await freezeRules(value.rules);
      fullState.request = value;
      fullState.demo = null;
      $("full-demo-select").value = "";
      fullState.fileName = file.name;
    }
    $("full-consent").checked = false;
    setFullError();
    fullControls();
  } catch (error) {
    setFullError(`材料未载入：${error.message} 现有材料与报告保留。`);
  } finally {
    fullState.loading = false;
    fullControls();
  }
  event.target.value = "";
});
$("full-verify").addEventListener("click", async () => {
  if (
    fullState.submitting || fullState.loading || fullState.uploading ||
    !fullState.request
  )
    return;
  let preparedRequest;
  try {
    preparedRequest = buildFullRequest();
  } catch (error) {
    return setFullError(error.message);
  }
  if ($("full-mode").value === "offline") {
    fullState.viewVersion++;
    setFullError();
    const request = preparedRequest;
    $("full-report").innerHTML =
      `<div class="card full-validation"><span class="badge">仅输入结构检查</span><h2>材料可读取，语义审计尚未运行</h2><p>${escapeHtml(request.title)} · ${request.trace.messages.length} 条消息 / ${request.commits.length} 个 Commit / ${request.materials.length} 份材料。</p><p>浏览器检查了输入字段和格式，未调用模型、未生成语义审计结论、未执行业务代码。服务端仍会独立校验范围与字数。</p><p>范围：${request.audit_context?.profile === "full_sop" ? "full_sop · 全部 SOP" : "code_fix · 代码修复；治理条件可延后但仍未核定"}。参考库不代表项目历史生效规范。</p>${fullState.rounds.length ? '<button type="button" class="button secondary" data-full-return>返回已有审计记录</button>' : ""}</div>`;
    return;
  }
  if (
    $("full-mode").value !== "model" ||
    !$("full-consent").checked ||
    !fullState.config?.available ||
    !fullState.config.model_configured
  )
    return setFullError("未确认模型发送或本地模型不可用，未发送材料。");
  const request = preparedRequest;
  fullState.viewVersion++;
  fullState.submitting = true;
  $("full-consent").checked = false;
  fullControls();
  setFullError();
  try {
    const result = await api("/api/full-audits", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ request, mode: "model" }),
    });
    if (typeof result.id !== "string" || !["queued", "running"].includes(result.status))
      throw new Error("未收到明确的作业身份；请检查后台记录，勿重复提交。");
    const round = retainFullJob(result);
    round.request = request;
    fullState.rounds = [round, ...fullState.rounds.filter((entry) => entry !== round)];
    for (const id of array(result.supersedes)) {
      const old = fullState.rounds.find((entry) => entry.id === id && !entry.imported);
      if (old && activeFullStatuses.includes(old.status)) Object.assign(old, { status: "cancelling", superseded_by: round.id });
    }
    fullState.active = 0;
    fullState.viewVersion++;
    fullState.query = "";
    fullState.filter = "";
    await pollFull(round);
  } catch (error) {
    if (error.code === "model_unconfigured" || error.code === "full_engine_unavailable") {
      fullState.providerBlocked = true;
      $("full-consent").checked = false;
    }
    setFullError(`未确认审计作业已创建：${error.message} 本页不会自动重新发送；请先核对后台记录。`);
  } finally {
    fullState.submitting = false;
    fullControls();
  }
});
$("full-report").addEventListener("input", (event) => {
  if (event.target.id === "full-search") {
    fullState.query = event.target.value;
    renderFullMatrix();
  }
});
$("full-report").addEventListener("change", (event) => {
  if (event.target.id === "full-filter") {
    fullState.filter = event.target.value;
    renderFullMatrix();
  }
  if (event.target.id === "full-history") {
    fullState.active = Number(event.target.value);
    fullState.viewVersion++;
    fullState.query = "";
    fullState.filter = "";
    renderFull();
  }
});
$("full-report").addEventListener("click", async (event) => {
  const button = event.target.closest("button");
  if (!button) return;
  if (button.hasAttribute("data-full-return")) {
    fullState.viewVersion++;
    return renderFull();
  }
  if (button.hasAttribute("data-full-job")) {
    const id = button.getAttribute("data-full-job");
    const version = ++fullState.viewVersion;
    try {
      retainFullJob(await api(`/api/full-audits/${encodeURIComponent(id)}`), id);
      if (version !== fullState.viewVersion) {
        fullControls();
        return;
      }
      fullState.active = fullState.rounds.findIndex((entry) => !entry.imported && entry.id === id);
      renderFull();
      fullControls();
    } catch (error) {
      if (version === fullState.viewVersion) setFullError(`关联任务未读取：${error.message} 旧轮记录保留。`);
    }
    return;
  }
  const round = fullState.rounds[fullState.active];
  if (!round) return;
  if (button.hasAttribute("data-full-poll")) {
    if (fullState.polling) {
      fullState.polling = false;
      fullState.pollVersion++;
      clearTimeout(fullState.timer);
      renderFull();
      fullControls();
    } else pollFull(round);
    return;
  }
});
async function startFull() {
  const results = await Promise.allSettled([
    api("/api/full-audit-config"),
    api("/api/sop-library"),
    api("/api/full-demo-catalog"),
    api("/api/full-audits/active"),
  ]);
  fullState.config = results[0].status === "fulfilled"
    ? results[0].value : { available: false, model_configured: false };
  if (results[1].status === "fulfilled") fullState.library = results[1].value;
  if (results[2].status === "fulfilled" && Array.isArray(results[2].value?.demos))
    fullState.demos = results[2].value.demos.filter((demo) => demo && typeof demo.id === "string" && /^[A-Za-z0-9_.-]+$/.test(demo.id) && /^[a-f0-9]{64}$/.test(demo.input_sha256) && Array.isArray(demo.license_files) && demo.license_files.length);
  renderDemoChoices();
  let restored;
  if (results[3].status === "fulfilled" && results[3].value?.job) {
    try {
      const metadata = results[3].value.job;
      if (!activeFullStatuses.includes(metadata.status)) throw new Error("活动任务状态无效。");
      restored = retainFullJob(metadata);
      if (fullState.rounds.length === 1) {
        fullState.active = 0;
        fullState.viewVersion++;
      }
      renderFull();
    } catch (error) { setFullError(`活动任务未恢复：${error.message} 未自动提交材料。`); }
  }
  fullControls();
  if (restored) await pollFull(restored);
}
startFull();

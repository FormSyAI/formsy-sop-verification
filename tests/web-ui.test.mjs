// Pure DOM/state checks. No browser, network, model, or extra runtime dependencies.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import vm from "node:vm";
const source = await readFile(new URL("../web/app.js", import.meta.url), "utf8");
const html = await readFile(new URL("../web/index.html", import.meta.url), "utf8");
class Element {
  constructor(tag = "div", registry) {
    this.tagName = tag;
    this.registry = registry;
    this.children = [];
    this.listeners = {};
    this.dataset = {};
    this.hidden = false;
    this.disabled = false;
    this.value = "";
    this.checked = false;
    this.className = "";
    this.attributes = {};
    this.options = new Map();
    this.classList = { toggle() {} };
  }
  set textContent(text) {
    this.text = String(text);
    this.children = [];
    this.html = "";
  }
  get textContent() {
    return (this.text ?? "") + this.children.map((child) => child.textContent).join("");
  }
  get innerText() {
    return this.textContent;
  }
  set innerHTML(value) {
    this.html = value;
    this.text = "";
    this.children = [];
    for (const [, id] of value.matchAll(/id="([^"]+)"/g))
      this.registry.set(id, new Element("div", this.registry));
  }
  get innerHTML() {
    return this.html ?? "";
  }
  append(...children) {
    this.children.push(
      ...children.map((child) => (typeof child === "string" ? { textContent: child } : child)),
    );
  }
  replaceChildren(...children) {
    this.children = [];
    this.text = "";
    this.append(...children);
  }
  addEventListener(name, handler) {
    (this.listeners[name] ??= []).push(handler);
  }
  setAttribute(name, value) {
    this.attributes[name] = value;
  }
  removeAttribute(name) {
    delete this.attributes[name];
  }
  hasAttribute(name) {
    return Object.hasOwn(this.attributes, name);
  }
  getAttribute(name) {
    return this.attributes[name] ?? null;
  }
  querySelector(selector) {
    if (!this.options.has(selector))
      this.options.set(selector, new Element("option", this.registry));
    return this.options.get(selector);
  }
  scrollIntoView() {}
  showModal() {
    this.open = true;
  }
  close() {
    this.open = false;
  }
}
function setup(hash = "", initialResponse) {
  const registry = new Map();
  for (const [, id] of html.matchAll(/id="([^"]+)"/g))
    registry.set(id, new Element("div", registry));
  registry.get("full-mode").value = "model";
  registry.get("full-sop-source").value = "default";
  registry.get("full-view").hidden = false;
  const nav = ["full"].map((view) => {
    const el = new Element("button", registry);
    el.dataset.view = view;
    return el;
  });
  const calls = [];
  let response = initialResponse;
  const context = vm.createContext({
    console,
    TextEncoder,
    structuredClone,
    Date,
    Map,
    Set,
    URL,
    JSON,
    Number,
    Object,
    Array,
    String,
    RegExp,
    Error,
    location: { hash },
    history: { replaceState() {} },
    setTimeout() {
      return 1;
    },
    clearTimeout() {},
    requestAnimationFrame() {},
    window: { addEventListener() {} },
    document: {
      getElementById: (id) => registry.get(id) ?? null,
      querySelectorAll: () => nav,
      createElement: (tag) => new Element(tag, registry),
      createTextNode: (text) => ({ textContent: String(text) }),
    },
    fetch(path, options) {
      calls.push({ path, options });
      return response ? Promise.resolve(response(path, options)) : new Promise(() => {});
    },
  });
  const ready = vm.runInContext(source, context);
  return {
    context,
    registry,
    calls,
    ready,
    run: (code) => vm.runInContext(code, context),
    setResponse: (handler) => (response = handler),
  };
}
const rules = [
  {
    id: "CUSTOM01",
    title: "零值保留",
    version: "1.0",
    criterion: "输入为0保留0；缺失才默认。",
    required_evidence: ["源码"],
  },
];
const input = {
  title: "合成 DOM 测试",
  trace: { messages: [{ role: "user", content: "保留0" }] },
  commits: [{ sha: "a".repeat(40), diff: "diff" }],
  materials: [],
};
const ref = { evidence_id: "E1", start_line: 1, end_line: 1, quote: "保留0" };
const summary = {
  source: {
    kind: "uploaded_rules",
    input_sha256: "upload-hash",
    catalog_sha256: "catalog-hash",
    contract_version: "1.0",
  },
  rule_count: 1,
  condition_count: 1,
  atomic_item_count: 1,
  documents: [{ id: "D1", title: "自定义规则", version: "1.0", sha256: "doc-hash" }],
};
const report = {
  schema_version: "2.1",
  title: "合成完整报告",
  formal_closed: false,
  rule_source: summary.source,
  tasks: [
    {
      id: "T1",
      title: "任务标题 marker",
      goal: "任务目标 marker",
      requirement_refs: [ref],
      inferred_requirements: ["推断要求 marker"],
      commit_ids: ["a".repeat(40)],
      target_commit_ids: ["a".repeat(40)],
      acceptance_points: [
        { id: "A1", kind: "behavior", requirement: "验收内容 marker", requirement_refs: [ref] },
      ],
    },
  ],
  acceptance_checks: [
    {
      task_id: "T1",
      acceptance_id: "A1",
      result: "满足",
      overall_result: "未核查",
      test_design_result: "满足",
      execution_result: "未核查",
      reason: "验收依据 marker",
      change_refs: [ref],
      assertion_refs: [ref],
      run_refs: [],
      change_ids: ["H1"],
      improvement: "验收改进 marker",
      verification: "复检 marker",
    },
  ],
  change_coverage: [
    {
      id: "H1",
      path: "zero.py",
      commit_id: "a".repeat(40),
      evidence_id: "E1",
      start_line: 1,
      end_line: 1,
      status: "mapped",
      acceptance_ids: ["A1"],
      relations: [],
    },
  ],
  unmapped_changes: [],
  rules,
  checks: [
    {
      id: "B1",
      task_id: "T1",
      rule_id: "CUSTOM01",
      local_result: "满足",
      automated_result: "未核查",
      sop_result: "未核查",
      reason: "基础依据 marker",
      evidence_refs: [ref],
      gate_details: [{ id: "G1", label: "需运行", met: false }],
      missing_materials: ["运行 marker"],
      improvement: "基础改进 marker",
    },
  ],
  findings: [
    {
      id: "F1",
      task_id: "T1",
      category: "evidence_gap",
      summary: "具体问题 marker",
      issue_key: "gap",
      evidence_refs: [ref],
      impact: "影响 marker",
      improvement: "问题改进 marker",
      verification: "验证 marker",
    },
  ],
  evidence: [
    {
      id: "E1",
      kind: "user_requirement",
      name: "用户要求",
      content: "保留0\r\nsecond\u2028third\n",
      sha256: "analysis",
      display_sha256: "display",
      original_sha256: "original",
      display_redacted: true,
    },
  ],
  sop_rules: [
    {
      id: "CUSTOM01",
      title: "自定义",
      conditions: [{ id: "C1", contract: { items: [{ id: "I1" }] } }],
    },
  ],
  sop_documents: [
    { id: "D1", title: "自定义规则", version: "1.0", content: "规则正文\n", sha256: "doc-hash" },
  ],
  sop_selection: {
    mode: "uploaded",
    task_selections: [
      {
        task_id: "T1",
        rules: [
          {
            rule_id: "CUSTOM01",
            selection: "selected",
            reason: "选择依据 marker",
            evidence_refs: [ref],
            source_ref: { document_id: "D1", start_line: 1, end_line: 1, quote: "规则正文" },
          },
        ],
      },
    ],
  },
  sop_condition_checks: [
    {
      task_id: "T1",
      rule_id: "CUSTOM01",
      condition_id: "C1",
      text: "条件 marker",
      result: "未核查",
      reason: "条件依据 marker",
      evidence_refs: [ref],
      atomic_checks: [
        {
          id: "I1",
          text: "原子 marker",
          result: "未核查",
          reason: "原子依据",
          evidence_refs: [ref],
        },
      ],
      source_ref: { document_id: "D1", start_line: 1, end_line: 1, quote: "规则正文" },
    },
  ],
  sop_coverage: {
    conditions: 1,
    results: { 未核查: 1 },
    matrix_complete: true,
    analysis_complete: false,
    current_scope: { profile: "code_fix", conditions: 1, deferred_conditions: 0 },
    failures: [],
    unsupported_sections: [],
  },
  automatic_review: { analysis_complete: true, outcome: "未核查" },
  original_sop: { status: "未确认", formal_closed: false },
  model_snapshot: { execution_mode: "offline_fake", model_invoked: false, api_request_count: 0 },
  integration: { known_limitations: [] },
  summary: {},
  warnings: [],
};
const json = (value) => JSON.stringify(value);
function configure(ui) {
  ui.run(
    `fullState.config=${json({ available: true, default_available: false, model_configured: true, max_total_calls: 80, max_sop_calls: 64 })};fullState.library={default_available:false,max_upload_rules:8};fullState.request=${json(input)};fullControls();`,
  );
}
function showReport(ui, value = report) {
  ui.run(
    `fullState.rounds=[{id:'import',status:'completed',imported:true,report:${json(value)}}];fullState.active=0;assertFullReport(fullState.rounds[0].report);renderFull();`,
  );
}
test("full deep links and seven native report blocks render their own data", () => {
  const ui = setup("#tasks-section");
  assert.doesNotMatch(html, /快速核查|quick-view|data-view="quick"/);
  assert.equal(ui.registry.get("full-view").hidden, false);
  showReport(ui);
  for (const id of [
    "overview",
    "tasks",
    "acceptance",
    "sop-coverage",
    "checks",
    "findings",
    "evidence",
  ])
    assert.ok(ui.registry.get(`${id}-section`), id);
  assert.match(ui.registry.get("tasks-content").textContent, /任务目标 marker/);
  assert.match(ui.registry.get("acceptance-content").textContent, /验收依据 marker/);
  assert.match(ui.registry.get("checks-content").textContent, /基础依据 marker/);
  assert.match(ui.registry.get("findings-content").textContent, /具体问题 marker/);
  assert.match(ui.registry.get("sop-selection-content").textContent, /选择依据 marker/);
  assert.match(ui.registry.get("sop-condition-content").textContent, /条件 marker/);
  assert.match(ui.registry.get("evidence-content").textContent, /用户要求/);
  assert.equal(ui.run("reportRuleSummary(currentFullReport()).rule_count"), 1);
  assert.equal(ui.run("reportRuleSummary(currentFullReport()).condition_count"), 1);
  assert.equal(ui.run("reportRuleSummary(currentFullReport()).atomic_item_count"), 1);
  assert.doesNotMatch(ui.registry.get("full-report").innerHTML, /33 条|144 个|184 个/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("DeepSeek is the default and local fallback appears only when unavailable", () => {
  const ui = setup();
  configure(ui);
  const mode = ui.registry.get("full-mode");
  assert.equal(mode.value, "model");
  assert.equal(mode.querySelector("[value=offline]").hidden, true);
  assert.match(ui.registry.get("full-model-status").textContent, /DeepSeek API · 已配置/);
  assert.match(ui.registry.get("full-verify").textContent, /使用 DeepSeek/);
  assert.match(ui.registry.get("full-consent-text").textContent, /发送至 DeepSeek，使用模型 deepseek-flash/);
  ui.run("fullState.config.model_configured=false;fullControls()");
  assert.equal(mode.value, "offline");
  assert.equal(mode.querySelector("[value=offline]").hidden, false);
  assert.match(ui.registry.get("full-mode-help").textContent, /不生成语义结论/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("TokenHub configuration discloses the actual provider, model, destination and cost", () => {
  const ui = setup();
  configure(ui);
  const config = { provider: "Tencent TokenHub", model: "configured-model",
    provider_endpoint: "https://tokenhub.example.test/v1/chat/completions" };
  ui.run(`Object.assign(fullState.config,${json(config)});fullControls()`);
  for (const id of ["full-model-status", "full-verify", "full-consent-text", "full-mode-help", "full-config-label"]) {
    const text = ui.registry.get(id).textContent;
    assert.match(text, /Tencent TokenHub/);
    assert.match(text, /configured-model/);
    assert.doesNotMatch(text, /发送至 DeepSeek|使用 DeepSeek/);
  }
  assert.match(ui.registry.get("full-mode").querySelector("[value=model]").textContent, /Tencent TokenHub/);
  assert.match(ui.registry.get("full-mode-help").textContent, /可能产生费用/);
  assert.ok(ui.registry.get("full-config-label").textContent.includes(config.provider_endpoint));
  assert.equal(ui.registry.get("full-consent").checked, false);
  ui.run("fullState.providerBlocked=true;fullControls()");
  assert.match(ui.registry.get("full-model-status").textContent, /Tencent TokenHub API · 本轮请求未完成/);
  assert.match(ui.registry.get("full-mode-help").textContent, /Tencent TokenHub 当前不可用/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("provider configuration stays text-only and its dialog escapes server values", async () => {
  const ui = setup();
  configure(ui);
  const config = { available: true, model_configured: true,
    provider: 'Tencent TokenHub <img src=x onerror="alert(1)">', model: '<script>alert(2)</script>',
    provider_endpoint: 'https://tokenhub.example.test/v1/chat/completions?label=<svg onload="alert(3)">' };
  ui.setResponse(() => ({ ok: true, json: async () => config }));
  await ui.registry.get("full-model-status").listeners.click[0]();
  assert.equal(ui.registry.get("source-title").textContent, `${config.provider} API`);
  const dialog = ui.registry.get("source-body").innerHTML;
  assert.match(dialog, /Tencent TokenHub &lt;img/);
  assert.match(dialog, /&lt;script&gt;/);
  assert.match(dialog, /label=&lt;svg/);
  assert.doesNotMatch(dialog, /<img|<script|<svg/);
  assert.ok(ui.registry.get("full-consent-text").textContent.includes(config.provider));
  assert.equal(ui.registry.get("full-consent-text").innerHTML, "");
  ui.setResponse(() => ({ ok: false, status: 503, json: async () => ({ error: { message: "unavailable" } }) }));
  await ui.registry.get("full-model-status").listeners.click[0]();
  assert.ok(ui.registry.get("full-model-status").textContent.includes(config.provider));
  assert.match(ui.registry.get("full-model-status").textContent, /不可用/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("report overview uses the stored route independently of current configuration and escapes its endpoint", () => {
  const ui = setup();
  configure(ui);
  for (const provider of [undefined, "Tencent TokenHub"]) {
    const value = structuredClone(report);
    value.model_snapshot = { model_invoked: true, model: 'stored-model <script>unsafe</script>', api_request_count: 1,
      ...(provider ? { provider } : {}),
      provider_endpoint: 'https://stored.example.test/v1/chat/completions?label=<img src=x>' };
    showReport(ui, value);
    const output = ui.registry.get("full-report").innerHTML;
    assert.ok(output.includes(`报告记录 ${provider ?? "DeepSeek"} / stored-model &lt;script&gt;`));
    assert.match(output, /报告记录的模型配置/);
    assert.match(output, /https:\/\/stored.example.test\/v1\/chat\/completions\?label=&lt;img/);
    assert.doesNotMatch(output, /<script>|<img src=x>/);
    assert.deepEqual(JSON.parse(ui.run("JSON.stringify(currentFullReport().model_snapshot)")), value.model_snapshot);
  }
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("r12 interpretation is distinct from machine contract and never replaces a historical source", () => {
  const ui = setup();
  configure(ui);
  const latest = { ...summary, source: { kind: "formsy_sop", release_id: "traceaudit-r12",
    interpretation_revision: "1.9.1", contract_version: "1.9", git_commit: "new-commit" } };
  ui.run(`fullState.library=${json(latest)}`);
  const value = structuredClone(report);
  value.rule_source = { kind: "formsy_sop", release_id: "traceaudit-r11", contract_version: "1.9", git_commit: "old-commit" };
  showReport(ui, value);
  const output = ui.registry.get("full-report").innerHTML;
  assert.match(output, /规则发布 traceaudit-r11/);
  assert.match(output, /机器契约 1\.9/);
  assert.doesNotMatch(output, /traceaudit-r12|1\.9\.1|new-commit/);
  assert.deepEqual(JSON.parse(ui.run("JSON.stringify(currentFullReport().rule_source)")), value.rule_source);
  const metadata = ui.run(`ruleSummaryHtml(${json(latest)})`);
  assert.match(metadata, /规则发布 traceaudit-r12 · 判定口径 1\.9\.1/);
  assert.match(metadata, /机器契约 1\.9/);
  latest.source.interpretation_revision = "<img src=x>";
  const escaped = ui.run(`ruleSummaryHtml(${json(latest)})`);
  assert.match(escaped, /&lt;img src=x&gt;/);
  assert.doesNotMatch(escaped, /<img src=x>/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("provider failure preserves the round and reveals fallback without a second submission", async () => {
  const ui = setup();
  configure(ui);
  ui.run(`fullState.uploaded={id:'upload',rules:${json(rules)},summary:${json(summary)}}`);
  ui.registry.get("full-sop-source").value = "uploaded";
  ui.registry.get("full-consent").checked = true;
  ui.setResponse((path) => ({
    ok: true,
    json: async () => path === "/api/full-audits"
      ? { id: "quota-job", status: "queued" }
      : { id: "quota-job", status: "failed", error: { code: "full_audit_failed", provider_code: "provider_quota_exhausted" } },
  }));
  await ui.registry.get("full-verify").listeners.click[0]();
  assert.equal(ui.run("fullState.rounds[0].status"), "failed");
  assert.equal(ui.registry.get("full-mode").value, "offline");
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 1);
});
test("failed job shows safe classification and recording failure without another submission", () => {
  const ui = setup();
  configure(ui);
  ui.run(`fullState.rounds=[{id:'failed-job',status:'failed',progress:'model:analysis.call-001',error:${json({
    code: "full_audit_failed", message: "完整审计未完成", error_category: "internal_unknown",
    failure_stage: "model:analysis.call-001", exception_type: "KeyError", phase: "engine", transport_retry: false,
    recording_error: { error_category: "storage", failure_stage: "job_failure_write", exception_type: "OSError" },
  })}}];fullState.active=0;renderFull()`);
  const output = ui.registry.get("full-report").innerHTML;
  assert.match(output, /错误代码：full_audit_failed/);
  assert.match(output, /错误类别：程序内部错误，原因尚未确定/);
  assert.match(output, /失败阶段：model:analysis.call-001/);
  assert.match(output, /异常类型：KeyError/);
  assert.match(output, /失败记录保存异常；原始故障仍保留/);
  assert.match(output, /错误类别：记录保存失败/);
  assert.match(output, /失败阶段：job_failure_write/);
  assert.match(output, /不自动重试/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("safe diagnostic rendering ignores arbitrary message fields and escapes displayed values", () => {
  const ui = setup();
  const output = ui.run(`failureDetailsHtml(${json({
    error_category: "timeout", failure_stage: "<stage>", exception_type: "TimeoutError",
    provider_code: "provider_network_or_timeout", message: "private exception body", traceback: "private stack",
    http_status: 500, phase: "read", response_saved: true,
  })})`);
  assert.match(output, /错误类别：模型请求超时/);
  assert.match(output, /失败阶段：&lt;stage&gt;/);
  assert.match(output, /模型服务代码：provider_network_or_timeout/);
  assert.match(output, /HTTP 状态：500/);
  assert.match(output, /请求阶段：read/);
  assert.match(output, /原始响应已保存：是/);
  assert.doesNotMatch(output, /private|<stage>/);
  const invalid = ui.run(`failureDetailsHtml(${json({http_status: "<secret>", phase: "private phase",
    response_saved: "private saved"})})`);
  assert.equal(invalid, "");
  for (const phase of ["prepare", "store", "engine", "job", "report"]) {
    assert.match(ui.run(`failureDetailsHtml(${json({phase})})`), new RegExp(`请求阶段：${phase}`));
  }
});
test("completed reports show recovered call diagnostics without changing the final job state", () => {
  const ui = setup();
  const value = structuredClone(report);
  value.model_snapshot.failure_diagnostics = [{
    error_category: "read_incomplete", failure_stage: "sop-T1-TC14.C01.call-023",
    exception_type: "IncompleteRead", phase: "read", response_partial: true,
    message: "private transport text", traceback: "private stack",
  }];
  value.sop_coverage.failures = [{
    condition_id: "SEC03.C05", atomic_item_id: "SEC03.C05.I01",
    stage: "sop-failure-review-exclusions-1-retry", kind: "exclusion_review_failure",
    reason: "适用性观察中的验收点 ID 无效",
  }];
  showReport(ui, value);
  const output = ui.registry.get("full-report").innerHTML;
  assert.match(output, /调用异常记录（可能包含已恢复尝试）/);
  assert.match(output, /错误类别：模型响应读取不完整/);
  assert.match(output, /失败阶段：sop-T1-TC14.C01.call-023/);
  assert.doesNotMatch(output, /private transport|private stack/);
  assert.equal(ui.run("fullState.rounds[0].status"), "completed");
  assert.match(ui.registry.get("sop-coverage-summary").textContent, /部分条件分析失败/);
  const failures = ui.registry.get("sop-coverage-summary").textContent;
  assert.match(failures, /条件：SEC03.C05/);
  assert.match(failures, /子项：SEC03.C05.I01/);
  assert.match(failures, /失败阶段：sop-failure-review-exclusions-1-retry/);
  assert.match(failures, /类别：exclusion_review_failure/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});
test("rule upload freezes offline and permits custom when default source is unavailable", async () => {
  const ui = setup();
  configure(ui);
  let posted;
  ui.setResponse((path, options) => {
    assert.equal(path, "/api/sop-uploads");
    posted = JSON.parse(options.body);
    return {
      ok: true,
      json: async () => ({ id: "upload-1", rules, summary, model_invoked: false }),
    };
  });
  await ui.run(`freezeRules(${json(rules)})`);
  assert.deepEqual(posted, { rules });
  assert.equal(ui.registry.get("full-sop-source").value, "uploaded");
  assert.equal(ui.registry.get("full-mode").querySelector("[value=model]").disabled, false);
  assert.match(ui.registry.get("full-sop-summary").innerHTML, /upload-hash/);
  ui.run("fullState.request.sop_selection={mode:'auto',document_ids:['old-pinned-document']}");
  const request = JSON.parse(ui.run("JSON.stringify(buildFullRequest())"));
  assert.deepEqual(request.rules, rules);
  assert.equal(Object.hasOwn(request, "sop_selection"), false);
  assert.equal(ui.run("fullState.request.sop_selection.document_ids[0]"), "old-pinned-document");
  assert.equal(ui.calls.filter((call) => call.path === "/api/full-audits").length, 0);
  ui.registry.get("full-sop-source").value = "default";
  assert.throws(() => ui.run("buildFullRequest()"), /默认 FormSy SOP 不可用/);
});
test("rule count limits and failed uploads preserve prior frozen rules and reports", async () => {
  const ui = setup();
  configure(ui);
  showReport(ui);
  ui.run(`fullState.uploaded={id:'old',rules:${json(rules)},summary:${json(summary)}}`);
  ui.registry.get("full-sop-source").value = "uploaded";
  await assert.rejects(ui.run("freezeRules(Array.from({length:9},()=>({})))"), /1–8/);
  ui.setResponse(() => ({
    ok: false,
    status: 422,
    json: async () => ({ error: { code: "invalid_sop_upload", message: "invalid" } }),
  }));
  await assert.rejects(ui.run(`freezeRules(${json(rules)})`), /invalid/);
  assert.equal(ui.run("fullState.uploaded.id"), "old");
  assert.equal(ui.run("currentFullReport().title"), report.title);
  assert.equal(ui.run("fullState.uploading"), false);
});
test("source and rule citations read the active report snapshot, with Python line coordinates", () => {
  const ui = setup();
  showReport(ui);
  ui.run(
    `fullState.request=${json(input)};fullState.uploaded={rules:[{id:'NEW'}]};openEvidence('E1',${json(ref)});`,
  );
  assert.match(ui.registry.get("source-body").innerHTML, /保留0/);
  assert.match(ui.registry.get("source-body").innerHTML, /已定位/);
  assert.match(ui.registry.get("source-body").innerHTML, /脱敏展示/);
  const segments = JSON.parse(
    ui.run(`JSON.stringify(pythonSegments(${json(report.evidence[0].content)}))`),
  );
  assert.deepEqual(segments, ["保留0\r\n", "second\u2028", "third\n"]);
  ui.run(`openEvidence('D1',{document_id:'D1',start_line:1,end_line:1,quote:'规则正文'},true)`);
  assert.match(ui.registry.get("source-body").innerHTML, /规则正文/);
  const refs = JSON.parse(
    ui.run(`JSON.stringify(changeReference(${json(report.change_coverage[0])}))`),
  );
  assert.equal(refs.quote, "保留0\r\n");
});
test("filtering affects conditions, keeps task/check/finding data and original references", () => {
  const ui = setup();
  showReport(ui);
  ui.run('fullState.filter="satisfied";renderFullMatrix()');
  assert.equal(ui.registry.get("full-filter-count").textContent, "0 / 1 条条件记录");
  assert.match(ui.registry.get("tasks-content").textContent, /任务目标 marker/);
  assert.match(ui.registry.get("checks-content").textContent, /基础依据 marker/);
  assert.match(ui.registry.get("findings-content").textContent, /具体问题 marker/);
  ui.run('fullState.filter="";renderFullMatrix()');
  assert.match(ui.registry.get("sop-condition-content").textContent, /条件 marker/);
});
test("model submission requires explicit mode and consent and includes the selected frozen rules", async () => {
  const ui = setup();
  configure(ui);
  ui.run(`fullState.uploaded={id:'upload',rules:${json(rules)},summary:${json(summary)}}`);
  ui.registry.get("full-sop-source").value = "uploaded";
  ui.registry.get("full-mode").value = "model";
  const click = ui.registry.get("full-verify").listeners.click[0];
  await click();
  assert.equal(ui.calls.filter((call) => call.path === "/api/full-audits").length, 0);
  ui.registry.get("full-consent").checked = true;
  let payload;
  ui.setResponse((path, options) => {
    if (path === "/api/full-audits") {
      payload = JSON.parse(options.body);
      return { ok: true, json: async () => ({ id: "job-1", status: "queued" }) };
    }
    assert.equal(path, "/api/full-audits/job-1");
    return { ok: true, json: async () => ({ id: "job-1", status: "completed", report }) };
  });
  await click();
  assert.equal(payload.mode, "model");
  assert.deepEqual(payload.request.rules, rules);
  assert.equal(Object.hasOwn(payload.request, "sop_selection"), false);
  assert.equal(ui.run("fullState.rounds[0].status"), "completed");
});
test("invalid condition imports are rejected without changing selected history", () => {
  const ui = setup();
  showReport(ui);
  const malformed = structuredClone(report);
  malformed.sop_condition_checks[0].evidence_refs = [null];
  assert.throws(() => ui.run(`assertFullReport(${json(malformed)})`), /schema_version/);
  assert.equal(ui.run("currentFullReport().title"), report.title);
});

test("malformed native task blocks cannot corrupt imported history", () => {
  const ui = setup();
  showReport(ui);
  for (const block of [
    { tasks: [null] },
    { tasks: [{ ...report.tasks[0], acceptance_points: [null] }] },
    { checks: [null] },
    { sop_selection: { task_selections: [null] } },
  ]) {
    assert.throws(
      () => ui.run(`assertFullReport(${json({ ...report, ...block })})`),
      /schema_version/,
    );
  }
  assert.equal(ui.run("currentFullReport().title"), report.title);
});

test("local failure review keeps final reason separate from unconfirmed model candidate", () => {
  const ui = setup(), value = structuredClone(report);
  Object.assign(value.checks[0], {
    reason: "最终程序理由 marker",
    local_result: "不满足",
    local_failure_candidate: { result: "不满足", reason: "原模型建议当义务 marker", evidence_refs: [ref], counter_refs: [ref] },
    local_failure_review: { status: "completed", confirmed: false, effective_result: "未核查",
      relation: "evidence_insufficient", scope_consistency: "uncertain", reason: "独立反例证据不足 marker" },
  });
  showReport(ui, value);
  const text = ui.registry.get("checks-content").textContent;
  assert.match(text, /判断依据最终程序理由 marker/);
  assert.match(text, /复核状态复核已完成/);
  assert.match(text, /反例关系反例证据不足/);
  assert.match(text, /范围一致性范围待确认/);
  assert.match(text, /尚无复核支持的同范围反例/);
  assert.match(text, /本次有效判断：未核查/);
  assert.match(text, /复核说明独立反例证据不足 marker/);
  assert.match(text, /原模型失败候选理由原模型建议当义务 marker/);
  assert.match(text, /原候选支持证据/);
  assert.match(text, /原候选反向证据/);
  assert.doesNotMatch(text, /复核结论复核支持同范围反例/);
});
test("only a completed consistent direct same-scope review displays confirmed failure", () => {
  const rows = [
    [{ status: "completed", confirmed: true, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, true],
    [{ status: "pending", confirmed: true, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
    [{ status: "failed", confirmed: true, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
    [{ status: "unknown", confirmed: true, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
    [{ status: "completed", confirmed: false, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
    [{ status: "completed", confirmed: true, effective_result: "未核查", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
    [{ status: "completed", confirmed: true, effective_result: "不满足", relation: "different_dimension", scope_consistency: "same_scope" }, false],
    [{ status: "completed", confirmed: true, effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "different_scope" }, false],
    [{ status: "completed", confirmed: "true", effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" }, false],
  ];
  for (const [review, confirmed] of rows) {
    const ui = setup(), value = structuredClone(report);
    value.checks[0].local_failure_review = review;
    showReport(ui, value);
    const text = ui.registry.get("checks-content").textContent;
    assert.equal(text.includes("复核结论复核支持同范围反例"), confirmed);
    assert.equal(text.includes("本次有效判断：不满足"), confirmed);
    assert.equal(text.includes("本次有效判断：未核查"), !confirmed);
  }
});
test("local failure review prose uses safe text and original citations keep active snapshot", () => {
  const ui = setup(), value = structuredClone(report), payload = '<img src=x onerror="marker">';
  value.checks[0].local_failure_review = { status: "completed", confirmed: false,
    effective_result: "未核查", relation: "evidence_insufficient", reason: payload };
  value.checks[0].local_failure_candidate = { reason: payload, counter_refs: [ref] };
  showReport(ui, value);
  const container = ui.registry.get("checks-content");
  assert.ok(container.textContent.includes(payload));
  const walk = (entry) => [entry, ...entry.children?.flatMap(walk) ?? []];
  const entries = walk(container);
  assert.ok(entries.every((entry) => !(entry.innerHTML || "").includes(payload)));
  const citation = entries.find((entry) => entry.tagName === "button" && entry.listeners.click);
  assert.ok(citation);
  citation.listeners.click[0]();
  assert.match(ui.registry.get("source-body").innerHTML, /保留0/);
  assert.match(ui.registry.get("source-body").innerHTML, /已定位/);
});
test("reports without review metadata and four-condition rendering keep their prior fields", () => {
  const ui = setup();
  showReport(ui);
  assert.doesNotMatch(ui.registry.get("checks-content").textContent, /模型反例复核|原模型失败候选理由/);
  assert.match(ui.registry.get("checks-content").textContent, /基础依据 marker/);
  const legacy = { ...structuredClone(report), schema_version: 1 };
  legacy.checks[0].result = "unverified";
  ui.run(`renderChecks(${json(legacy)})`);
  const before = ui.registry.get("checks-content").textContent;
  legacy.checks[0].local_failure_review = { status: "completed", confirmed: true };
  legacy.checks[0].local_failure_candidate = { reason: "must not enter four-condition view" };
  ui.run(`renderChecks(${json(legacy)})`);
  assert.equal(ui.registry.get("checks-content").textContent, before);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("completed check review does not authenticate original finding candidates or old schema records", () => {
  const ui = setup(), value = structuredClone(report);
  value.findings[0].category = "implementation_defect";
  showReport(ui, value);
  const before = ui.registry.get("findings-content").textContent;
  value.checks[0].local_failure_review = { status: "completed", confirmed: true,
    effective_result: "不满足", relation: "direct_counterexample", scope_consistency: "same_scope" };
  showReport(ui, value);
  assert.match(ui.registry.get("checks-content").textContent, /复核支持同范围反例/);
  const findings = ui.registry.get("findings-content").textContent;
  assert.equal(findings, before);
  assert.match(findings, /实现问题候选/);
  assert.match(findings, /原始问题记录仍是未独立复核的模型候选；某检查的反例复核不自动认证这些记录。/);
  assert.doesNotMatch(findings, /复核支持同范围反例/);
  const legacy = { ...structuredClone(value), schema_version: 1 };
  ui.run(`renderFindings(${json(legacy)})`);
  assert.equal(ui.registry.get("findings-content").textContent, findings);
  assert.match(ui.registry.get("findings-content").textContent, /具体问题 marker/);
});

const ok = (value) => ({ ok: true, json: async () => value });
function enableFullSubmit(ui) {
  configure(ui);
  ui.run(`fullState.uploaded={rules:${json(rules)},summary:${json(summary)}}`);
  ui.registry.get("full-sop-source").value = "uploaded";
  ui.registry.get("full-consent").checked = true;
  ui.run("fullControls()");
}
const descendants = (entry) => [entry, ...(entry.children?.flatMap(descendants) ?? [])];

test("current audit object uses input identities and safe original user text, without inferred IDs", () => {
  const ui = setup(), attack = '<img src=x onerror="object-marker">', value = structuredClone(input);
  value.title = attack;
  value.trace.trace_id = "declared-trace";
  value.trace.repository = "owner/input-repository";
  value.trace.messages.push({ role: "assistant", content: "not an original user request" },
    { role: "user", content: attack });
  value.materials.push({ kind: "source", name: "zero.py", content: "x = 0" });
  configure(ui);
  showReport(ui);
  ui.run(`fullState.rounds[0].report.tasks[0].target_commit_ids=['${"b".repeat(40)}'];fullState.request=${json(value)};fullState.fileName=${json(attack + ".json")};fullControls()`);
  const content = ui.registry.get("full-object-content"), text = content.textContent;
  for (const expected of [attack, "declared-trace", "owner/input-repository", "a".repeat(40), "3 条消息 · 1 份材料", "保留0", "原用户请求 · 2 条"])
    assert.ok(text.includes(expected), expected);
  assert.doesNotMatch(content.children.find((entry) => entry.tagName === "details").textContent, /not an original user request/);
  assert.ok(!text.includes("b".repeat(40)));
  assert.ok(descendants(content).every((entry) => !(entry.innerHTML || "").includes(attack)));
  assert.equal(descendants(content).find((entry) => entry.tagName === "details").open, undefined);
  ui.run("fullState.request=structuredClone(fullState.request);delete fullState.request.trace.trace_id;fullControls()");
  assert.match(content.textContent, /材料声明的 Trace ID未提供/);
  ui.run("fullState.request=structuredClone(fullState.request);fullState.request.trace.id=0;fullControls()");
  assert.match(content.textContent, /材料声明的 Trace ID0/);
  const long = "原用户请求".repeat(1600);
  ui.run(`fullState.request=structuredClone(fullState.request);fullState.request.trace.messages=[{role:'user',content:${json(long)}}];fullControls()`);
  assert.match(content.textContent, /仅预览前 6000 字符/);
  assert.equal(ui.run("fullState.request.trace.messages[0].content.length"), long.length);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("full Trace text and public example identity remain distinct and expanded details survive progress renders", () => {
  const ui = setup(), messages = [{ role: "user", content: "u".repeat(8000) },
    { role: "tool", content: '<img src=x onerror="trace-marker">' }, { role: "assistant", content: "complete last message" }];
  configure(ui);
  ui.run(`fullState.request={...fullState.request,trace:{messages:${json(messages)}}};fullState.demo={id:'public-example',input_sha256:'${"d".repeat(64)}'};fullControls()`);
  const container = ui.registry.get("full-object-content"), details = container.children.filter((entry) => entry.tagName === "details"), full = details[1];
  assert.match(container.textContent, /公开示例 IDpublic-example/);
  assert.match(container.textContent, new RegExp(`公开示例原文件 SHA256${"d".repeat(64)}`));
  assert.match(container.textContent, /材料声明的 Trace ID未提供/);
  assert.match(full.textContent, /完整 Trace 消息正文 · 3 条/);
  assert.deepEqual(full.children.filter((entry) => entry.tagName === "pre").map((entry) => entry.textContent), messages.map((message) => message.content));
  assert.ok(descendants(full).every((entry) => !(entry.innerHTML || "").includes("<img")));
  full.open = true;
  ui.run("fullState.rounds=[{id:'pending',status:'running',progress:'model:analysis-1.call-001'}];fullControls();renderAuditObject()");
  assert.equal(container.children.filter((entry) => entry.tagName === "details")[1], full);
  assert.equal(full.open, true);
  ui.run("fullState.fileName='different.json';fullControls()");
  assert.notEqual(container.children.filter((entry) => entry.tagName === "details")[1], full);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("a new explicit submission supersedes running work once and preserves old reports and stop metadata", async () => {
  const ui = setup();
  enableFullSubmit(ui);
  ui.run(`fullState.rounds=[{id:'old',status:'running',report:${json(report)}}];fullState.active=0;fullControls()`);
  assert.equal(ui.registry.get("full-verify").disabled, false);
  assert.match(ui.registry.get("full-verify").textContent, /停止旧任务/);
  let releasePost, oldStopped = false;
  ui.setResponse((path, options) => {
    if (options?.method === "POST") return new Promise((resolve) => { releasePost = () => resolve(ok({ id: "new", status: "queued", supersedes: ["old"] })); });
    if (path.endsWith("/new")) return ok({ id: "new", status: "queued", supersedes: ["old"], progress: "等待旧请求退出" });
    if (path.endsWith("/old")) return ok({ id: "old", status: oldStopped ? "cancelled" : "cancelling", superseded_by: "new",
      ...(oldStopped ? { cancelled_at: "2026-10-14T12:00:00Z", stop: { stage: "model.call-001" } } : {}) });
    throw new Error(path);
  });
  const submit = ui.registry.get("full-verify").listeners.click[0];
  const pending = submit();
  assert.equal(ui.registry.get("full-verify").disabled, true);
  assert.equal(ui.registry.get("full-consent").checked, false);
  await submit();
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 1);
  releasePost();
  await pending;
  assert.equal(ui.run("fullState.rounds[0].id"), "new");
  assert.equal(ui.run("fullState.rounds[1].status"), "cancelling");
  assert.equal(ui.run("fullState.rounds[1].report.title"), report.title);
  assert.match(ui.registry.get("full-report").innerHTML, /新审计已排队，等待旧请求退出后运行/);
  assert.match(ui.registry.get("full-report").innerHTML, /data-full-job="old"/);
  assert.equal(ui.registry.get("full-verify").disabled, true);
  oldStopped = true;
  await ui.run("pollFull(fullState.rounds[0])");
  assert.equal(ui.run("fullState.rounds[1].status"), "cancelled");
  ui.run("fullState.active=1;renderFull()");
  const stopped = ui.registry.get("full-report").innerHTML;
  assert.match(stopped, /此轮已停止，已有响应与停止记录保留/);
  assert.match(stopped, /停止阶段：model.call-001/);
  assert.match(stopped, /合成完整报告/);
  assert.match(stopped, /data-full-job="new"/);
  assert.equal(ui.run("fullState.providerBlocked"), false);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 1);
});

test("cancelled polling is terminal but stop-record storage failures remain failures", async () => {
  const ui = setup();
  configure(ui);
  ui.run("fullState.rounds=[{id:'stopping',status:'cancelling'}];fullState.active=0");
  ui.setResponse(() => ok({ id: "stopping", status: "cancelled", cancelled_at: "now", stop: { stage: "<unsafe>" } }));
  await ui.run("pollFull(fullState.rounds[0])");
  assert.equal(ui.run("fullState.polling"), false);
  assert.equal(ui.run("fullState.providerBlocked"), false);
  const stopped = ui.registry.get("full-report").innerHTML;
  assert.match(stopped, /审计已停止/);
  assert.match(stopped, /停止阶段：&lt;unsafe&gt;/);
  assert.doesNotMatch(stopped, /本轮失败已保留|作业失败|<unsafe>/);
  ui.run("fullState.rounds=[{id:'failed-stop',status:'cancelling'}];fullState.active=0");
  ui.setResponse(() => ok({ id: "failed-stop", status: "failed", progress: "审计已退出；停止记录保存失败",
    error: { code: "full_audit_storage_failed", error_category: "storage", failure_stage: "job_failure_write", phase: "store" } }));
  await ui.run("pollFull(fullState.rounds[0])");
  assert.match(ui.registry.get("full-report").innerHTML, /作业失败|full_audit_storage_failed/);
  assert.doesNotMatch(ui.registry.get("full-report").innerHTML, /此轮已停止/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("refresh restores only active task metadata and association links read records without submitting", async () => {
  const ui = setup("", (path) => {
    if (path === "/api/full-audit-config") return ok({ available: true, model_configured: true });
    if (path === "/api/sop-library") return ok(summary);
    if (path === "/api/full-demo-catalog") return ok({ demos: [] });
    if (path === "/api/full-audits/active") return ok({ job: { id: "new", status: "queued", input_sha256: "sha256:active", supersedes: ["old"] } });
    if (path.endsWith("/new")) return ok({ id: "new", status: "queued", input_sha256: "sha256:active", supersedes: ["old"] });
    if (path.endsWith("/old")) return ok({ id: "old", status: "cancelled", superseded_by: "new", stop: { stage: "job_waiting" } });
    throw new Error(path);
  });
  await ui.ready;
  assert.equal(ui.run("fullState.request"), null);
  assert.match(ui.registry.get("full-object-content").textContent, /尚未载入审计材料/);
  assert.match(ui.registry.get("full-active-status").textContent, /new.*等待审计.*sha256:active/);
  assert.equal(ui.registry.get("full-verify").disabled, true);
  const button = new Element("button", ui.registry);
  button.setAttribute("data-full-job", "old");
  await ui.registry.get("full-report").listeners.click[0]({ target: { closest: () => button } });
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "old");
  assert.match(ui.registry.get("full-report").innerHTML, /停止阶段：job_waiting/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

function delayedAssociation(ui, otherResponse) {
  let resolve, reject;
  ui.setResponse((path, options) => {
    if (path === "/api/full-audits/old") return new Promise((done, fail) => { resolve = done; reject = fail; });
    if (otherResponse) return otherResponse(path, options);
    throw new Error(path);
  });
  const button = new Element("button", ui.registry);
  button.setAttribute("data-full-job", "old");
  const pending = ui.registry.get("full-report").listeners.click[0]({ target: { closest: () => button } });
  return { pending, resolve: (value) => resolve(ok(value)), reject: (error) => reject(error) };
}

test("delayed association success preserves a later history choice and retains the old record", async () => {
  const ui = setup();
  configure(ui);
  ui.run("fullState.rounds=[{id:'current',status:'cancelled',supersedes:['old']},{id:'old',status:'cancelling'}];fullState.active=0;renderFull();fullControls()");
  const request = ui.run("JSON.stringify(fullState.request)"), pollVersion = ui.run("fullState.pollVersion");
  const lookup = delayedAssociation(ui);
  ui.registry.get("full-report").listeners.change[0]({ target: { id: "full-history", value: "0" } });
  lookup.resolve({ id: "old", status: "cancelled", stop: { stage: "old-stop" } });
  await lookup.pending;
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "current");
  assert.equal(ui.run("fullState.rounds.find((round)=>round.id==='old').stop.stage"), "old-stop");
  assert.equal(ui.run("JSON.stringify(fullState.request)"), request);
  assert.equal(ui.run("fullState.pollVersion"), pollVersion);
  assert.equal(ui.registry.get("full-active-status").hidden, true);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("delayed association success cannot replace the view selected by a new submission", async () => {
  const ui = setup();
  enableFullSubmit(ui);
  ui.run("fullState.rounds=[{id:'current',status:'running',supersedes:['old']},{id:'old',status:'cancelling'}];fullState.active=0;renderFull()");
  const request = ui.run("JSON.stringify(fullState.request)");
  const lookup = delayedAssociation(ui, (path, options) => {
    if (options?.method === "POST") return ok({ id: "new", status: "queued", supersedes: ["current"] });
    if (path.endsWith("/new")) return ok({ id: "new", status: "queued", supersedes: ["current"] });
    if (path.endsWith("/current")) return ok({ id: "current", status: "cancelled" });
    throw new Error(path);
  });
  await ui.registry.get("full-verify").listeners.click[0]();
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "new");
  const pollVersion = ui.run("fullState.pollVersion");
  lookup.resolve({ id: "old", status: "cancelled", stop: { stage: "old-stop" } });
  await lookup.pending;
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "new");
  assert.equal(ui.run("JSON.stringify(fullState.request)"), request);
  assert.equal(ui.run("fullState.pollVersion"), pollVersion);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 1);
});

test("delayed association failure cannot overwrite feedback after a later history choice", async () => {
  const ui = setup();
  configure(ui);
  ui.run("fullState.rounds=[{id:'current',status:'running',supersedes:['old']}];fullState.active=0;renderFull()");
  const lookup = delayedAssociation(ui);
  ui.registry.get("full-report").listeners.change[0]({ target: { id: "full-history", value: "0" } });
  ui.run("setFullError('最新操作提示')");
  lookup.reject(new Error("old lookup failed"));
  await lookup.pending;
  assert.equal(ui.registry.get("full-error").textContent, "最新操作提示");
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "current");
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("delayed association replies cannot replace feedback from a failed new submission", async () => {
  for (const outcome of ["success", "failure"]) {
    const ui = setup();
    enableFullSubmit(ui);
    ui.run("fullState.rounds=[{id:'current',status:'running',supersedes:['old']}];fullState.active=0;renderFull()");
    const lookup = delayedAssociation(ui, (_path, options) => {
      assert.equal(options?.method, "POST");
      return { ok: false, status: 503, json: async () => ({ error: {
        code: "full_audit_start_failed", message: "new submission rejected",
      } }) };
    });
    await ui.registry.get("full-verify").listeners.click[0]();
    const feedback = ui.registry.get("full-error").textContent;
    assert.match(feedback, /未确认审计作业已创建.*new submission rejected/);
    if (outcome === "success") lookup.resolve({ id: "old", status: "cancelled" });
    else lookup.reject(new Error("old lookup failed"));
    await lookup.pending;
    assert.equal(ui.registry.get("full-error").textContent, feedback);
    assert.equal(ui.run("fullState.rounds[fullState.active].id"), "current");
    assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 1);
  }
});

test("delayed association still opens the requested old task when no newer view was chosen", async () => {
  const ui = setup();
  configure(ui);
  ui.run("fullState.rounds=[{id:'current',status:'running',supersedes:['old']}];fullState.active=0;renderFull()");
  const lookup = delayedAssociation(ui);
  lookup.resolve({ id: "old", status: "cancelled", stop: { stage: "old-stop" } });
  await lookup.pending;
  assert.equal(ui.run("fullState.rounds[fullState.active].id"), "old");
  assert.match(ui.registry.get("full-report").innerHTML, /停止阶段：old-stop/);
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("public demo selection loads only catalogued material and clears consent without model submission", async () => {
  const ids = ["Melevir__cognitive_complexity-15", "akolar__ogn-lib-18", "DCC-Lab__RayTracing-273", "tobymao__sqlglot-2063"],
    demos = ids.map((id, index) => ({ id, title: index ? id : '<img src=x onerror="catalog-marker">',
      repository: "owner/repo", input_sha256: String(index).repeat(64), license_files: ["LICENSE"] }));
  const ui = setup();
  enableFullSubmit(ui);
  showReport(ui);
  ui.run(`fullState.demos=${json(demos)};renderDemoChoices();fullControls()`);
  const options = ui.registry.get("full-demo-select").children;
  assert.deepEqual(options.slice(1).map((option) => option.value), ids);
  assert.ok(options[1].textContent.includes(demos[0].title));
  assert.equal(options[1].innerHTML, "");
  assert.match(ui.registry.get("full-demo-status").textContent, /4 份公开完整 Trace/);
  const next = { ...structuredClone(input), title: "selected public input", trace: { messages: input.trace.messages } };
  ui.setResponse((path) => {
    assert.equal(path, `/api/full-demo/${ids[0]}`);
    return ok({ demo: demos[0], request: next });
  });
  await ui.registry.get("full-demo-select").listeners.change[0]({ target: { value: ids[0] } });
  assert.equal(ui.run("fullState.request.title"), next.title);
  assert.equal(ui.registry.get("full-consent").checked, false);
  assert.match(ui.registry.get("full-object-content").textContent, /材料声明的 Trace ID未提供/);
  assert.equal(ui.run("currentFullReport().title"), report.title);
  ui.registry.get("full-consent").checked = true;
  ui.setResponse(() => ok({ demo: { ...demos[1], input_sha256: "mismatch" }, request: input }));
  await ui.registry.get("full-demo-select").listeners.change[0]({ target: { value: ids[1] } });
  assert.equal(ui.run("fullState.request.title"), next.title);
  assert.equal(ui.registry.get("full-demo-select").value, ids[0]);
  assert.match(ui.registry.get("full-error").textContent, /示例身份或输入摘要与目录不一致/);
  ui.setResponse((path) => { assert.equal(path, "/api/full-audit-demo"); return ok(input); });
  await ui.registry.get("full-demo").listeners.click[0]();
  assert.equal(ui.run("fullState.demo"), null);
  assert.equal(ui.run("fullState.fileName"), "完整审计安全合成示例");
  assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("catalog failures and partial catalogues never invent unavailable public examples", async () => {
  const valid = { id: "akolar__ogn-lib-18", title: "one licensed input", input_sha256: "a".repeat(64), license_files: ["LICENSE"] };
  const ui = setup("", (path) => ok(path === "/api/full-demo-catalog" ? { demos: [valid,
    { ...valid, id: "unlicensed", license_files: [] }, { ...valid, id: "bad-hash", input_sha256: "wrong" },
    { ...valid, id: "../escape" }] } : path === "/api/full-audits/active" ? { job: null } : summary));
  await ui.ready;
  assert.equal(ui.registry.get("full-demo-select").children.length, 2);
  assert.match(ui.registry.get("full-demo-status").textContent, /1 份公开完整 Trace/);
  const unavailable = setup("", (path) => path === "/api/full-demo-catalog"
    ? { ok: false, status: 503, json: async () => ({ error: { message: "catalog unavailable" } }) }
    : ok(path === "/api/full-audits/active" ? { job: null } : summary));
  await unavailable.ready;
  assert.equal(unavailable.registry.get("full-demo-select").disabled, true);
  assert.match(unavailable.registry.get("full-demo-status").textContent, /仍可使用安全合成示例或导入 JSON/);
  assert.equal(unavailable.calls.filter((call) => call.options?.method === "POST").length, 0);
});

test("file and rule switches clear consent before asynchronous reads and cannot submit stale material", async () => {
  for (const id of ["full-request-file", "full-sop-file"]) {
    const ui = setup();
    enableFullSubmit(ui);
    showReport(ui);
    let release;
    const file = { name: "new.json", size: 5, text: () => new Promise((resolve) => { release = resolve; }) },
      target = { files: [file], value: "new.json" };
    const loading = ui.registry.get(id).listeners.change[0]({ target });
    assert.equal(ui.registry.get("full-consent").checked, false);
    assert.equal(ui.registry.get("full-verify").disabled, true);
    await ui.registry.get("full-verify").listeners.click[0]();
    assert.equal(ui.calls.filter((call) => call.options?.method === "POST").length, 0);
    release("invalid JSON");
    await loading;
    assert.equal(ui.run("fullState.request.title"), input.title);
    assert.equal(ui.run("currentFullReport().title"), report.title);
    assert.equal(ui.run("fullState.loading"), false);
    assert.equal(ui.registry.get("full-consent").checked, false);
  }
});

test("consent cannot carry across pending demo loads or rule freezes even if reticked while waiting", async () => {
  const ui = setup(), demo = { id: "akolar__ogn-lib-18", title: "next", input_sha256: "a".repeat(64), license_files: ["LICENSE"] };
  enableFullSubmit(ui);
  ui.run(`fullState.demos=[${json(demo)}]`);
  let release;
  ui.setResponse(() => new Promise((resolve) => { release = resolve; }));
  const loading = ui.run(`loadFullDemo('${demo.id}')`);
  assert.equal(ui.registry.get("full-consent").disabled, true);
  ui.registry.get("full-consent").checked = true;
  release(ok({ demo, request: { ...input, title: "new input requires fresh consent" } }));
  await loading;
  assert.equal(ui.registry.get("full-consent").disabled, false);
  assert.equal(ui.registry.get("full-consent").checked, false);
  assert.equal(ui.registry.get("full-verify").disabled, true);
  const freezing = ui.run(`freezeRules(${json(rules)})`);
  assert.equal(ui.registry.get("full-consent").disabled, true);
  ui.registry.get("full-consent").checked = true;
  release(ok({ id: "upload-after-wait", rules, summary, model_invoked: false }));
  await freezing;
  assert.equal(ui.registry.get("full-consent").checked, false);
  assert.equal(ui.registry.get("full-verify").disabled, true);
  assert.equal(ui.calls.filter((call) => call.path === "/api/full-audits").length, 0);
});

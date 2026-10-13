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
function setup(hash = "") {
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
  let response;
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
  vm.runInContext(source, context);
  return {
    context,
    registry,
    calls,
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
  ui.run("fullState.config.model_configured=false;fullControls()");
  assert.equal(mode.value, "offline");
  assert.equal(mode.querySelector("[value=offline]").hidden, false);
  assert.match(ui.registry.get("full-mode-help").textContent, /不生成语义结论/);
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
  })})`);
  assert.match(output, /错误类别：模型请求超时/);
  assert.match(output, /失败阶段：&lt;stage&gt;/);
  assert.match(output, /模型服务代码：provider_network_or_timeout/);
  assert.doesNotMatch(output, /private|<stage>/);
});
test("completed reports show recovered call diagnostics without changing the final job state", () => {
  const ui = setup();
  const value = structuredClone(report);
  value.model_snapshot.failure_diagnostics = [{
    error_category: "read_incomplete", failure_stage: "sop-T1-TC14.C01.call-023",
    exception_type: "IncompleteRead", phase: "read", response_partial: true,
    message: "private transport text", traceback: "private stack",
  }];
  showReport(ui, value);
  const output = ui.registry.get("full-report").innerHTML;
  assert.match(output, /调用异常记录（可能包含已恢复尝试）/);
  assert.match(output, /错误类别：模型响应读取不完整/);
  assert.match(output, /失败阶段：sop-T1-TC14.C01.call-023/);
  assert.doesNotMatch(output, /private transport|private stack/);
  assert.equal(ui.run("fullState.rounds[0].status"), "completed");
  assert.match(ui.registry.get("sop-coverage-summary").textContent, /部分条件分析失败/);
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
  const request = JSON.parse(ui.run("JSON.stringify(buildFullRequest())"));
  assert.deepEqual(request.rules, rules);
  assert.equal(request.sop_selection.mode, "uploaded");
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
  assert.equal(payload.request.sop_selection.mode, "uploaded");
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

// Offline bridge checks; no browser, network, model, or added dependencies.
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../web/embed.js", import.meta.url), "utf8");
const origin = "http://127.0.0.1:4175";

function setup({ search = `?embed=1&parent_origin=${encodeURIComponent(origin)}`, referrer = "", framed = true } = {}) {
  const messages = [];
  const classes = new Set();
  const styles = new Map();
  const listeners = new Map();
  const observed = [];
  let resize;
  let height = 600.2;
  const location = { search, hash: "" };
  const parent = { postMessage: (data, targetOrigin) => messages.push({ data: JSON.parse(JSON.stringify(data)), targetOrigin }) };
  const window = {
    parent,
    scrollY: 50,
    addEventListener: (type, handler) => listeners.set(type, handler),
  };
  if (!framed) window.parent = window;
  const body = { getBoundingClientRect: () => ({ height }) };
  const targets = new Map([["evidence-section", { getBoundingClientRect: () => ({ top: 300 }) }]]);
  const document = {
    referrer,
    body,
    documentElement: {
      classList: { add: (name) => classes.add(name) },
      style: { setProperty: (name, value) => styles.set(name, value) },
    },
    getElementById: (id) => targets.get(id) ?? null,
  };
  vm.runInNewContext(source, {
    URL,
    URLSearchParams,
    location,
    window,
    document,
    ResizeObserver: class {
      constructor(callback) { resize = callback; }
      observe(element) { observed.push(element); }
    },
  });
  return {
    messages, classes, styles, listeners, observed, body, location, parent,
    resize: () => resize?.(),
    setHeight: (value) => { height = value; },
    message: (data, event = {}) => listeners.get("message")?.({ source: parent, origin, data, ...event }),
    hashchange: (hash) => { location.hash = hash; listeners.get("hashchange")?.(); },
  };
}

test("standalone mode does not activate the bridge or post messages", () => {
  for (const search of ["", "?embed=0", "?embed=true"]) {
    const ui = setup({ search });
    ui.resize();
    ui.message({ type: "formsy-sop-workbench:viewport", top: 0, height: 800 });
    assert.equal(ui.classes.size, 0);
    assert.equal(ui.listeners.size, 0);
    assert.equal(ui.observed.length, 0);
    assert.deepEqual(ui.messages, []);
  }
});

test("embedded resize and anchor events send geometry only to the configured origin", () => {
  const ui = setup();
  assert.ok(ui.classes.has("workbench-embedded"));
  assert.deepEqual(ui.observed, [ui.body]);
  ui.resize();
  ui.resize();
  ui.setHeight(900);
  ui.resize();
  ui.hashchange("#evidence%2Dsection");
  assert.deepEqual(ui.messages, [
    { data: { type: "formsy-sop-workbench:height", height: 601 }, targetOrigin: origin },
    { data: { type: "formsy-sop-workbench:height", height: 900 }, targetOrigin: origin },
    { data: { type: "formsy-sop-workbench:scroll", top: 350 }, targetOrigin: origin },
  ]);
  ui.hashchange("#unknown");
  ui.hashchange("#%E0%A4%A");
  assert.equal(ui.messages.length, 3);
});

test("invalid parent origins and unframed embeds cannot exchange messages", () => {
  for (const configured of ["*", "null", "javascript:alert(1)", "file:///tmp/page", `${origin}/tasks`, `${origin}?x=1`, `${origin}#x`]) {
    const ui = setup({ search: `?embed=1&parent_origin=${encodeURIComponent(configured)}` });
    ui.resize();
    assert.equal(ui.listeners.size, 0, configured);
    assert.deepEqual(ui.messages, [], configured);
  }
  const unframed = setup({ framed: false });
  assert.equal(unframed.listeners.size, 0);
  assert.deepEqual(unframed.messages, []);
  const trailingSlash = setup({ search: `?embed=1&parent_origin=${encodeURIComponent(`${origin}/`)}` });
  trailingSlash.resize();
  assert.equal(trailingSlash.messages[0].targetOrigin, origin);
});

test("referrer fallback extracts the parent origin from a full task URL", () => {
  const ui = setup({ search: "?embed=1", referrer: `${origin}/projects/p1/tasks/t1?tab=verify#report` });
  ui.resize();
  assert.deepEqual(ui.messages, [{ data: { type: "formsy-sop-workbench:height", height: 601 }, targetOrigin: origin }]);
  ui.message({ type: "formsy-sop-workbench:viewport", top: 10, height: 700 });
  assert.equal(ui.styles.get("--embed-visible-top"), "10px");
  assert.equal(ui.styles.get("--embed-visible-height"), "700px");
});

test("viewport updates require the parent window, exact origin, type, and bounded finite numbers", () => {
  const ui = setup();
  const valid = { type: "formsy-sop-workbench:viewport", top: 24, height: 768 };
  for (const event of [
    { origin: "https://example.invalid" },
    { origin: `${origin}/` },
    { source: {} },
    { source: null },
  ]) ui.message(valid, event);
  for (const data of [
    null, undefined, "viewport", {},
    { ...valid, type: "formsy-sop-workbench:run" },
    ...[NaN, Infinity, -Infinity, -1, 100001, "10", null, undefined].flatMap((value) => [
      { ...valid, top: value },
      { ...valid, height: value },
    ]),
  ]) ui.message(data);
  assert.equal(ui.styles.size, 0);
  assert.deepEqual(ui.messages, []);
  ui.message(valid);
  assert.equal(ui.styles.get("--embed-visible-top"), "24px");
  assert.equal(ui.styles.get("--embed-visible-height"), "768px");
  assert.deepEqual(ui.messages, [{ data: { type: "formsy-sop-workbench:height", height: 601 }, targetOrigin: origin }]);
  ui.message({ ...valid, top: 0, height: 0 });
  assert.equal(ui.styles.get("--embed-visible-top"), "0px");
  assert.equal(ui.styles.get("--embed-visible-height"), "200px");
  ui.message({ ...valid, top: 100000, height: 100000 });
  assert.equal(ui.styles.get("--embed-visible-top"), "100000px");
  assert.equal(ui.styles.get("--embed-visible-height"), "100000px");
  assert.equal(ui.messages.length, 1);
});

test("repeated viewport messages acknowledge once and cannot sustain a height feedback loop", () => {
  const ui = setup();
  ui.resize();
  const viewport = { type: "formsy-sop-workbench:viewport", top: 0, height: 800 };
  ui.message(viewport);
  assert.equal(ui.messages.length, 2);
  for (let top = 1; top <= 100; top++) ui.message({ ...viewport, top });
  assert.equal(ui.messages.length, 2);
  assert.equal(ui.styles.get("--embed-visible-top"), "100px");
  ui.resize();
  assert.equal(ui.messages.length, 2);
  ui.setHeight(1000);
  ui.resize();
  assert.equal(ui.messages.length, 3);
  assert.deepEqual(ui.messages[2], { data: { type: "formsy-sop-workbench:height", height: 1000 }, targetOrigin: origin });
  ui.message(viewport);
  assert.equal(ui.messages.length, 3);
});

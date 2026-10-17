// The configuration builder page: library, canvas, YAML pane, filters,
// hover help and autosave.
import {
  filterSettings, catalogCount, reachChips, emptyModel, addSetting, removeSetting, moveSetting, setValue,
  modelToTree, clone, settingRoot,
} from "./model.js";
import { emitYAML } from "./yaml-emit.js";
import { safeStorage } from "./storage.js";
import { editorFor, h } from "./editors.js";
import { createChecks } from "./checks.js";

const STORE_KEY = "agentedict-builder-v1";
const FILES = [
  { id: "profile", label: "Profile", hint: "Codex, Claude Code, OpenCode" },
  { id: "native", label: "Native profile", hint: "Gemini, Cursor, Antigravity, Copilot, Kiro, Windsurf, Cline" },
  { id: "map", label: "Policy map", hint: "Who gets which profile" },
];
const LEVEL_TEXT = {
  "enforced": "Enforced", "partial": "Partly enforced", "configuration-only": "Configuration only",
  "not-applicable": "Doesn't apply", "not-available": "Not available", "not-documented": "Not documented",
};
const OFF = new Set(["not-applicable", "not-available"]);

const $ = id => document.getElementById(id);
const storage = safeStorage();
export const app = { catalog: null, state: null };

function freshModel(file) {
  let model = emptyModel(file);
  for (const s of app.catalog.settings) if (s.file === file && s.required) model = addSetting(model, s);
  return model;
}

function validModel(model, file) {
  return model && model.file === file && Array.isArray(model.order) && typeof model.values === "object" &&
    model.order.every(id => app.catalog.settings.some(s => s.id === id && s.file === file && s.status === "supported"));
}

function loadState() {
  const saved = storage.load(STORE_KEY);
  const state = { tab: "profile", filters: { oses: [], tools: [], query: "" }, models: {} };
  if (saved && FILES.some(f => f.id === saved.tab)) state.tab = saved.tab;
  if (saved?.filters) {
    state.filters.oses = (saved.filters.oses ?? []).filter(o => app.catalog.oses.includes(o));
    state.filters.tools = (saved.filters.tools ?? []).filter(t => app.catalog.tools.includes(t));
    state.filters.query = typeof saved.filters.query === "string" ? saved.filters.query : "";
  }
  for (const { id } of FILES) state.models[id] = validModel(saved?.models?.[id], id) ? saved.models[id] : freshModel(id);
  return state;
}

export const save = () => storage.save(STORE_KEY, app.state);
const model = () => app.state.models[app.state.tab];
export const settingById = id => app.catalog.settings.find(s => s.id === id);
const toolName = t => app.catalog.tool_names[t] ?? t;
const osName = o => app.catalog.os_names[o] ?? o;

export function announce(text) {
  const el = $("status");
  el.textContent = "";
  setTimeout(() => { el.textContent = text; }, 30);
}

let checks;

export function setModel(next, { canvas = true } = {}) {
  app.state.models[app.state.tab] = next;
  save();
  if (canvas) renderCanvas();
  renderLibrary();
  renderYAML();
  checks?.modelChanged();
}

// ---- Tabs and filters ----

function renderTabs() {
  $("tabs").replaceChildren(...FILES.map(f => h("button", {
    type: "button", role: "tab", class: "tab", id: `tab-${f.id}`, "aria-selected": String(app.state.tab === f.id),
    tabindex: app.state.tab === f.id ? "0" : "-1", "aria-controls": "canvas-pane",
    onclick: () => switchTab(f.id),
    onkeydown: e => {
      const i = FILES.findIndex(x => x.id === app.state.tab);
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (d) { e.preventDefault(); switchTab(FILES[(i + d + FILES.length) % FILES.length].id); $(`tab-${app.state.tab}`).focus(); }
    },
  }, f.label, h("small", { text: f.hint }))));
}

export function switchTab(id) {
  app.state.tab = id;
  save();
  hideHelp(true);
  checks?.hide();
  renderAll();
}

function renderFilters() {
  const f = app.state.filters;
  const active = () => f.oses.length + f.tools.length > 0 || f.query.trim() !== "";
  const clear = h("button", { type: "button", class: "btn small ghost", text: "Clear all", disabled: !active(),
    onclick: () => { f.oses.length = 0; f.tools.length = 0; f.query = ""; save(); renderFilters(); renderLibrary(); } });
  const toggle = (list, value, label) => h("button", {
    type: "button", class: "toggle", "aria-pressed": String(list.includes(value)), text: label,
    onclick: () => {
      const i = list.indexOf(value);
      if (i >= 0) list.splice(i, 1); else list.push(value);
      save(); renderFilters(); renderLibrary();
    },
  });
  const search = h("input", { type: "search", id: "search", value: f.query, placeholder: "Search, e.g. sandbox, mcp or prefer_mxc",
    "aria-label": "Search settings", "aria-controls": "library", autocomplete: "off", spellcheck: "false" });
  search.addEventListener("input", () => {
    f.query = search.value;
    save();
    renderLibrary();
    clear.disabled = !active();
  });
  $("filters").replaceChildren(
    h("div", { class: "filter-row" }, h("span", { text: "Search" }), search),
    h("div", { class: "filter-row" }, h("span", { text: "OS" }), app.catalog.oses.map(o => toggle(f.oses, o, osName(o)))),
    h("div", { class: "filter-row" }, h("span", { text: "Agent" }), app.catalog.tools.map(t => toggle(f.tools, t, toolName(t))), clear));
}

// ---- Library ----

function chips(setting) {
  const all = reachChips(setting, app.state.filters.oses);
  const shown = all.filter(c => !OFF.has(c.level) && (app.state.filters.tools.length === 0 || app.state.filters.tools.includes(c.tool)));
  const everyAgent = app.state.filters.tools.length === 0 && shown.length === app.catalog.tools.length && new Set(shown.map(c => c.level)).size === 1;
  if (everyAgent) return h("span", { class: "chips" }, h("span", { class: `chip ${shown[0].level}`, title: `Every agent: ${LEVEL_TEXT[shown[0].level]}`, text: "All agents" }));
  return h("span", { class: "chips" }, shown.map(c => h("span", { class: `chip ${c.level}`, title: `${toolName(c.tool)}: ${LEVEL_TEXT[c.level]}`, text: toolName(c.tool) })));
}

function renderLibrary() {
  const file = app.state.tab;
  const shown = filterSettings(app.catalog, { file, ...app.state.filters });
  const nothing = app.state.filters.query.trim() ? `No settings match "${app.state.filters.query.trim()}".` : "No settings match these filters.";
  const total = catalogCount(app.catalog, file);
  $("count").textContent = `Showing ${shown.length} of ${total} settings`;
  const used = new Set(model().order);
  const groups = app.catalog.topics.map(t => [t, shown.filter(s => s.topic === t.id)]).filter(([, list]) => list.length);
  const body = groups.map(([topic, list]) => [
    h("h3", { class: "topic", text: topic.title }),
    h("ul", { class: "lib-list" }, list.map(s => libraryItem(s, used.has(s.id)))),
  ]);
  const elsewhere = app.state.filters.query.trim() ? FILES.filter(f => f.id !== file).map(f => [f, filterSettings(app.catalog, { ...app.state.filters, file: f.id }).length]).filter(([, n]) => n) : [];
  const others = elsewhere.length ? h("p", { class: "elsewhere" }, "Also matching: ", elsewhere.map(([f, n], i) => [i ? ", " : "",
    h("button", { type: "button", class: "btn small", text: `${n} in ${f.label}`, onclick: () => { switchTab(f.id); $("search").focus(); } })])) : null;
  $("library").replaceChildren(...[others, ...(body.length ? body.flat() : [h("p", { class: "hint", text: nothing })])].filter(Boolean));
}

function libraryItem(setting, inFile) {
  const supported = setting.status === "supported";
  const canAdd = supported && !inFile;
  const item = h("li", { class: `lib-item${supported ? "" : " unsupported"}`, "data-id": setting.id, draggable: canAdd ? "true" : null },
    h("div", { class: "lib-main" },
      h("span", { class: "lib-title", text: setting.title }), chips(setting),
      supported ? null : h("span", { class: "label", text: app.catalog.labels[setting.status] })),
    infoButton(setting),
    canAdd ? h("button", { type: "button", class: "btn small", text: "Add", "aria-label": `Add ${setting.title} to your file`,
      onclick: () => addToFile(setting) }) : supported ? h("span", { class: "added", text: "Added" }) : null);
  item.addEventListener("dragstart", e => {
    e.dataTransfer.setData("text/x-agentedict-setting", setting.id);
    e.dataTransfer.effectAllowed = "copy";
    $("canvas-pane").classList.add("dragging");
  });
  item.addEventListener("dragend", () => $("canvas-pane").classList.remove("dragging"));
  return item;
}

export function addToFile(setting, index) {
  let next = addSetting(model(), setting);
  if (index !== undefined) next = moveSetting(next, setting.id, index - (next.order.length - 1));
  setModel(next);
  announce(`Added ${setting.title}.`);
}

// ---- Canvas ----

function renderCanvas() {
  const m = model();
  const file = FILES.find(f => f.id === app.state.tab);
  $("canvas-hint").textContent = `${file.label}: ${file.hint}`;
  $("drop-note").textContent = m.order.length ? "Drop more settings here, or drag a card to reorder." : "Drop settings here.";
  $("canvas").replaceChildren(...m.order.map((id, i) => card(settingById(id), i, m.order.length)));
}

function card(setting, index, count) {
  const m = model();
  const head = h("div", { class: "card-head", draggable: "true" },
    h("span", { class: "grip", "aria-hidden": "true", text: "⋮⋮" }),
    h("div", { class: "card-title" }, h("h3", { text: setting.title }), chips(setting)),
    h("div", { class: "card-actions" }, infoButton(setting),
    h("button", { type: "button", class: "btn small ghost", text: "Up", "aria-label": `Move ${setting.title} up`, disabled: index === 0,
      onclick: () => { setModel(moveSetting(model(), setting.id, -1)); focusCard(setting.id, "Up"); } }),
    h("button", { type: "button", class: "btn small ghost", text: "Down", "aria-label": `Move ${setting.title} down`, disabled: index === count - 1,
      onclick: () => { setModel(moveSetting(model(), setting.id, 1)); focusCard(setting.id, "Down"); } }),
    setting.required ? null : h("button", { type: "button", class: "btn small ghost", text: "Remove", "aria-label": `Remove ${setting.title}`,
      onclick: () => { setModel(removeSetting(model(), setting.id)); announce(`Removed ${setting.title}.`); } })));
  const body = h("div", { class: "card-body" },
    editorFor(setting.value, m.values[setting.id], v => setModel(setValue(model(), setting.id, clone(v)), { canvas: false }), setting.title));
  const li = h("li", { class: "card", "data-id": setting.id }, head, body);
  head.addEventListener("dragstart", e => {
    e.dataTransfer.setData("text/x-agentedict-card", setting.id);
    e.dataTransfer.effectAllowed = "move";
  });
  return li;
}

function focusCard(id, label) {
  const btn = [...document.querySelectorAll(`.card[data-id="${id}"] .card-head button`)].find(b => b.textContent === label && !b.disabled);
  (btn ?? document.querySelector(`.card[data-id="${id}"] .card-head button`))?.focus();
}

function dropIndex(e) {
  const target = e.target.closest?.(".card");
  return target ? model().order.indexOf(target.dataset.id) : model().order.length;
}

function setupDrop() {
  const pane = $("canvas-pane");
  const clear = () => document.querySelectorAll(".drop-before").forEach(el => el.classList.remove("drop-before"));
  pane.addEventListener("dragover", e => {
    const types = [...e.dataTransfer.types];
    if (!types.includes("text/x-agentedict-setting") && !types.includes("text/x-agentedict-card")) return;
    e.preventDefault();
    clear();
    e.target.closest?.(".card")?.classList.add("drop-before");
  });
  pane.addEventListener("dragleave", e => { if (!pane.contains(e.relatedTarget)) clear(); });
  pane.addEventListener("drop", e => {
    e.preventDefault();
    clear();
    pane.classList.remove("dragging");
    const index = dropIndex(e);
    const newId = e.dataTransfer.getData("text/x-agentedict-setting");
    const cardId = e.dataTransfer.getData("text/x-agentedict-card");
    if (newId) {
      const setting = settingById(newId);
      if (setting?.status === "supported" && setting.file === app.state.tab && !model().order.includes(newId)) addToFile(setting, index);
    } else if (cardId) {
      const from = model().order.indexOf(cardId);
      if (from < 0) return;
      setModel(moveSetting(model(), cardId, (index > from ? index - 1 : index) - from));
    }
  });
}

// ---- YAML ----

export function currentYAML() {
  return emitYAML(modelToTree(model(), app.catalog));
}

export function fileName() {
  const m = model();
  const safe = v => (typeof v === "string" && /^[A-Za-z0-9][A-Za-z0-9_-]*$/.test(v) ? v : "profile");
  if (m.file === "map") return "policy-map.yaml";
  if (m.file === "native") return `${safe(m.values["native-name"])}.native.yaml`;
  return `${safe(m.values["profile-name"])}.yaml`;
}

function renderYAML() {
  $("yaml").firstElementChild.textContent = currentYAML();
  $("filename").textContent = fileName();
}

function setupYAMLButtons() {
  $("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(currentYAML());
      announce("Copied the YAML.");
    } catch {
      const range = document.createRange();
      range.selectNodeContents($("yaml"));
      getSelection().removeAllRanges();
      getSelection().addRange(range);
      announce("Copying was blocked. The YAML is selected: press Ctrl+C or Command+C.");
    }
  });
  $("download").addEventListener("click", () => {
    const url = URL.createObjectURL(new Blob([currentYAML()], { type: "text/yaml" }));
    const a = h("a", { href: url, download: fileName() });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    announce(`Downloaded ${fileName()}.`);
  });
}

// ---- Help popover ----

let helpFor = null, pinned = false, hideTimer = 0;

function infoButton(setting) {
  const btn = h("button", { type: "button", class: "btn small info", text: "?", "aria-label": `About ${setting.title}`, "aria-expanded": "false",
    "aria-controls": "help", "data-help": setting.id });
  btn.addEventListener("click", e => {
    e.stopPropagation();
    if (pinned && helpFor === setting.id) { hideHelp(true); return; }
    showHelp(setting, btn, true);
    $("help").focus();
  });
  hoverHelp(btn, setting);
  return btn;
}

// Details open while the pointer is over the "?" button or it has keyboard
// focus, and stay open while the pointer is over the details themselves.
function hoverHelp(el, setting) {
  el.addEventListener("mouseenter", () => { if (!pinned) showHelp(setting, el, false); });
  el.addEventListener("mouseleave", () => scheduleHide());
  el.addEventListener("focusin", () => { if (!pinned) showHelp(setting, el, false); });
  el.addEventListener("focusout", e => { if (!pinned && !$("help").contains(e.relatedTarget)) scheduleHide(); });
}

function scheduleHide() {
  if (pinned) return;
  clearTimeout(hideTimer);
  hideTimer = setTimeout(() => hideHelp(false), 180);
}

export function hideHelp(force) {
  if (pinned && !force) return;
  clearTimeout(hideTimer);
  const help = $("help");
  help.hidden = true;
  document.querySelectorAll('[data-help][aria-expanded="true"]').forEach(b => b.setAttribute("aria-expanded", "false"));
  if (pinned && force) document.querySelector(`[data-help="${helpFor}"]`)?.focus();
  helpFor = null;
  pinned = false;
}

function helpContent(setting) {
  const notes = [];
  const cell = (r, span) => {
    if (!r) return h("td", { class: "muted", colspan: span, text: "—" });
    let mark = 0;
    if (r.note) {
      mark = notes.indexOf(r.note) + 1 || notes.push(r.note);
    }
    const cls = r.level === "enforced" ? "enforced" : r.level === "partial" ? "partial" : OFF.has(r.level) ? "muted" : "";
    return h("td", { class: cls, colspan: span },
      (LEVEL_TEXT[r.level] ?? r.level) + (span ? " on every OS" : ""), mark ? h("sup", { text: String(mark) }) : null,
      r.writes ? h("span", { class: "writes", text: r.writes }) : null);
  };
  const same = (a, b) => a && b && a.level === b.level && a.writes === b.writes && a.note === b.note;
  const rows = Object.entries(setting.reach).map(([tool, perOS]) => {
    const cells = app.catalog.oses.map(o => perOS[o]);
    const uniform = cells.every(c => same(c, cells[0]));
    return h("tr", {}, h("th", { scope: "row", text: toolName(tool) }), uniform ? cell(cells[0], app.catalog.oses.length) : cells.map(c => cell(c)));
  });
  return [
    h("button", { type: "button", class: "btn small ghost close", text: "Close", onclick: () => hideHelp(true) }),
    h("h3", { text: setting.title }),
    setting.status === "supported" ? null : h("span", { class: "label", text: app.catalog.labels[setting.status] }),
    h("p", { text: setting.description }),
    setting.vendor_key ? h("p", {}, "Vendor setting: ", h("code", { text: setting.vendor_key })) : null,
    setting.yaml_paths ? h("p", {}, "AgentEdict key: ", h("code", { text: settingRoot(setting) })) : null,
    h("table", {}, h("thead", {}, h("tr", {}, h("th", { text: "Agent" }), app.catalog.oses.map(o => h("th", { scope: "col", text: osName(o) })))), h("tbody", {}, rows)),
    notes.length ? h("ol", {}, notes.map(n => h("li", { text: n }))) : null,
    h("p", { class: "sources" }, "Sources: ", setting.sources.map((src, i) => [i ? " · " : "", h("a", { href: src.url, target: "_blank", rel: "noopener", text: src.title })]),
      `. Researched ${setting.researched}.`),
  ];
}

function showHelp(setting, anchor, pin) {
  clearTimeout(hideTimer);
  const help = $("help");
  if (helpFor !== setting.id) help.replaceChildren(...helpContent(setting).filter(Boolean));
  helpFor = setting.id;
  pinned = pin;
  document.querySelectorAll("[data-help]").forEach(b => b.setAttribute("aria-expanded", String(pin && b.dataset.help === setting.id)));
  help.hidden = false;
  help.tabIndex = -1;
  const r = anchor.getBoundingClientRect();
  const w = help.offsetWidth, hgt = help.offsetHeight;
  let left = r.right + 12;
  if (left + w > innerWidth - 16) left = Math.max(16, r.left - w - 12);
  if (left < 16 || innerWidth < 760) left = Math.max(16, Math.min(r.left, innerWidth - w - 16));
  let top = Math.min(Math.max(64, r.top), innerHeight - hgt - 16);
  help.style.left = `${left}px`;
  help.style.top = `${Math.max(16, top)}px`;
}

function setupHelp() {
  const help = $("help");
  help.addEventListener("mouseenter", () => clearTimeout(hideTimer));
  help.addEventListener("mouseleave", () => scheduleHide());
  document.addEventListener("keydown", e => { if (e.key === "Escape" && !help.hidden) hideHelp(true); });
  document.addEventListener("click", e => { if (pinned && !help.contains(e.target)) hideHelp(true); });
}

// ---- Toolbar ----

function renderToolbar() {
  $("toolbar").replaceChildren(...(checks?.buttons() ?? []),
    h("button", { type: "button", class: "btn ghost", text: "Start over", onclick: () => {
      if (!confirm("Start over? This clears all three files in this browser.")) return;
      storage.clear(STORE_KEY);
      checks?.hide();
      app.state = loadState();
      renderAll();
      announce("Started over.");
    } }));
}

export function renderAll() {
  renderTabs();
  renderToolbar();
  renderFilters();
  renderLibrary();
  renderCanvas();
  renderYAML();
}

export const ready = (async () => {
  try {
    const res = await fetch("catalog.json");
    if (!res.ok) throw new Error(`catalog.json: HTTP ${res.status}`);
    app.catalog = await res.json();
  } catch (err) {
    $("app").prepend(h("p", { class: "error", text: `The settings catalog didn't load (${err.message}).` }));
    throw err;
  }
  app.state = loadState();
  checks = createChecks({ app, model, setModel, switchTab, currentYAML, announce, toolName });
  setupDrop();
  setupYAMLButtons();
  setupHelp();
  renderAll();
})();

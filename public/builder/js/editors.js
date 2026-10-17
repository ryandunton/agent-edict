// Form controls for each catalog value type. Every editor takes the value
// spec, the current value and an onChange callback, and returns an element.
import { clone, defaultValue, renumberList, windowsGroupHint } from "./model.js";

let seq = 0;
const uid = prefix => `${prefix}-${++seq}`;

export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const child of children.flat(Infinity)) if (child !== null && child !== undefined && child !== false) el.append(child);
  return el;
}

const OS_LIST_KEYS = [["common", "Every OS"], ["unix", "macOS and Linux"], ["windows", "Windows"]];
const OS_ENUM_LABELS = { unix: "macOS and Linux", windows: "Windows" };
const isMap = v => typeof v === "object" && v !== null && !Array.isArray(v);
const lines = text => text.split("\n").map(l => l.trim()).filter(Boolean);

function datalist(id, options) {
  return options?.length ? h("datalist", { id }, options.map(o => h("option", { value: o }))) : null;
}

function field(label, control, id, extra) {
  return h("div", { class: "field" }, h("label", { for: id, text: label }), control, extra);
}

function textInput(spec, value, onChange, label) {
  const id = uid("f");
  const listId = spec.suggestions?.length ? uid("dl") : null;
  const error = h("p", { class: "field-error", hidden: true });
  const input = h("input", { type: "text", id, value: value ?? "", list: listId, spellcheck: "false", autocomplete: "off" });
  input.addEventListener("input", () => {
    const bad = spec.pattern && input.value !== "" && !new RegExp(spec.pattern).test(input.value);
    input.setAttribute("aria-invalid", bad ? "true" : "false");
    error.hidden = !bad;
    error.textContent = bad ? "Letters, numbers, underscores and hyphens only." : "";
    onChange(input.value === "" ? undefined : input.value);
  });
  return field(label, input, id, [datalist(listId, spec.suggestions), error]);
}

function textArea(value, onChange, label, rows = 6) {
  const id = uid("f");
  const area = h("textarea", { id, rows, spellcheck: "true" });
  area.value = value ?? "";
  area.addEventListener("input", () => onChange(area.value === "" ? undefined : area.value));
  return field(label, area, id);
}

function boolInput(value, onChange, label) {
  const box = h("input", { type: "checkbox", checked: value === true });
  box.addEventListener("change", () => onChange(box.checked));
  return h("div", { class: "field" }, h("label", { class: "switch" }, box, label));
}

function intInput(spec, value, onChange, label) {
  const id = uid("f");
  const input = h("input", { type: "number", id, min: spec.min, max: spec.max, step: 1, value: value ?? "" });
  input.addEventListener("input", () => {
    const n = Number(input.value);
    const ok = input.value !== "" && Number.isInteger(n) && (spec.min === undefined || n >= spec.min) && (spec.max === undefined || n <= spec.max);
    input.setAttribute("aria-invalid", ok || input.value === "" ? "false" : "true");
    if (ok) onChange(n);
    else if (input.value === "") onChange(undefined);
  });
  return field(label, input, id);
}

function select(options, value, onChange, id) {
  const all = value !== undefined && !options.includes(value) ? [...options, value] : options;
  const sel = h("select", { id }, all.map(o => h("option", { value: o, selected: o === value, text: o })));
  if (value === undefined) sel.prepend(h("option", { value: "", selected: true, text: "Choose…" }));
  sel.addEventListener("change", () => onChange(sel.value === "" ? undefined : sel.value));
  return sel;
}

function enumInput(spec, value, onChange, label) {
  const id = uid("f");
  return field(label, select(spec.options, value, onChange, id), id);
}

function listInput(spec, value, onChange, label) {
  const current = Array.isArray(value) ? [...value] : [];
  if (spec.options?.length) {
    const options = [...spec.options, ...current.filter(v => !spec.options.includes(v))];
    const boxes = options.map(option => {
      const box = h("input", { type: "checkbox", checked: current.includes(option), value: option });
      box.addEventListener("change", () => onChange(options.filter((_, i) => boxes[i].checked)));
      return box;
    });
    return h("fieldset", {}, h("legend", { text: label }),
      h("div", { class: "checks" }, options.map((o, i) => h("label", {}, boxes[i], h("span", { class: "mono", text: o })))));
  }
  const id = uid("f");
  const area = h("textarea", { id, rows: Math.min(10, Math.max(3, current.length + 1)), spellcheck: "false" });
  area.value = current.join("\n");
  area.addEventListener("input", () => onChange(lines(area.value)));
  const hint = spec.suggestions?.length ? h("p", { class: "hint", text: "For example: " + spec.suggestions.join(", ") }) : null;
  return field(label + " (one per line)", area, id, hint);
}

function osListInput(value, onChange, label) {
  const current = isMap(value) ? { ...value } : {};
  const parts = OS_LIST_KEYS.map(([key, name]) => {
    const id = uid("f");
    const area = h("textarea", { id, rows: Math.max(2, (current[key]?.length ?? 0) + 1), spellcheck: "false" });
    area.value = (current[key] ?? []).join("\n");
    area.addEventListener("input", () => {
      const items = lines(area.value);
      if (items.length) current[key] = items; else delete current[key];
      onChange({ ...current });
    });
    return field(name, area, id);
  });
  return h("fieldset", {}, h("legend", { text: label }), h("p", { class: "hint", text: "One per line." }), h("div", { class: "os-split" }, parts));
}

function osEnumInput(spec, value, onChange, label) {
  const keys = spec.keys ?? ["unix", "windows"];
  const current = typeof value === "string" ? Object.fromEntries(keys.map(k => [k, value])) : { ...(value ?? {}) };
  const parts = keys.map(key => {
    const id = uid("f");
    return field(OS_ENUM_LABELS[key] ?? key, select(spec.options, current[key], v => {
      if (v === undefined) delete current[key]; else current[key] = v;
      onChange({ ...current });
    }, id), id);
  });
  return h("fieldset", {}, h("legend", { text: label }), h("div", { class: "os-split" }, parts));
}

function objectInput(spec, value, onChange, label) {
  const current = isMap(value) ? clone(value) : {};
  const rows = spec.fields.map(f => editorFor(f, current[f.key], v => {
    if (v === undefined || (isMap(v) && Object.keys(v).length === 0 && f.optional)) delete current[f.key];
    else current[f.key] = v;
    onChange(clone(current));
  }, f.label ?? f.key));
  return label ? h("fieldset", {}, h("legend", { text: label }), rows) : h("div", { class: "field" }, rows);
}

function mapInput(spec, value, onChange, label) {
  let current = isMap(value) ? clone(value) : {};
  const box = h("fieldset", {}, h("legend", { text: label }));
  const keyLabel = spec.key_label ?? "Name";
  const listId = spec.key_suggestions?.length ? uid("dl") : null;
  const emit = () => onChange(clone(current));
  const render = () => {
    const entries = Object.entries(current).map(([key, v]) => {
      const keyInput = h("input", { type: "text", value: key, "aria-label": keyLabel, list: listId, spellcheck: "false" });
      keyInput.addEventListener("change", () => {
        const next = keyInput.value.trim();
        if (next === key) return;
        if (!next || next in current) { keyInput.setAttribute("aria-invalid", "true"); return; }
        current = Object.fromEntries(Object.entries(current).map(([k, val]) => [k === key ? next : k, val]));
        emit(); render();
      });
      const remove = h("button", { type: "button", class: "btn small ghost", text: "Remove", "aria-label": `Remove ${key}`,
        onclick: () => { delete current[key]; emit(); render(); } });
      const editor = editorFor(spec.values, v, nv => { current[key] = nv; emit(); }, spec.values?.type === "object" ? "" : "Value");
      return h("div", { class: "entry" }, h("div", { class: "entry-head" }, keyInput, remove), editor);
    });
    const newKey = h("input", { type: "text", placeholder: keyLabel, "aria-label": `New ${keyLabel.toLowerCase()}`, list: listId, spellcheck: "false" });
    const add = () => {
      const key = newKey.value.trim();
      if (!key || key in current) { newKey.setAttribute("aria-invalid", "true"); return; }
      current[key] = defaultValue(spec.values);
      emit(); render();
    };
    newKey.addEventListener("keydown", e => { if (e.key === "Enter") { e.preventDefault(); add(); } });
    box.replaceChildren(h("legend", { text: label }), ...entries,
      h("div", { class: "add-row" }, newKey, h("button", { type: "button", class: "btn small", text: "Add", onclick: add })),
      datalist(listId, spec.key_suggestions) ?? "");
  };
  render();
  return box;
}

function listOfInput(spec, value, onChange, label) {
  let current = Array.isArray(value) ? clone(value) : [];
  const items = spec.items ?? { type: "string" };
  const box = h("fieldset", {});
  const emit = () => onChange(clone(current));
  const render = () => {
    const rows = current.map((item, i) => {
      const move = (d) => { const j = i + d; if (j < 0 || j >= current.length) return; [current[i], current[j]] = [current[j], current[i]]; emit(); render(); };
      return h("div", { class: "entry" },
        h("div", { class: "entry-head" }, h("span", { class: "entry-title", text: `Item ${i + 1}` }),
          h("button", { type: "button", class: "btn small ghost", text: "Up", "aria-label": `Move item ${i + 1} up`, disabled: i === 0, onclick: () => move(-1) }),
          h("button", { type: "button", class: "btn small ghost", text: "Down", "aria-label": `Move item ${i + 1} down`, disabled: i === current.length - 1, onclick: () => move(1) }),
          h("button", { type: "button", class: "btn small ghost", text: "Remove", "aria-label": `Remove item ${i + 1}`, onclick: () => { current.splice(i, 1); emit(); render(); } })),
        editorFor(items, item, v => { current[i] = v; emit(); }, items.type === "object" ? "" : "Value"));
    });
    box.replaceChildren(h("legend", { text: label }), ...rows,
      h("div", { class: "add-row" }, h("button", { type: "button", class: "btn small", text: "Add item",
        onclick: () => { current.push(defaultValue(items)); emit(); render(); } })));
  };
  render();
  return box;
}

const GROUP_OSES = [["windows", "Windows"], ["linux", "Linux"], ["darwin", "macOS"]];

// Policy map rules: priorities follow the list order unless the admin types
// one, and Windows group entries are explained as they're typed.
function rulesInput(spec, value, onChange, label) {
  let current = Array.isArray(value) ? clone(value) : [];
  const agentOptions = spec.items.fields.find(f => f.key === "agents")?.options ?? ["all"];
  const box = h("div", { class: "rules", role: "group", "aria-label": label });
  const emit = () => onChange(clone(current));
  const structural = () => { current = renumberList(current); emit(); render(); };
  const move = (from, to) => {
    if (to < 0 || to >= current.length || from === to) return;
    current.splice(to, 0, current.splice(from, 1)[0]);
    structural();
    box.querySelectorAll(".rule")[to]?.querySelector(".rule-head button")?.focus();
  };

  function groupsField(rule, os, name) {
    const id = uid("f");
    const area = h("textarea", { id, rows: Math.max(2, (rule.match_groups?.[os]?.length ?? 0) + 1), spellcheck: "false" });
    area.value = (rule.match_groups?.[os] ?? []).join("\n");
    const hints = h("ul", { class: "group-hints" });
    const showHints = items => hints.replaceChildren(...(os === "windows" ? items.map(entry => {
      const hint = windowsGroupHint(entry);
      return h("li", { class: hint.kind === "invalid" ? "error" : "" }, h("code", { text: entry }), " ", hint.message);
    }) : []));
    area.addEventListener("input", () => {
      const items = lines(area.value);
      rule.match_groups = { ...(rule.match_groups ?? {}) };
      if (items.length) rule.match_groups[os] = items; else delete rule.match_groups[os];
      showHints(items);
      emit();
    });
    showHints(rule.match_groups?.[os] ?? []);
    return field(name, area, id, hints);
  }

  function agentsField(rule) {
    const all = (rule.agents ?? []).includes("all");
    const boxes = agentOptions.map(option => {
      const cb = h("input", { type: "checkbox", value: option, checked: (rule.agents ?? []).includes(option), disabled: option !== "all" && all });
      cb.addEventListener("change", () => {
        rule.agents = option === "all" && cb.checked ? ["all"] : agentOptions.filter((o, i) => o !== "all" && boxes[i].checked);
        if (option !== "all" && cb.checked) rule.agents = rule.agents.filter(a => a !== "all");
        emit(); render();
      });
      return cb;
    });
    return h("fieldset", {}, h("legend", { text: "Agents" }),
      h("div", { class: "checks" }, agentOptions.map((o, i) => h("label", {}, boxes[i], h("span", { text: o === "all" ? "All managed agents" : o })))));
  }

  function ruleCard(rule, i) {
    const pid = uid("f");
    const priority = h("input", { type: "number", id: pid, min: 1, step: 1, value: rule.priority ?? "", class: "priority" });
    priority.addEventListener("input", () => {
      const n = Number(priority.value);
      if (!Number.isInteger(n) || n < 1) { priority.setAttribute("aria-invalid", "true"); return; }
      priority.setAttribute("aria-invalid", "false");
      rule.priority = n;
      rule.priorityLocked = true;
      emit();
      source.textContent = "Set by you.";
      auto.hidden = false;
    });
    const source = h("span", { class: "hint", text: rule.priorityLocked ? "Set by you." : "From the order." });
    const auto = h("button", { type: "button", class: "btn small ghost", text: "Use order", hidden: !rule.priorityLocked,
      onclick: () => { delete rule.priorityLocked; structural(); } });
    const head = h("div", { class: "entry-head rule-head", draggable: "true" },
      h("span", { class: "grip", "aria-hidden": "true", text: "⋮⋮" }),
      h("span", { class: "entry-title", text: `Rule ${i + 1}${rule.profile ? `: ${rule.profile}` : ""}` }),
      h("button", { type: "button", class: "btn small ghost", text: "Up", "aria-label": `Move rule ${i + 1} up`, disabled: i === 0, onclick: () => move(i, i - 1) }),
      h("button", { type: "button", class: "btn small ghost", text: "Down", "aria-label": `Move rule ${i + 1} down`, disabled: i === current.length - 1, onclick: () => move(i, i + 1) }),
      h("button", { type: "button", class: "btn small ghost", text: "Remove", "aria-label": `Remove rule ${i + 1}`, onclick: () => { current.splice(i, 1); structural(); } }));
    head.addEventListener("dragstart", e => { e.stopPropagation(); e.dataTransfer.setData("text/x-agentedict-rule", String(i)); e.dataTransfer.effectAllowed = "move"; });
    const card = h("div", { class: "entry rule", "data-index": String(i) }, head,
      h("div", { class: "rule-grid" },
        h("div", { class: "field" }, h("label", { for: pid, text: "Priority (lower wins)" }), h("div", { class: "add-row" }, priority, auto), source),
        editorFor({ type: "string" }, rule.profile, v => { rule.profile = v ?? ""; emit(); }, "Profile name"),
        editorFor({ type: "string" }, rule.description, v => { if (v === undefined) delete rule.description; else rule.description = v; emit(); }, "Description")),
      agentsField(rule),
      h("fieldset", {}, h("legend", { text: "Groups (one per line; a user in any of them matches)" }),
        h("div", { class: "os-split" }, GROUP_OSES.map(([os, name]) => groupsField(rule, os, name)))));
    card.addEventListener("dragover", e => {
      if (![...e.dataTransfer.types].includes("text/x-agentedict-rule")) return;
      e.preventDefault(); e.stopPropagation();
      card.classList.add("drop-before");
    });
    card.addEventListener("dragleave", () => card.classList.remove("drop-before"));
    card.addEventListener("drop", e => {
      const from = e.dataTransfer.getData("text/x-agentedict-rule");
      if (from === "") return;
      e.preventDefault(); e.stopPropagation();
      card.classList.remove("drop-before");
      const f = Number(from);
      move(f, f < i ? i - 1 : i);
    });
    return card;
  }

  function render() {
    box.replaceChildren(...current.map(ruleCard),
      h("div", { class: "add-row" }, h("button", { type: "button", class: "btn small", text: "Add rule", onclick: () => {
        current.push({ priority: 0, profile: "", agents: ["all"], match_groups: {} });
        structural();
        box.querySelectorAll(".rule input[type=text]")[current.length * 2 - 2]?.focus();
      } })),
      h("p", { class: "hint", text: "Each agent is matched on its own. When several people are logged in, the lowest number wins, and someone who matches no rule brings the standard policy at its priority." }));
  }
  render();
  return box;
}

export function editorFor(spec, value, onChange, label = "Value") {
  if (spec?.editor === "rules") return rulesInput(spec, value, onChange, label);
  switch (spec?.type) {
    case "text": return textArea(value, onChange, label);
    case "bool": return boolInput(value, onChange, label);
    case "int": return intInput(spec, value, onChange, label);
    case "enum": return enumInput(spec, value, onChange, label);
    case "string-list": return listInput(spec, value, onChange, label);
    case "os-string-list": return osListInput(value, onChange, label);
    case "os-enum": return osEnumInput(spec, value, onChange, label);
    case "object": return objectInput(spec, value, onChange, label);
    case "map": return mapInput(spec, value, onChange, label);
    case "list": return listOfInput(spec, value, onChange, label);
    case "fixed": return h("div", { class: "field" }, h("span", { class: "field-label", text: label }), h("output", { class: "fixed", text: String(spec.value) }));
    default: return textInput(spec ?? {}, value, onChange, label);
  }
}

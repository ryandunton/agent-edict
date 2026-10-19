// Paste a file, check the current file with AgentEdict's own code, apply
// one-click fixes, and preview each agent's files.
import { h } from "./editors.js";
import { treeToModel, detectKind } from "./model.js";
import { applyFix } from "./fixes.js";
import { loadEdict } from "./wasm.js";

const MAX_INPUT = 1 << 20;
const FILE_LABEL = { profile: "Profile", native: "Native profile", map: "Policy map" };
const LINT = { profile: "lintProfile", native: "lintNative", map: "lintMap" };
const OS_NAMES = { windows: "Windows", linux: "Linux", darwin: "macOS" };
const NATIVE = ["gemini", "cursor", "antigravity", "copilot", "kiro", "windsurf", "cline"];

export function createChecks(ctx) {
  // ctx: { app, model(), setModel(m), switchTab(id), currentYAML(), announce(text), toolName(t) }
  let live = false, timer = 0;
  const panel = h("section", { class: "checks-panel", id: "checks", "aria-label": "Check results", hidden: true });
  document.getElementById("toolbar").after(panel);

  async function edict() {
    try { return await loadEdict(); }
    catch (err) { showPanel([h("p", { class: "error", text: `AgentEdict's checks didn't load: ${err.message}. The site needs builder/edict.wasm and builder/wasm_exec.js, which make builder creates.` })]); throw err; }
  }

  function showPanel(children) {
    panel.hidden = false;
    panel.replaceChildren(...children);
  }

  // ---- Check ----
  function agentSummary(rows) {
    const byAgent = new Map();
    for (const r of rows ?? []) {
      if (!byAgent.has(r.agent)) byAgent.set(r.agent, []);
      byAgent.get(r.agent).push(r);
    }
    return [...byAgent].map(([agent, list]) => {
      const ok = list.filter(r => r.ok).map(r => OS_NAMES[r.os]);
      const bad = list.filter(r => !r.ok);
      const toolOnly = [...new Set(list.flatMap(r => r.tool_level_only ?? []))];
      return h("li", {}, h("strong", { text: ctx.toolName(agent) }), ": ",
        ok.length ? `compiles for ${ok.join(", ")}` : "",
        ok.length && bad.length ? "; " : "",
        bad.length ? h("span", { class: "error" }, `won't compile for ${bad.map(r => OS_NAMES[r.os]).join(", ")}`) : "",
        bad.length ? h("ul", {}, [...new Set(bad.map(r => r.error))].map(e => h("li", { class: "mono small", text: e }))) : "",
        toolOnly.length ? h("p", { class: "hint", text: `Enforced only in ${ctx.toolName(agent)}'s own tools: ${toolOnly.join(", ")}.` }) : "");
    });
  }

  function problemItem(p) {
    const where = [p.line ? `line ${p.line}` : "", p.agent ? ctx.toolName(p.agent) : "", p.os ? OS_NAMES[p.os] : ""].filter(Boolean).join(", ");
    return h("li", { class: `problem ${p.severity}` },
      h("span", { class: "sev", text: p.severity === "error" ? "Error" : "Warning" }), " ", p.message,
      where ? h("span", { class: "hint", text: ` (${where})` }) : "",
      p.fix ? h("button", { type: "button", class: "btn small", text: "Fix", "aria-label": `Fix: ${p.message}`, onclick: () => fix(p.fix) }) : "");
  }

  async function check({ quiet = false } = {}) {
    const api = await edict();
    const file = ctx.model().file;
    const report = api[LINT[file]](ctx.currentYAML());
    live = true;
    const problems = report.problems ?? [];
    showPanel([
      h("div", { class: "checks-head" },
        h("h2", { text: report.valid ? (problems.length ? "Valid, with warnings" : "Valid") : "Not valid yet" }),
        h("span", { class: "hint", text: `${FILE_LABEL[file]} checked by AgentEdict ${api.version()}. Checks rerun as you edit.` }),
        h("button", { type: "button", class: "btn small ghost", text: "Hide", onclick: () => { live = false; panel.hidden = true; } })),
      problems.length ? h("ul", { class: "problems" }, problems.map(problemItem)) : null,
      report.agents?.length ? h("ul", { class: "agents" }, agentSummary(report.agents)) : null,
    ].filter(Boolean));
    if (!quiet) ctx.announce(report.valid ? "The file is valid." : `${problems.length} problem${problems.length === 1 ? "" : "s"} found.`);
    return report;
  }

  async function fix(fixId) {
    if (fixId === "map-convert-v1") {
      const api = await edict();
      const converted = api.convertV1Map(ctx.currentYAML());
      loadTree(api.yamlToJSON(converted), "map");
    } else {
      ctx.setModel(applyFix(ctx.model(), fixId, ctx.app.catalog));
    }
    ctx.announce("Fixed.");
    await check({ quiet: true });
  }

  function modelChanged() {
    if (!live || panel.hidden) return;
    clearTimeout(timer);
    timer = setTimeout(() => check({ quiet: true }).catch(() => {}), 300);
  }

  // ---- Paste ----
  function loadTree(tree, file) {
    const { model } = treeToModel(tree, ctx.app.catalog, file);
    if (ctx.app.state.tab !== file) ctx.switchTab(file);
    ctx.setModel(model);
  }

  function pasteDialog() {
    const dialog = h("dialog", { class: "dialog", "aria-labelledby": "paste-h" });
    const area = h("textarea", { id: "paste-text", rows: 16, spellcheck: "false", "aria-label": "YAML to load" });
    const out = h("div", { class: "dialog-out", "aria-live": "polite" });
    const close = () => { dialog.close(); dialog.remove(); };
    const file = ctx.model().file;
    let pendingLoad = null;
    const load = async () => {
      out.replaceChildren(h("p", { class: "hint", text: "Checking…" }));
      const text = area.value;
      if (new Blob([text]).size > MAX_INPUT) { out.replaceChildren(h("p", { class: "error", text: "The file is over the 1 MiB limit." })); return; }
      let api, pasted;
      try { api = await edict(); pasted = api.parsePasted(text); }
      catch (err) { out.replaceChildren(h("p", { class: "error", text: `This file can't be read: ${err.message}` })); return; }
      const tree = pasted.tree;
      // A Codex requirements.toml always becomes a profile.
      const kind = pasted.format === "codex-requirements" ? "profile" : detectKind(tree);
      if (kind === "map" && tree?.version === 1) {
        out.replaceChildren(h("p", { text: "This is a version 1 policy map. The builder edits version 2 maps, where the old machine_profile becomes the standard policy." }),
          h("button", { type: "button", class: "btn primary", text: "Convert to version 2 and load", onclick: () => {
            try { loadTree(api.yamlToJSON(api.convertV1Map(text)), "map"); close(); ctx.announce("Converted and loaded the policy map."); check({ quiet: true }); }
            catch (err) { out.append(h("p", { class: "error", text: err.message })); }
          } }));
        return;
      }
      const { unknown } = treeToModel(tree, ctx.app.catalog, kind);
      const notes = pasted.notes;
      const doLoad = () => { loadTree(tree, kind); close(); ctx.announce(`Loaded into ${FILE_LABEL[kind]}.`); check({ quiet: true }); };
      const parts = [];
      if (kind !== file) parts.push(h("p", { text: `This looks like a ${FILE_LABEL[kind].toLowerCase()}, so it will load into the ${FILE_LABEL[kind]} tab.` }));
      if (unknown.length) parts.push(h("p", { class: "error", text: "These keys aren't AgentEdict settings and won't be loaded:" }),
        h("ul", { class: "mono small" }, unknown.slice(0, 50).map(u => h("li", { text: u }))));
      if (notes.length) parts.push(h("ul", {}, notes.map(n => h("li", { text: n }))));
      if (!parts.length) { doLoad(); return; }
      pendingLoad = doLoad;
      parts.push(h("p", { class: "hint", text: `Loading replaces what's in the ${FILE_LABEL[kind]} tab.` }),
        h("button", { type: "button", class: "btn primary", text: "Load anyway", onclick: () => pendingLoad?.() }));
      out.replaceChildren(...parts);
    };
    dialog.append(
      h("h2", { id: "paste-h", text: "Paste a file" }),
      h("p", { class: "hint", text: "Paste a profile, native profile or policy map, or a Codex requirements.toml to turn into a profile. It's read in your browser by AgentEdict's own code and never leaves this page." }),
      area, out,
      h("div", { class: "dialog-actions" },
        h("button", { type: "button", class: "btn primary", text: "Load", onclick: load }),
        h("button", { type: "button", class: "btn ghost", text: "Cancel", onclick: close })));
    dialog.addEventListener("cancel", () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    area.focus();
  }

  // ---- Preview ----
  function previewDialog() {
    const file = ctx.model().file;
    const yaml = ctx.currentYAML();
    const agents = file === "profile" ? ["codex", "claude", "opencode"]
      : NATIVE.filter(p => ctx.model().order.some(id => id.startsWith(`${p}-`)));
    const dialog = h("dialog", { class: "dialog wide", "aria-labelledby": "preview-h" });
    const close = () => { dialog.close(); dialog.remove(); };
    const osSel = h("select", { "aria-label": "Operating system" }, Object.entries(OS_NAMES).map(([v, t]) => h("option", { value: v, text: t })));
    const agentSel = h("select", { "aria-label": "Agent" }, agents.map(a => h("option", { value: a, text: ctx.toolName(a) })));
    const out = h("div", { class: "dialog-out", "aria-live": "polite" });
    const render = async () => {
      if (!agents.length) { out.replaceChildren(h("p", { class: "hint", text: "Add a setting for one of the native tools first." })); return; }
      const api = await edict();
      const result = api.preview(file, yaml, osSel.value, agentSel.value);
      out.replaceChildren(...(result.error ? [h("p", { class: "error", text: result.error })] : [
        ...result.files.map(f => h("figure", { class: "preview-file" }, h("figcaption", { class: "mono", text: f.path }), h("pre", { class: "code", tabindex: "0", text: f.content }))),
        result.tool_level_only?.length ? h("p", { class: "hint", text: `Enforced only in the agent's own tools: ${result.tool_level_only.join(", ")}.` }) : null,
      ].filter(Boolean)));
    };
    osSel.addEventListener("change", render);
    agentSel.addEventListener("change", render);
    dialog.append(h("h2", { id: "preview-h", text: "Preview" }),
      h("p", { class: "hint", text: "The exact files AgentEdict installs for this agent on this OS." }),
      h("div", { class: "dialog-controls" }, osSel, agentSel), out,
      h("div", { class: "dialog-actions" }, h("button", { type: "button", class: "btn ghost", text: "Close", onclick: close })));
    dialog.addEventListener("cancel", () => dialog.remove());
    document.body.append(dialog);
    dialog.showModal();
    render().catch(err => out.replaceChildren(h("p", { class: "error", text: err.message })));
  }

  const buttons = () => [
    h("button", { type: "button", class: "btn", text: "Paste a file", onclick: pasteDialog }),
    h("button", { type: "button", class: "btn", text: "Check", onclick: () => check().catch(() => {}) }),
    ctx.model().file === "map" ? null : h("button", { type: "button", class: "btn", text: "Preview", onclick: previewDialog }),
  ].filter(Boolean);
  return { buttons, modelChanged, check, hide: () => { live = false; panel.hidden = true; } };
}

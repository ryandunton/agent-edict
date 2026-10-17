import { test } from "node:test";
import assert from "node:assert/strict";
import { fixture } from "./fixture-catalog.mjs";
import {
  filterSettings, catalogCount, reachChips, emptyModel, addSetting, removeSetting, moveSetting,
  modelToTree, treeToModel, detectKind, settingRoot, renumberRules, windowsGroupHint, setValue,
} from "../../../public/builder/js/model.js";
import { applyFix } from "../../../public/builder/js/fixes.js";
import { safeStorage } from "../../../public/builder/js/storage.js";
import { loadEdict } from "./load-wasm.mjs";

const byId = id => fixture.settings.find(s => s.id === id);
const ids = list => list.map(s => s.id);

test("test_filterOpenCodeWindows", () => {
  const shown = filterSettings(fixture, { file: "profile", tools: ["opencode"], oses: ["windows"] });
  assert.deepEqual(ids(shown), ["commands-deny"]);
  assert.equal(filterSettings(fixture, { file: "profile", tools: [], oses: [] }).length, catalogCount(fixture, "profile"));
  assert.equal(catalogCount(fixture, "profile"), 7);
  assert.deepEqual(ids(filterSettings(fixture, { file: "profile", tools: ["codex"], oses: ["linux"] })),
    ["profile-name", "commands-deny", "deny-read", "mcp-servers"]);
  assert.deepEqual(ids(filterSettings(fixture, { file: "profile", tools: [], oses: ["windows"] })).includes("codex-prefer-mxc"), true);
  assert.deepEqual(ids(filterSettings(fixture, { file: "profile", tools: [], oses: ["macos"] })).includes("codex-prefer-mxc"), false);
});

test("reachChips takes the strongest level across the chosen OSes", () => {
  assert.deepEqual(reachChips(byId("deny-read"), ["windows"]),
    [{ tool: "codex", level: "enforced" }, { tool: "opencode", level: "not-available" }, { tool: "claude", level: "partial" }]);
  assert.deepEqual(reachChips(byId("deny-read"), []).find(c => c.tool === "claude"), { tool: "claude", level: "enforced" });
});

test("test_addRejectsUnsupported", () => {
  assert.throws(() => addSetting(emptyModel("profile"), byId("codex-prefer-mxc")), /can't be added/);
  assert.throws(() => addSetting(emptyModel("map"), byId("commands-deny")), /belongs in/);
});

test("add, move and remove keep the order", () => {
  let m = emptyModel("profile");
  m = addSetting(m, byId("profile-name"));
  m = addSetting(m, byId("commands-deny"));
  m = addSetting(m, byId("deny-read"), { common: ["~/.ssh"] });
  assert.deepEqual(m.order, ["profile-name", "commands-deny", "deny-read"]);
  assert.deepEqual(m.values["commands-deny"], { unix: ["sudo"] });
  const before = m;
  m = moveSetting(m, "deny-read", -1);
  assert.deepEqual(m.order, ["profile-name", "deny-read", "commands-deny"]);
  assert.deepEqual(before.order, ["profile-name", "commands-deny", "deny-read"], "models are not mutated");
  assert.deepEqual(moveSetting(m, "profile-name", -5).order, m.order);
  m = removeSetting(m, "deny-read");
  assert.deepEqual(m.order, ["profile-name", "commands-deny"]);
  assert.equal("deny-read" in m.values, false);
  assert.throws(() => addSetting(m, byId("commands-deny")), /already/);
});

test("settingRoot cuts at map keys and list items", () => {
  assert.equal(settingRoot(byId("commands-deny")), "commands.deny");
  assert.equal(settingRoot(byId("mcp-servers")), "mcp_servers");
  assert.equal(settingRoot(byId("map-rules")), "rules");
  assert.equal(settingRoot(byId("profile-name")), "name");
});

test("test_modelTreeRoundTrip", () => {
  let m = emptyModel("profile");
  m = addSetting(m, byId("profile-name"), "eng");
  m = addSetting(m, byId("deny-read"), { common: ["~/.ssh"], windows: ["C:/x"] });
  m = addSetting(m, byId("mcp-servers"), {});
  const tree = modelToTree(m, fixture);
  assert.deepEqual(tree, { version: 1, name: "eng", filesystem: { deny_read: { common: ["~/.ssh"], windows: ["C:/x"] } }, mcp_servers: {} });
  const back = treeToModel(tree, fixture, "profile");
  assert.deepEqual(back.unknown, []);
  assert.deepEqual(back.model.values, m.values);
  assert.deepEqual(back.model.order, m.order);

  const extra = treeToModel({ version: 1, name: "x", bogus: 1, filesystem: { deny_read: { unix: ["/etc"] }, deny_write: { common: ["/"] } } }, fixture, "profile");
  assert.deepEqual(extra.unknown.sort(), ["bogus", "filesystem.deny_write.common"]);
  assert.deepEqual(extra.model.order, ["profile-name", "deny-read"]);
  assert.deepEqual(treeToModel({ version: 2, name: "x" }, fixture, "profile").unknown, ["version"]);
  assert.deepEqual(modelToTree(emptyModel("map"), fixture), { version: 2 });
});

test("treeToModel follows the pasted file's order", () => {
  const { model } = treeToModel({ version: 1, commands: { deny: { unix: ["su"] } }, name: "x" }, fixture, "profile");
  assert.deepEqual(model.order, ["commands-deny", "profile-name"]);
});

test("test_detectKind", () => {
  assert.equal(detectKind({ version: 2, managed_agents: ["codex"] }), "map");
  assert.equal(detectKind({ rules: [] }), "map");
  assert.equal(detectKind({ version: 1, name: "n", cursor: { hooks: {} } }), "native");
  assert.equal(detectKind({ version: 1, name: "n", sandbox: { modes: [] } }), "profile");
  assert.equal(detectKind("just text"), "profile");
});

test("test_applyFixClaudeSandbox", () => {
  const m = applyFix(emptyModel("profile"), "claude-sandbox-split", fixture);
  assert.deepEqual(m.values["claude-sandbox"], { unix: "required", windows: "tools-only" });
  assert.deepEqual(m.order, ["claude-sandbox"]);
  const again = applyFix(m, "claude-sandbox-split", fixture);
  assert.deepEqual(again.order, ["claude-sandbox"]);
});

test("test_applyFixElevated", () => {
  let m = addSetting(emptyModel("profile"), byId("windows-sandbox-implementations"), ["unelevated"]);
  assert.deepEqual(applyFix(m, "windows-fallback-elevated", fixture).values["windows-sandbox-implementations"], ["elevated"]);
  m = addSetting(emptyModel("profile"), byId("windows-sandbox-implementations"), ["unelevated", "elevated"]);
  assert.deepEqual(applyFix(m, "windows-fallback-elevated", fixture).values["windows-sandbox-implementations"], ["elevated"]);
  assert.throws(() => applyFix(m, "map-convert-v1", fixture), /convertV1Map/);
  assert.throws(() => applyFix(m, "nope", fixture), /Unknown fix/);
});

test("test_storageFallsBackWhenUnavailable", () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, "localStorage");
  try {
    Object.defineProperty(globalThis, "localStorage", { configurable: true, get() { throw new Error("denied"); } });
    const store = safeStorage();
    assert.equal(store.load("k"), null);
    assert.doesNotThrow(() => store.save("k", { a: 1 }));
    assert.doesNotThrow(() => store.clear("k"));
    const data = new Map();
    Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
      getItem: k => data.get(k) ?? null, setItem: (k, v) => data.set(k, String(v)), removeItem: k => data.delete(k) } });
    const real = safeStorage();
    real.save("k", { a: 1 });
    assert.deepEqual(real.load("k"), { a: 1 });
    data.set("bad", "{not json");
    assert.equal(real.load("bad"), null);
    real.clear("k");
    assert.equal(real.load("k"), null);
  } finally {
    if (saved) Object.defineProperty(globalThis, "localStorage", saved);
    else delete globalThis.localStorage;
  }
});

test("test_pasteWarnsAboutComments", async () => {
  const edict = await loadEdict();
  assert.equal(edict.pasteNotes("a: 1 # note\n").length, 1);
  assert.equal(edict.pasteNotes('url: "x#y"\n').length, 0);
});

const mapModel = rules => setValue(setValue(emptyModel("map"), "map-standard", { profile: "standard", priority: 100 }), "map-rules", rules);

test("test_renumberRules", () => {
  const rules = [{ profile: "a", priority: 5 }, { profile: "b", priority: 6 }, { profile: "c", priority: 7 }];
  let m = mapModel(rules);
  m = setValue(m, "map-rules", [rules[2], rules[0], rules[1]]);
  assert.deepEqual(renumberRules(m).values["map-rules"].map(r => [r.profile, r.priority]), [["c", 10], ["a", 20], ["b", 30]]);
  const locked = mapModel([{ profile: "a", priority: 5 }, { profile: "b", priority: 15, priorityLocked: true }, { profile: "c" }]);
  assert.deepEqual(renumberRules(locked).values["map-rules"].map(r => r.priority), [10, 15, 30]);
  const clash = mapModel([{ profile: "a", priority: 20, priorityLocked: true }, { profile: "b" }]);
  assert.deepEqual(renumberRules(clash).values["map-rules"].map(r => r.priority), [20, 21]);
  assert.equal(renumberRules(locked).values["map-standard"].priority, 100);
  assert.deepEqual(renumberRules(emptyModel("map")).values, {});
});

test("modelToTree leaves out the builder's priority locks", () => {
  const catalog = { settings: [...fixture.settings, { id: "map-standard", file: "map", status: "supported", yaml_paths: ["standard.profile", "standard.priority"] }] };
  let m = mapModel([{ profile: "a", priority: 15, priorityLocked: true }]);
  m = { ...m, order: ["map-standard", "map-rules"] };
  assert.deepEqual(modelToTree(m, catalog), { version: 2, standard: { profile: "standard", priority: 100 }, rules: [{ profile: "a", priority: 15 }] });
});

test("test_windowsGroupHint", () => {
  const kind = entry => windowsGroupHint(entry).kind;
  assert.equal(kind("S-1-5-21-1-2-3-1104"), "sid");
  assert.equal(kind("s-1-12-1-1"), "sid");
  assert.equal(kind("entra:3f2a8c1e-5b7d-4e2a-9c1f-0a1b2c3d4e5f"), "entra");
  assert.equal(kind(".\\Contractors"), "local");
  assert.equal(kind("CORP\\SG-Engineers"), "domain");
  assert.equal(kind("SG-Engineers"), "invalid");
  assert.equal(kind("entra:nope"), "invalid");
  assert.equal(kind("CORP\\a\\b"), "invalid");
  assert.equal(kind(" padded"), "invalid");
  assert.match(windowsGroupHint("SG-Engineers").message, /SID, entra:<object id>, \.\\LocalGroup or DOMAIN\\Group/);
});

test("test_searchSettings", () => {
  const find = (query, more = {}) => ids(filterSettings(fixture, { file: "profile", query, ...more }));
  assert.deepEqual(find("mxc"), ["codex-prefer-mxc"], "matches the title");
  assert.deepEqual(find("PREFER_MXC"), ["codex-prefer-mxc"], "matches the vendor key, ignoring case");
  assert.deepEqual(find("sudo"), ["commands-deny"], "matches the description");
  assert.deepEqual(find("deny_read"), ["deny-read"], "matches the YAML path");
  assert.deepEqual(find("deny commands"), ["commands-deny"], "every word must match");
  assert.deepEqual(find("deny nothing-like-this"), []);
  assert.deepEqual(find("  "), ids(filterSettings(fixture, { file: "profile" })), "blank searches show everything");
  assert.deepEqual(find("deny", { tools: ["opencode"], oses: ["windows"] }), ["commands-deny"], "search combines with the filters");
});

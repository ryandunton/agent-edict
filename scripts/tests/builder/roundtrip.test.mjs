// Every repository profile, native profile and map loads into the builder
// with nothing left over, and the YAML the builder writes back compiles to
// byte-identical files for every agent on every OS.
import { test } from "node:test";
import assert from "node:assert/strict";
import { readdirSync } from "node:fs";
import path from "node:path";
import { loadEdict, readRepo, repoRoot } from "./load-wasm.mjs";
import { treeToModel, modelToTree, detectKind } from "../../../public/builder/js/model.js";
import { emitYAML } from "../../../public/builder/js/yaml-emit.js";

const catalog = JSON.parse(readRepo("public", "builder", "catalog.json"));
const yamlFiles = dir => readdirSync(path.join(repoRoot, dir)).filter(f => f.endsWith(".yaml")).map(f => path.join(dir, f));
const files = [...yamlFiles("profiles"), ...yamlFiles("examples/role-policy/profiles"), "examples/native/local-guardrails.yaml"];
const OSES = ["windows", "linux", "darwin"];
const NATIVE = ["gemini", "cursor", "antigravity", "copilot", "kiro", "windsurf", "cline"];

for (const file of files) {
  test(`round trip ${file}`, async () => {
    const edict = await loadEdict();
    const original = readRepo(file);
    const tree = edict.yamlToJSON(original);
    const kind = detectKind(tree);
    const { model, unknown } = treeToModel(tree, catalog, kind);
    assert.deepEqual(unknown, [], "paths the builder can't hold");
    const rebuilt = emitYAML(modelToTree(model, catalog));
    assert.deepEqual(edict.yamlToJSON(rebuilt), tree, "the rebuilt YAML parses to the same tree");
    const agents = kind === "native" ? NATIVE.filter(p => p in tree) : ["codex", "claude", "opencode"];
    let compared = 0;
    for (const agent of agents) {
      for (const os of OSES) {
        const before = edict.preview(kind, original, os, agent);
        if (before.error) continue;
        const after = edict.preview(kind, rebuilt, os, agent);
        assert.equal(after.error ?? "", "", `${agent}/${os}`);
        assert.deepEqual(after.files, before.files, `${agent}/${os} files differ`);
        compared++;
      }
    }
    assert.ok(compared > 0, "nothing compiled to compare");
  });
}

test("round trip examples/role-policy/policy-map.yaml", async () => {
  const edict = await loadEdict();
  const original = readRepo("examples", "role-policy", "policy-map.yaml");
  const tree = edict.yamlToJSON(original);
  const { model, unknown } = treeToModel(tree, catalog, "map");
  assert.deepEqual(unknown, []);
  const rebuilt = emitYAML(modelToTree(model, catalog));
  assert.deepEqual(edict.yamlToJSON(rebuilt), tree);
  assert.equal(edict.lintMap(rebuilt).valid, true);
});

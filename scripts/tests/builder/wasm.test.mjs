import { test } from "node:test";
import assert from "node:assert/strict";
import { loadEdict, readRepo } from "./load-wasm.mjs";

test("the WebAssembly runs AgentEdict's own map and profile checks", async () => {
  const edict = await loadEdict();
  assert.equal(edict.lintMap(readRepo("examples", "role-policy", "policy-map.yaml")).valid, true);
  const bad = edict.lintProfile("bogus: 1\n");
  assert.equal(bad.valid, false);
  assert.match(bad.problems[0].message, /bogus/);
  assert.match(edict.version(), /^\d+\.\d+\.\d+$/);
});

test("preview returns files at their installed paths", async () => {
  const edict = await loadEdict();
  const out = edict.preview("profile", readRepo("examples", "role-policy", "profiles", "standard.yaml"), "windows", "codex");
  assert.equal(out.files[0].path, "C:\\ProgramData\\OpenAI\\Codex\\requirements.toml");
  assert.ok(out.files[0].content.length > 0);
});

test("a missing argument is an error, not a crash", async () => {
  await loadEdict();
  const reply = JSON.parse(globalThis.edictBuilder.lintProfile());
  assert.equal(reply.ok, false);
});

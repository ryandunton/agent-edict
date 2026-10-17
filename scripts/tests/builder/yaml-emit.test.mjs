import { test } from "node:test";
import assert from "node:assert/strict";
import { emitYAML } from "../../../public/builder/js/yaml-emit.js";
import { loadEdict } from "./load-wasm.mjs";

const parse = async text => JSON.parse(JSON.stringify((await loadEdict()).yamlToJSON(text)));

test("test_emitQuotesSpecialValues", async () => {
  const tree = { groups: ["CORP\\SG-Engineers", ".\\Contractors", "*", "a: b", "yes", "007", "#x", "", " pad ",
    "-dash", "?q", "it's", 'say "hi"', "tab\there", "null", "~", "1e3", "2026-10-17", "@at", "`tick`", "ok plain", "ünïcode"],
    ":read-only": true, "key with space": 1, "": "empty key" };
  const text = emitYAML(tree);
  assert.deepEqual(await parse(text), tree, text);
  assert.match(text, /- ok plain\n/);
});

test("test_emitMultilineText", async () => {
  const tree = { guardian_extra_policy: "## Heading\n\nApprove when needed.\n", trimmed: "line one\nline two",
    kept: "a\n\n", indented: "  leading spaces\nnext\n" };
  const text = emitYAML(tree);
  assert.match(text, /guardian_extra_policy: \|\n  ## Heading\n\n  Approve when needed.\n/);
  assert.deepEqual(await parse(text), tree, text);
});

test("emits nested maps, lists of maps, and empty collections", async () => {
  const tree = { version: 2, managed_agents: ["codex", "claude"], standard: { profile: "standard", priority: 100 },
    rules: [{ priority: 10, agents: ["all"], match_groups: { windows: ["S-1-5-21-1"], linux: [] } }, { priority: 20, empty: {} }],
    mcp_servers: {}, args: [], nested: [["a", "b"], []], flag: false, n: 0 };
  const text = emitYAML(tree);
  assert.deepEqual(await parse(text), tree, text);
  assert.match(text, /^version: 2\nmanaged_agents:\n  - codex\n  - claude\n/);
  assert.match(text, /rules:\n  - priority: 10\n    agents:\n      - all\n/);
  assert.match(text, /mcp_servers: \{\}\n/);
});

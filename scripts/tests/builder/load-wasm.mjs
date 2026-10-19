// Loads the builder's WebAssembly in Node, the same files the page serves.
import { readFileSync } from "node:fs";
import { fileURLToPath, pathToFileURL } from "node:url";
import path from "node:path";

export const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const builderDir = path.join(repoRoot, "public", "builder");

let api;
export async function loadEdict() {
  if (api) return api;
  await import(pathToFileURL(path.join(builderDir, "wasm_exec.js")).href);
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(readFileSync(path.join(builderDir, "edict.wasm")), go.importObject);
  go.run(instance);
  const raw = globalThis.edictBuilder;
  if (!raw) throw new Error("edictBuilder was not registered");
  const call = name => (...args) => {
    const reply = JSON.parse(raw[name](...args));
    if (!reply.ok) throw new Error(reply.error);
    return reply.value;
  };
  api = Object.fromEntries(["yamlToJSON", "lintProfile", "lintNative", "lintMap", "convertV1Map", "parsePasted", "preview", "version"].map(n => [n, call(n)]));
  return api;
}

export const readRepo = (...parts) => readFileSync(path.join(repoRoot, ...parts), "utf8");

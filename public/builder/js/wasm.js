// Loads AgentEdict's checks (Go compiled to WebAssembly) the first time the
// page needs them: paste, check or preview.
const NAMES = ["yamlToJSON", "lintProfile", "lintNative", "lintMap", "convertV1Map", "parsePasted", "preview", "version"];
let loading;

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const script = Object.assign(document.createElement("script"), { src, onload: resolve,
      onerror: () => reject(new Error(`${src} didn't load`)) });
    document.head.append(script);
  });
}

async function load() {
  if (!globalThis.Go) await loadScript("wasm_exec.js");
  const res = await fetch("edict.wasm");
  if (!res.ok) throw new Error(`edict.wasm: HTTP ${res.status}`);
  const go = new globalThis.Go();
  const { instance } = await WebAssembly.instantiate(await res.arrayBuffer(), go.importObject);
  go.run(instance);
  const raw = globalThis.edictBuilder;
  if (!raw) throw new Error("AgentEdict's checks didn't start");
  return Object.fromEntries(NAMES.map(name => [name, (...args) => {
    const reply = JSON.parse(raw[name](...args.map(String)));
    if (!reply.ok) throw new Error(reply.error);
    return reply.value;
  }]));
}

export function loadEdict() {
  loading ??= load().catch(err => { loading = undefined; throw err; });
  return loading;
}

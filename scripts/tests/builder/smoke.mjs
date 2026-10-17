// Headless Chrome check of the builder page at desktop and phone widths.
// Chrome is driven over --remote-debugging-pipe and the page is served from
// public/ by intercepting requests, so no local web server is needed.
// Usage: node scripts/tests/builder/smoke.mjs [path-to-chrome]
import { spawn } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { repoRoot } from "./load-wasm.mjs";

const chrome = process.argv[2] ?? process.env.CHROME ?? "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const ORIGIN = "http://builder.test";
const TYPES = { ".html": "text/html", ".js": "text/javascript", ".mjs": "text/javascript", ".css": "text/css", ".json": "application/json",
  ".wasm": "application/wasm", ".svg": "image/svg+xml", ".png": "image/png", ".gz": "application/gzip" };
const profileDir = mkdtempSync(path.join(tmpdir(), "builder-smoke-"));
const proc = spawn(chrome, ["--headless=new", "--remote-debugging-pipe", "--no-first-run", "--no-default-browser-check",
  `--user-data-dir=${profileDir}`, "about:blank"], { stdio: ["ignore", "ignore", "ignore", "pipe", "pipe"] });
const [toChrome, fromChrome] = [proc.stdio[3], proc.stdio[4]];
let seq = 0, buf = "";
const pending = new Map(), events = [];
const send = (method, params = {}, sessionId) => new Promise(resolve => {
  const msg = { id: ++seq, method, params };
  if (sessionId) msg.sessionId = sessionId;
  pending.set(msg.id, resolve);
  toChrome.write(JSON.stringify(msg) + "\0");
});
function serve(params, sessionId) {
  const url = new URL(params.request.url);
  const file = path.join(repoRoot, "public", decodeURIComponent(url.pathname));
  if (!file.startsWith(path.join(repoRoot, "public")) || !existsSync(file)) {
    send("Fetch.fulfillRequest", { requestId: params.requestId, responseCode: 404, body: "" }, sessionId);
    return;
  }
  const type = TYPES[path.extname(file)] ?? "application/octet-stream";
  send("Fetch.fulfillRequest", { requestId: params.requestId, responseCode: 200,
    responseHeaders: [{ name: "Content-Type", value: type }], body: readFileSync(file).toString("base64") }, sessionId);
}
fromChrome.on("data", chunk => {
  buf += chunk.toString();
  let i;
  while ((i = buf.indexOf("\0")) >= 0) {
    const msg = JSON.parse(buf.slice(0, i));
    buf = buf.slice(i + 1);
    if (msg.id && pending.has(msg.id)) { pending.get(msg.id)(msg); pending.delete(msg.id); }
    else if (msg.method === "Fetch.requestPaused") serve(msg.params, msg.sessionId);
    else events.push(msg);
  }
});
const sleep = ms => new Promise(r => setTimeout(r, ms));
const failures = [];
const check = (ok, what) => { if (!ok) failures.push(what); };

const { result: { targetId } } = await send("Target.createTarget", { url: "about:blank" });
const { result: { sessionId: s } } = await send("Target.attachToTarget", { targetId, flatten: true });
await send("Fetch.enable", { patterns: [{ urlPattern: `${ORIGIN}/*` }] }, s);
await send("Runtime.enable", {}, s);
await send("Log.enable", {}, s);
await send("Page.enable", {}, s);
const evalJS = async expr => {
  const r = await send("Runtime.evaluate", { expression: expr, returnByValue: true, awaitPromise: true }, s);
  if (r.result.exceptionDetails) throw new Error(JSON.stringify(r.result.exceptionDetails).slice(0, 400));
  return r.result.result.value;
};

// Each stage runs in the page and returns {name: value} facts to check.
const helpers = `
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  const mod = await import("/builder/js/app.js");
  await mod.ready;
  const q = sel => document.querySelector(sel);
  const qa = sel => [...document.querySelectorAll(sel)];
  const yaml = () => q("#yaml").textContent;
  const button = text => qa("button").find(b => b.textContent === text || b.getAttribute("aria-label") === text);
  const overflow = () => document.documentElement.scrollWidth - innerWidth;
  const waitFor = async (fn, ms = 8000) => { const end = Date.now() + ms; let v; while (!(v = fn()) && Date.now() < end) await sleep(50); return v; };
  const paste = async text => {
    button("Paste a file").click();
    const area = await waitFor(() => q("#paste-text"));
    area.value = text;
    button("Load").click();
    await waitFor(() => !q("dialog[open]") || q("dialog[open] .dialog-out button, dialog[open] .dialog-out .error:not(:empty)"));
  };
`;
const repoText = (...parts) => JSON.stringify(readFileSync(path.join(repoRoot, ...parts), "utf8"));

const stages = [
  ["library, filters and help", `
    const r = {};
    r.overflow = overflow();
    r.count = q("#count").textContent;
    const toggle = label => qa(".toggle").find(b => b.textContent === label);
    toggle("OpenCode").click(); toggle("Windows").click();
    await sleep(50);
    r.filtered = q("#count").textContent;
    const reach = (s, t, o) => !["not-applicable", "not-available"].includes(s.reach[t]?.[o]?.level ?? "not-applicable");
    r.allMatch = qa(".lib-item").every(li => reach(mod.app.catalog.settings.find(s => s.id === li.dataset.id), "opencode", "windows"));
    r.filteredItems = qa(".lib-item").length;
    button("Clear all").click();
    await sleep(50);
    r.cleared = q("#count").textContent;
    const mxc = q('.lib-item[data-id="codex-prefer-mxc"]');
    r.mxcLabel = mxc?.querySelector(".label")?.textContent;
    r.mxcAdd = !!mxc?.querySelector("button:not(.info)");
    mxc.querySelector(".info").focus();
    await sleep(50);
    r.helpOnFocus = !q("#help").hidden && q("#help h3").textContent;
    mxc.querySelector(".info").click();
    await sleep(50);
    r.helpPinned = q("#help").textContent.includes("Windows 11 24H2");
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
    await sleep(50);
    r.helpClosed = q("#help").hidden;
    mxc.dispatchEvent(new MouseEvent("mouseenter"));
    q('.lib-item[data-id="codex-prefer-mxc"] .lib-title').dispatchEvent(new MouseEvent("mouseover", { bubbles: true }));
    await sleep(50);
    r.hoverItemShows = !q("#help").hidden;
    mxc.querySelector(".info").dispatchEvent(new MouseEvent("mouseenter"));
    await sleep(50);
    r.hoverInfoShows = !q("#help").hidden;
    mxc.querySelector(".info").dispatchEvent(new MouseEvent("mouseleave"));
    await sleep(300);
    r.leaveHides = q("#help").hidden;
    const search = q("#search");
    search.value = "prefer_mxc"; search.dispatchEvent(new Event("input"));
    await sleep(50);
    r.searchCount = q("#count").textContent;
    r.searchIds = qa(".lib-item").map(li => li.dataset.id);
    r.searchFocus = document.activeElement === search || document.activeElement === document.body;
    search.value = "no such control"; search.dispatchEvent(new Event("input"));
    await sleep(50);
    r.searchNone = q("#library").textContent;
    search.value = "copilot"; search.dispatchEvent(new Event("input"));
    await sleep(50);
    r.elsewhere = q(".elsewhere")?.textContent ?? "";
    q(".elsewhere button")?.click();
    await sleep(50);
    r.jumped = q('.tab[aria-selected="true"]').textContent.startsWith("Native profile") && qa(".lib-item").length > 0 && q("#search").value === "copilot";
    qa(".tab").find(t => t.textContent.startsWith("Profile")).click();
    await sleep(50);
    button("Clear all").click();
    await sleep(50);
    r.searchCleared = q("#search").value === "" && q("#count").textContent;
    button("Add Deny commands to your file").click();
    await sleep(50);
    await sleep(50);
    r.yamlHasDeny = yaml().includes("commands:\\n  deny:\\n    unix:\\n      - sudo");
    r.card = !!q('.card[data-id="commands-deny"]');
    r.overflowAfter = overflow();
    return r;`,
    (r, w) => {
      check(r.overflow <= 0 && r.overflowAfter <= 0, `${w}: horizontal overflow ${r.overflow}/${r.overflowAfter}`);
      const total = r.count.match(/of (\d+)/)?.[1];
      check(r.count === `Showing ${total} of ${total} settings`, `${w}: count ${r.count}`);
      check(r.allMatch && r.filteredItems > 0 && r.filtered !== r.count, `${w}: OpenCode+Windows filter ${r.filtered} (${r.filteredItems})`);
      check(r.cleared === r.count, `${w}: Clear all gave ${r.cleared}`);
      check(r.mxcLabel === "not yet supported by AgentEdict" && !r.mxcAdd, `${w}: MXC item ${r.mxcLabel} add=${r.mxcAdd}`);
      check(r.helpOnFocus === "Codex: prefer the MXC sandbox" && r.helpPinned && r.helpClosed, `${w}: help ${r.helpOnFocus} ${r.helpPinned} ${r.helpClosed}`);
      check(r.yamlHasDeny && r.card, `${w}: adding Deny commands`);
      check(!r.hoverItemShows && r.hoverInfoShows && r.leaveHides, `${w}: details on ? only: item=${r.hoverItemShows} ?=${r.hoverInfoShows} leave=${r.leaveHides}`);
      check(r.searchIds.includes("codex-prefer-mxc") && r.searchIds.length === 1 && r.searchCount === `Showing 1 of ${total} settings`, `${w}: search ${r.searchCount} ${r.searchIds}`);
      check(r.searchNone.includes('No settings match "no such control".'), `${w}: empty search ${r.searchNone}`);
      check(/Also matching: \d+ in Native profile/.test(r.elsewhere) && r.jumped, `${w}: other tabs ${r.elsewhere} jumped=${r.jumped}`);
      check(r.searchCleared === r.count, `${w}: Clear all after search gave ${r.searchCleared}`);
    }],
  ["paste, check, fix and preview", `
    const r = {};
    await paste(${repoText("examples", "role-policy", "profiles", "engineering.yaml")});
    const anyway = button("Load anyway");
    r.engineeringNotes = q("dialog[open] .dialog-out")?.textContent ?? "";
    anyway?.click();
    await waitFor(() => !q("dialog[open]"));
    r.cards = qa(".card").length;
    r.hasMcp = !!q('.card[data-id="mcp-servers"]');
    r.checkPanel = await waitFor(() => !q("#checks").hidden && q("#checks h2")?.textContent);
    await paste("version: 1\\nname: x\\nbogus: 1\\n");
    r.bogus = q("dialog[open] .dialog-out")?.textContent ?? "";
    button("Cancel").click();
    await paste("version: 1\\nname: fixme\\nfilesystem:\\n  deny_read:\\n    common: [\\"~/.ssh\\"]\\n");
    await waitFor(() => q('#checks button[aria-label^="Fix"]'));
    r.firstCards = qa(".card").map(c => c.dataset.id).join(",");
    r.fixButton = !!q('#checks button[aria-label^="Fix"]');
    q('#checks button[aria-label^="Fix"]')?.click();
    await waitFor(() => yaml().includes("claude:"));
    r.fixedYaml = yaml().includes("claude:\\n  sandbox:\\n    unix: required\\n    windows: tools-only");
    r.validAfterFix = await waitFor(() => q("#checks h2")?.textContent === "Valid" && "Valid");
    button("Preview").click();
    await waitFor(() => q("dialog[open] figcaption"));
    r.previewPath = q("dialog[open] figcaption")?.textContent;
    const os = q('dialog[open] select[aria-label="Operating system"]');
    os.value = "linux"; os.dispatchEvent(new Event("change"));
    await waitFor(() => q("dialog[open] figcaption")?.textContent === "/etc/codex/requirements.toml");
    r.linuxPath = q("dialog[open] figcaption")?.textContent;
    r.overflow = overflow();
    return r;`,
    (r, w) => {
      check(r.cards > 20 && r.hasMcp, `${w}: pasted engineering.yaml gave ${r.cards} cards`);
      check(/Comments won't be kept/.test(r.engineeringNotes), `${w}: paste notes ${r.engineeringNotes.slice(0, 120)}`);
      check(!!r.checkPanel, `${w}: check panel after paste`);
      check(/bogus/.test(r.bogus), `${w}: unknown key not reported: ${r.bogus.slice(0, 120)}`);
      check(r.firstCards === "profile-name,deny-read", `${w}: pasted order ${r.firstCards}`);
      check(r.fixButton && r.fixedYaml && r.validAfterFix === "Valid", `${w}: claude sandbox fix ${r.fixButton} ${r.fixedYaml} ${r.validAfterFix}`);
      check(r.previewPath === "C:\\ProgramData\\OpenAI\\Codex\\requirements.toml" && r.linuxPath === "/etc/codex/requirements.toml", `${w}: preview ${r.previewPath} ${r.linuxPath}`);
      check(r.overflow <= 0, `${w}: overflow ${r.overflow}`);
    }],
  ["policy map rules", `
    const r = {};
    const type = (el, text) => { el.value = text; el.dispatchEvent(new Event("input", { bubbles: true })); };
    qa(".tab").find(t => t.textContent.startsWith("Policy map")).click();
    await sleep(50);
    button("Add Group rules to your file").click();
    await sleep(50);
    button("Add rule").click(); await sleep(30);
    button("Add rule").click(); await sleep(30);
    const rules = () => qa(".rule");
    const field = (rule, label) => qa("label", rule).find(l => l.textContent === label)?.control ?? [...rule.querySelectorAll("label")].find(l => l.textContent === label)?.control;
    const fill = (i, profile, os, groups) => {
      const rule = rules()[i];
      type([...rule.querySelectorAll("label")].find(l => l.textContent === "Profile name").control, profile);
      type([...rule.querySelectorAll("label")].find(l => l.textContent === os).control, groups);
    };
    fill(0, "engineering", "Windows", "CORP\\\\SG-Engineers\\nSG-Engineers");
    fill(1, "contractors", "Linux", "contractors");
    r.hints = qa(".group-hints li").map(li => li.textContent);
    type([...rules()[0].querySelectorAll("label")].find(l => l.textContent === "Windows").control, "CORP\\\\SG-Engineers");
    button("Move rule 2 up").click();
    await sleep(50);
    r.yaml = yaml();
    button("Check").click();
    r.valid = await waitFor(() => q("#checks h2")?.textContent === "Valid" && "Valid");
    r.problems = q("#checks")?.textContent?.slice(0, 300);
    r.overflow = overflow();
    return r;`,
    (r, w) => {
      check(r.hints.some(h => h.includes("A group in the CORP domain.")) && r.hints.some(h => h.startsWith("SG-Engineers") && h.includes("Use a SID")), `${w}: group hints ${JSON.stringify(r.hints)}`);
      check(/rules:\n  - priority: 10\n    profile: contractors\n    agents:\n      - all\n    match_groups:\n      linux:\n        - contractors\n  - priority: 20\n    profile: engineering\n/.test(r.yaml), `${w}: rule order in YAML ${r.yaml.slice(-400)}`);
      check(r.valid === "Valid", `${w}: map check ${r.problems}`);
      check(r.overflow <= 0, `${w}: overflow ${r.overflow}`);
    }],
];
export const extraStages = stages;

try {
  for (const width of [1280, 390]) {
    await send("Emulation.setDeviceMetricsOverride", { width, height: 900, deviceScaleFactor: 1, mobile: width < 500 }, s);
    await send("Page.navigate", { url: `${ORIGIN}/builder/index.html` }, s);
    await sleep(800);
    await evalJS("localStorage.clear()");
    for (const [name, body, verify] of stages) {
      await send("Page.reload", {}, s);
      await sleep(800);
      const facts = await evalJS(`(async () => { ${helpers} ${body} })()`);
      if (process.env.SMOKE_VERBOSE) console.log(width, name, JSON.stringify(facts));
      verify(facts, `${width}px ${name}`);
      if (process.env.SMOKE_SHOTS) {
        const shot = await send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true }, s);
        writeFileSync(path.join(process.env.SMOKE_SHOTS, `${name.replace(/\W+/g, "-")}-${width}.png`), Buffer.from(shot.result.data, "base64"));
      }
      await evalJS("localStorage.clear()");
    }
  }
  if (process.env.SMOKE_SHOTS) {
    await send("Emulation.setDeviceMetricsOverride", { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false }, s);
    await send("Page.reload", {}, s);
    await sleep(800);
    await evalJS(`(async () => { ${helpers} const box = q("#search"); box.value = "sandbox"; box.dispatchEvent(new Event("input")); box.focus(); await sleep(100); })()`);
    const searchShot = await send("Page.captureScreenshot", { format: "png" }, s);
    writeFileSync(path.join(process.env.SMOKE_SHOTS, "search-1280.png"), Buffer.from(searchShot.result.data, "base64"));
    await evalJS(`(async () => { ${helpers} const box = q("#search"); box.value = ""; box.dispatchEvent(new Event("input")); q('.lib-item[data-id="deny-read"] .info').click(); await sleep(100); })()`);
    const shot = await send("Page.captureScreenshot", { format: "png" }, s);
    writeFileSync(path.join(process.env.SMOKE_SHOTS, "help-1280.png"), Buffer.from(shot.result.data, "base64"));
    await send("Emulation.setEmulatedMedia", { features: [{ name: "prefers-color-scheme", value: "light" }] }, s);
    await sleep(200);
    const light = await send("Page.captureScreenshot", { format: "png" }, s);
    writeFileSync(path.join(process.env.SMOKE_SHOTS, "help-1280-light.png"), Buffer.from(light.result.data, "base64"));
    await send("Emulation.setEmulatedMedia", { features: [] }, s);
  }
  // Opened straight from disk, browsers block the module scripts; the page must say so.
  await send("Page.navigate", { url: `file://${path.join(repoRoot, "public", "builder", "index.html")}` }, s);
  await sleep(1500);
  const fromDisk = await evalJS(`({ shown: !document.getElementById("boot-error").hidden, items: document.querySelectorAll(".lib-item").length })`);
  check(fromDisk.shown && fromDisk.items === 0, `file:// page: message shown=${fromDisk.shown}`);
  events.length = 0; // the blocked-script errors there are expected
} catch (err) {
  failures.push(`page script failed: ${err.message}`);
}
const consoleErrors = events.filter(e => e.method === "Runtime.exceptionThrown" ||
  (e.method === "Runtime.consoleAPICalled" && ["error", "warning"].includes(e.params.type)) ||
  (e.method === "Log.entryAdded" && e.params.entry.level === "error")).map(e => JSON.stringify(e.params).slice(0, 300));
check(consoleErrors.length === 0, `console errors: ${consoleErrors.join(" | ")}`);
await new Promise(resolve => { proc.once("exit", resolve); proc.kill(); });
try { rmSync(profileDir, { recursive: true, force: true, maxRetries: 5 }); } catch { /* temp dir; the OS cleans it */ }
if (failures.length) { console.error("FAIL\n- " + failures.join("\n- ")); process.exit(1); }
console.log(`PASS: ${stages.length} stages at 1280px and 390px, no console errors`);
process.exit(0);

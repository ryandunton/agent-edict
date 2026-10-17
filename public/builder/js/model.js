// The builder's document model: which settings are on the canvas, in what
// order, with what values, and how that maps to and from a YAML tree.

const FILE_VERSION = { profile: 1, native: 1, map: 2 };
const NATIVE_KEYS = ["gemini", "cursor", "antigravity", "copilot", "kiro", "windsurf", "cline"];
const STRENGTH = ["enforced", "partial", "configuration-only", "not-documented", "not-applicable", "not-available"];
const OFF = new Set(["not-applicable", "not-available"]);

export const clone = value => (value === undefined ? undefined : JSON.parse(JSON.stringify(value)));

// The YAML key a setting owns: the common prefix of its paths, cut before a
// map key (*) or list item ([]).
export function settingRoot(setting) {
  const split = setting.yaml_paths.map(p => p.split("."));
  const root = [];
  for (let i = 0; i < split[0].length; i++) {
    const seg = split[0][i];
    if (!split.every(parts => parts[i] === seg)) break;
    if (seg === "*") break;
    if (seg.endsWith("[]")) { root.push(seg.slice(0, -2)); break; }
    root.push(seg);
  }
  return root.join(".");
}

function reaches(setting, tools, oses) {
  return Object.entries(setting.reach).some(([tool, perOS]) =>
    (tools.length === 0 || tools.includes(tool)) &&
    Object.entries(perOS).some(([os, r]) => (oses.length === 0 || oses.includes(os)) && !OFF.has(r.level)));
}

// Every word of the query must appear in the title, description, vendor key
// or YAML paths, ignoring case.
function matches(setting, words) {
  const text = [setting.title, setting.description, setting.vendor_key, ...(setting.yaml_paths ?? [])].join(" ").toLowerCase();
  return words.every(w => text.includes(w));
}

export function filterSettings(catalog, { file, oses = [], tools = [], query = "" }) {
  const words = query.toLowerCase().split(/\s+/).filter(Boolean);
  return catalog.settings.filter(s => s.file === file && (tools.length + oses.length === 0 || reaches(s, tools, oses)) &&
    (words.length === 0 || matches(s, words)));
}

export const catalogCount = (catalog, file) => catalog.settings.filter(s => s.file === file).length;

export function reachChips(setting, oses = []) {
  return Object.entries(setting.reach).map(([tool, perOS]) => {
    const levels = Object.entries(perOS).filter(([os]) => oses.length === 0 || oses.includes(os)).map(([, r]) => r.level);
    const level = levels.sort((a, b) => STRENGTH.indexOf(a) - STRENGTH.indexOf(b))[0] ?? "not-applicable";
    return { tool, level };
  });
}

export const emptyModel = file => ({ file, values: {}, order: [] });

// The value a setting starts with: its spec's default, else an empty value
// of its type. Object fields without a default start unset.
export function defaultValue(spec) {
  if (!spec) return "";
  if ("default" in spec) return clone(spec.default);
  switch (spec.type) {
    case "bool": return false;
    case "int": return spec.min ?? 0;
    case "enum": return spec.options[0];
    case "string-list": return [];
    case "os-string-list": return { common: [] };
    case "os-enum": return Object.fromEntries((spec.keys ?? ["unix", "windows"]).map(k => [k, spec.options[0]]));
    case "fixed": return spec.value;
    case "map": return {};
    case "list": return [];
    case "object": {
      const out = {};
      for (const f of spec.fields) if ("default" in f || f.type === "fixed") out[f.key] = defaultValue(f);
      return out;
    }
    default: return "";
  }
}

export function addSetting(model, setting, value) {
  if (setting.status !== "supported") throw new Error(`${setting.title ?? setting.id} can't be added: AgentEdict doesn't write it`);
  if (setting.file !== model.file) throw new Error(`${setting.id} belongs in the ${setting.file} file`);
  if (model.order.includes(setting.id)) throw new Error(`${setting.id} is already in the file`);
  return { ...model, values: { ...model.values, [setting.id]: value === undefined ? defaultValue(setting.value) : clone(value) },
           order: [...model.order, setting.id] };
}

export function removeSetting(model, id) {
  const values = { ...model.values };
  delete values[id];
  return { ...model, values, order: model.order.filter(x => x !== id) };
}

export function moveSetting(model, id, delta) {
  const order = [...model.order];
  const from = order.indexOf(id);
  if (from < 0) return model;
  const to = Math.max(0, Math.min(order.length - 1, from + delta));
  order.splice(to, 0, order.splice(from, 1)[0]);
  return { ...model, order };
}

export const setValue = (model, id, value) => ({ ...model, values: { ...model.values, [id]: value } });

function setAt(tree, path, value) {
  const keys = path.split(".");
  let node = tree;
  for (const key of keys.slice(0, -1)) {
    if (typeof node[key] !== "object" || node[key] === null || Array.isArray(node[key])) node[key] = {};
    node = node[key];
  }
  node[keys.at(-1)] = clone(value);
}

// priorityLocked marks a rule priority the admin typed; it never reaches YAML.
const withoutLocks = rules => (Array.isArray(rules) ? rules.map(({ priorityLocked, ...rule }) => rule) : rules);

export function modelToTree(model, catalog) {
  const tree = { version: FILE_VERSION[model.file] };
  for (const id of model.order) {
    const setting = catalog.settings.find(s => s.id === id);
    const value = id === "map-rules" ? withoutLocks(model.values[id]) : model.values[id];
    if (setting && value !== undefined) setAt(tree, settingRoot(setting), value);
  }
  return tree;
}

// Gives policy map rules priorities 10, 20, 30... in list order. A priority
// the admin typed stays; a computed one that clashes moves up by one.
export function renumberRules(model) {
  const rules = model.values["map-rules"];
  return Array.isArray(rules) ? setValue(model, "map-rules", renumberList(rules)) : model;
}

export function renumberList(rules) {
  const taken = new Set(rules.filter(r => r.priorityLocked).map(r => r.priority));
  const next = rules.map((rule, i) => {
    if (rule.priorityLocked) return { ...rule };
    let priority = (i + 1) * 10;
    while (taken.has(priority)) priority++;
    taken.add(priority);
    return { ...rule, priority };
  });
  return next;
}

const SID = /^[Ss]-1(-[0-9]+)+$/;
const GUID = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const GROUP_FORMS = "Use a SID, entra:<object id>, .\\LocalGroup or DOMAIN\\Group.";

// A hint for one Windows group entry, mirroring the forms the map accepts.
// AgentEdict's own check is the authority; this only explains the entry.
export function windowsGroupHint(entry) {
  if (entry !== entry.trim() || entry === "") return { kind: "invalid", message: "Remove the spaces around the group." };
  if (SID.test(entry)) return { kind: "sid", message: "A security identifier (SID)." };
  if (entry.toLowerCase().startsWith("entra:")) {
    return GUID.test(entry.slice(6))
      ? { kind: "entra", message: "A Microsoft Entra group, by object ID. AgentEdict turns it into the group's S-1-12-1 SID." }
      : { kind: "invalid", message: "entra: needs the group's object ID, a GUID." };
  }
  const slash = entry.indexOf("\\");
  const domain = entry.slice(0, slash), name = entry.slice(slash + 1);
  if (slash > 0 && name && !name.includes("\\")) {
    return domain === "." ? { kind: "local", message: "A group on this computer." } : { kind: "domain", message: `A group in the ${domain} domain.` };
  }
  return { kind: "invalid", message: GROUP_FORMS };
}

const isMap = v => typeof v === "object" && v !== null && !Array.isArray(v);

// Every key path in document order, parents before children.
function pathsInOrder(node, prefix = "", out = []) {
  if (!isMap(node)) return out;
  for (const key of Object.keys(node)) {
    const path = prefix ? `${prefix}.${key}` : key;
    out.push(path);
    pathsInOrder(node[key], path, out);
  }
  return out;
}

// Removes the value at path and returns it, pruning parents it leaves empty.
function takeAt(tree, path) {
  const keys = path.split(".");
  const parents = [];
  let node = tree;
  for (const key of keys.slice(0, -1)) {
    if (!isMap(node) || !(key in node)) return undefined;
    parents.push([node, key]);
    node = node[key];
  }
  const last = keys.at(-1);
  if (!isMap(node) || !(last in node)) return undefined;
  const value = node[last];
  delete node[last];
  for (let i = parents.length - 1; i >= 0; i--) {
    const [parent, key] = parents[i];
    if (isMap(parent[key]) && Object.keys(parent[key]).length === 0) delete parent[key];
    else break;
  }
  return value;
}

function leafPaths(node, prefix, out) {
  if (!isMap(node) || Object.keys(node).length === 0) { out.push(prefix); return out; }
  for (const [key, child] of Object.entries(node)) leafPaths(child, prefix ? `${prefix}.${key}` : key, out);
  return out;
}

// Loads a parsed YAML tree. unknown lists the paths no supported setting owns;
// their values are not loaded.
export function treeToModel(tree, catalog, file) {
  const rest = isMap(tree) ? clone(tree) : {};
  const unknown = [];
  if (rest.version !== FILE_VERSION[file]) unknown.push("version");
  delete rest.version;
  const order = pathsInOrder(rest);
  const found = [];
  for (const setting of catalog.settings) {
    if (setting.file !== file || setting.status !== "supported") continue;
    const root = settingRoot(setting);
    const at = order.indexOf(root);
    const value = takeAt(rest, root);
    if (value !== undefined) found.push({ id: setting.id, value, at });
  }
  found.sort((a, b) => a.at - b.at);
  const model = emptyModel(file);
  for (const { id, value } of found) {
    model.values[id] = value;
    model.order.push(id);
  }
  for (const [key, value] of Object.entries(rest)) leafPaths(value, key, unknown);
  return { model, unknown };
}

export function detectKind(tree) {
  if (!isMap(tree)) return "profile";
  if (tree.version === 2 || "managed_agents" in tree || "standard" in tree || "rules" in tree) return "map";
  if (NATIVE_KEYS.some(k => k in tree)) return "native";
  return "profile";
}

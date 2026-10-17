// Writes a plain JSON-like tree as block-style YAML that AgentEdict's YAML
// parser reads back to the same values.

const SPECIAL = /[:#{}\[\],&*!|>'"%@`\\]/;
const LOOKS_TYPED = /^(true|false|yes|no|on|off|y|n|null|~)$/i;
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;

function needsQuotes(s) {
  return s === "" || s !== s.trim() || SPECIAL.test(s) || /^[-?.+\d]/.test(s) || LOOKS_TYPED.test(s) ||
    s.includes("\t") || s.includes("\n") || CONTROL.test(s);
}

// JSON string syntax is valid YAML double-quoted syntax.
const scalarString = s => (needsQuotes(s) ? JSON.stringify(s) : s);
const key = k => scalarString(String(k));

function blockText(s, indent) {
  if (CONTROL.test(s) || s.includes("\r")) return null;
  const body = s.replace(/\n+$/, "");
  const trailing = s.length - body.length;
  const chomp = trailing === 0 ? "-" : trailing === 1 ? "" : "+";
  const indicator = /^[ \n]/.test(s) ? "2" : "";
  const pad = " ".repeat(indent + 2);
  const lines = s.slice(0, trailing > 1 ? s.length - 1 : body.length).split("\n");
  return `|${indicator}${chomp}\n` + lines.map(l => (l === "" ? "" : pad + l)).join("\n") + "\n";
}

function scalar(value, indent) {
  if (value === null || value === undefined) return "null\n";
  if (typeof value === "string") {
    if (value.includes("\n")) {
      const block = blockText(value, indent);
      if (block) return block;
    }
    return scalarString(value) + "\n";
  }
  return String(value) + "\n";
}

const isMap = v => typeof v === "object" && v !== null && !Array.isArray(v);
const isEmpty = v => (Array.isArray(v) ? v.length === 0 : isMap(v) && Object.keys(v).length === 0);
const empty = v => (Array.isArray(v) ? "[]\n" : "{}\n");

function emitMap(map, indent) {
  const pad = " ".repeat(indent);
  let out = "";
  for (const [k, v] of Object.entries(map)) {
    if (isEmpty(v)) out += `${pad}${key(k)}: ${empty(v)}`;
    else if (isMap(v)) out += `${pad}${key(k)}:\n` + emitMap(v, indent + 2);
    else if (Array.isArray(v)) out += `${pad}${key(k)}:\n` + emitList(v, indent + 2);
    else out += `${pad}${key(k)}: ` + scalar(v, indent);
  }
  return out;
}

function emitList(list, indent) {
  const pad = " ".repeat(indent);
  let out = "";
  for (const item of list) {
    if (isEmpty(item)) out += `${pad}- ${empty(item)}`;
    else if (isMap(item)) out += `${pad}- ` + emitMap(item, indent + 2).slice(indent + 2);
    else if (Array.isArray(item)) out += `${pad}-\n` + emitList(item, indent + 2);
    else out += `${pad}- ` + scalar(item, indent);
  }
  return out;
}

export function emitYAML(tree) {
  return isEmpty(tree) ? "{}\n" : emitMap(tree, 0);
}

// One-click fixes for problems the Go checks report, by fix id.
import { addSetting, setValue } from "./model.js";

function put(model, catalog, id, value) {
  if (model.order.includes(id)) return setValue(model, id, value);
  return addSetting(model, catalog.settings.find(s => s.id === id), value);
}

export function applyFix(model, fixId, catalog) {
  switch (fixId) {
    case "claude-sandbox-split":
      return put(model, catalog, "claude-sandbox", { unix: "required", windows: "tools-only" });
    case "windows-fallback-elevated": {
      const current = model.values["windows-sandbox-implementations"] ?? [];
      return put(model, catalog, "windows-sandbox-implementations",
        [...new Set(current.map(v => (v === "unelevated" ? "elevated" : v)))]);
    }
    case "map-convert-v1":
      throw new Error("map-convert-v1 is applied with convertV1Map");
    default:
      throw new Error(`Unknown fix ${fixId}`);
  }
}

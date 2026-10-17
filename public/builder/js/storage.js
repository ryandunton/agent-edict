// Autosave that quietly turns itself off when browser storage is unavailable
// (private windows, blocked site data).
export function safeStorage() {
  const store = () => { try { return globalThis.localStorage ?? null; } catch { return null; } };
  return {
    load(key) {
      try { const raw = store()?.getItem(key); return raw == null ? null : JSON.parse(raw); } catch { return null; }
    },
    save(key, value) {
      try { store()?.setItem(key, JSON.stringify(value)); } catch { /* autosave off */ }
    },
    clear(key) {
      try { store()?.removeItem(key); } catch { /* autosave off */ }
    },
  };
}

// Minimal localStorage shim so the browser store can run under node for tests.
// Mirrors the real Storage semantics for key()/length so tests don't drift.
const mem = new Map<string, string>();
(globalThis as unknown as { localStorage: Storage }).localStorage = {
  getItem: (k: string) => (mem.has(k) ? (mem.get(k) as string) : null),
  setItem: (k: string, v: string) => void mem.set(k, String(v)),
  removeItem: (k: string) => void mem.delete(k),
  clear: () => mem.clear(),
  key: (index: number) => Array.from(mem.keys())[index] ?? null,
  get length() {
    return mem.size;
  },
} as Storage;

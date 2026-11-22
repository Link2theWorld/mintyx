/** A controllable matchMedia for jsdom: tests flip media features and listeners fire. */
type Listener = (e: MediaQueryListEvent) => void;

const features = { dark: false, mobile: false };
const lists = new Set<{ query: string; listeners: Set<Listener> }>();

function evaluate(query: string): boolean {
  if (query.includes("prefers-color-scheme: dark")) return features.dark;
  if (query.includes("max-width")) return features.mobile;
  return false;
}

export function installMatchMedia(): void {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    configurable: true,
    value: (query: string) => {
      const entry = { query, listeners: new Set<Listener>() };
      lists.add(entry);
      return {
        get matches() { return evaluate(query); },
        media: query,
        onchange: null,
        addEventListener: (_: string, l: Listener) => entry.listeners.add(l),
        removeEventListener: (_: string, l: Listener) => entry.listeners.delete(l),
        dispatchEvent: () => false,
      } as unknown as MediaQueryList;
    },
  });
}

export function setMedia(next: Partial<typeof features>): void {
  Object.assign(features, next);
  for (const entry of lists) {
    const event = { matches: evaluate(entry.query), media: entry.query } as MediaQueryListEvent;
    for (const l of entry.listeners) l(event);
  }
}

export function resetMedia(): void {
  features.dark = false;
  features.mobile = false;
  lists.clear();
}

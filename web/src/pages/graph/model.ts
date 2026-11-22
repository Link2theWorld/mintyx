import type { Exit, ExitLatency, Line, Routing } from "../../api/schemas";

/** The longest chain of exits a line may leave through; the server enforces the same. */
export const MAX_HOPS = 4;

/**
 * Wiring the admin has drawn but not applied yet. Applying costs one Xray restart, which drops
 * visitors' open connections, so edits collect here first.
 */
export interface Draft {
  lineExit: Record<number, number | null>;
  exitNext: Record<number, number | null>;
}

export function draftFrom(lines: Line[], exits: Exit[]): Draft {
  const d: Draft = { lineExit: {}, exitNext: {} };
  for (const l of lines) d.lineExit[l.id] = l.exitId ?? null;
  for (const e of exits) d.exitNext[e.id] = e.nextId;
  return d;
}

/** The changed entries only, ready for PUT /api/routing; null when nothing changed. */
export function changes(draft: Draft, base: Draft): Routing | null {
  const lines = Object.entries(draft.lineExit)
    .filter(([id, v]) => id in base.lineExit && base.lineExit[Number(id)] !== v)
    .map(([id, v]) => ({ id: Number(id), exitId: v }));
  const exits = Object.entries(draft.exitNext)
    .filter(([id, v]) => id in base.exitNext && base.exitNext[Number(id)] !== v)
    .map(([id, v]) => ({ id: Number(id), nextId: v }));
  return lines.length + exits.length === 0 ? null : { lines, exits };
}

export function changeCount(draft: Draft, base: Draft): number {
  const c = changes(draft, base);
  return c ? c.lines.length + c.exits.length : 0;
}

/** One wiring edit: what the server had when the admin changed it, and what they chose. */
export interface Edit { from: number | null; to: number | null }

/**
 * Only the entries the admin actually changed, each with the value it replaced. Laid over the
 * server's latest wiring, an edit counts only while the server still has its from value: if
 * someone else changed that entry meanwhile (another device or tab), the server wins and the
 * stale edit is dropped instead of being written back.
 */
export interface Edits {
  lineExit: Record<number, Edit>;
  exitNext: Record<number, Edit>;
}

export const noEdits: Edits = { lineExit: {}, exitNext: {} };

export function editCount(e: Edits): number {
  return Object.keys(e.lineExit).length + Object.keys(e.exitNext).length;
}

/** The entries where draft differs from base, remembering base's value. */
export function editsBetween(draft: Draft, base: Draft): Edits {
  const out: Edits = { lineExit: {}, exitNext: {} };
  for (const l of changes(draft, base)?.lines ?? []) out.lineExit[l.id] = { from: base.lineExit[l.id] ?? null, to: l.exitId };
  for (const e of changes(draft, base)?.exits ?? []) out.exitNext[e.id] = { from: base.exitNext[e.id] ?? null, to: e.nextId };
  return out;
}

/** The edits that still apply to base: the entry exists, still holds from, and to still exists. */
export function prune(edits: Edits, base: Draft): Edits {
  const usable = (to: number | null) => to === null || to in base.exitNext;
  const keep = (m: Record<number, Edit>, now: Record<number, number | null>) => {
    const out: Record<number, Edit> = {};
    for (const [id, e] of Object.entries(m)) {
      if (id in now && (now[Number(id)] ?? null) === e.from && usable(e.to)) out[Number(id)] = e;
    }
    return out;
  };
  return { lineExit: keep(edits.lineExit, base.lineExit), exitNext: keep(edits.exitNext, base.exitNext) };
}

/**
 * The server's wiring with the admin's edits on top. If the result would loop or run too long,
 * because someone else's newer wiring combines badly with these edits, the exit-to-exit edits
 * are left out rather than showing (and later sending) an impossible chain.
 */
export function overlay(base: Draft, edits: Edits): Draft {
  const live = prune(edits, base);
  const apply = (withExits: boolean): Draft => {
    const out: Draft = { lineExit: { ...base.lineExit }, exitNext: { ...base.exitNext } };
    for (const [id, e] of Object.entries(live.lineExit)) out.lineExit[Number(id)] = e.to;
    if (withExits) for (const [id, e] of Object.entries(live.exitNext)) out.exitNext[Number(id)] = e.to;
    return out;
  };
  const full = apply(true);
  return firstProblem(full) ? apply(false) : full;
}

/**
 * The edits as the page keeps them once base is known: only what overlay actually shows. Edits
 * base overtook, exit edits overlay leaves out because they no longer fit, and edits base has
 * caught up with are all dropped, so none can come back later.
 */
export function settle(edits: Edits, base: Draft): Edits {
  return editsBetween(overlay(base, edits), base);
}

/** Reads edits back from storage, or none when the stored value is not edits of this shape. */
export function parseEdits(raw: unknown): Edits {
  const isId = (v: unknown) => v === null || (typeof v === "number" && Number.isInteger(v));
  const isMap = (m: unknown): m is Record<number, Edit> =>
    typeof m === "object" && m !== null && !Array.isArray(m) &&
    Object.entries(m).every(([k, v]) => /^\d+$/.test(k) && typeof v === "object" && v !== null &&
      isId((v as Edit).from) && isId((v as Edit).to));
  if (typeof raw !== "object" || raw === null) return noEdits;
  const r = raw as Partial<Edits>;
  return isMap(r.lineExit) && isMap(r.exitNext) ? { lineExit: r.lineExit, exitNext: r.exitNext } : noEdits;
}

export type ChainProblem = { kind: "loop"; ids: number[] } | { kind: "tooLong"; ids: number[] };

/** The exits traffic entering at first passes, in order, or why that chain is unusable. */
export function chainFrom(draft: Draft, first: number | null): { ids: number[]; problem?: ChainProblem } {
  const ids: number[] = [];
  const seen = new Set<number>();
  for (let id = first; id !== null; id = draft.exitNext[id] ?? null) {
    if (seen.has(id)) return { ids, problem: { kind: "loop", ids: [...ids, id] } };
    seen.add(id);
    ids.push(id);
    if (ids.length > MAX_HOPS) return { ids, problem: { kind: "tooLong", ids } };
  }
  return { ids };
}

/** Whether the draft, after an edit, still has every exit's onward chain finite and short. */
export function firstProblem(draft: Draft): ChainProblem | null {
  for (const id of Object.keys(draft.exitNext)) {
    const { problem } = chainFrom(draft, Number(id));
    if (problem) return problem;
  }
  return null;
}

export const nodeId = {
  visitors: "visitors",
  server: "server",
  internet: "internet",
  line: (id: number) => `line-${String(id)}`,
  exit: (id: number) => `exit-${String(id)}`,
};

export function parseNodeId(id: string): { kind: "line" | "exit"; id: number } | { kind: "visitors" | "server" | "internet" } {
  const m = /^(line|exit)-(\d+)$/.exec(id);
  if (m) return { kind: m[1] as "line" | "exit", id: Number(m[2]) };
  return { kind: id as "visitors" | "server" | "internet" };
}

/**
 * Applies a drawn connection to the draft. Returns the new draft, or null when the connection
 * means nothing (e.g. into a line), and a problem when it would close a loop or be too long.
 */
export function connect(draft: Draft, source: string, target: string): { draft: Draft | null; problem?: ChainProblem } {
  const s = parseNodeId(source);
  const t = parseNodeId(target);
  const to = t.kind === "exit" ? t.id : t.kind === "internet" ? null : undefined;
  if (to === undefined) return { draft: null };
  let next: Draft;
  if (s.kind === "line") next = { ...draft, lineExit: { ...draft.lineExit, [s.id]: to } };
  else if (s.kind === "exit") {
    if (to === s.id) return { draft: null };
    next = { ...draft, exitNext: { ...draft.exitNext, [s.id]: to } };
  } else return { draft: null };
  const problem = firstProblem(next);
  return problem ? { draft: null, problem } : { draft: next };
}

/** Sends the source of an edge straight to the internet, as deleting the edge means. */
export function disconnect(draft: Draft, source: string): Draft {
  const s = parseNodeId(source);
  if (s.kind === "line") return { ...draft, lineExit: { ...draft.lineExit, [s.id]: null } };
  if (s.kind === "exit") return { ...draft, exitNext: { ...draft.exitNext, [s.id]: null } };
  return draft;
}

export interface GraphEdge {
  id: string;
  source: string;
  target: string;
  /** Traffic flows here: an enabled line's path. */
  live: boolean;
  /** Drawn but not applied. */
  pending: boolean;
  /** The target exit cannot be reached from the server. */
  broken: boolean;
  /** Edges from the visitors are part of the picture, not wiring the admin can change. */
  fixed: boolean;
}

/** Every edge of the graph for this draft, compared against what the server runs (base). */
export function edgesFor(lines: Line[], exits: Exit[], draft: Draft, base: Draft, latency?: ExitLatency): GraphEdge[] {
  const broken = new Set((latency?.exits ?? []).filter((l) => l.error).map((l) => l.id));
  // Exits reached from an enabled line carry traffic; follow each line's chain to find them.
  const liveExits = new Set<number>();
  for (const l of lines) {
    if (!l.enabled) continue;
    for (const id of chainFrom(draft, draft.lineExit[l.id] ?? null).ids) liveExits.add(id);
  }
  const reached = new Set<number>();
  for (const l of lines) {
    const first = draft.lineExit[l.id];
    if (first !== null && first !== undefined) reached.add(first);
  }
  for (const e of exits) {
    const next = draft.exitNext[e.id];
    if (next !== null && next !== undefined) reached.add(next);
  }

  const edges: GraphEdge[] = [];
  for (const l of lines) {
    edges.push({ id: `v-${String(l.id)}`, source: nodeId.visitors, target: nodeId.line(l.id), live: l.enabled, pending: false, broken: false, fixed: true });
    const to = draft.lineExit[l.id] ?? null;
    edges.push({
      id: `l-${String(l.id)}`,
      source: nodeId.line(l.id),
      target: to === null ? nodeId.internet : nodeId.exit(to),
      live: l.enabled,
      pending: (base.lineExit[l.id] ?? null) !== to,
      broken: to !== null && broken.has(to),
      fixed: false,
    });
  }
  for (const e of exits) {
    const to = draft.exitNext[e.id] ?? null;
    // An exit nothing sends traffic to and that sends nowhere has no edge yet: it floats.
    if (to === null && !reached.has(e.id)) continue;
    edges.push({
      id: `e-${String(e.id)}`,
      source: nodeId.exit(e.id),
      target: to === null ? nodeId.internet : nodeId.exit(to),
      live: liveExits.has(e.id),
      pending: (base.exitNext[e.id] ?? null) !== to,
      broken: to !== null && broken.has(to),
      fixed: false,
    });
  }
  return edges;
}

/** The nodes and edges on the way from the visitors to the internet through node. */
export function pathThrough(node: string, edges: GraphEdge[]): Set<string> {
  const on = new Set<string>([node]);
  const out = new Map<string, GraphEdge[]>();
  const into = new Map<string, GraphEdge[]>();
  for (const e of edges) {
    out.set(e.source, [...(out.get(e.source) ?? []), e]);
    into.set(e.target, [...(into.get(e.target) ?? []), e]);
  }
  const walk = (from: string, step: Map<string, GraphEdge[]>, next: (e: GraphEdge) => string) => {
    const queue = [from];
    while (queue.length > 0) {
      const n = queue.shift() ?? "";
      for (const e of step.get(n) ?? []) {
        if (on.has(e.id)) continue;
        on.add(e.id);
        const m = next(e);
        if (!on.has(m)) {
          on.add(m);
          queue.push(m);
        }
      }
    }
  };
  walk(node, out, (e) => e.target);
  walk(node, into, (e) => e.source);
  return on;
}

export interface Position { x: number; y: number }

/**
 * Where nodes go when the admin has not placed them: visitors on the left, the server's lines
 * in a column, exits in columns by how far down a chain they first appear, the internet last.
 */
export function defaultLayout(lines: Line[], exits: Exit[], draft: Draft): Record<string, Position> {
  const pos: Record<string, Position> = {};
  const col = (i: number) => 40 + i * 300;
  const depth = new Map<number, number>();
  for (const l of lines) {
    chainFrom(draft, draft.lineExit[l.id] ?? null).ids.forEach((id, i) => {
      depth.set(id, Math.min(depth.get(id) ?? Infinity, i));
    });
  }
  for (const e of exits) if (!depth.has(e.id)) depth.set(e.id, 0);
  const maxDepth = Math.max(0, ...depth.values());
  const linesHeight = Math.max(1, lines.length) * 120;
  pos[nodeId.visitors] = { x: col(0), y: 40 + linesHeight / 2 - 50 };
  pos[nodeId.server] = { x: col(1) - 20, y: 0 };
  lines.forEach((l, i) => { pos[nodeId.line(l.id)] = { x: 20, y: 60 + i * 120 }; });
  const rows = new Map<number, number>();
  for (const e of exits) {
    const d = depth.get(e.id) ?? 0;
    const r = rows.get(d) ?? 0;
    rows.set(d, r + 1);
    pos[nodeId.exit(e.id)] = { x: col(2 + d), y: 40 + r * 130 };
  }
  pos[nodeId.internet] = { x: col(3 + maxDepth), y: 40 + linesHeight / 2 - 40 };
  return pos;
}

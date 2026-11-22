import { describe, expect, it } from "vitest";
import type { Exit, Line } from "../../api/schemas";
import { changeCount, changes, connect, disconnect, draftFrom, edgesFor, editsBetween, noEdits, overlay, parseEdits, pathThrough, prune, settle } from "./model";

const line = (id: number, exitId: number | null, enabled = true): Line => ({
  id, name: `L${String(id)}`, protocol: "vless-reality", port: 440 + id, enabled, host: "", createdAt: "", exitId,
  reality: { publicKey: "", shortId: "", serverName: "", target: "" },
});
function must<T>(v: T | null): T {
  if (v === null) throw new Error("unexpected null");
  return v;
}
const exit = (id: number, nextId: number | null): Exit => ({
  id, name: `E${String(id)}`, region: "", nextId, createdAt: "",
  summary: { protocol: "shadowsocks", host: "h", port: 1, network: "", security: "none", serverName: "", flow: "", method: "", auth: false, obfs: false, pinned: false, plaintext: false, udp: false },
});

describe("route graph model", () => {
  const lines = [line(1, null), line(2, 10, false)];
  const exits = [exit(10, 11), exit(11, null), exit(12, null)];
  const base = draftFrom(lines, exits);

  it("collects edits and sends only what changed", () => {
    const d = must(connect(must(connect(base, "line-1", "exit-10").draft), "exit-11", "exit-12").draft);
    expect(changeCount(d, base)).toBe(2);
    expect(changes(d, base)).toEqual({ lines: [{ id: 1, exitId: 10 }], exits: [{ id: 11, nextId: 12 }] });
    expect(changes(base, base)).toBeNull();
    expect(disconnect(d, "line-1").lineExit[1]).toBeNull();
  });

  it("refuses loops and chains longer than four exits", () => {
    expect(connect(base, "exit-11", "exit-10").problem?.kind).toBe("loop");
    expect(connect(base, "exit-12", "exit-12").draft).toBeNull();
    const long = [exit(1, 2), exit(2, 3), exit(3, 4), exit(4, null), exit(5, null)];
    const d = draftFrom([], long);
    expect(connect(d, "exit-4", "exit-5").problem?.kind).toBe("tooLong");
    expect(connect(d, "line-1", "line-2").draft).toBeNull();
  });

  it("marks live, pending and fixed edges", () => {
    const d = must(connect(base, "line-1", "exit-10").draft);
    const edges = edgesFor(lines, exits, d, base);
    const byId = Object.fromEntries(edges.map((e) => [e.id, e]));
    expect(byId["v-1"]).toMatchObject({ fixed: true, live: true });
    expect(byId["l-1"]).toMatchObject({ target: "exit-10", live: true, pending: true });
    expect(byId["l-2"]).toMatchObject({ target: "exit-10", live: false, pending: false });
    expect(byId["e-11"]).toMatchObject({ target: "internet", live: true });
    // Exit 12 is unwired: no edge at all.
    expect(edges.some((e) => e.source === "exit-12")).toBe(false);
    const on = pathThrough("exit-10", edges);
    expect(on.has("visitors") && on.has("internet") && on.has("line-1")).toBe(true);
  });

  it("lays only the admin's own edits on the server's latest wiring", () => {
    // Line 1 is edited here; meanwhile another device wires line 2 elsewhere.
    const edits = editsBetween(must(connect(base, "line-1", "exit-12").draft), base);
    expect(edits).toEqual({ lineExit: { 1: { from: null, to: 12 } }, exitNext: {} });
    const later = draftFrom([line(1, null), line(2, 11)], exits);
    const d = overlay(later, edits);
    expect(d.lineExit).toEqual({ 1: 12, 2: 11 }); // line 2 keeps the newer wiring
    expect(changes(d, later)).toEqual({ lines: [{ id: 1, exitId: 12 }], exits: [] });
    // Edits about things that are gone are skipped.
    const gone = draftFrom([line(1, null)], [exit(10, 11), exit(11, null)]);
    expect(overlay(gone, edits).lineExit).toEqual({ 1: null });
  });

  it("drops an edit once the server changed that entry, and never brings it back", () => {
    const edits = editsBetween(must(connect(base, "line-1", "exit-10").draft), base);
    // Another device applies the same change: nothing is pending, and the edit is spent.
    const same = draftFrom([line(1, 10), line(2, 10, false)], exits);
    expect(changeCount(overlay(same, edits), same)).toBe(0);
    expect(prune(edits, same)).toEqual(noEdits);
    // Even if line 1 later goes back to its old value, a pruned edit stays gone.
    const back = draftFrom([line(1, null), line(2, 10, false)], exits);
    expect(changeCount(overlay(back, prune(edits, same)), back)).toBe(0);
  });

  it("leaves out exit edits that would loop with someone else's newer wiring", () => {
    // Here exit 12 is sent to exit 10 (10 -> 11 on the server); elsewhere 11 -> 12 is saved.
    const edits = editsBetween(must(connect(base, "exit-12", "exit-10").draft), base);
    const later = draftFrom(lines, [exit(10, 11), exit(11, 12), exit(12, null)]);
    const d = overlay(later, edits);
    expect(d.exitNext[12]).toBeNull();
    expect(changes(d, later)).toBeNull();
    // Settling drops the left-out edit for good: once the server removes 11 -> 12 again, it
    // does not reappear as a pending change nobody made on this screen.
    const kept = settle(edits, later);
    expect(kept).toEqual(noEdits);
    const after = draftFrom(lines, [exit(10, 11), exit(11, null), exit(12, null)]);
    expect(changeCount(overlay(after, kept), after)).toBe(0);
  });

  it("keeps line edits when settling drops exit edits that no longer fit", () => {
    let d = must(connect(base, "line-1", "exit-12").draft);
    d = must(connect(d, "exit-12", "exit-10").draft);
    const edits = editsBetween(d, base);
    const later = draftFrom(lines, [exit(10, 11), exit(11, 12), exit(12, null)]);
    expect(settle(edits, later)).toEqual({ lineExit: { 1: { from: null, to: 12 } }, exitNext: {} });
  });

  it("ignores stored edits of the wrong shape", () => {
    expect(parseEdits(null)).toEqual(noEdits);
    expect(parseEdits({})).toEqual(noEdits);
    expect(parseEdits({ lineExit: { 1: 5 }, exitNext: {} })).toEqual(noEdits);
    expect(parseEdits({ lineExit: { 1: { from: null, to: 5 } }, exitNext: {} })).toEqual({ lineExit: { 1: { from: null, to: 5 } }, exitNext: {} });
  });
});

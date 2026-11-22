import type { ReachStatus, ReachTarget, ReachVerdict } from "../api/schemas";
import type { MessageKey } from "../i18n/zh";

/** What the overview card shows instead of the list, or "list" when there are lines to show. */
export type ReachView = "off" | "noHost" | "noLines" | "list";

export function reachView(s: ReachStatus): ReachView {
  if (!s.enabled) return "off";
  // A missing address hides lines from `targets`, so it must win over the empty-list message.
  if (!s.configured) return "noHost";
  return s.targets.length === 0 ? "noLines" : "list";
}

export const verdictColor: Record<ReachVerdict, "success" | "error" | "warning" | "default"> = {
  ok: "success",
  port_blocked: "error",
  ip_blocked: "error",
  down: "warning",
  unknown: "default",
};

const isBad = (v: ReachVerdict | "") => v === "port_blocked" || v === "ip_blocked" || v === "down";

/** A bad latest round that the confirmed verdict does not reflect yet. */
export function pendingResult(t: ReachTarget): ReachVerdict | null {
  return t.lastResult !== "" && isBad(t.lastResult) && t.lastResult !== t.verdict ? t.lastResult : null;
}

/** The sentence under a line telling the owner what the verdict means and what to do, if anything. */
export function adviceKey(t: ReachTarget): MessageKey | null {
  switch (t.verdict) {
    case "ok": return null;
    case "unknown": return t.lastResult === "" ? "reach.notChecked" : "reach.advice.unknown";
    default: return `reach.advice.${t.verdict}`;
  }
}

const errorKeys: Record<string, MessageKey> = {
  rate_limited: "reach.err.rate_limited",
  too_many_lines: "reach.err.too_many_lines",
  probe_failed: "reach.err.probe_failed",
};

/** The note for the last round's error; an error code this build does not know still gets one. */
export function roundErrorKey(code: string): MessageKey | null {
  if (code === "") return null;
  return errorKeys[code] ?? "reach.err.probe_failed";
}

/** "host:port" as a client would dial it; a UDP line shows the address alone since only that was tested. */
export function targetAddress(t: ReachTarget): string {
  if (t.ipOnly) return t.host;
  return t.host.includes(":") ? `[${t.host}]:${String(t.port)}` : `${t.host}:${String(t.port)}`;
}

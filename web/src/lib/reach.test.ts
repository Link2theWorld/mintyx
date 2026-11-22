import { describe, expect, it } from "vitest";
import type { ReachStatus, ReachTarget } from "../api/schemas";
import { adviceKey, pendingResult, reachView, roundErrorKey, targetAddress } from "./reach";

const target = (over: Partial<ReachTarget> = {}): ReachTarget => ({
  lineId: 1, lineName: "Tokyo", protocol: "vless-reality", host: "vps.example.com", port: 443, ipOnly: false,
  verdict: "ok", since: null, lastResult: "ok", chinaReached: 5, chinaAnswered: 5, controlReached: 3, controlAnswered: 3,
  ...over,
});

const status = (over: Partial<ReachStatus> = {}): ReachStatus => ({
  enabled: true, configured: true, running: false, lastCheckAt: null, nextCheckAt: null,
  lastError: "", lastErrorDetail: "", alertError: "", targets: [target()], ...over,
});

describe("reachView", () => {
  it.each([
    ["off wins over everything, nothing is probed", status({ enabled: false, configured: false, targets: [] }), "off"],
    ["a missing address is named even though the list is empty", status({ configured: false, targets: [] }), "noHost"],
    ["no enabled lines", status({ targets: [] }), "noLines"],
    ["lines to show", status(), "list"],
    ["lines with their own address still show while another lacks one", status({ configured: false }), "noHost"],
  ] as const)("%s", (_, s, want) => {
    expect(reachView(s)).toBe(want);
  });
});

describe("pendingResult", () => {
  it.each([
    ["first bad round while still confirmed ok", target({ verdict: "ok", lastResult: "port_blocked" }), "port_blocked"],
    ["bad round before anything was confirmed", target({ verdict: "unknown", lastResult: "down" }), "down"],
    ["confirmed trouble is not pending", target({ verdict: "ip_blocked", lastResult: "ip_blocked" }), null],
    ["a round without data is not pending trouble", target({ verdict: "ok", lastResult: "unknown" }), null],
    ["never checked", target({ verdict: "unknown", lastResult: "" }), null],
    ["recovery waits for confirmation too", target({ verdict: "down", lastResult: "ok" }), "ok"],
    ["confirmed ok is not pending", target(), null],
  ] as const)("%s", (_, t, want) => {
    expect(pendingResult(t)).toBe(want);
  });
});

describe("adviceKey", () => {
  it.each([
    [target(), null],
    [target({ verdict: "port_blocked" }), "reach.advice.port_blocked"],
    [target({ verdict: "ip_blocked" }), "reach.advice.ip_blocked"],
    [target({ verdict: "down" }), "reach.advice.down"],
    [target({ verdict: "unknown", lastResult: "unknown" }), "reach.advice.unknown"],
    [target({ verdict: "unknown", lastResult: "" }), "reach.notChecked"],
  ] as const)("%#", (t, want) => {
    expect(adviceKey(t)).toBe(want);
  });
});

describe("roundErrorKey", () => {
  it("has no note for a clean round and a generic one for a code added later", () => {
    expect(roundErrorKey("")).toBeNull();
    expect(roundErrorKey("rate_limited")).toBe("reach.err.rate_limited");
    expect(roundErrorKey("quota_gone")).toBe("reach.err.probe_failed");
  });
});

describe("targetAddress", () => {
  it("brackets IPv6 and drops the port of a line whose port was not tested", () => {
    expect(targetAddress(target())).toBe("vps.example.com:443");
    expect(targetAddress(target({ host: "2001:db8::1" }))).toBe("[2001:db8::1]:443");
    expect(targetAddress(target({ ipOnly: true, port: 8443 }))).toBe("vps.example.com");
  });
});

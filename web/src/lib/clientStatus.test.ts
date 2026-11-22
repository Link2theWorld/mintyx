import { describe, expect, it } from "vitest";
import type { Client } from "../api/schemas";
import { clientStatus } from "./clientStatus";

const GB = 1024 ** 3;
const now = new Date("2026-06-01T12:00:00Z");

function client(over: Partial<Client>): Client {
  return { id: 1, name: "c", disabled: "", quotaBytes: 0, expiresAt: null, usedUp: 0, usedDown: 0, createdAt: "2026-01-01T00:00:00Z", quotaResetDay: 0, nextResetAt: null, ...over };
}

describe("clientStatus", () => {
  it.each([
    ["", "active"],
    ["manual", "manual"],
    ["quota", "quota"],
    ["expired", "expired"],
  ] as const)("disabled=%j → %s", (disabled, state) => {
    expect(clientStatus(client({ disabled }), now).state).toBe(state);
  });

  it("sums up and down traffic against the quota", () => {
    const s = clientStatus(client({ quotaBytes: 10 * GB, usedUp: 2 * GB, usedDown: 3 * GB }), now);
    expect([s.used, s.fraction, s.nearQuota]).toEqual([5 * GB, 0.5, false]);
  });

  it("warns at 90% of quota but not just below", () => {
    expect(clientStatus(client({ quotaBytes: 100, usedDown: 90 }), now).nearQuota).toBe(true);
    expect(clientStatus(client({ quotaBytes: 100, usedDown: 89 }), now).nearQuota).toBe(false);
  });

  it("has no fraction and never warns when unlimited", () => {
    const s = clientStatus(client({ quotaBytes: 0, usedDown: 50 * GB }), now);
    expect([s.fraction, s.nearQuota]).toEqual([null, false]);
  });

  it("does not add a near-quota warning once the client is already stopped for quota", () => {
    const s = clientStatus(client({ disabled: "quota", quotaBytes: 100, usedDown: 120 }), now);
    expect([s.state, s.nearQuota]).toEqual(["quota", false]);
  });

  it("warns when expiry is within 3 days", () => {
    expect(clientStatus(client({ expiresAt: "2026-06-04T12:00:00Z" }), now).nearExpiry).toBe(true);
    expect(clientStatus(client({ expiresAt: "2026-06-05T12:00:01Z" }), now).nearExpiry).toBe(false);
  });
});

import { describe, expect, it } from "vitest";
import { BYTES_PER_GB, MAX_QUOTA_GB, bytesToGb, daysUntil, formatBytes, gbToBytes } from "./format";

describe("formatBytes", () => {
  it.each([
    [0, "0 B"],
    [-5, "0 B"],
    [1023, "1023 B"],
    [1024, "1 KB"],
    [1536, "1.5 KB"],
    [1024 ** 2 * 10.25, "10.3 MB"],
    [1024 ** 3 * 1.5, "1.5 GB"],
    [1024 ** 3 * 250, "250 GB"],
    [1024 ** 4 * 2, "2 TB"],
    [1024 ** 6 * 3, "3072 PB"],
  ])("%d bytes → %s", (bytes, want) => {
    expect(formatBytes(bytes)).toBe(want);
  });
});

describe("GB ↔ bytes", () => {
  it("treats empty, zero and negative quota as unlimited (0)", () => {
    expect([gbToBytes(null), gbToBytes(undefined), gbToBytes(0), gbToBytes(-3), gbToBytes(Number.NaN)]).toEqual([0, 0, 0, 0, 0]);
  });

  it("uses 1024³ bytes per GB and rounds fractional input to whole bytes", () => {
    expect(gbToBytes(1)).toBe(1_073_741_824);
    expect(gbToBytes(0.5)).toBe(536_870_912);
    expect(Number.isInteger(gbToBytes(0.333))).toBe(true);
  });

  it("clamps absurd quotas so bytes stay a safe integer", () => {
    expect(gbToBytes(1e12)).toBe(MAX_QUOTA_GB * BYTES_PER_GB);
    expect(Number.isSafeInteger(gbToBytes(1e12))).toBe(true);
  });

  it("round-trips the values the form shows", () => {
    for (const gb of [1, 2.5, 100, 0.01]) expect(bytesToGb(gbToBytes(gb))).toBe(gb);
    expect(bytesToGb(0)).toBe(0);
    expect(bytesToGb(1_500_000_000)).toBe(1.4);
  });
});

describe("daysUntil", () => {
  it("counts calendar days, so an end-of-day expiry 30 days out reads as 30", () => {
    const now = new Date(2026, 10, 21, 9, 30);
    expect(daysUntil(new Date(2026, 11, 21, 23, 59, 59).toISOString(), now)).toBe(30);
    expect(daysUntil(new Date(2026, 10, 21, 23, 59).toISOString(), now)).toBe(0);
    expect(daysUntil(new Date(2026, 10, 20, 23, 59).toISOString(), now)).toBe(-1);
  });
});

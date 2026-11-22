import { describe, expect, it } from "vitest";
import { attackKinds } from "../api/schemas";
import { en } from "../i18n/en";
import { zh } from "../i18n/zh";
import { countryName, kindColor, kindLabelKey, niceCeil, reportMailto, reportText, sortKinds, trendDays } from "./attacks";

describe("attack kinds", () => {
  it("gives every kind its own colour in each theme, and a label and description in both languages", () => {
    for (const theme of ["day", "night", "midnight"] as const) {
      expect(new Set(attackKinds.map((k) => kindColor(k, theme))).size).toBe(attackKinds.length);
    }
    for (const k of attackKinds) {
      const key = kindLabelKey(k);
      expect(key).not.toBeNull();
      if (key) {
        expect(zh[key]).toBeTruthy();
        expect(en[key]).toBeTruthy();
        expect(zh[`${key}.desc`]).toBeTruthy();
      }
    }
  });

  it("keeps an unknown kind grey and unlabelled instead of borrowing a colour", () => {
    expect(attackKinds.map((k) => kindColor(k, "day"))).not.toContain(kindColor("something_new", "day"));
    expect(kindLabelKey("something_new")).toBeNull();
  });

  it("orders kinds by the palette, not by count", () => {
    const sorted = sortKinds([{ kind: "zzz" }, { kind: "line_probe" }, { kind: "ssh_login" }, { kind: "aaa" }]);
    expect(sorted.map((k) => k.kind)).toEqual(["ssh_login", "line_probe", "aaa", "zzz"]);
  });
});

describe("countryName", () => {
  it("names a code in the interface language and leaves registry free text alone", () => {
    expect(countryName("NL", "en")).toBe("Netherlands");
    expect(countryName("NL", "zh")).toBe("荷兰");
    expect(countryName("Somewhere Else", "en")).toBe("Somewhere Else");
    expect(countryName("", "en")).toBe("");
  });
});

describe("trend", () => {
  it("totals each day and drops kinds with nothing", () => {
    const days = trendDays([
      { day: "2026-11-20", hits: {} },
      { day: "2026-11-21", hits: { line_probe: 4, ssh_login: 6, ssh_scan: 0 } },
    ]);
    expect(days[0]).toEqual({ day: "2026-11-20", total: 0, segments: [] });
    expect(days[1]).toEqual({ day: "2026-11-21", total: 10, segments: [{ kind: "ssh_login", hits: 6 }, { kind: "line_probe", hits: 4 }] });
  });

  it("rounds the axis top up to a round number", () => {
    expect([0, 3, 5, 6, 10, 11, 24, 26, 180, 999, 1000, 1001].map(niceCeil)).toEqual([5, 5, 5, 10, 10, 20, 25, 50, 200, 1000, 1000, 2000]);
  });
});

describe("report", () => {
  const r = { ip: "203.0.113.5", to: "abuse@example.net", network: "Example", subject: "Abuse report: SSH & more", body: "Hello,\n100% unsolicited\n" };

  it("builds a mailto link that survives special characters", () => {
    const link = reportMailto(r);
    expect(link).toBe("mailto:abuse%40example.net?subject=Abuse%20report%3A%20SSH%20%26%20more&body=Hello%2C%0A100%25%20unsolicited%0A");
    expect(reportMailto({ ...r, to: "" })).toBeNull();
  });

  it("puts recipient, subject and body in the copied text", () => {
    expect(reportText(r)).toBe("To: abuse@example.net\nSubject: Abuse report: SSH & more\n\nHello,\n100% unsolicited\n");
  });
});

import { describe, expect, it } from "vitest";
import { en } from "./en";
import { auditActionLabel, makeTranslate, shareFormatLabel } from "./translate";
import { zh } from "./zh";

describe("auditActionLabel", () => {
  it("translates known action ids per language", () => {
    expect(auditActionLabel("client.rotate", makeTranslate("zh"))).toBe("更换访客密钥");
    expect(auditActionLabel("login.fail", makeTranslate("en"))).toBe("Failed sign-in");
    expect(auditActionLabel("reach.test_email", makeTranslate("zh"))).toBe("发送测试邮件");
  });

  it("falls back to the raw id for actions the UI does not know", () => {
    expect(auditActionLabel("backup.export", makeTranslate("zh"))).toBe("backup.export");
  });

  it("does not resolve ids that collide with other audit page keys", () => {
    // "audit.title" is a page heading, not an action translation.
    expect(auditActionLabel("title", makeTranslate("en"))).toBe("title");
  });
});

describe("shareFormatLabel", () => {
  it("translates formats the UI knows", () => {
    expect(shareFormatLabel("links", makeTranslate("en"))).toBe("Universal (most apps)");
    expect(shareFormatLabel("mihomo", makeTranslate("zh"))).toBe("Clash Meta / mihomo");
  });

  it("falls back to the raw name for a format the server adds later", () => {
    expect(shareFormatLabel("v2rayng", makeTranslate("zh"))).toBe("v2rayng");
  });
});

describe("makeTranslate", () => {
  it("fills placeholders and leaves unknown ones intact", () => {
    const t = makeTranslate("en");
    expect(t("clients.usage", { used: "1 GB", quota: "10 GB" })).toBe("1 GB of 10 GB");
    expect(t("clients.usage", { used: "1 GB" })).toBe("1 GB of {quota}");
  });

  it("English uses the same placeholders as Chinese for every key", () => {
    const names = (s: string) => [...s.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();
    const mismatched = (Object.keys(zh) as (keyof typeof zh)[]).filter((k) => names(zh[k]).join() !== names(en[k]).join());
    expect(mismatched).toEqual([]);
  });
});

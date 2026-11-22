import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

// The handwritten font is a subset of the characters the UI text uses. New text with a character
// outside it would render in a fallback font mid-word: rerun `node scripts/subset-fonts.mjs`.
describe("handwritten font subset", () => {
  it("covers every character in the UI dictionaries and the deployer's page", () => {
    const here = join(process.cwd(), "src");
    const charset = new Set(readFileSync(join(here, "assets", "fonts", "charset-hand.txt"), "utf8"));
    const files = [join(here, "i18n", "zh.ts"), join(here, "i18n", "en.ts"), join(process.cwd(), "..", "internal", "deploy", "localui", "page.html")];
    const text = files.map((f) => readFileSync(f, "utf8")).join("");
    const missing = [...new Set(text)].filter((c) => c >= " " && !charset.has(c));
    expect(missing, "rerun node scripts/subset-fonts.mjs").toEqual([]);
  });
});

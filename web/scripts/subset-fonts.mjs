// Builds the self-hosted font subsets the Flover look needs, from the original OFL font files.
//
//   1. Put the originals in web/.font-cache/ (not committed):
//        LongCang-Regular.ttf  from github.com/google/fonts ofl/longcang
//        Caveat-wght.ttf       from github.com/google/fonts ofl/caveat (Caveat[wght].ttf)
//   2. node scripts/subset-fonts.mjs
//
// Long Cang keeps every character the UI text uses (zh.ts, en.ts and the deployer's page, which
// serves these same files) plus printable ASCII, so headings never fall back mid-word; Caveat keeps Latin, digits and a few symbols for numbers
// and stickers. Rerun after adding UI text: a test fails when a character is missing.
import { readFileSync, writeFileSync, copyFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import subsetFont from "subset-font";

const web = join(dirname(fileURLToPath(import.meta.url)), "..");
const cache = join(web, ".font-cache");
const out = join(web, "src", "assets", "fonts");

const ascii = Array.from({ length: 0x7f - 0x20 }, (_, i) => String.fromCharCode(0x20 + i)).join("");
const extras = "·…“”‘’—–×→←↑↓✓%°";

/** Files whose text may be drawn in the handwritten font. */
export const uiTextFiles = [
  join(web, "src", "i18n", "zh.ts"),
  join(web, "src", "i18n", "en.ts"),
  join(web, "..", "internal", "deploy", "localui", "page.html"),
];

/** Every character in the UI text, minus line breaks. */
export function uiCharacters() {
  const text = uiTextFiles.map((f) => readFileSync(f, "utf8")).join("");
  return [...new Set([...text + ascii + extras])].filter((c) => c >= " ").sort().join("");
}

async function main() {
  const hand = uiCharacters();
  const longCang = await subsetFont(readFileSync(join(cache, "LongCang-Regular.ttf")), hand, { targetFormat: "woff2" });
  writeFileSync(join(out, "LongCang-subset.woff2"), longCang);
  writeFileSync(join(out, "charset-hand.txt"), hand + "\n");

  const caveat = await subsetFont(readFileSync(join(cache, "Caveat-wght.ttf")), ascii + extras, {
    targetFormat: "woff2",
    variationAxes: { wght: 600 },
  });
  writeFileSync(join(out, "Caveat-600-subset.woff2"), caveat);

  copyFileSync(join(cache, "OFL-LongCang.txt"), join(out, "OFL-LongCang.txt"));
  copyFileSync(join(cache, "OFL-Caveat.txt"), join(out, "OFL-Caveat.txt"));
  console.log(`Long Cang: ${[...hand].length} characters, ${longCang.length} bytes; Caveat: ${caveat.length} bytes`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();

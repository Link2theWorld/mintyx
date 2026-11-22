import { readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { describe, expect, it } from "vitest";

const webRoot = resolve(import.meta.dirname, "../..");
// Assembled so this file does not match itself.
const ownerSite = ["fand", "dev"].join(".");

function sourceFiles(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sourceFiles(join(dir, e.name)) : [join(dir, e.name)],
  );
}

describe("owner site privacy", () => {
  it("is named in lib/guides.ts and nowhere else the browser loads", () => {
    // A second mention means a hard-coded link at best, a fetch/img/prefetch to the site at worst.
    const files = [...sourceFiles(join(webRoot, "src")), join(webRoot, "index.html")];
    const mentions = files
      .filter((f) => readFileSync(f, "utf8").toLowerCase().includes(ownerSite))
      .map((f) => relative(webRoot, f).split("\\").join("/"));
    expect(mentions).toEqual(["src/lib/guides.ts"]);
  });
});

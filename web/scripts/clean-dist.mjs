// Empties dist/ before a build but keeps the committed placeholder page.
import { readdirSync, rmSync, mkdirSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dist = join(dirname(fileURLToPath(import.meta.url)), "..", "dist");
const keep = new Set(["unbuilt.html"]);

mkdirSync(dist, { recursive: true });
for (const entry of readdirSync(dist)) {
  if (!keep.has(entry)) rmSync(join(dist, entry), { recursive: true, force: true });
}

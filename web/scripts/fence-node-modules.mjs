// Some npm packages ship .go files; a go.mod here makes node_modules its own
// module so `go build ./...` / `go vet ./...` from the repo root skip it.
import { writeFileSync, existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "node_modules");
if (existsSync(dir)) writeFileSync(join(dir, "go.mod"), "module mintyx.invalid/node_modules\n");

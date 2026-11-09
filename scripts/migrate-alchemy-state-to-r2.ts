// One-time copy of local Alchemy state (.alchemy/state) into the encrypted R2
// state store (deploy/alchemy/r2-state.ts). Refuses to overwrite non-empty R2
// state unless --force. Needs the same env as the store (see r2-state.ts).
//   node --experimental-strip-types scripts/migrate-alchemy-state-to-r2.ts [stateDir] [--force]
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import { isDeepStrictEqual } from "node:util";
import { readStateDoc, writeStateDoc } from "../deploy/alchemy/r2-state.ts";

const args = process.argv.slice(2);
const force = args.includes("--force");
const stateDir = args.find((a) => !a.startsWith("--")) ?? ".alchemy/state";

const existing = await readStateDoc();
if (Object.keys(existing.stacks).length > 0 && !force) {
  console.error("R2 state is not empty; pass --force to overwrite.");
  process.exit(1);
}

const doc = {
  version: 1 as const,
  stacks: {} as Record<
    string,
    Record<string, { resources: Record<string, unknown>; output?: unknown }>
  >,
};
let count = 0;
for (const stack of readdirSync(stateDir)) {
  for (const stage of readdirSync(path.join(stateDir, stack))) {
    const data: { resources: Record<string, unknown>; output?: unknown } = {
      resources: {},
    };
    for (const file of readdirSync(path.join(stateDir, stack, stage))) {
      if (!file.endsWith(".json")) continue;
      const raw = readFileSync(path.join(stateDir, stack, stage, file), "utf8");
      if (!raw.trim()) continue;
      const value = JSON.parse(raw); // already in encoded (JSON) form
      if (file === "__stack_output__.json") data.output = value;
      else {
        // LocalState encodes "/" in FQNs as "__".
        data.resources[file.slice(0, -5).replaceAll("__", "/")] = value;
        count++;
      }
    }
    (doc.stacks[stack] ??= {})[stage] = data;
  }
}
await writeStateDoc(doc);
const roundTrip = await readStateDoc();
if (!isDeepStrictEqual(roundTrip, doc)) {
  console.error("Round-trip mismatch after upload.");
  process.exit(1);
}
console.log(
  `Migrated ${count} resources (${Object.keys(doc.stacks).join(", ")}) to R2; round-trip verified.`,
);

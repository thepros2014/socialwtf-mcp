#!/usr/bin/env node
// Builds dist/socialwtf-mcp.mcpb (the bundle format Smithery uses for local stdio servers).
// Usage: node scripts/build-mcpb.mjs
// Requires network access for `npm install` and `npx @anthropic-ai/mcpb`.
import { cpSync, mkdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const stage = join(root, ".mcpb-stage");
const out = join(root, "dist", "socialwtf-mcp.mcpb");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const npx = process.platform === "win32" ? "npx.cmd" : "npx";

function run(cmd, args, cwd) {
  // shell:true is required for .cmd shims on Windows with current Node versions.
  const r = spawnSync(cmd, args, { cwd, stdio: "inherit", shell: process.platform === "win32" });
  if (r.status !== 0) {
    console.error(`Failed: ${cmd} ${args.join(" ")}`);
    process.exit(r.status ?? 1);
  }
}

rmSync(stage, { recursive: true, force: true });
mkdirSync(stage, { recursive: true });
mkdirSync(dirname(out), { recursive: true });

for (const f of ["manifest.json", "index.mjs", "package.json", "package-lock.json", "LICENSE", "README.md"]) {
  cpSync(join(root, f), join(stage, f));
}

run(npm, ["install", "--omit=dev", "--no-audit", "--no-fund"], stage);
run(npx, ["--yes", "@anthropic-ai/mcpb", "validate", "manifest.json"], stage);
// Relative output path: with shell:true on Windows, absolute paths containing spaces get split into extra args.
run(npx, ["--yes", "@anthropic-ai/mcpb", "pack", ".", join("..", "dist", "socialwtf-mcp.mcpb")], stage);

rmSync(stage, { recursive: true, force: true });
console.log(`\nBuilt ${out}`);

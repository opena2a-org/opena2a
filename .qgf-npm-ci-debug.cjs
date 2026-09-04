// Temporary diagnostic (not for delivery): re-run the approved `npm ci`
// with verbose logging and logs kept inside the worktree.
"use strict";
const { spawnSync } = require("node:child_process");
const res = spawnSync(
  "npm",
  [
    "ci",
    "--no-audit",
    "--no-fund",
    "--loglevel=notice",
    "--logs-dir=.npm-logs",
    "--maxsockets=2",
    "--fetch-retries=1",
  ],
  {
    cwd: __dirname,
    stdio: "inherit",
    env: { ...process.env, NODE_OPTIONS: "--max-old-space-size=4096" },
  },
);
console.error("npm ci exit status:", res.status, res.signal ?? "");
process.exit(res.status ?? 1);

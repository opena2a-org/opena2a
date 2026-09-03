// Temporary helper (not committed): re-run the already-approved `npm ci`
// with a larger V8 heap — the plain run OOM'd at the ~4GB default.
"use strict";
const { spawnSync } = require("node:child_process");
const res = spawnSync("npm", ["ci", "--no-audit", "--no-fund"], {
  cwd: __dirname,
  stdio: "inherit",
  env: { ...process.env, NODE_OPTIONS: "--max-old-space-size=6144" },
});
process.exit(res.status ?? 1);

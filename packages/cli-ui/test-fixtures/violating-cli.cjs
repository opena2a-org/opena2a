#!/usr/bin/env node
// Violating front-door fixture for src/conformance.test.ts (OPA-03.AC3).
// Plain Node script, no build step. Breaks every grammar property in turn:
//   1. a banner precedes the verdict line;
//   2. the JSON envelope disagrees with the human view (verdict, score,
//      findings count, nextSteps);
//   3. the process exit code (3) differs from envelope.exitCode (0);
//   4. ANSI escapes are emitted even under NO_COLOR / piped stdout;
//   5. the cited next step does not parse against --help (help exits 1).
"use strict";

const TOOL = "violating-cli.cjs";
const args = process.argv.slice(2);

if (args.includes("--help")) {
  process.stderr.write(TOOL + " has no help\n");
  process.exit(1);
}

if (args.includes("--json")) {
  process.stdout.write(
    JSON.stringify({
      schemaVersion: "1",
      tool: TOOL,
      version: "1.0.0",
      verdict: "safe",
      score: 95,
      findings: [],
      nextSteps: [TOOL + " frobnicate"],
      exitCode: 0,
    }) + "\n",
  );
  process.exit(3);
}

process.stdout.write("\x1b[35mWelcome to " + TOOL + "!\x1b[0m\n");
process.stdout.write("✖ BLOCKED — 1 finding\n");
process.stdout.write("12/100\n");
process.stdout.write("HIGH  Fabricated finding  src/x.js:1\n");
process.stdout.write("  Verify: " + TOOL + " verify\n");
process.stdout.write("  Fix: " + TOOL + " fix\n");
process.exit(3);

#!/usr/bin/env node
// Conforming front-door fixture for src/conformance.test.ts (OPA-03.AC3).
// Plain Node script, no build step. Holds all five grammar properties:
// verdict line first, human/JSON parity, exit code == envelope.exitCode,
// no ANSI when piped, and every cited command parses against --help.
"use strict";

const TOOL = "conforming-cli.cjs";
const args = process.argv.slice(2);
const command = args.find((a) => !a.startsWith("-")) || "scan";

if (args.includes("--help")) {
  if (!["scan", "verify", "fix"].includes(command)) {
    process.stderr.write("Unknown command: " + command + "\n");
    process.exit(2);
  }
  process.stdout.write(
    [
      "Usage: " + TOOL + " <command> [--json]",
      "",
      "Commands:",
      "  scan     Scan the current directory",
      "  verify   Re-observe the reported finding",
      "  fix      Apply the recommended fix",
      "",
    ].join("\n"),
  );
  process.exit(0);
}

const envelope = {
  schemaVersion: "1",
  tool: TOOL,
  version: "1.0.0",
  verdict: "warning",
  score: 72,
  findings: [
    {
      severity: "medium",
      title: "Example finding",
      file: "src/app.js",
      line: 3,
      why: "It demonstrates the front-door contract in one sentence.",
      verify: TOOL + " verify",
      fix: TOOL + " fix",
    },
  ],
  nextSteps: [TOOL + " fix"],
  exitCode: 1,
};

if (args.includes("--json")) {
  process.stdout.write(JSON.stringify(envelope, null, 2) + "\n");
  process.exit(envelope.exitCode);
}

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const dim = (s) => (useColor ? "\x1b[2m" + s + "\x1b[22m" : s);
process.stdout.write(
  [
    dim("⚠ WARNING — 1 finding"),
    "72/100 -> 100 by " + TOOL + " fix",
    "",
    "MEDIUM  Example finding  src/app.js:3",
    "  It demonstrates the front-door contract in one sentence.",
    "  Verify: " + TOOL + " verify",
    "  Fix: " + TOOL + " fix",
    "",
    "Next:",
    "  → " + TOOL + " fix",
    "",
  ].join("\n"),
);
process.exit(envelope.exitCode);

# @opena2a/cli-ui

Shared terminal UI primitives for OpenA2A CLIs (`ai-trust`, `hackmyagent`, `opena2a`).

One place to update score meters, dividers, trust level legends, and verdict colors so the three CLIs stay visually consistent.

## What's in the box

- `scoreMeter(value, max?)` — full-width colored bar: `━━━━━━━━━━━━━━━━━━━━ 87/100`
- `miniMeter(value, max?)` — compact 8-cell bar for table cells
- `divider(label?)` — section divider, optionally labeled
- `verdictColor(verdict)` / `normalizeVerdict(verdict)` — collapse registry verdict variants and get a chalk color
- `trustLevelLabel(0-4)` / `trustLevelColor(0-4)` / `trustLevelLegend(current)` — render the 5-level trust ladder
- `formatScanAge(timestamp)` — "3 days ago" or "120 days ago (stale)"
- `renderObservationsBlock(input)` — Surfaces / Checks / Categories / Verdict block for scan output (0.2.0)
- `renderCheckBlock(input)` — canonical `check <pkg>` block: header, verdict, trust level, meter (gated on scanStatus), optional publisher / permissions / revocation / community scans / last-scan rows (0.3.0)
- `renderNotFoundBlock(input)` — "package not found" block with did-you-mean suggestions, optional error hint, optional skill-fallback CTA (0.3.0)
- `renderNextSteps(input)` — Next-Steps CTAs with primary/default bullet styling (0.3.0)

## Usage

```ts
import { scoreMeter, divider, trustLevelLegend, verdictColor } from "@opena2a/cli-ui";

console.log(`  Trust     ${scoreMeter(87)}`);
console.log(divider("Findings"));
console.log(`  ${trustLevelLegend(3)}`);
```

## Terminal grammar (0.6.0)

Seven grammar exports render the shared front-door language every OpenA2A CLI speaks (verdict line first, path-up score, bounded next steps):

- `renderVerdict({ verdict, summary })` — the verdict line, always printed first: one line, no leading blank.
- `renderScore({ score, pathTo100 })` — `72/100 -> 100 by <cmd>` plus a meter; only ever the path up, never a delta (`-5`) or a letter grade (`B+`).
- `renderFinding(finding)` — severity, title, `file:line`, one sentence of why, a `Verify:` command, a `Fix:` command, at most one URL.
- `renderNextSteps(commands)` — one to three runnable commands (throws `RangeError` outside that range), first one primary. This is the grammar's command-list variant — see the import note below.
- `renderProgress(input, sink)` — writes only to the caller-supplied stderr sink and scrubs the home directory to `~` before anything is emitted.
- `renderError({ what, unchanged, next })` — what happened, what was not changed, and the one command to run next.
- `envelope(input)` — builds the one `--json` object every front door prints: exactly `schemaVersion`, `tool`, `version`, `verdict`, `score`, `findings[]`, `nextSteps[]` (1-3 commands), `exitCode`, camelCase, no other top-level key.

All of these except `renderNextSteps` are imported from the package barrel:

```ts
import { renderVerdict, envelope } from "@opena2a/cli-ui";

console.log(renderVerdict({ verdict: "warning", summary: "2 findings need review" }));
// ⚠ WARNING — 2 findings need review

const json = envelope({
  tool: "hackmyagent",
  version: "1.4.2",
  verdict: "warning",
  score: 72,
  nextSteps: ["hackmyagent secure --fix"],
  exitCode: 1,
});
console.log(JSON.stringify(json));
```

### Importing the grammar's `renderNextSteps`

The barrel keeps the existing 0.3.0 `renderNextSteps` (CTA objects) binding, so `import { renderNextSteps } from "@opena2a/cli-ui"` stays the CTA variant. The grammar's command-list variant is imported from the built module directly:

```ts
import { renderNextSteps } from "@opena2a/cli-ui/dist/grammar.js";

console.log(renderNextSteps(["hackmyagent secure --fix", "hackmyagent report"]));
```

### Conformance

`frontDoorConformance(target)` spawns a built CLI front door with a fresh temporary `HOME`, `NO_COLOR=1` and stdin closed, and reports pass/fail with the observed value for the five front-door properties: verdict line first; `--json` envelope parity with the human view; process exit code equals `envelope.exitCode`; zero ANSI bytes under `NO_COLOR` + non-TTY; every cited `nextSteps` / `Verify:` / `Fix:` command parses against the binary's own `--help`. Consumers adopt it as a `cli-grammar-conformance.test.ts` run against their built front door:

```ts
import { frontDoorConformance } from "@opena2a/cli-ui";
import { expect, test } from "vitest";

test("front door speaks the CLI grammar", async () => {
  const result = await frontDoorConformance({
    bin: "./dist/cli.js",
    args: ["check", "left-pad"],
  });
  const failed = result.properties.filter((p) => !p.pass);
  expect(failed, JSON.stringify(failed, null, 2)).toEqual([]);
});
```

## Color rules

- Score / meter: green ≥ 70, yellow ≥ 40, red below.
- Trust level: green (3, 4), yellow (1, 2), red (0).
- Verdict: safe → green, warning → yellow, blocked → red, listed → cyan.

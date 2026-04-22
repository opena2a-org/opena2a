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

## Color rules

- Score / meter: green ≥ 70, yellow ≥ 40, red below.
- Trust level: green (3, 4), yellow (1, 2), red (0).
- Verdict: safe → green, warning → yellow, blocked → red, listed → cyan.

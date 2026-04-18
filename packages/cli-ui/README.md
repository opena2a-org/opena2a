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

# @opena2a/check-core

Data-shape and orchestration primitives for the `check` command across
OpenA2A CLIs (`hackmyagent`, `opena2a`, `ai-trust`).

One implementation of:
- input classification (npm / pypi / github / local / url)
- download-error translation
- registry-status → meter-gate mapping
- canonical `CheckOutput` + `NotFoundOutput` JSON shape
- registry-first, scan-on-miss orchestrator (pluggable adapters)

Rendering stays in [`@opena2a/cli-ui`](../cli-ui). This package is data only.

## Why

Three CLIs emit `check --json`. Before 0.18.3 their outputs disagreed on
five load-bearing fields (trustLevel, verdict, packageType, scanStatus,
name). M2 closed that by convention; M3 closes it by construction — there
is exactly one implementation, and every CLI imports it.

Parent design: [`briefs/cli-consolidation.md`](https://github.com/opena2a-org/opena2a-org-public/blob/main/briefs/cli-consolidation.md).
Milestone: [CA-034] M3.

## API

```ts
import {
  checkPackage,
  buildCheckOutput,
  buildNotFoundOutput,
  translateDownloadError,
  mapScanStatusForMeter,
  parseCheckInput,
} from "@opena2a/check-core";
```

### Orchestrator (registry-first, scan-on-miss)

```ts
const res = await checkPackage({
  target: "@modelcontextprotocol/server-filesystem",
  mode: "scan-on-miss",
  registry: (name, type) => client.checkTrust(name, type),
  scan: (name) => runLocalScan(name),
  skillFallback: (name) => resolveSkill(name),
});

if (res.kind === "found") {
  console.log(JSON.stringify(res.output, null, 2));
} else {
  console.log(JSON.stringify(res.output, null, 2));
  process.exitCode = 2;
}
```

### Pure helpers (for CLIs that keep their own flow)

```ts
const output = buildCheckOutput({
  name: "express",
  type: "npm-package",
  scan: { score: 100, maxScore: 100, findings: [] },
  registry: trustAnswer,
});

const hint = translateDownloadError("anthropic/code-review", "code 128");
// { errorHint: "Looks like a git-style name. npm packages use ...", suggestions: [...] }
```

## Contract

The emission order of `buildCheckOutput` is load-bearing: the
`opena2a-parity` harness compares JSON byte-for-byte across CLIs. Do not
reorder fields without bumping to a new minor — consumers rely on stable
shape.

### `check --json` score fields — which one do I gate CI on?

A found result can carry up to three score-shaped numbers on different
scales from two sources. They are **orthogonal, not contradictory**.
`CHECK_FIELD_GUIDE` and `checkJsonSchema` are the exported, machine-readable
documentation of this (one entry per field, with `source`, `scale`, and
`gating`); `check-json-schema.test.ts` keeps them consistent with the emitter.

| Field(s) | Source | Scale | What it answers |
|----------|--------|-------|-----------------|
| `score` / `maxScore` / `findings` | local-scan | 0..100 | "Did my local static checks pass on this artifact?" |
| `trustLevel` | registry | 0..4 ordinal | "Does the registry trust this package?" (gate here) |
| `trustScore` | registry | 0..1 | continuous *input* to `trustLevel` — not a standalone gate |
| `verdict` | registry | string | the word label of `trustLevel` ("blocked".."verified") |
| `scanStatus` | registry | enum | has the registry's *server-side* scan run yet |

- `score: 100` means "the local scan found nothing" — **not** a registry
  trust verdict. A package the registry has never scanned can still read
  `score: 100`, with `scanStatus: "pending"`. That is not a contradiction:
  the local scan ran; the registry's has not.
- `trustLevel` (0..4: Blocked, Warning, Listed, Scanned, Verified) is
  derived from `trustScore` **plus hard gates** — a critical finding forces
  Blocked, Verified additionally needs SLSA L2+, 30+ days observation, and a
  verified signature. So a package can have `trustScore: 0.9` and still
  `trustLevel: 0`. **Gate on `trustLevel`, not a raw `trustScore` cutoff** —
  the cutoff would miss those hard gates. `verdict` is the same signal as
  `trustLevel`, in words.
- Never compare a 0..100 `score` against a 0..1 `trustScore`.

```ts
import { CHECK_FIELD_GUIDE, checkJsonSchema } from "@opena2a/check-core";
CHECK_FIELD_GUIDE.score.gating;      // "Gate on this for 'did my local static checks pass'..."
CHECK_FIELD_GUIDE.trustLevel.source; // "registry"
```

**1.0.0 (deferred breaking change, CHIEF-CA + CHIEF-CPO):** the flat object
namespaces the two layers — `{ localScan: { score, maxScore, findings },
registry: { trustScore, trustLevel, verdict, scanStatus } }`. Whether to keep
both `verdict` and `trustLevel` is a separate 1.0.0 decision. Until then the
wire shape is frozen for the parity contract and `CHECK_FIELD_GUIDE` is the
contract.

## License

Apache-2.0

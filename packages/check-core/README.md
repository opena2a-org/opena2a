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

## License

Apache-2.0

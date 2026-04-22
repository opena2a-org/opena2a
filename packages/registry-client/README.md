# @opena2a/registry-client

HTTP client for the [OpenA2A Registry](https://api.oa2a.org) trust query endpoints. Shared implementation used by `hackmyagent`, `opena2a-cli`, and `ai-trust` so all three CLIs produce identical trust output on the same input.

## Install

```bash
npm install @opena2a/registry-client
```

Consumers pin exact versions (no caret) per the OpenA2A supply-chain policy. Use `"@opena2a/registry-client": "0.1.0"` in `dependencies`.

## Usage

```ts
import { RegistryClient, PackageNotFoundError } from "@opena2a/registry-client";

const client = new RegistryClient({
  baseUrl: "https://api.oa2a.org",
  userAgent: "my-cli/1.2.3",
});

try {
  const answer = await client.checkTrust("@modelcontextprotocol/server-filesystem");
  console.log(answer.trustLevel, answer.verdict);
} catch (err) {
  if (err instanceof PackageNotFoundError) {
    console.log(`Not in registry: ${err.packageName}`);
  } else {
    throw err;
  }
}
```

### Batch lookups

```ts
const batch = await client.batchQuery([
  { name: "react" },
  { name: "@modelcontextprotocol/server-filesystem", type: "mcp_server" },
]);
console.log(batch.meta.found, "of", batch.meta.total, "found");
```

### Publish scan results

```ts
const result = await client.publishScan({
  name: "my-pkg",
  score: 95,
  maxScore: 100,
  findings: [],
  tool: "hackmyagent",
  toolVersion: "0.18.0",
  scanTimestamp: new Date().toISOString(),
});
```

## Design constraints

- **The client never computes a trust level.** `trustLevel` comes from the server. If the server returns no level, the CLI renders a "Listed — not yet assessed" path.
- **Opinionated defaults, minimal knobs.** 10 s per-request timeout, 60 s read-method cache TTL, both tunable via `RegistryClientOptions`.
- **Structured errors.** `PackageNotFoundError` on 404; `RegistryApiError` with a `code` (`not_found | unauthorized | forbidden | rate_limited | bad_request | server_error | network | timeout | invalid_response`) and optional `statusCode` + `body` for everything else. CLIs render prose from these codes.
- **No telemetry side effects.** The client sends the `User-Agent` the caller provides; it does not log or emit anything.

## Context

Part of the CLI consolidation track — see `opena2a-org/briefs/cli-consolidation.md` and `opena2a-org/todo/2026-04-22-cli-consolidation-sequenced.md` for the milestone plan.

## License

Apache-2.0

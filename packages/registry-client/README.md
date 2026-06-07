# @opena2a/registry-client

HTTP client for the [OpenA2A Registry](https://api.oa2a.org) trust query endpoints. Shared implementation used by `hackmyagent`, `opena2a-cli`, and `ai-trust` so all three CLIs produce identical trust output on the same input.

## Install

```bash
npm install @opena2a/registry-client
```

Consumers pin exact versions (no caret) per the OpenA2A supply-chain policy. Use `"@opena2a/registry-client": "0.2.0"` in `dependencies`.

This package is ESM-only (`"type": "module"`). Consumers must use ESM (`"type": "module"` in their `package.json`, or `.mjs`/`.mts` files).

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

Unsigned publishes are recorded by the registry as `community` (the safe default).

### First-party provenance signing

To self-tag a privileged provenance class (`first_party_scanner | ci | partner`), pass a
`FirstPartySigner` as the second argument to `publishScan`. The signer stamps
`source`/`nonce`/`signedAt`/`signature`/`publicKey` over the registry's strong canonical
(`name|version|score|maxScore|source|nonce|signedAt`). The registry honors the claimed
`source` only when the signing key is on its `FIRST_PARTY_SCANNER_PUBKEYS` allowlist and
the signature, single-use nonce, and freshness window all check out — otherwise it fails
closed and records the scan as `community` (no error).

```ts
import { RegistryClient, firstPartySignerFromEnv, FirstPartySigner } from "@opena2a/registry-client";

// Recommended: build the signer from a secret in the environment (never commit the key).
// Returns undefined when the env var is unset, so end-user runs publish as community.
const signer = firstPartySignerFromEnv({
  keyEnv: "MY_SCANNER_SIGNING_KEY", // base64/hex Ed25519 32-byte seed or 64-byte secret key
  source: "first_party_scanner",
});

await client.publishScan(submission, signer);

// Or construct directly from a raw key (e.g. for tests):
const direct = new FirstPartySigner({ secretKey: seed32, source: "ci" });
console.log(direct.publicKey); // base64 — register this in FIRST_PARTY_SCANNER_PUBKEYS
```

`signedAt` is stamped in Unix seconds; each `sign()` mints a fresh single-use nonce. The
tweetnacl signature is byte-compatible with the registry's Go `crypto/ed25519` verifier.

## Design constraints

- **The client never computes a trust level.** `trustLevel` comes from the server. If the server returns no level, the CLI renders a "Listed — not yet assessed" path.
- **Opinionated defaults, minimal knobs.** 10 s per-request timeout, 60 s read-method cache TTL, both tunable via `RegistryClientOptions`.
- **Structured errors.** `PackageNotFoundError` on 404; `RegistryApiError` with a `code` (`not_found | unauthorized | forbidden | rate_limited | bad_request | server_error | network | timeout | invalid_response`) and optional `statusCode` + `body` for everything else. CLIs render prose from these codes.
- **No telemetry side effects.** The client sends the `User-Agent` the caller provides; it does not log or emit anything.

## Context

Part of the CLI consolidation track — see `opena2a-org/briefs/cli-consolidation.md` and `opena2a-org/todo/2026-04-22-cli-consolidation-sequenced.md` for the milestone plan.

## License

Apache-2.0

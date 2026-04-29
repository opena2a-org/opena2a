# @opena2a/credential-patterns

Canonical credential regex catalog and match-with-allowlist helpers for OpenA2A security tools.

One place to update credential detection so `secretless-ai`, `hackmyagent`, and any downstream OpenA2A scanner share the same patterns and the same known-example allowlist. Add new patterns here, not in tools — duplicate catalogs are how detection drifts.

## Install

```bash
npm install @opena2a/credential-patterns
```

Pin exactly. Per OpenA2A convention across the CLI consolidation, depend with `"@opena2a/credential-patterns": "0.1.0"`, not `^0.1.0`. Trades dependency-update PR volume for supply-chain tightness; removes transitive surprise.

This package is **ESM-only** (`"type": "module"`, no CJS build).

- ESM consumers (`"type": "module"`, or `.mjs` / `.mts` files): use a static `import { ... } from '@opena2a/credential-patterns'` as shown below.
- CommonJS consumers (`"type": "commonjs"`, including any `.ts` file under a CJS `tsconfig` with `module: "Node16"`): use a dynamic `await import('@opena2a/credential-patterns')` inside an async function. A static `import` will fail with TypeScript `TS1479` ("CommonJS module ... cannot be imported with `require`"). This is the path `secretless-ai` uses today for `@opena2a/cli-ui` and is the same path PR 2 will use here.

## Exports

```ts
import {
  CREDENTIAL_PATTERNS,           // CredentialPattern[] — ordered, prefix-specific first
  CREDENTIAL_PREFIX_QUICK_CHECK, // RegExp (no /g flag — safe to call .test() repeatedly)
  KNOWN_EXAMPLE_KEYS,            // Set<string> — exact public example keys to allowlist
  PLACEHOLDER_INDICATORS,        // string[] — case-insensitive placeholder substrings
  SECRET_FILE_PATTERNS,          // string[] — file globs that must never reach AI tools
  CONFIG_FILES,                  // string[] — config files that may carry hardcoded secrets
  SOURCE_FILE_EXTENSIONS,        // Set<string> — extensions to scan for inline credentials
  SOURCE_SKIP_DIRS,              // Set<string> — directory names to skip when walking
  findRealMatch,                 // (line, pattern) => RegExpMatchArray | null
  isKnownExample,                // (line, match) => boolean
  type CredentialPattern,        // { id, name, regex, envPrefix, category? }
} from '@opena2a/credential-patterns';
```

## Pattern shape

```ts
interface CredentialPattern {
  id: string;        // stable identifier — e.g. "anthropic", "aws-access"
  name: string;      // human-readable — "Anthropic API Key"
  regex: RegExp;     // detection pattern; non-global is fine, findRealMatch promotes
  envPrefix: string; // suggested env var name — "ANTHROPIC_API_KEY"
  category?: string; // ai-ml | cloud | communication | developer | payment | database | auth | monitoring
}
```

## Ordering

The order of `CREDENTIAL_PATTERNS` is load-bearing: more specific prefixes (e.g. `sk-ant-`, `sk-proj-`, `sk-or-v1-`) precede catch-all patterns (e.g. `openai-legacy` `sk-[a-zA-Z0-9]{48,}`) because scanners iterate the array and break on first match.

## Allowlist semantics

`isKnownExample(line, match)` returns true if the matched value should be excluded from results. Three rules in order:

1. The matched value is in `KNOWN_EXAMPLE_KEYS` (e.g. `AKIAIOSFODNN7EXAMPLE`).
2. The matched value contains any `PLACEHOLDER_INDICATORS` substring (case-insensitive).
3. The line carries a comment marker (`//` or `#`) AND mentions `example`, `placeholder`, or `fake`.

`findRealMatch(line, pattern)` walks every match on the line (promoting non-`/g` regexes to `/g`) and returns the first one that passes `isKnownExample`. Returns null if every match is allowlisted.

## Consumers

- `secretless-ai` — primary consumer (PR 2 will migrate from local `src/patterns.ts`).
- `hackmyagent` — PR 3 replaces `src/plugins/credvault.ts`'s parallel inferior copy.

## Versioning

- Patches (`0.1.x`): bug fixes, new patterns, allowlist additions.
- Minors (`0.x.0`): breaking pattern semantics (regex narrowing/widening, schema changes), new exports.

Detection-logic changes go through Phase 4.5 adversarial review per `~/workspace/claude-skills/skills/pre-push-review/SKILL.md`.

## License

Apache-2.0.

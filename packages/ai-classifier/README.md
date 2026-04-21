# @opena2a/ai-classifier

Decides whether a package is AI-native, AI-adjacent, or unrelated so `ai-trust`, `hackmyagent`, and `opena2a` can route it correctly.

## Why it exists

`ai-trust` is for AI packages. Scanning `lodash` with it produces confusing scores and wastes the user's time. This package is the shared rulebook that every OpenA2A CLI uses to answer one question: **does AI trust apply to this package?**

## Tiers (v0.1)

| Tier | Meaning | Example | ai-trust behavior |
|---|---|---|---|
| **native** | AI-specific (MCP server, A2A agent, skill, AI tool, LLM) | `@modelcontextprotocol/server-filesystem` | Full trust verification |
| **adjacent** | General-purpose but in the AI trust boundary | `openai`, `dotenv` | *Stubbed in v0.3 → v0.4* |
| **unrelated** | General-purpose library, no AI surface | `express`, `chalk`, `typescript` | Defer to HMA |
| **unknown** | Can't classify confidently | novel or unnamed packages | Surface uncertainty, let user decide |

## Usage

```ts
import { classify, isAiTrustScope } from "@opena2a/ai-classifier";

const result = classify({ name: "express", packageType: "library" });
// { tier: "unrelated", reasons: [], reasoning: "Registered as a general-purpose library" }

if (isAiTrustScope(result)) {
  // run ai-trust verification
} else {
  // route to HMA
}
```

## Design rules

- **Registry `package_type` is the strongest signal.** We trust the registry's classification first.
- **Name-based fallback is conservative.** We only call a package "unrelated" by name when it's on a curated allowlist of well-known libraries (`chalk`, `typescript`, `@types/*`, etc.).
- **Never false-classify as unrelated.** Ambiguous packages return `unknown`, not `unrelated`. False rejections (dropping an AI package from an audit) are worse than uncertainty.

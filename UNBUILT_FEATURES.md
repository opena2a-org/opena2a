# Unbuilt Features — Documented from Blog Audit
Audit date: 2026-03-04. All priorities completed 2026-03-04.

---

## Priority 1: SOUL Scanner — Expand from 26 to 68 Controls
**Status: DONE** — hackmyagent@0.9.2

All 68 controls implemented across 8 domains:
| Domain | Controls |
|--------|---------|
| 7: Trust Hierarchy | 8 |
| 8: Capability Boundaries | 10 |
| 9: Injection Hardening | 8 |
| 10: Data Handling | 8 |
| 11: Hardcoded Behaviors | 8 |
| 12: Agentic Safety | 10 |
| 13: Honesty and Transparency | 8 |
| 14: Human Oversight | 8 |

Tier counts: BASIC=18, TOOL-USING=26, AGENTIC=37, MULTI-AGENT=68.

---

## Priority 2: SOUL Scanner — Layer 3 Semantic Analysis (--deep flag)
**Status: DONE** — hackmyagent@0.9.2

`--deep` flag implemented. Calls `claude --print` first; falls back to Anthropic API (`claude-haiku-4-5-20251001`) if Claude CLI not available. Only invoked for controls that fail keyword check. Confidence bump: 0.7 → 0.95 on semantic pass.

---

## Priority 3: OASB v2 Conformance Levels
**Status: DONE** — hackmyagent@0.9.2

`conformance: 'none' | 'essential' | 'standard' | 'hardened'` added to `SoulScanResult`.
- **none** — any CRITICAL control fails (grade capped at C)
- **essential** — all CRITICAL controls pass
- **standard** — all CRITICAL + HIGH controls pass, score >= 60
- **hardened** — all controls pass, score >= 75

Displayed in scan output: `Conformance: ESSENTIAL`

---

## Priority 4: scan-soul Composite Scoring with OASB v1
**Status: DONE** — hackmyagent@0.9.2

`secure --benchmark oasb-2` runs both OASB v1 (infrastructure) and soul scan (governance), combines 50/50. Prints composite score and per-half breakdown.

---

## Priority 5: `secure --benchmark oasb-2` Command
**Status: DONE** — hackmyagent@0.9.2

`npx hackmyagent secure --benchmark oasb-2` runs full combined OASB v1+v2 assessment.

---

## Non-Priority (Wrong Tool Attribution)

The following features were claimed in blogs but actually belong to **separate tools** (AIM Platform, Python SDK). These are correct as positioned — they're not CLI features.

| Feature | Blog | Actual Tool |
|---------|------|-------------|
| Ed25519 keypair generation | how-do-you-give-an-ai-agent-a-verifiable-identity | AIM Platform (agent-identity-management) |
| MCP server attestation | owasp-agentic-top-10-nhi-governance | AIM Platform |
| Behavioral trust scoring (8-factor) | echoleak-one-line-secure-ai-agents | AIM Platform |
| Capability-based access control | why-your-nhi-strategy-doesnt-cover-ai-agents | AIM Platform |
| Agent lifecycle management | introducing-aim-agent-identity-management | AIM Platform |
| `from aim_sdk import secure` wrapping | echoleak-one-line-secure-ai-agents | Python SDK (aim_sdk) |
| OpenClaw PR contributions | openclaw-merges-security-scanner, securing-openclaw-6-security-fixes | External repo (OpenClaw) |

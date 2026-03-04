# Unbuilt Features — Documented from Blog Audit

This document tracks features claimed in OpenA2A blogs that have not yet been built.
Audit date: 2026-03-04. Build in priority order.

---

## Priority 1: SOUL Scanner — Expand from 26 to 68 Controls

**Blog:** soul-md-ai-governance-opena2a
**Current state:** `scan-soul` implements 26 of 68 specified OASB v2 controls
**Gap:** Need to add 42 more controls (currently ~3 per domain; spec targets 8-10 per domain)

Per-domain expansion needed:

| Domain | Current | Target | Gap |
|--------|---------|--------|-----|
| 7: Trust Hierarchy | 2 | 8 | +6 |
| 8: Capability Boundaries | 4 | 10 | +6 |
| 9: Injection Hardening | 3 | 8 | +5 |
| 10: Data Handling | 3 | 8 | +5 |
| 11: Hardcoded Behaviors | 3 | 8 | +5 |
| 12: Agentic Safety | 3 | 10 | +7 |
| 13: Honesty and Transparency | 3 | 8 | +5 |
| 14: Human Oversight | 3 | 8 | +5 |

**File:** `hackmyagent/src/soul/scanner.ts` — add controls to `CONTROL_DEFS`
**Test:** `hackmyagent/src/soul/soul.test.ts` — update expected counts

---

## Priority 2: SOUL Scanner — Layer 3 Semantic Analysis (--deep flag)

**Blog:** "Three-Layer Detection" section
**Current state:** Layer 1 (structural) and Layer 2 (keyword) implemented. Layer 3 marked as "Future".
**Gap:** `--deep` flag not implemented. Should use `claude --print` (Claude Code CLI) to do LLM-based semantic analysis.

Implementation notes:
- Add `--deep` flag to `scan-soul` command in `cli.ts`
- In scanner, after keyword check, if `--deep` enabled:
  - Call `execSync('claude --print "..."')` with control-specific prompt
  - Fallback to `$ANTHROPIC_API_KEY` API call if `claude` not available
- Target confidence bump: 0.7 → 0.95 for controls that pass semantic check

---

## Priority 3: OASB v2 Conformance Levels

**Blog:** scoring section (Essential, Standard, Hardened)
**Current state:** Scanner outputs score + grade but no conformance level label
**Gap:** Add conformance determination to scan result output

Spec:
- **Essential** — All CRITICAL controls pass (IH-003, HB-001)
- **Standard** — All CRITICAL + HIGH controls pass, score >= 60
- **Hardened** — All controls pass, score >= 75

Add `conformance: 'none' | 'essential' | 'standard' | 'hardened'` to `SoulScanResult`
Display in scan output: `Conformance: ESSENTIAL`

**File:** `hackmyagent/src/soul/scanner.ts`, `src/cli.ts` (display)

---

## Priority 4: scan-soul Composite Scoring with OASB v1

**Blog:** "50% infrastructure (domains 1–6) + 50% governance (domains 7–14)"
**Current state:** `scan-soul` only scores governance (domains 7–14). No integration with OASB v1 infrastructure scores.
**Gap:** `opena2a benchmark` runs OASB v1; no way to get composite score.

Implementation notes:
- `scan-soul --with-benchmark` could run OASB v1 and combine scores
- Or `opena2a review` could combine both scan results into a composite score
- This is a significant integration effort

---

## Priority 5: `secure --benchmark oasb-2` Command

**Blog:** "Full OASB v2 assessment" via `npx hackmyagent secure --benchmark oasb-2`
**Current state:** The `secure` command exists but `--benchmark oasb-2` flag is not implemented.
**Gap:** Need to add `--benchmark oasb-2` to run full v1+v2 combined assessment.

---

## Non-Priority (Wrong Product Attribution)

The following features were claimed in blogs but actually belong to **separate products** (AIM Platform, Python SDK). These are correct as positioned — they're not CLI features.

| Feature | Blog | Actual Product |
|---------|------|----------------|
| Ed25519 keypair generation | how-do-you-give-an-ai-agent-a-verifiable-identity | AIM Platform (agent-identity-management) |
| MCP server attestation | owasp-agentic-top-10-nhi-governance | AIM Platform |
| Behavioral trust scoring (8-factor) | echoleak-one-line-secure-ai-agents | AIM Platform |
| Capability-based access control | why-your-nhi-strategy-doesnt-cover-ai-agents | AIM Platform |
| Agent lifecycle management | introducing-aim-agent-identity-management | AIM Platform |
| `from aim_sdk import secure` wrapping | echoleak-one-line-secure-ai-agents | Python SDK (aim_sdk) |
| OpenClaw PR contributions | openclaw-merges-security-scanner, securing-openclaw-6-security-fixes | External repo (OpenClaw) |

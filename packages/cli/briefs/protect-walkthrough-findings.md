# `opena2a protect` real-world walkthrough findings — 2026-04-17

Captured during the new-user walkthrough that ran against
`/tmp/hma-real-world/` fixtures after the 12-bug fix commit `7c2f976`.
Scenarios and the playbook itself live at
`packages/cli/__tests__/PROTECT_WALKTHROUGH.md`.

Findings are ordered by ship-impact. Bugs #1 and #6 should land in the same
PR as the 12-bug fix; the rest are next-iteration UX work.

---

## #1 — CRITICAL: CRED-004 false-negative on JSON-quoted keys

**Reproducer:** S1 in the playbook. `mcp.json` contains
`"WATSONX_API_KEY": "ibm-api-FAKE-key-for-testing-1234567890"`. `protect`
prints "No hardcoded credentials detected" — clean miss.

**Root cause.** The CRED-004 regex requires `(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]`.
In the source line, between `API_KEY` and the `:` there is a closing `"` of
the JSON key, breaking the contiguous `key\s*[:=]` shape. This is the same
class of bug that CRED-005 had before the 2026-04-17 fix (`['"]{0,2}` was
inserted around the separator).

**Why it matters.** Vendor-prefixed API keys (Watsonx, Composio, Cohere,
Mistral, etc.) are a primary class of secrets in MCP server configs. Missing
them silently means `protect` runs on a vulnerable repo and reports it clean.
That's worse than not running protect at all.

**Fix.** Update CRED-004 regex to allow `['"]{0,2}` between the key and the
separator, mirroring CRED-005. Add a JSON-form regression in
`__tests__/util/credential-patterns.test.ts` and a fixture-driven test in
`__tests__/commands/protect.test.ts`.

---

## #6 — HIGH: Stale rollback manifest is never cleaned up

**Reproducer:** S8 in the playbook. Run protect → 1 credential migrated →
manifest written. Manually restore the source. Run protect again → reports
zero credentials → **manifest still claims the credential is in vault.**

**Root cause.** `migrateCredentials` writes the manifest only when
`vaultStored.length > 0`. On a no-credential run, the previous manifest is
never overwritten or deleted, so it lingers as a misleading record.

**Why it matters.** A user reading the manifest after a successful rollback
will believe their secrets are still in vault and may unnecessarily run
`secretless-ai secret rm` against keys that aren't there, or skip rotating a
secret they think is still protected. Trust bug.

**Fix.** When `vaultStored.length === 0` and the manifest exists, either
delete it or rewrite with empty `credentials` and a `clearedAt` timestamp.
Add a regression test that runs protect twice and asserts the manifest state.

---

## #13 (was #1 in this brief, renumbered for ship priority): same as #1

---

## #2 — UX BUG: markdown files with embedded code emit broken Python

**Reproducer:** S2 in the playbook. `composio-skill/SKILL.md` has
`api_key="comp_fake_..."` inside a Python block. Replacement output is
`api_key="${API_KEY}"` — a literal Python string at runtime, not env
interpolation.

**Root cause.** `getEnvVarReplacement` switches on file extension. `.md`
falls through the JS/Python/etc. branches and lands in the config-file path
that emits `${VAR}`. The function does not consider that markdown often
embeds code blocks of other languages.

**Options.**
- (a) Detect fenced code blocks and use the language tag (` ```python `, etc.)
  to choose the right replacement.
- (b) Refuse to autopatch markdown when a credential is found and emit a
  manual-fix instruction.
- (c) Ship a comment-style replacement that is correct in any language
  (`# secret moved to env var API_KEY — restore from .env.example`).

Recommended: (b) for now, (a) for the next major.

---

## #3 — UX GAP: env var name is generic when source context names a vendor

**Reproducer:** S2. `composio.Client(api_key="...")` produces env var
`API_KEY`. Should be `COMPOSIO_API_KEY`.

**Fix.** When CRED-004 fires, look 50 chars left of the match for an
identifier ending in `.Client(`, `.create(`, or a SDK constructor pattern.
Use that identifier as the env-var prefix. If no identifier found, fall back
to `API_KEY`.

---

## #4 + #5 — UX GAP: zero-credentials output is too thin and silent about hygiene

**Reproducer:** S3. `mega-mcp` (already secured) outputs only:

```
No hardcoded credentials detected.
protect also applies git hygiene and config signing.
```

But protect also: created `.gitignore`, wrote `.env.example`, edited
`CLAUDE.md`, signed `mcp.json` into `.opena2a/guard/signatures.json`, made a
backup directory. The user is told nothing.

**Fix.** Promote the existing additionalFixes report to the zero-credential
path. Show what was done and what to do next:

```
No hardcoded credentials detected.

Hardening applied:
  .gitignore added with .env exclusion
  .env.example created (1 placeholder)
  CLAUDE.md updated with secretless guidance
  mcp.json signed (config integrity)

Next steps:
  opena2a runtime start    Enable runtime monitoring
  opena2a guard resign     After editing signed configs
```

---

## #7 — UX GAP: no masked secret preview on findings

**Reproducer:** S9. The findings table shows finding ID, type, location, and
env var name — but no preview of which secret matched. The HMA standard
documented in user memory is "first 5 + ****" (`AIzaB****`).

**Fix.** Add a `masked` column to the findings table (verbose mode only) that
shows the first 5 chars + `****` of the captured value. Helps the user verify
the match.

---

## Ship plan

This walkthrough was run AFTER commit `7c2f976` (the 12-bug fix). Findings #1
and #6 should be fixed in a follow-up commit on the same branch
`fix/protect-credential-migration-bugs` BEFORE pre-push and BEFORE publish.
Findings #2, #3, #4/#5, #7 are next-iteration UX work — open a separate brief
for them under `briefs/protect-ux-roundtwo.md` when ready to attack.

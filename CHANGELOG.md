# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### What this release does not fix
- **A tree-local package-manager configuration runs before the CLI's first instruction.** A committed `.npmrc` carrying a `node-options` line is read by npm itself whenever the CLI is started through `npx`, `npm exec` or `npm run` inside that tree, and the options it names take effect before the CLI's first instruction. Yarn's `.yarnrc` and `.yarnrc.yml` and pnpm's `.pnpmfile.cjs` are the same class for those package managers. No in-process check can detect it: by the time any opena2a-cli code executes, the code that configuration loaded has already run and could have altered anything a check would look at. This is a permanent limit of starting the CLI through a package manager from inside the tree it is pointed at, not a defect a later release can close. **Verify in a tree you are about to scan:** `find <tree> -name node_modules -prune -o \( -name .npmrc -o -name .yarnrc -o -name .yarnrc.yml -o -name .pnpmfile.cjs \) -print` prints each such file; treat anything it prints as code that runs when a package manager is invoked inside that tree. **Fix:** start the CLI from outside the tree and name the target as an operand, for example `npx opena2a-cli review "$GITHUB_WORKSPACE"` with `working-directory: ${{ runner.temp }}` in a GitHub Actions step; the `opena2a-cli` recipes in `docs/use-cases/ci-cd.md` for GitHub Actions, GitLab CI, Azure Pipelines and CircleCI take this form. Do this whichever way the CLI is installed: the scanner runs the CLI delegates to are started from the directory you run `opena2a` in, some of them through `npx`, and this release does not change that. The documented `npx opena2a-cli` lines for `init`, `protect`, `review`, `status`, `detect`, `setup`, `runtime`, `scan-soul`, `harden-soul`, `harden-skill`, `benchmark`, `comply`, `check`, `trust` and `claim` — the fifteen commands the test enforces — now name their target, and `packages/cli/__tests__/repo/docs-npx-explicit-target.test.ts` fails `npm run test` when one of those lines stops doing so. This repository's own CI and release build jobs refuse to install while any of these files, or an `.envrc`, is tracked; that protects this project's builds and does nothing for a tree you scan.

### Fixed
- Two `opena2a` processes writing an event at the same time no longer fork the tamper-evident log. `writeEvent` read the last line for its `prevHash` and then appended, with nothing serialising the two steps, so interleaved writers appended two events claiming the same predecessor. Measured on a fresh log with 8 concurrent writer processes: `{"valid":false,"brokenAt":1}` on 5 of 5 runs, and 7 of 10 runs at 2 writers. No attacker involved — a shell preexec hook firing while `opena2a` runs, or a git hook racing a CI step, is enough. That fork used to be cosmetic; now that `review` verifies the chain, it produces a `critical` finding, a "Not safe to ship" verdict, exit 1, and the permanent exclusion of every later event, on a clean project. The read-and-append sequence (and the size-based rotation that can rename the file underneath it) now runs under an `O_EXCL` lockfile with a synchronous wait. A lock whose recorded pid is dead on this host, or that is older than 5s, is taken over; the 6s acquisition timeout deliberately exceeds that staleness window so an abandoned lock is always reclaimed rather than outliving every waiter. On a genuine timeout the event is still written — losing a security event is worse than a forked chain — but never silently: stderr names the lock, the holder's pid and host, and the wait. `O_EXCL` is atomic locally and not reliable on NFS, so a network-mounted home degrades to the age rule.
- `SHIELD-INT-002` (broken event-log hash chain) has a path to green. Its remediation was `opena2a shield selfcheck && opena2a shield recover --forensic`; followed verbatim on a broken log, selfcheck reported the config intact, `recover` reported "System is not in lockdown" (a chain break does not trigger lockdown), and `review` kept raising the critical. No command reset or rotated the event log, so the only exit was deleting `~/.opena2a/shield/events.jsonl` by hand — in a tamper-evidence system. New `opena2a shield recover --archive-log` refuses when the chain is intact, and otherwise renames the broken log to a timestamped `events-<ISO>.jsonl` sibling (the naming rotation already uses), starts a fresh genesis-anchored chain, and records the archive path, its sha256, the break index and the excluded-event count as that chain's first event. The log is archived, never deleted: it is the evidence, and anchoring its digest in the new chain means a break cannot be laundered by rotating it away. The remediation string now names this command.

### Changed
- `opena2a shield recover` no longer advertises `--forensic` or `--reset`. Both were registered as options and documented in `shield recover --help`, and neither was ever read — `handleRecover` branched only on `--verify`. `--forensic` was described as "Forensic mode (read-only, no changes)" while the command it ran unconditionally exited lockdown, so its help text stated the opposite of its effect. They are removed rather than implemented; `--verify` and the new `--archive-log` are the two flags the command actually acts on. `SHIELD-POL-003` likewise cited `opena2a shield policy --enforce`, where `--enforce` is a `guard` flag that `shield` swallowed via `allowUnknownOption()` — the remediation now names the command that prints the policy mode, since no CLI path switches that mode today. A new structural test walks every `FINDING_CATALOG` remediation, resolves each command and subcommand against the CLI's own routing surface, and fails on any cited flag that is unregistered or registered-but-never-read, so a remediation cannot become a dead end again without the suite going red.

- The bundled `hackmyagent` pin moves 0.25.2 to 0.30.0, exact. Both copies opena2a-cli resolved before this release were deprecated by us: `npm view hackmyagent@0.25.2 deprecated` prints a notice naming three defects, and `npm view hackmyagent@0.30.0 deprecated` is empty. `scan-soul`, `harden-soul`, `benchmark` and `init` load this copy in process. `scan`, and `check` when the target is a local path, resolve it too, but as a spawned child process from `node_modules/.bin` rather than an in-process import — still this pinned copy, never `PATH`. `review` gets there by a different route — it spawns `npx hackmyagent secure`, which resolves this pinned copy when opena2a-cli is installed in a project, but falls back to your `PATH` (or to whatever npm serves as current) for a global install with no project `node_modules`. **One behaviour change follows from it, under one condition.** For an npm package, a GitHub repo, or a `skill:`/`mcp:` target, `opena2a check` spawns the `hackmyagent` on your `PATH` and returns its exit code verbatim. The pin does not move that binary, so if you have one installed, this release changes nothing about that command. If you do not, `check` falls back to the copy this package bundles, and there the pin carries the fix for hackmyagent#373 (`check --json` exits 0 despite critical findings, first fixed in 0.26.1): `opena2a check <target> --json` then exits non-zero where it previously exited 0. A pipeline that read exit 0 as "no critical findings" was reading a defect and will now fail where it used to pass. That is the fix working, but it is a CI-visible change and worth checking before you upgrade. `hackmyagent --version` tells you which of the two cases you are in.
- `MIN_HMA_VERSION` moves 0.16.7 to 0.26.1. It governs a different copy from the pin above: the `hackmyagent` on your `PATH`, which is the binary `check` spawns for the targets named above. Below 0.26.1 that binary carries #373, so the command cannot fail a CI job; opena2a-cli now says so on stderr, once per process, instead of staying silent. It warns and never blocks, because a below-floor scanner still produces a useful report — the defect is in the exit code, not the findings. The floor is deliberately not raised to match the pin, and deliberately does not exclude hackmyagent#406: that defect is in the `attack` verb, opena2a-cli registers no `attack` command (`opena2a attack` returns `unknown command`), and warning about a defect that cannot reach you through this tool would be noise.

### Security
- **New `SECURITY.md` "Known advisories" section**, covering `adm-zip` (GHSA-xcpc-8h2w-3j85, high), reached transitively through `hackmyagent` → `onnxruntime-node`. No fix is available from us today; see that file for the verify command and why.

### Known issues
- **A second, deprecated copy of `hackmyagent` survives this release, and one command still reaches it.** The pin above moves the copy opena2a-cli itself loads. It does not move the copy nested under `ai-trust`, which arrives through `ai-trust`'s dependency range rather than ours: opena2a-cli declares `ai-trust: "^0.2.23"`, that caret resolves `ai-trust@0.2.25`, and `0.2.25` declares `hackmyagent: "^0.17.1"`. Every version published in that range is one we deprecated — `npm view 'hackmyagent@^0.17.1' deprecated` prints the same notice for all eleven of them — so which one npm picks for you does not change the finding, and this note deliberately does not name one. **Verify in your own tree:** `npm ls hackmyagent` lists every resolved copy and the dependency that pulled it in (add `-g` if you installed opena2a-cli globally), and `npm view hackmyagent@<the version it printed> deprecated` prints the notice for that copy. **What it affects:** `opena2a registry <package>` and `opena2a publish` reach it. Both route through the same adapter, which delegates to `ai-trust check`, and `ai-trust` resolves its own copy. `scan`, `review`, `check`, `scan-soul`, `harden-soul` and `benchmark` do not. **Fix:** npm honours an `overrides` block only in the root `package.json` of a project, never one declared inside an installed dependency ([npm docs](https://docs.npmjs.com/cli/v11/configuring-npm/package-json#overrides)), which is why we cannot ship this fix and you can. Adding `"overrides": { "ai-trust": { "hackmyagent": "0.30.0" } }` to your own `package.json` and reinstalling collapses the two copies into a single non-deprecated `hackmyagent@0.30.0`; measured on 2026-08-11, `ai-trust check express` still runs and exits 0 under it. What that measurement does not cover is every `ai-trust` code path against a scanner outside its declared range, so treat it as a workaround to re-check after any `ai-trust` upgrade, not as a supported configuration. If you would rather not, run `hackmyagent check <package>` from a current `hackmyagent` and read that verdict instead. Upgrading `ai-trust` does not help on its own: `ai-trust@0.7.6`, the current release, pins `hackmyagent 0.23.11`, which carries the same deprecation notice. The durable fix is an `ai-trust` release that admits a non-deprecated `hackmyagent`, and `npm view ai-trust dependencies.hackmyagent` is the one-line check that tells you when that has happened.

## [0.10.13] - 2026-08-05

### Fixed
- Scans are scoped to what you asked them to scan, and credentials are caught whatever shape the key is. Both fixes live in the pinned scanner and land here with the `hackmyagent` pin moving 0.25.1 -> 0.25.2 (exact), which this release carries. `secure`/`scan`/`review` were folding findings from the AI runtimes installed in `$HOME` — `~/.openclaw`, `~/.nemoclaw` and peers — into the score for whatever directory you pointed them at. Measured on a machine with a populated `~/.openclaw`: `opena2a review <an empty directory>` reported **0/100 and 1782 findings**, opening "Not safe to ship. [OpenClaw] Browser Data Access + 1781 more", where the same directory under a sandboxed `HOME` scored 98 with 1 finding. `--fail-below` was therefore not a CI gate: the identical commit scored 98 on a runner and 0 on a laptop. Those runtimes are now reported in their own labelled section — name, path and a runnable command that scans that scope — and are never scanned here, never counted in the target's findings, score or exit code, and carry no score of their own. Separately, `opena2a scan` returned **98/100 and exit 0** on a source file holding a hardcoded legacy `sk-` key while returning 69/100 and exit 1 on the same file using a `sk-proj-` key. The scanner adds the one missing pattern (`sk-[a-zA-Z0-9]{48,}`) and anchors every existing one so a vendor prefix glued to an identifier tail no longer matches — `disk-<sha256>` had read as an OpenAI key. See the hackmyagent 0.25.2 notes for why the fix is deliberately limited to that shape.
- The CLI points at one registry, and it is one that resolves. `opena2a config show` reported `https://registry.opena2a.org` on a fresh install and `opena2a trust <pkg>` failed with "fetch failed", while `scan --help` advertised `https://api.oa2a.org` — two conflicting defaults in one CLI. That hostname has no DNS deliberately: it names the unreleased Registry frontend, not the API. The cause was a stale dependency pin — `@opena2a/shared` at 0.1.0 shipped the dead host as its built-in default and carried no migration — so the value was always present and always wrong. The pin moves to 0.1.2 and the registry URL is now resolved in one place: unset, blank, and every known stale host all resolve to `https://api.oa2a.org`, while a deliberately configured self-hosted registry is left alone. `trust`, `claim`, `mcp-audit` and `detect` all route through it and no longer carry private default constants; `admin` keeps its own on purpose, because it transmits the internal admin key and must never follow ambient config.

  **One behaviour change worth stating plainly:** if you have opted into community contributions, reports that previously failed to leave your machine now arrive. Nothing about consent changed — every submission path was, and still is, gated on `isContributeEnabled()` before the URL is ever resolved — but the URL those consented submissions were being sent to did not exist, so they silently failed at the network layer. They now reach `https://api.oa2a.org`. If that is not what you want, `opena2a config contribute off`.
- Two different measurements no longer share one name. `review` computed a Shield runtime posture (active tools, policy, shell integration, penalized by findings) and `init` computed a project governance posture; both were called `postureScore` and both rendered under the label "Posture Score", so one report showed 52 on the Overview page and 35 on the Shield page with nothing saying they measured different things. The Shield field is now `shieldPostureScore` and the report reads "Project Posture" and "Shield Posture". Two finding-count tiles that both read "Findings" are now "Scan Findings" and "Shield Findings". The three surfaces still answer different questions and still report different numbers — that part is by design, and each already states its scope (#252) — but a number a reader cannot trace to what it measured is not a measurement.
- `comply` no longer reports a bare `process.env.X` reference as a CREDENTIAL violation (#254). The generic keyword rule in `@opena2a/aicomply` captured the 26-character accessor `process.env.OPENAI_API_KEY` as the secret, because `apiKey` satisfies `/api[_-]?key/i` and the value character class contained `.`; the masked preview `pro****EY` was that string, not a key. This is the shape `protect` rewrites a hardcoded key *into*, so a user who followed the remediation and then ran `comply` as a CI gate got a VIOLATION on correctly-fixed code, and two commands in the same CLI disagreed about whether best practice is a violation. Fixed upstream and shipped: the pinned `@opena2a/aicomply` moves 2.2.0 -> 2.2.3 (exact). That release also stops an empty-valued key adopting the next line as its secret, which had produced a false CREDENTIAL on `.env.example` files — verified downstream here as well.
- `protect` no longer exits 0 after a non-interactive run that changed nothing (#256). `opena2a protect < /dev/null` printed the credential table, printed the raw confirmation prompt, and exited 0 with the credential still in source: the prompt rejects at EOF and the catch treated that as "no". Exit 0 is an affirmative claim, so a pipeline checking the exit code concluded the migration had happened. A non-TTY stdin is now detected before prompting; protect exits 2 and names `--ci` and `--dry-run`. A prompt that throws mid-run also exits 2, because no decision was reached. A deliberate "n" still exits 0 — the user was asked and answered. The gate sits above the output-format branch, so `--format json` is no longer a consent bypass: previously `opena2a --format json protect` with stdin closed rewrote source files, moved secrets into the vault, edited `.gitignore` and signed configs without ever asking, because the confirmation was skipped entirely in JSON mode. It now returns the same refusal as `code: CONFIRMATION_REQUIRED`. `--ci` was reachable only as a global option and never appeared in `protect --help`; it is now registered on the command, and either placement works.

  Note for automation: a bare non-interactive `opena2a protect` changes from exit 0 to exit 2. That is the point of the fix — exit 0 was an affirmative claim about work that never ran — but any pipeline relying on the old behavior must add `--ci` (to migrate) or `--dry-run` (to preview). No in-repo caller depends on protect's exit code.
- `protect`'s rollback guidance is runnable where it is printed (#257). The sole advertised undo was `git checkout -- <files>`, printed unconditionally — including in a `mktemp -d` with no repository, where it cannot run, and there is no `--undo` flag to fall back on. Rollback rendering now asks git whether the target is inside a work tree (via `rev-parse`, so a subdirectory of a repo still qualifies) and only offers `git checkout` there. Outside a repo it states that the source edit is not reversible from disk and names `npx secretless-ai secret list` / `secret get <NAME>`, verified subcommands of the vault protect writes to. Deliberately not a rollback manifest: the original file still holds the plaintext credential, so a backup on disk would re-create the exposure protect had just removed.
- Both halves of an AWS key pair are judged by one rule (#258). AWS's published documentation pair produced exactly one finding — DRIFT-002 on the access key id, nothing on the secret — so a user acting on the output migrated the harmless identifier and left the dangerous value in place. Re-running the same file shape with a non-example 40-char secret produced both findings, which establishes that CRED-005's pattern was never broken: suppression ran only for `nameGated` patterns, and CRED-005 is name-gated while DRIFT-002 is not. Prefix-bearing patterns now suppress on EXACT membership in the canonical `@opena2a/credential-patterns` `KNOWN_EXAMPLE_KEYS`, which lists both halves of the AWS pair source-verified against the IAM User Guide. Deliberately exact and not a substring test: every prefix-bearing pattern admits `_`/`-` in its body, so a substring rule would let `<live key>-SAMPLE` match greedily, contain a placeholder word, and be dropped — while `.replace('-SAMPLE','')` restores the key at runtime. It would also blank the project's own malicious corpus, whose fixture credentials are deliberately marked `FAKE`, and disagree with `hackmyagent` on the same bytes. Name-gated patterns keep the broader placeholder + entropy guard, because their match rests on a nearby name rather than the value's shape. Both duplicated match loops now call one predicate, so `init` and `protect` cannot drift on what counts as a credential.
- `shield evaluate` reports a verdict in its default text mode (#255). It wrote zero bytes and exited 0, which is indistinguishable from a crash, while `--json` proved the work had happened. The silence protected the shell preexec hook, which runs `evaluate` on every interactive command; that is preserved, because the installed hook always passes the command as a positional argument and never passes `--action`/`--target`. Hook mode is keyed off the raw arguments rather than the parsed command string, so an absolute-path command is not misread as a direct invocation. `--action` and `--target` are now registered options: they are printed as remediation by the Shield findings themselves, but `allowUnknownOption` silently swallowed them, so the evaluated target was always the empty string and the run printed nothing — following the tool's own advice reproduced the bug it was meant to fix. The verdict names the outcome, deciding rule, agent, and the subject actually evaluated, and states a default-allow out loud rather than implying the action was vetted.
- `skill create` generates a skill that passes `scan` (#259). `skill create` → `scan` is the documented quickstart, and it reported the tool's own pristine output as `malicious` with 5 HIGH findings. Measured against hackmyagent 0.25.1: 55/100 · 5 high · `malicious` → 69/100 · 1 high · `unknown`. SKILL.md now carries inline Trust Hierarchy and Constraints sections (the prompt-security checks read the artifact's own constraints, so a sibling SOUL.md would not have satisfied them); the `heartbeat:` frontmatter block is gone, because SKILL-003 matches it per-line and the schedule already lives in HEARTBEAT.md; HEARTBEAT.md declares `activeHours:`; and the scaffold ships a `.gitignore` that does not ignore `.env.example`. The remaining findings all require an AIM identity, a verified publisher, or a registry submission and cannot be satisfied by generated files. `skill create` also no longer claims "Signed SKILL.md and HEARTBEAT.md" when what it wrote is an opena2a-guard pinned hash — it says so, and names `hackmyagent fix-all --with-aim` as the way to get an AIM signature.

### Security
- `self-register` no longer writes to the public registry without consent. The command submits community scan-result records to `api.oa2a.org`; `--dry-run` existed but the destructive path was the default and nothing was asked before it ran. A release-test harness invoking the bare command published records from a developer laptop — a sandboxed `HOME` did not prevent it, and `OPENA2A_TELEMETRY_URL` does not apply because `self-register` talks to the registry directly. It now confirms interactively, and a non-interactive shell (`--ci`, or any pipe where stdin is not a TTY) must pass `--yes`. The refusal exits 2 and names both `--yes` and `--dry-run`, in text and in JSON (`code: CONFIRMATION_REQUIRED`), so an automated caller relying on the old behavior fails visibly rather than silently doing nothing. The gate sits ahead of the per-tool loop, so a refused run performs no existence checks and no HMA scans — previously a bare invocation made 33 requests before finishing.

## [0.10.12] - 2026-07-29

### Security
- Delegated tools now receive an allowlisted environment declared by their own adapter registry entry, instead of the operator's entire environment (#228). Measured on one developer machine: 128 variables reached the child, 11 of them credentials; now 20 and none. The contract lives on each `ADAPTER_REGISTRY` entry (`envAllow` / `envAllowPrefixes`) rather than in a single generic list, because these adapters run first-party tools with real environment contracts — `secretless-ai` needs `VAULT_ADDR`/`VAULT_TOKEN`/`AWS_*` because it is a credential broker, and `hackmyagent` needs `NANOMIND_URL`/`NANOMIND_GUARD_SOCK`/`ANTHROPIC_API_KEY` or it silently returns different findings with a zero exit code. Both reach the spawn path through the import-adapter fallback. New `util/child-env.ts` supplies the base allowlist (PATH/HOME/locale, proxy and custom-CA settings, CI markers, telemetry opt-out, the `*_CLI_PREFIX` citation vars) and a credential-name guard over prefix matches; exact entries bypass the guard, which is how a tool declares the credential it genuinely uses and how `SECRETLESS_CLI_PREFIX` survives a substring match on "secret". Availability probes (`which x`, `x --version`, `python -c "import m"`) get a narrower probe environment with no credentials at all. Operators can extend the allowlist with `OPENA2A_CHILD_ENV_ALLOW="NAME,PREFIX_*"`; a bare `*` and any prefix under three characters are refused, entries are capped, the widening is reported on stderr, and the variable is never forwarded to the child. The `release-smoke-comply` and `release-smoke-init` harnesses use the same mechanism. `secrets` and `broker` are declared EXEMPT (`envInherit`) rather than allowlisted: `secretless-ai` reads credential names it discovers at runtime, so a static list made `opena2a secrets verify` report a different machine than `secretless-ai verify` with both exiting 0. Their availability probes stay narrow regardless. The direct `hackmyagent` spawns in `router.ts`/`index.ts`/`review.ts`, `shield/llm-backend`, and the corpus parity harness still inherit the full environment and are tracked in #246. Scope note: this reduces environment-borne exposure only — `HOME` is forwarded by design, so `~/.npmrc`, `~/.aws/credentials` and `~/.docker/config.json` remain reachable by any child, and the guard matches names, not values.
- `shield recover --verify` now verifies before it recovers, which is what the flag has always claimed (#228). A `degraded` result still unlocks — a missing shell rc file must not strand anyone — but it no longer reports "successful verification"; the warnings are named in both the text and JSON output. Note `enterLockdown` has no production caller today, so this closes a fail-open on a path the shipped CLI does not currently reach. It previously called `exitLockdown()` first and re-entered lockdown only if the checks came back compromised, because `runIntegrityChecks` short-circuits while the lockdown marker is present. That briefly unlocked a compromised machine, and a check that threw — or a SIGINT, or a kill — during the window left it unlocked permanently. `runIntegrityChecks` takes a new `ignoreLockdown` option so the battery can run with the marker still in place; every other caller keeps the short-circuit.

### Fixed
- `benchmark` no longer certifies controls it never evaluated (#250). It returned `Certified`, `L1: 100% (39/39)` for an empty directory and for a project with a hardcoded API key, because a control counted as passing whenever no finding mentioned its check id — and the only source consulted evaluates none of the 39 OASB L1 controls. Scoring is now coverage-gated: unevaluated controls leave both sides of the ratio and are disclosed by count on the score line and by id under `--verbose`; `Certified`/`Passing` require complete coverage; zero coverage reports `Not assessable`. Credential controls are genuinely evaluated via the same scanner `init` and `protect` use, so `protect` and `benchmark` now agree that a hardcoded key fails CRED-002. Categories with no controls at the requested level report `n/a` rather than `0%`. New `npm run release-smoke:benchmark` corpus-tier gate.
- Every score line now states its scope (#252). `init`, `scan`, `review` and `benchmark` measure different things, and four bare numbers for one directory read as a contradiction. `init` labels project posture; `review` labels the composite and says when a critical dimension capped it rather than an average producing it; `benchmark` states evaluated-vs-total coverage.
- `init` detects credential-shaped values in template env files (#227).
- `review`'s verdict line no longer disagrees with the composite band it reports (#221, #222).
- Telemetry is suppressed in CI and under `DO_NOT_TRACK` (#240); the SDK's default endpoint points at the canonical ingest path (#225).

### Changed
- `hackmyagent` pin 0.23.6 -> 0.25.1 (#229, #239, and this release). 0.10.11 shipped 0.23.6, so the delegated scanner moves three steps for anyone upgrading and corpus aggregate scores move with it (the 0.25.0 -> 0.25.1 step alone: 83 -> 69, 76 -> 69). Across that last step the finding sets are byte-identical on every affected fixture — same check ids, same severity histogram — so the movement is 0.25.1's scoring corrections removing inflation rather than lost detection, and the parity goldens are re-baked per the documented pin-bump process. 0.25.1 also carries the artifact-intent reconciliation that stops `scan` printing a raw classifier label on a clean artifact, which is the label half of #251.
- Published security contact address is now info@opena2a.org (#235).

### Added
- `protect --grant <grant-ref> --atx <path>`: opt-in Agent Authorization Protocol gate. Before any scan, `protect` presents an ATX to the local Secretless broker and proceeds only if the broker authorizes the grant. The `packages/cli/src/aap/` broker client is the first TypeScript AAP consumer. Defends T-3002, T-3003, T-3006, T-8002 at the CLI surface.
  - Exit codes: 0 (broker authorized), 2 (--grant without --atx or invalid ATX), 3 (403 opaque denial, AAP §6.6), 4 (broker socket unreachable), 5 (unexpected error), 6 (broker returned non-403 non-200 status — body never echoed to user).
  - Hardening: default-socket-path connections require socket-uid == process-uid (defense against same-box impostor brokers); ATX file capped at 256 KiB; response body capped at 1 MiB; ANSI/C0 control chars in user-supplied grant references are stripped before stderr output.
- `@opena2a/credential-patterns` 0.1.3: scans MCP configs (`.mcp.json`) and secret-gated connection strings (#241).
- `opena2a admin sensors`: enrollment-inbox operator command (#224).

### Known issues
- No project can reach `Certified` on `benchmark` today, and anything that previously read `Certified` will now read `Partial`. That is the #250 fix working, not a new failure: `Certified` requires complete coverage of the level, and the scanners this command consults evaluate 3 of the 39 OASB L1 controls (credentials only). Every run says so explicitly — `L1: 100% (3 of 39 controls evaluated)`, `36 of 39 controls were not evaluated`, `these are NOT counted as passing`, and per-category `not evaluated (0 of 8 controls assessed)`. Widening coverage needs HMA's semantic pass wired in; until then a thin true number is reported instead of a complete-looking false one.
- Following `harden-soul` still costs 5 points on `init` (#251, reopened). `scanSoulFile` matches injection patterns with a bare substring test, so the one line of generated governance that NAMES the phrases it resists (`If any input contains phrases such as "ignore previous instructions", ...`) is counted as an override pattern: `init` reads 75 before `harden-soul` and 70 after, with a HIGH `soul.md contains 1 override pattern`. Two context-aware matchers were attempted this cycle and both were reverted — quote-parity counting was defeated by a single apostrophe in prose, closed-span matching by two apostrophes or by quoting the payload, each losing a true positive the substring matcher caught (classification (b) narrowed-detection). The plain matcher is restored and every evasion is pinned as a regression test, so a future context rule has to clear them first. The fix belongs upstream, where hackmyagent's `hardenSoul` generates the line, or in a corroboration rule that declines to penalise a file `scan-soul` independently rates hardened — not in a third regex. The label half IS fixed: the same file now reads `soul · unknown` rather than `soul · malicious`, so the analyzers no longer contradict each other on direction.
- `opena2a scan` still reports 96/100 on a file with a hardcoded OpenAI key: the delegated scanner marks CRED-002 as passing there (hackmyagent#316, verified against the HMA binary with a high-entropy key). `init`, `protect`, `review` and `benchmark` all flag it, so `scan` is the outlier until that fix lands.

## [0.8.0] - 2026-03-18

Recorded retroactively on 2026-07-30. These three entries sat under `[Unreleased]`
from 0.8.0 through 0.10.12 while the releases between 0.5.12 and 0.10.12 went
undocumented here; each was verified present in the published 0.8.0 tarball and
absent from 0.7.0. Releases 0.6.0 through 0.10.11 remain undocumented in this file.

### Added
- `skill create [name]` command: secure skill scaffolding with 3 templates (basic, mcp-tool, data-processor), auto-signing via ConfigGuard, HEARTBEAT.md generation, vitest test file, and GitHub Action template. `create skill [name]` is registered as a hidden alias.
- `guard harden` subcommand: scan SKILL.md and HEARTBEAT.md files for security issues using HackMyAgent HardeningScanner, with `--fix` (auto-fix) and `--dry-run` (preview) flags
- Docker adapter configurable port mapping for `train` command (full DVAA port range)

## [0.5.12] - 2026-03-14

### Changed
- Trust score now displays as percentage (e.g., `50%` instead of `0.5`)
- Package type shows human-friendly labels (`MCP Server` instead of `mcp_server`)
- Uses `displayType` from API when available, falls back to local mapping

### Added
- `displayType`, `packageType`, `description`, `repositoryUrl` fields in ATP response types

## [0.5.8] - 2026-03-12

### Fixed
- Fix `claim` command failing to find packages that `trust` could find -- now defaults source to 'npm' before registry lookup
- Fix `trust --verbose` producing identical output to non-verbose -- now shows request URL, response time, agent ID, source, and version

## [0.5.0] - 2026-03-05

### Fixed
- Fix all adapter --help commands (scan, secrets, benchmark, registry, broker, train, crypto) -- now pass through to underlying tool help instead of showing generic Commander.js description
- Fix `status` command crash ("unknown command" error) -- now shows unified security status via Shield
- Fix `check` command missing directory argument -- `opena2a check /path` now works
- Fix `benchmark` dispatch showing HMA help instead of running -- converted to direct command using HMA programmatic API
- Fix `registry` crash when invoked with no arguments -- now shows usage with examples
- Fix review "Grade F" UX violation -- replaced with recovery-framed scoring ("path to 100 available")
- Fix vault migration silently falling back to .env (AI tools read .env files, defeating the purpose)
- Fix vault migration not detecting missing 1Password CLI (op) -- now shows pre-flight error with setup instructions
- Fix protect output not showing which files were signed

### Added
- `status` command: unified security status across all installed tools
- `benchmark` command: direct OASB-1 compliance checking with --level L1/L2/L3
- OS Keychain vault backend option in protect migration flow
- Per-file signing details in protect output
- Rollback commands in protect output (undo signing, restore files)
- "For deeper analysis" hint in init output pointing to scan secure
- Storage location tracking (VAULT / SHELL PROFILE / FAILED) in migration report

### Changed
- Benchmark moved from adapter to direct command (programmatic HMA API)
- Vault fallback: shell profile exports instead of .env files
- Removed all registry.opena2a.org references (registry not yet available)

## [0.4.0] - 2026-03-04

### Fixed
- Fix scan-soul/harden-soul dispatch: moved from broken ImportAdapter fallback to direct SoulScanner programmatic API
- Fix registry command: changed from import to spawn method (ai-trust parses process.argv on import)
- Fix SpawnAdapter.isAvailable(): missing await on Promise || Promise caused false negatives
- Fix guard verify/status/diff ignoring positional directory argument
- Fix runtime status/tail rejecting positional directory argument
- Fix CRED-002 misclassifying sk-ant-* Anthropic keys as OpenAI (broadened negative lookahead)
- Fix CRITICAL/HIGH severity label visibility in terminal output
- Fix drift detection tip text inaccuracy
- Exclude CLI own source files from credential scanning

### Added
- Bundle hackmyagent, secretless-ai, ai-trust as dependencies (npx opena2a-cli scan-soul works out of the box)
- Direct scan-soul command with --profile, --tier, --deep options
- Direct harden-soul command with --dry-run, --profile, --tier options
- Progress-oriented scan-soul output with path-forward guidance

### Changed
- Remove "product" language throughout CLI (replaced with tool/platform/library)
- scan-soul and harden-soul are now direct commands, not adapter-backed

## [0.3.1] - 2026-03-02

### Fixed
- Fix review score fairness: redesign score breakdown with structured explainers
- Fix NL natural language input requiring literal shell quotes (multi-word fallback before Commander)
- Wire `--contribute` flag to report-submission.ts (was dead code)
- Fix broker/dlp commands routing identically to secrets (added subcommand differentiation)
- Make Shield events project-scoped (`.opena2a/shield/`) instead of always global
- Fix command injection in detect.ts (use `execFileSync` instead of `execSync`)
- Fix RC file overwrite in init.ts (use `appendFileSync` instead of `writeFileSync`)
- Fix npx auto-install in status.ts (add `whichBinary` gate before exec)
- Fix genesis hash bug in integrity.ts (used empty string instead of `GENESIS_HASH`)
- Fix 13 additional security, correctness, and UX bugs found during QA review

### Changed
- Replace generic stat-hero cards with score banner and structured explainers in review dashboard
- Update help text to show quote-free NL examples (`find secrets`, `detect credentials`)

## [0.3.0] - 2026-03-02

### Added
- Shield `init` orchestration: unified security setup that runs scan, policy, and hooks
- Cross-tab navigation for finding IDs in HTML dashboard
- Standardized tool nav bar ordering across repos

### Fixed
- Fix CI security checks: sync lock file, remove redundant secret-scan job

### Changed
- Update README with Shield command, adapter mappings, and ecosystem table

## [0.2.0] - 2026-03-02

### Added
- ConfigGuard: 18 features including sign, verify, status, watch, diff, enforce, policy, hook, resign, snapshot
- ConfigGuard pre-commit hook integration
- ConfigGuard skill and heartbeat file signing
- Shield enforcement mode with command blocking and event logging
- Shield adaptive baselines module (learn/suggest/protect flow)
- Shield interactive HTML posture report
- Shield CI integration workflow and example
- Shield E2E integration test covering full lifecycle
- ARP-Shield bridge with genesis hash fix and posture scoring
- Actionable security reports with finding IDs, SARIF, and compliance mapping

### Fixed
- Fix posture score: exclude Shield diagnostic events from threat scoring
- Fix ConfigGuard detection in shield status
- Fix guard type mismatch from cherry-pick merge

### Changed
- Upgrade report to multi-page dashboard with improved scoring

## [0.1.2] - 2026-03-02

### Added
- DRIFT-002 AWS Bedrock liveness verification
- DRIFT-001 Google Maps/Gemini scope drift detection with liveness verification
- Shield modules wired to CLI with signing, LLM, and session support
- Init command: security posture assessment with trust scoring
- Guard command: config file integrity signing and verification
- Runtime command: ARP agent runtime protection wrapper
- Advisory intelligence with vulnerability database checks
- Community contribution prompting system
- Self-register, verify, and baselines commands
- Secretless AI integration for broker and DLP adapters

### Changed
- Rename npm package from `@opena2a/cli` to `opena2a-cli`
- Fix credential detection accuracy and CLI UX

## [0.1.0] - 2026-03-02

### Added
- Initial release: meta repo with ecosystem overview and security policy
- Terminal demo GIFs showcasing security checks
- AI Browser Guard ecosystem entry

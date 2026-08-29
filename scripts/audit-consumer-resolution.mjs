#!/usr/bin/env node
/**
 * Audit the tree a CONSUMER of `opena2a-cli` resolves, not the tree this repo pins.
 *
 * `.github/workflows/security.yml` runs `npm ci && npm audit --audit-level=high`
 * against this monorepo. That measures the workspace root: every package under
 * `packages/*`, every devDependency, and whatever the committed lockfile pins.
 * A user gets none of that. They get one published tarball and its production
 * dependency closure, resolved fresh against the registry on their machine.
 *
 * The two numbers are different, and on 2026-08-10 the difference was a live
 * high advisory:
 *
 *   $ npm install --omit=dev opena2a-cli@0.10.13 && npm audit --omit=dev
 *   2 high severity vulnerabilities
 *   adm-zip  <0.6.0  GHSA-xcpc-8h2w-3j85
 *   via opena2a-cli -> hackmyagent@0.25.2 -> onnxruntime-node@1.27.0 -> adm-zip@0.5.18
 *
 * `hackmyagent`'s own dependency-audit workflow was green the whole time; that
 * is why that repo added a consumer-resolution job. `opena2a` never received
 * the fan-out, and `opena2a` is the package that shipped it to users.
 *
 * The rule: a gate is defined by the artifact it measures. A gate that measures
 * the repo when the risk lives in the published tree is decorative regardless
 * of its colour.
 *
 * ## The two artifacts, and why both are measured
 *
 * That rule cuts both ways, and the first version of this script failed its own
 * test. It defaulted to `opena2a-cli@latest` and the workflow passed no
 * `--target`, so on a pull request it resolved the ALREADY-PUBLISHED package.
 * It therefore could not fail on the PR's own diff: a PR adding a vulnerable
 * dependency went green, because the gate was looking at npm rather than at
 * what the PR would publish.
 *
 * So there are two runs, asking two genuinely different questions:
 *
 *   CANDIDATE  (`--target <tarball>`, wired to pull_request and push)
 *     "Would the tree a user resolves from THIS BRANCH carry an advisory?"
 *     The workflow runs `npm pack -w packages/cli` and points the gate at the
 *     resulting tarball. This is the run that can fail on a diff, and it is the
 *     one that has to be green before a change lands.
 *
 *   PUBLISHED  (default `opena2a-cli@latest`, wired to the weekly schedule)
 *     "Has the tree users already installed drifted into an advisory?"
 *     Nothing in this repository has to change for that answer to flip — an
 *     advisory published against an untouched transitive dependency does it —
 *     so it is asked on a timer rather than on a diff. A PR cannot turn this
 *     one green; only a release can.
 *
 * Both print their mode in the banner and in the closing line, because the two
 * numbers are not comparable and a reader has to be able to tell which tree a
 * given failure describes.
 *
 * ## What this installs, and why it installs at all
 *
 * The upstream version of this gate resolves `--package-lock-only`, so nothing
 * is fetched into an executable position. This port cannot: rule 4 below
 * requires reading files out of a dependency's own tarball at run time, which
 * needs the tree on disk. So it installs, and buys the safety back a different
 * way:
 *
 *   - `--ignore-scripts` on every install, so no `postinstall` runs. That is
 *     not theoretical here: `onnxruntime-node` has a `postinstall` that
 *     downloads a nupkg from nuget.org and unzips it (see the derived facts
 *     printed below).
 *   - nothing from the target is ever executed or imported by this script. It
 *     is unpacked, its manifests are read as text, and that is all.
 *
 * In CANDIDATE mode the tarball IS built from the branch under test, so the
 * older claim that "none of the fork's code is installed" no longer holds and
 * is not made here. What holds instead: the branch's code is unpacked but never
 * run, and the workflow packs with `--ignore-scripts` so the branch's own
 * `prepack`/`prepare` hooks do not execute either. The workflow also does not
 * build first — deliberately. What decides whether a user inherits an advisory
 * is the manifest's dependency closure, which `npm pack` carries whether or not
 * `dist/` was compiled, so building would buy no measurement and would cost
 * arbitrary code execution from a fork's branch. (The separate
 * `dependency-audit` job in the same workflow does `npm ci` on the PR branch;
 * that is tracked separately and deliberately untouched here.)
 *
 * ## Why the gate is an allowlist and not a count
 *
 * The advisory above had no fix reachable from a consumer for months:
 * `onnxruntime-node` pinned `adm-zip: ^0.5.16` while the patched `adm-zip` was
 * `0.6.0`, outside that caret, and `overrides` are not published, so nothing
 * this repo writes reaches a user's resolution. A gate that can only ever be
 * red is switched off inside a release and then protects nothing. (On
 * 2026-08-25 `onnxruntime-node@1.29.0` declared `adm-zip: ^0.6.0`, the advisory
 * left the consumer tree, rule 2 below failed the build, and the waiver was
 * deleted — the lifecycle this design intends.)
 *
 * So every high/critical advisory must be NAMED in ALLOWED with a reason and a
 * review date. Anything unlisted fails, an entry that stops matching fails, and
 * an entry past its date fails. A waiver nobody rechecks reads exactly like a
 * considered one, so the list is not allowed to accumulate quietly.
 *
 * ## Why waivers derive their facts instead of stating them
 *
 * This is the load-bearing difference from the upstream script, and it comes
 * from a real defect rather than from taste. The upstream `adm-zip` waiver
 * asserted a reachability claim in prose — that the shipped binaries make the
 * install script exit before `adm-zip` is needed. The claim was false, it was
 * false in our favour, and nothing detected the drift for weeks, because prose
 * is not measured by anything.
 *
 * So a waiver here may not state an environment-dependent fact. It carries a
 * `derive(ctx)` that reads the fact out of the installed tree on every run and
 * returns it for printing. If `derive` cannot take its measurement — package
 * missing, metadata unreadable, file layout changed underneath it — the gate
 * FAILS. Being unable to check a waiver is not the same as the waiver holding.
 */
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, existsSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const SELF = path.relative(REPO_ROOT, fileURLToPath(import.meta.url));

/**
 * The already-published package, used when no `--target` is given.
 *
 * This is the PUBLISHED question (see the header). The CANDIDATE question is
 * asked by passing `--target` a tarball from `npm pack -w packages/cli`.
 */
const DEFAULT_TARGET = 'opena2a-cli@latest';

/**
 * Which of the two questions this invocation is answering.
 *
 * Decided from the target rather than from a flag, so the label cannot drift
 * away from the thing actually installed: a target that exists on disk as a
 * tarball is by construction something this repo just built, and anything else
 * is resolved from the registry.
 */
function classifyTarget(spec) {
  const asPath = spec.startsWith('file:') ? spec.slice('file:'.length) : spec;
  if (/\.(tgz|tar\.gz)$/i.test(asPath) && existsSync(asPath)) {
    return {
      mode: 'CANDIDATE',
      spec: path.resolve(asPath),
      headline: 'CANDIDATE artifact — the tree a user would resolve from THIS BRANCH',
      question: 'Would merging this change ship an advisory to users?',
    };
  }
  return {
    mode: 'PUBLISHED',
    spec,
    headline: 'PUBLISHED artifact — the tree a user resolves from npm right now',
    question: 'Has the already-shipped tree drifted into an advisory since release?',
  };
}

// ---------------------------------------------------------------------------
// Derivations. Each returns lines of MEASURED fact, or throws.
// ---------------------------------------------------------------------------

/**
 * Where the second copy of `hackmyagent` comes from, and whether bumping the
 * intermediate would still leave it there.
 *
 * The second half is the part that matters and the part that rots. This waiver
 * only holds while "bump the intermediate" is not a fix, and that is a fact
 * about somebody else's release history, not about this repo. So it is asked of
 * the registry on every run: the moment the intermediate's latest stops pulling
 * a second copy, this derivation throws and the waiver fails, because the
 * honest action then is to bump the range rather than to re-date the waiver.
 *
 * An earlier draft of this entry asserted in prose that every published version
 * of the intermediate pins `hackmyagent`. That was false — 19 of its 41
 * published versions carry no such dependency — which is precisely the class of
 * quiet, in-our-favour drift the derivation requirement exists to catch.
 */
function deriveNestedHackmyagent(ctx) {
  const copies = nestedCopies(ctx.lock, 'hackmyagent');
  if (copies.length === 0) {
    throw new Error('no nested hackmyagent found, so there is nothing to describe.');
  }
  const shipped = ctx.lock.packages['node_modules/hackmyagent']?.version;
  if (!shipped) {
    throw new Error(
      'the consumer tree has no top-level hackmyagent, so "a second copy" is the wrong ' +
        'description of what is happening here. Re-read the tree.'
    );
  }

  const lines = [];
  const parents = new Set();
  for (const p of copies) {
    const version = ctx.lock.packages[p]?.version ?? '?';
    // `node_modules/a/node_modules/b` -> the parent is `node_modules/a`.
    const parentPath = p.slice(0, p.lastIndexOf('/node_modules/'));
    const parent = ctx.lock.packages[parentPath];
    const parentName = parentPath.slice(parentPath.lastIndexOf('node_modules/') + 'node_modules/'.length);
    parents.add(parentName);
    lines.push(
      `${p} resolves hackmyagent@${version}, required by ${parentName}@${parent?.version ?? '?'} ` +
        `as "${parent?.dependencies?.hackmyagent ?? '?'}". This CLI ships hackmyagent@${shipped}, ` +
        'so a consumer carries both.'
    );
  }

  // Is "bump the intermediate" a fix? Ask, do not assume.
  for (const parentName of parents) {
    const latest = ctx.registryLatest(parentName);
    const pinned = latest.dependencies?.hackmyagent;
    if (!pinned) {
      throw new Error(
        `${parentName}@${latest.version} (latest) no longer depends on hackmyagent, so raising ` +
          `the ${parentName} range in packages/cli would remove this nested copy. This waiver ` +
          'says the nesting is not fixable here; that is no longer true. Bump the range instead ' +
          'of re-dating the waiver.'
      );
    }
    // `pinned` is a semver RANGE and `shipped` is a VERSION, so the question
    // "would raising the intermediate collapse the two copies" is a semver
    // satisfaction, not a string comparison. This previously read
    // `pinned === shipped`, which answers "no" for every range that is not
    // written as a bare exact version — `^0.25.0` vs `0.25.2` compared unequal
    // and the waiver held, when npm would in fact have deduped them into one
    // copy and the honest action was to bump the range.
    // Resolved against `hackmyagent`, NOT against `parentName`: `pinned` is the
    // range the intermediate declares FOR hackmyagent, and `shipped` is a
    // hackmyagent version, so the intermediate is the wrong version list to ask.
    // Asking the wrong one returns the right answer today only by accident —
    // `ai-trust@0.23.11` does not exist, so it 404s to "does not admit" — and
    // would flip the day the intermediate happens to publish a version number
    // matching the pin string.
    if (ctx.rangeAdmits('hackmyagent', pinned, shipped)) {
      throw new Error(
        `${parentName}@${latest.version} (latest) pins hackmyagent "${pinned}", which npm ` +
          `resolves to include hackmyagent@${shipped} — the version this CLI ships — so ` +
          `raising the ${parentName} range would collapse the two copies into one. Bump the ` +
          'range instead of re-dating the waiver.'
      );
    }
    lines.push(
      `${parentName}@${latest.version} (latest today) pins hackmyagent "${pinned}". npm ` +
        `resolves that range against the published version list and it does NOT admit the ` +
        `hackmyagent@${shipped} this CLI ships, so raising the ${parentName} range moves the ` +
        'nested copy forward without removing it.'
    );
  }
  return lines;
}

// ---------------------------------------------------------------------------
// The lists.
// ---------------------------------------------------------------------------

/**
 * Advisories accepted in the consumer tree, keyed by GHSA id.
 *
 * An entry is a statement that a user installing `opena2a-cli` inherits this
 * advisory and we decided to ship anyway. `reason` has to survive that user
 * asking "why is my audit red because of your CLI", so it names the blocker,
 * not the severity — and it does not restate anything `derive` measures.
 */
const ALLOWED = [];

/**
 * Packages that must never appear in a consumer tree, at any version.
 *
 * `where: 'nested'` means: not the copy the consumer asked for. A second,
 * differently-versioned copy of a tool is a defect even when it carries no
 * advisory, which is why this is read off the lockfile rather than the audit
 * report — reading it from the advisory list would make the check vanish the
 * day upstream patches something unrelated.
 *
 * An entry may carry a `waiver`, on the same terms as ALLOWED: named, reasoned,
 * dated, and derived. A waiver for a package that is no longer nested fails, so
 * this list cannot rot either.
 */
const FORBIDDEN_PACKAGES = [
  {
    name: 'opena2a-cli',
    where: 'nested',
    reason:
      'A second, older copy of this CLI inside its own dependency tree. Beyond the disk ' +
      'cost, the nested copy is what `require`-ing the package from a dependency resolves ' +
      'to, so behaviour would depend on which copy the caller reached.',
  },
  {
    name: 'hackmyagent',
    where: 'nested',
    reason:
      'A second copy of the scanner. The nested one is the version some dependency pinned, ' +
      'not the version this CLI ships, so scan output can differ from what `opena2a` claims ' +
      'to run — and a sufficiently old copy prints its own deprecation notice during ' +
      '`npm install opena2a-cli`, describing defects in a version the user never asked for.',
    waiver: {
      reason:
        'Not fixable from this repository today. The nested copy is pulled by an intermediate ' +
        'dependency that pins hackmyagent itself; the edge, the versions, and whether bumping ' +
        'that intermediate would fix it are all printed under `derived` below, asked fresh on ' +
        'every run rather than claimed here. While it stays unfixable the real remedies are ' +
        'upstream dropping the dependency or this CLI dropping the intermediate, neither of ' +
        'which a CI gate should force. Dated rather than deleted so the decision is re-taken ' +
        'rather than inherited. Note the user-visible cost while it stands: `npm install ' +
        'opena2a-cli` prints the nested copy deprecation notice, which describes defects in a ' +
        'version nobody asked for.',
      reviewBy: '2026-11-01',
      derive: deriveNestedHackmyagent,
    },
  },
];

// ---------------------------------------------------------------------------
// Machinery.
// ---------------------------------------------------------------------------

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], ...opts });
}

/**
 * Read `onnxruntime-node`'s install metadata.
 *
 * It is a CommonJS module rather than JSON, so it has to be evaluated. That
 * happens in a child process: not as a security boundary (a child process runs
 * with the same privileges) but so that a throw, a mutated global or a stray
 * `process.exit` inside vendor code cannot be mistaken for a fault in this
 * gate. The real boundary is that `--ignore-scripts` means nothing in the
 * consumer tree has run before this point.
 */
function readInstallMetadata(pkgDir) {
  const metaPath = path.join(pkgDir, 'script', 'install-metadata.js');
  if (!existsSync(metaPath)) {
    throw new Error(
      `onnxruntime-node has no script/install-metadata.js, so the affected-platform list ` +
        'cannot be derived. Not a pass.'
    );
  }
  let raw;
  try {
    raw = run(process.execPath, [
      '-e',
      'process.stdout.write(JSON.stringify(require(process.argv[1])))',
      metaPath,
    ]);
  } catch (e) {
    throw new Error(
      `evaluating script/install-metadata.js failed, so the affected-platform list could ` +
        `not be measured: ${(e.stderr || e.message || '').toString().trim().slice(0, 300)}`
    );
  }
  try {
    return JSON.parse(raw);
  } catch {
    throw new Error('script/install-metadata.js did not yield JSON-serialisable metadata.');
  }
}

/**
 * Assert `npm audit --json` actually returned a MEASUREMENT, and hand back the
 * counts.
 *
 * This is not defensive tidying, it closes a hole that silently inverted the
 * gate. When the advisory database is unreachable, `npm audit --json` exits
 * non-zero but writes VALID JSON to stdout:
 *
 *   {"message":"request to https://registry.npmjs.org/-/npm/v1/security/
 *     advisories/bulk failed, reason: connect ECONNREFUSED","error":{...}}
 *
 * No `vulnerabilities` key, no `metadata`. `JSON.parse` succeeds, every reader
 * below is written `?? {}`, and the run reports "0 critical, 0 high" and passes
 * — so an outage, a proxy, an auth failure or a rate limit all present as a
 * clean tree, which is the single worst direction for this gate to be wrong in.
 *
 * A structure we cannot read a count out of means the tree was not measured,
 * and not measured is not a pass.
 */
function assertMeasurableReport(report, raw) {
  const fail = (why) => {
    const said = (report && typeof report === 'object' && report.message) || raw || '(nothing)';
    throw new Error(
      `npm audit returned no usable report, so the consumer tree was NOT measured: ${why}.\n` +
        '    Unknown is not a pass — an unreachable advisory database otherwise reads as ' +
        'zero vulnerabilities. Check network access to the npm advisory database and re-run.\n' +
        `    npm said: ${String(said).trim().slice(0, 400)}`
    );
  };
  if (!report || typeof report !== 'object' || Array.isArray(report)) fail('not a JSON object');
  if (!report.vulnerabilities || typeof report.vulnerabilities !== 'object') {
    fail('no `vulnerabilities` map — this is exactly the shape an advisory-database failure returns');
  }
  const counts = report.metadata?.vulnerabilities;
  if (!counts || typeof counts !== 'object') fail('no `metadata.vulnerabilities` counts');
  for (const key of ['critical', 'high', 'moderate', 'low', 'total']) {
    if (typeof counts[key] !== 'number') fail(`\`metadata.vulnerabilities.${key}\` is not a number`);
  }
  return counts;
}

/**
 * Assert the tree under test was actually RESOLVED, and say what it resolved to.
 *
 * Everything below reads the lockfile, and every one of those readers treats an
 * absent entry as "nothing to report". So a botched install — a target that
 * resolved to nothing, an `npm install` that half-failed, an empty probe —
 * produces an empty lockfile and a clean, confident, meaningless pass. The
 * liveness facts are therefore asserted before any of them run.
 *
 * The root name is taken from the lockfile rather than parsed out of the target
 * spec, because the spec may be a filesystem path to a tarball, from which the
 * package name cannot be recovered by string surgery.
 */
function assertTreeResolved(lock, probe) {
  const rootDeps = lock.packages?.['']?.dependencies ?? {};
  const names = Object.keys(rootDeps);
  if (names.length !== 1) {
    throw new Error(
      `the probe's lockfile records ${names.length} root dependencies (${names.join(', ') || 'none'}) ` +
        'where exactly one was installed. The tree under test was not resolved, so nothing ' +
        'below measured anything. Not a pass.'
    );
  }
  const rootName = names[0];
  const rootEntry = lock.packages[`node_modules/${rootName}`];
  if (!rootEntry?.version) {
    throw new Error(
      `\`${rootName}\` is named as the root dependency but has no node_modules/${rootName} ` +
        'entry in the lockfile, so the target was never resolved. Not a pass.'
    );
  }
  if (!existsSync(path.join(probe, 'node_modules', rootName))) {
    throw new Error(
      `the lockfile resolves \`${rootName}\` but node_modules/${rootName} is not on disk, so ` +
        'the install did not complete. Not a pass.'
    );
  }
  const entries = Object.keys(lock.packages).filter((p) => p !== '');
  if (entries.length <= 1) {
    throw new Error(
      `the consumer tree resolved to ${entries.length} package(s) — \`${rootName}\` and nothing ` +
        'below it. This package has production dependencies, so a closure that small means the ' +
        'install did not resolve them rather than that the tree is clean. Not a pass.'
    );
  }
  return { rootName, rootVersion: rootEntry.version, packageCount: entries.length };
}

/** Install `spec` the way a consumer does, and return npm's audit report. */
function auditConsumerTree(spec, probe) {
  writeFileSync(
    path.join(probe, 'package.json'),
    JSON.stringify({ name: 'consumer-resolution-probe', version: '1.0.0', private: true }) + '\n'
  );
  // `--omit=dev`: a consumer never installs our devDependencies.
  // `--ignore-scripts`: no dependency's postinstall runs. See the header.
  run('npm', ['install', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund', spec], {
    cwd: probe,
  });

  let raw;
  try {
    raw = run('npm', ['audit', '--omit=dev', '--json'], { cwd: probe });
  } catch (e) {
    // `npm audit` exits non-zero whenever it finds anything. The report is
    // still on stdout and is the entire point of the call.
    raw = e.stdout ?? '';
  }

  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    // A gate that could not take its measurement has not passed. `npm audit`
    // reaches the live advisory database, so an unreachable registry, a proxy
    // or a rate limit all land here — and every one of them would otherwise
    // surface as a raw SyntaxError that reads like a bug in this script.
    throw new Error(
      'npm audit produced no parseable report, so the consumer tree was never measured. ' +
        'This is not a pass. Check network access to the npm advisory database and re-run.\n' +
        `npm said: ${(raw || '(nothing)').slice(0, 500)}`
    );
  }
  // Parseable is not usable, and usable is not resolved. Both are asserted
  // before anything downstream is allowed to read a zero as good news.
  const counts = assertMeasurableReport(report, raw);

  const lockPath = path.join(probe, 'package-lock.json');
  if (!existsSync(lockPath)) {
    throw new Error(
      'the probe wrote no package-lock.json, so npm never resolved a tree here and every ' +
        'lockfile-driven check below would report nothing found. Not a pass.'
    );
  }
  const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
  const liveness = assertTreeResolved(lock, probe);
  return { report, lock, counts, liveness };
}

/** Every GHSA id at `high` or `critical`, with the package it lands on. */
function highAndCritical(report) {
  const out = new Map();
  for (const [name, v] of Object.entries(report.vulnerabilities ?? {})) {
    if (v.severity !== 'high' && v.severity !== 'critical') continue;
    for (const via of v.via ?? []) {
      if (typeof via !== 'object' || !via.url) continue;
      const id = via.url.split('/').pop();
      if (!out.has(id)) out.set(id, { id, severity: via.severity ?? v.severity, packages: new Set() });
      out.get(id).packages.add(name);
    }
  }
  return out;
}

/** Copies of `name` that are not the one the consumer asked for. */
function nestedCopies(lock, name) {
  return Object.keys(lock.packages ?? {}).filter(
    (p) => p !== `node_modules/${name}` && p.endsWith(`node_modules/${name}`)
  );
}

/** What a `derive` gets: the installed tree, and a way to find things in it. */
function makeContext(probe, lock, report) {
  return {
    lock,
    report,

    /**
     * The vulnerable range this run's audit report gives for `id` on `pkg`.
     *
     * Read out of the report rather than typed into a waiver, because it is a
     * property of the live advisory and advisories get revised. A waiver that
     * hardcodes "<0.6.0" keeps printing "<0.6.0" after the advisory is widened.
     */
    vulnerableRange(pkg, id) {
      const entry = report.vulnerabilities?.[pkg];
      if (!entry) {
        throw new Error(
          `the audit report has no entry for \`${pkg}\`, so the advisory range for ${id} ` +
            'cannot be read. Not a pass.'
        );
      }
      for (const via of entry.via ?? []) {
        if (typeof via === 'object' && via.url?.endsWith(id) && via.range) return via.range;
      }
      throw new Error(
        `the audit report's entry for \`${pkg}\` names no ${id} advisory carrying a range, so ` +
          'the vulnerable range cannot be measured. Not a pass.'
      );
    },

    /**
     * Every PUBLISHED version of `name` that `range` admits, resolved by npm.
     *
     * npm's own semver against the real version list, which is the same
     * resolution a consumer's install performs. Doing it this way rather than
     * hand-rolling range arithmetic keeps the answer identical to the one that
     * decides what a user actually gets, and keeps this script dependency-free
     * — the job installs nothing from this repo, so `semver` is not importable
     * here.
     */
    versionsSatisfying(name, range) {
      let raw;
      try {
        raw = run('npm', ['view', `${name}@${range}`, 'version', '--json']);
      } catch (e) {
        const said = `${e.stdout ?? ''}${e.stderr ?? ''}`;
        // "nothing published satisfies this range" is a real, usable answer.
        if (/E404|No match found for version/.test(said)) return [];
        throw new Error(
          `could not resolve "${name}@${range}" against the registry, so the versions it ` +
            `admits are unknown: ${said.trim().slice(0, 200)}`
        );
      }
      let parsed;
      try {
        parsed = JSON.parse(raw);
      } catch {
        throw new Error(`npm view "${name}@${range}" returned no parseable version list.`);
      }
      // `npm view` returns a bare string when exactly one version matches.
      const versions = (Array.isArray(parsed) ? parsed : [parsed]).filter(
        (v) => typeof v === 'string'
      );
      if (versions.length === 0) {
        throw new Error(`npm view "${name}@${range}" returned no versions in a usable shape.`);
      }
      return versions;
    },

    /**
     * Does `range` admit `version`, per npm's semver?
     *
     * The question "would raising this range collapse the two copies" is a
     * semver satisfaction. It was previously asked with `===` between a RANGE
     * and a VERSION, which answers "no" for every range not written as a bare
     * exact version, so the check silently held open a waiver that had already
     * become fixable.
     */
    rangeAdmits(name, range, version) {
      return this.versionsSatisfying(name, range).includes(version);
    },
    installed(name) {
      const dir = path.join(probe, 'node_modules', name);
      const manifestPath = path.join(dir, 'package.json');
      if (!existsSync(manifestPath)) {
        throw new Error(
          `${name} is not installed at node_modules/${name} in the consumer tree, so the ` +
            'facts this waiver depends on cannot be measured. Not a pass.'
        );
      }
      const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
      return { name, dir, manifest, version: manifest.version };
    },
    /**
     * The published manifest of `name@latest`.
     *
     * For facts about somebody else's release history, which no amount of
     * reading the installed tree can answer. Goes through `npm view` rather
     * than a raw fetch so it honours whatever registry, proxy and auth the
     * runner is configured with. A failure here throws, and an underivable
     * waiver fails the gate — same rule as everywhere else.
     */
    registryLatest(name) {
      let raw;
      try {
        raw = run('npm', ['view', `${name}@latest`, '--json']);
      } catch (e) {
        throw new Error(
          `could not read ${name}@latest from the registry, so it is unknown whether this ` +
            `waiver still holds: ${(e.stderr || e.message || '').toString().trim().slice(0, 200)}`
        );
      }
      const manifest = JSON.parse(raw);
      // `npm view` returns an array when the spec matches more than one version.
      const one = Array.isArray(manifest) ? manifest[manifest.length - 1] : manifest;
      if (!one?.version) throw new Error(`npm view ${name}@latest returned no version.`);
      return one;
    },
  };
}

/**
 * Print a waiver and the facts it stands on. Returns a failure string when the
 * facts cannot be measured — an underivable waiver is a failure, not a pass.
 */
function reportWaiver(label, waiver, ctx, failures) {
  console.log(`  allowed  ${label}  (review by ${waiver.reviewBy})`);
  console.log(`           ${waiver.reason.replace(/\s+/g, ' ')}`);
  if (typeof waiver.derive !== 'function') {
    failures.push(
      `Waiver ${label} has no derive(). Every waiver has to re-measure the facts it rests ` +
        `on, because prose is checked by nobody — add one in ${SELF}.`
    );
    console.log('           derived  (no derivation supplied)\n');
    return;
  }
  let lines;
  try {
    lines = waiver.derive(ctx);
  } catch (e) {
    failures.push(
      `Waiver ${label} could not derive the facts it rests on: ${e.message}\n` +
        `    A waiver that cannot be checked has not been checked. Re-read the dependency, ` +
        `then update the entry in ${SELF}.`
    );
    console.log('           derived  UNAVAILABLE — see failure below\n');
    return;
  }
  if (!Array.isArray(lines) || lines.length === 0) {
    failures.push(`Waiver ${label} derived no facts. Not a pass; fix the derivation in ${SELF}.`);
    console.log('           derived  (nothing)\n');
    return;
  }
  for (const line of lines) console.log(`           derived  ${line}`);
  console.log('');
}

function expired(reviewBy, today) {
  return !(typeof reviewBy === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(reviewBy) && reviewBy >= today);
}

function main() {
  const argv = process.argv.slice(2);
  const i = argv.indexOf('--target');
  const requested = i !== -1 ? argv[i + 1] : DEFAULT_TARGET;
  if (!requested) {
    console.error('--target needs a value (an npm spec or a path to a tarball).');
    process.exit(2);
  }
  const target = classifyTarget(requested);
  const spec = target.spec;

  const scratch = mkdtempSync(path.join(tmpdir(), 'opena2a-consumer-audit-'));
  const failures = [];
  let rootName = '(unresolved)';
  try {
    const probe = path.join(scratch, 'probe');
    mkdirSync(probe, { recursive: true });

    // Which of the two questions this run answers, said before anything else,
    // so a failure in the log is attributable to a tree without reading the
    // workflow that produced it.
    console.log(`[${target.mode}] ${target.headline}`);
    console.log(`[${target.mode}] ${target.question}`);
    console.log(`[${target.mode}] Target: ${spec}\n`);

    const { report, lock, counts, liveness } = auditConsumerTree(spec, probe);
    const ctx = makeContext(probe, lock, report);
    rootName = liveness.rootName;

    // Say what was actually measured. In PUBLISHED mode `latest` is a moving
    // target by design, and in CANDIDATE mode the tarball name does not have to
    // match what is inside it, so the resolved version is read back off the
    // lockfile or the measurement is unattributable.
    console.log(
      `[${target.mode}] Resolved ${liveness.rootName}@${liveness.rootVersion} — ` +
        `${liveness.packageCount} packages in the production closure\n`
    );

    console.log(
      `Consumer resolution: ${counts.critical ?? 0} critical, ${counts.high ?? 0} high, ` +
        `${counts.moderate ?? 0} moderate, ${counts.low ?? 0} low`
    );
    console.log(
      "(This repo's own workspace audit measures a different tree — devDependencies " +
        'included, `overrides` honoured, nothing published — and its number does not ' +
        'describe what a user installs.)\n'
    );

    const found = highAndCritical(report);
    const allowedById = new Map(ALLOWED.map((a) => [a.id, a]));
    const today = new Date().toISOString().slice(0, 10);

    // 1. Every high/critical advisory must be allowlisted.
    for (const adv of found.values()) {
      const allow = allowedById.get(adv.id);
      if (!allow) {
        failures.push(
          `Unlisted ${adv.severity} advisory in the consumer tree: ${adv.id} ` +
            `(via ${[...adv.packages].join(', ')}).\n` +
            `    A user installing ${rootName} inherits it. Either raise the floor to a ` +
            `patched version, drop the dependency, or add it to ALLOWED in ${SELF} with a ` +
            `reason a user would accept, a review date, and a derivation for anything about ` +
            `it that depends on the environment.`
        );
        continue;
      }
      // No silent caps: say what was waived, and on what evidence, every run.
      reportWaiver(`${adv.id}  ${allow.package}`, allow, ctx, failures);
    }

    // 2. An allowlist entry that no longer matches is removed, not left to rot.
    for (const allow of ALLOWED) {
      if (found.has(allow.id)) continue;
      failures.push(
        `Stale allowlist entry: ${allow.id} (${allow.package}) is no longer in the consumer ` +
          `tree. Delete it — a waiver nobody rechecks reads the same as a considered one.`
      );
    }

    // 3. Allowlist entries expire.
    for (const allow of ALLOWED) {
      if (!expired(allow.reviewBy, today)) continue;
      failures.push(
        `Allowlist entry ${allow.id} (${allow.package}) is past its review date ` +
          `(${allow.reviewBy}, today is ${today}). Re-check whether the chain now resolves ` +
          `clean, then either fix it or move the date with a fresh reason.`
      );
    }

    // 4. Forbidden packages, advisory or not — on the same waiver discipline.
    for (const forbidden of FORBIDDEN_PACKAGES) {
      const copies = nestedCopies(lock, forbidden.name);
      const label = `nested ${forbidden.name}`;
      if (copies.length === 0) {
        if (forbidden.waiver) {
          failures.push(
            `Stale waiver: \`${forbidden.name}\` is no longer nested in the consumer tree. ` +
              `Delete the waiver in ${SELF} and let the entry go back to being unconditional.`
          );
        }
        continue;
      }
      if (!forbidden.waiver) {
        const versions = copies.map((p) => `${lock.packages[p]?.version ?? '?'} at ${p}`);
        failures.push(
          `Forbidden nested copy of \`${forbidden.name}\` in the consumer tree: ` +
            `${versions.join(', ')}.\n    ${forbidden.reason.replace(/\s+/g, ' ')}`
        );
        continue;
      }
      reportWaiver(label, forbidden.waiver, ctx, failures);
      if (expired(forbidden.waiver.reviewBy, today)) {
        failures.push(
          `Waiver for ${label} is past its review date (${forbidden.waiver.reviewBy}, today ` +
            `is ${today}). Re-check whether the edge still exists, then either fix it or move ` +
            `the date with a fresh reason.`
        );
      }
    }
  } catch (e) {
    // A throw before or during measurement means there IS no measurement.
    // Routed through `failures` rather than left to crash, so it exits in the
    // gate's own failure format instead of a stack trace that reads like a bug
    // in this script — and so it can never be mistaken for a clean run.
    failures.push(
      `The consumer tree was not measured, so this run produced no result:\n    ${e?.message ?? e}`
    );
    if (process.env.CONSUMER_AUDIT_DEBUG) console.error(e?.stack ?? e);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error(`\n[${target.mode}] Consumer-resolution audit FAILED — ${target.headline}:\n`);
    for (const f of failures) console.error(`  - ${f}\n`);
    if (target.mode === 'CANDIDATE') {
      console.error(
        '  This is the CANDIDATE run. It measured the tarball this branch would publish, so a\n' +
          '  failure here is about the change under review and is fixable in this branch.\n'
      );
    } else {
      console.error(
        '  This is the PUBLISHED run. It measured what users can install right now, so a\n' +
          '  failure here is NOT fixable by merging — it clears when a fix is released.\n'
      );
    }
    process.exit(1);
  }
  console.log(`[${target.mode}] Consumer-resolution audit passed (${rootName}).`);
}

main();

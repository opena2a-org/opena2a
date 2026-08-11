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
 * ## What this installs, and why it installs at all
 *
 * The upstream version of this gate resolves `--package-lock-only`, so nothing
 * is fetched into an executable position. This port cannot: rule 4 below
 * requires reading files out of a dependency's own tarball at run time, which
 * needs the tree on disk. So it installs, and buys the safety back a different
 * way:
 *
 *   - `--ignore-scripts`, so no `postinstall` runs. That is not theoretical
 *     here: `onnxruntime-node` has a `postinstall` that downloads a nupkg from
 *     nuget.org and unzips it (see the derived facts printed below).
 *   - the thing installed is a PUBLISHED registry package, never this
 *     repository's working tree. A pull request from a fork cannot reach code
 *     execution through this job, because none of the fork's code is installed
 *     or run. (The `dependency-audit` job in the same workflow does `npm ci` on
 *     the PR branch; that is tracked separately and deliberately untouched
 *     here.)
 *
 * ## Why the gate is an allowlist and not a count
 *
 * The advisory above has no fix reachable from a consumer: `onnxruntime-node`
 * pins `adm-zip: ^0.5.16` and the patched `adm-zip` is `0.6.0`, outside that
 * caret. `overrides` are not published, so nothing this repo writes reaches a
 * user's resolution. A gate that can only ever be red is switched off inside a
 * release and then protects nothing.
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

/** The published package this repo ships. Overridable with `--target <spec>`. */
const DEFAULT_TARGET = 'opena2a-cli@latest';

// ---------------------------------------------------------------------------
// Derivations. Each returns lines of MEASURED fact, or throws.
// ---------------------------------------------------------------------------

/**
 * Why `adm-zip` is stuck below the patched version, and where in a consumer's
 * install it is actually reached.
 *
 * Everything here is read from the installed `onnxruntime-node` tarball. In
 * particular the platform list is computed, never typed: `requirements` names
 * the manifests each platform needs, `manifests` names the files each manifest
 * provides, and `postinstall` only downloads (and therefore only unzips) when
 * one of those files is absent from the tarball. So the set of platforms that
 * genuinely parse a ZIP at install time is a function of what shipped, and it
 * changes without warning when upstream cuts a release.
 */
function deriveAdmZipReachability(ctx) {
  const ort = ctx.installed('onnxruntime-node');
  const zip = ctx.installed('adm-zip');
  const lines = [];

  // 1. The trap: the declared range cannot reach the patched version.
  const declared = ort.manifest.dependencies?.['adm-zip'];
  if (!declared) {
    throw new Error(
      `onnxruntime-node@${ort.version} no longer declares an adm-zip dependency. ` +
        'The reason this waiver exists has changed; re-read it.'
    );
  }
  lines.push(
    `onnxruntime-node@${ort.version} declares adm-zip "${declared}"; the consumer tree ` +
      `resolves adm-zip@${zip.version}. The advisory range is <0.6.0 and 0.6.0 is outside ` +
      `that caret, so no version satisfying "${declared}" is clean.`
  );

  // 2. Is adm-zip loaded at all, and on which platforms?
  const utilsRel = path.join('script', 'install-utils.js');
  const utils = path.join(ort.dir, utilsRel);
  if (!existsSync(utils)) {
    throw new Error(
      `${ort.name}@${ort.version} has no ${utilsRel}; the install path this waiver ` +
        'describes no longer exists. Re-derive the reachability claim by hand.'
    );
  }
  const src = readFileSync(utils, 'utf8').split('\n');
  // Top level == column 0. A require moved inside a function or a branch would
  // be conditional, which is a different claim, so we do not match it.
  const requireLine = src.findIndex((l) => /^(?:const|let|var|import)\b.*\brequire\(['"]adm-zip['"]\)/.test(l));
  if (requireLine === -1) {
    throw new Error(
      `${utilsRel} no longer requires adm-zip at top level. That is a material change ` +
        'to this waiver (the dependency may now be unreachable, or reached somewhere ' +
        'else entirely). Re-read the install path before re-dating this entry.'
    );
  }
  lines.push(
    `${utilsRel}:${requireLine + 1} requires adm-zip at top level, so it is loaded on ` +
      'every platform whenever postinstall runs at all.'
  );

  // 3. Which platforms actually PARSE a ZIP. Computed, not asserted.
  const meta = readInstallMetadata(ort.dir);
  const requirements = meta.requirements;
  const manifests = meta.manifests ?? {};
  if (!requirements || typeof requirements !== 'object' || Object.keys(requirements).length === 0) {
    throw new Error(
      'onnxruntime-node install metadata has no usable `requirements` map, so the set of ' +
        'affected platforms cannot be measured. Not a pass.'
    );
  }
  const binRoot = path.join(ort.dir, 'bin', 'napi-v6');
  if (!existsSync(binRoot)) {
    throw new Error(
      `onnxruntime-node@${ort.version} has no bin/napi-v6 directory; the binary layout ` +
        'this derivation reads has changed and the platform list would be wrong.'
    );
  }

  const parses = [];
  const clean = [];
  for (const [platform, names] of Object.entries(requirements)) {
    if (!Array.isArray(names)) {
      throw new Error(`install metadata requirements["${platform}"] is not an array.`);
    }
    const missingByManifest = [];
    for (const name of names) {
      const manifest = manifests[`${platform}:${name}`];
      if (!manifest || typeof manifest !== 'object') {
        throw new Error(
          `install metadata names manifest "${platform}:${name}" in requirements but does ` +
            'not define it. The metadata is inconsistent; the platform list cannot be trusted.'
        );
      }
      const files = Object.keys(manifest);
      const missing = files.filter((f) => !existsSync(path.join(binRoot, platform, f)));
      if (missing.length > 0) missingByManifest.push({ name, missing, total: files.length });
    }
    if (missingByManifest.length > 0) parses.push({ platform, missingByManifest });
    else clean.push(platform);
  }

  const total = Object.keys(requirements).length;
  if (parses.length === 0) {
    lines.push(
      `On all ${total} declared platforms every manifest file is already present in the ` +
        'tarball, so postinstall exits before downloading or unzipping anything.'
    );
  } else {
    for (const { platform, missingByManifest } of parses) {
      const detail = missingByManifest
        .map((m) => `${m.name} (${m.missing.length} of ${m.total} files absent: ${m.missing.join(', ')})`)
        .join('; ');
      lines.push(
        `install-time ZIP parse IS reached on ${platform} — manifest ${detail}. postinstall ` +
          'downloads that package and unzips it with the vulnerable adm-zip.'
      );
    }
    lines.push(
      `Not reached on ${clean.length} of ${total} declared platforms: ${clean.join(', ') || '(none)'}.`
    );
  }

  return lines;
}

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
    if (pinned === shipped) {
      throw new Error(
        `${parentName}@${latest.version} (latest) now pins hackmyagent@${pinned}, the same ` +
          `version this CLI ships, so raising the ${parentName} range would collapse the two ` +
          'copies into one. Bump the range instead of re-dating the waiver.'
      );
    }
    lines.push(
      `${parentName}@${latest.version} (latest today) pins hackmyagent "${pinned}", which is ` +
        `not the hackmyagent@${shipped} this CLI ships, so raising the ${parentName} range ` +
        'moves the nested copy forward without removing it.'
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
const ALLOWED = [
  {
    id: 'GHSA-xcpc-8h2w-3j85',
    package: 'adm-zip',
    reason:
      'Reached only through hackmyagent -> onnxruntime-node, which the CLI needs for local ' +
      'NanoMind inference. There is no version of this dependency chain that resolves clean: ' +
      'the caret pin and the resolved versions are printed under `derived` below, and no ' +
      '`overrides` we write reaches a consumer, since overrides are not published. The impact ' +
      'is availability-only and install-time — a crafted ZIP makes the postinstall allocate — ' +
      'and it lands only on the platforms `derived` names, which is measured on every run ' +
      'rather than claimed here. The fix has to come from upstream raising its adm-zip range; ' +
      'when it does, this advisory leaves the consumer tree and rule 2 below fails the build ' +
      'until this entry is deleted.',
    reviewBy: '2026-11-01',
    derive: deriveAdmZipReachability,
  },
];

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
  const lock = JSON.parse(readFileSync(path.join(probe, 'package-lock.json'), 'utf8'));
  return { report, lock };
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
function makeContext(probe, lock) {
  return {
    lock,
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
  const spec = i !== -1 ? argv[i + 1] : DEFAULT_TARGET;
  if (!spec) {
    console.error('--target needs a value (an npm spec or a path to a tarball).');
    process.exit(2);
  }

  const scratch = mkdtempSync(path.join(tmpdir(), 'opena2a-consumer-audit-'));
  const failures = [];
  try {
    const probe = path.join(scratch, 'probe');
    mkdirSync(probe, { recursive: true });

    console.log(`Resolving the tree a consumer gets for: ${spec}\n`);
    const { report, lock } = auditConsumerTree(spec, probe);
    const ctx = makeContext(probe, lock);

    // Say which artifact was actually measured. `latest` is a moving target by
    // design — this gate is meant to go red when the published package goes
    // bad, not only when a diff touches it — so the resolved version has to be
    // in the log or the measurement is unattributable.
    const rootName = spec.replace(/^(@?[^@]*(?:\/[^@]*)?)@.*$/, '$1');
    const resolved = lock.packages?.[`node_modules/${rootName}`]?.version;
    if (resolved) console.log(`Resolved ${rootName}@${resolved}\n`);

    const counts = report.metadata?.vulnerabilities ?? {};
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
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error('\nConsumer-resolution audit FAILED:\n');
    for (const f of failures) console.error(`  - ${f}\n`);
    process.exit(1);
  }
  console.log('Consumer-resolution audit passed.');
}

main();

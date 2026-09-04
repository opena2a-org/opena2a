#!/usr/bin/env node
/**
 * Review one packed tarball between `build` and `publish` in release.yml.
 *
 * The build job packs eleven workspaces and the publish job signs whatever
 * bytes survived transport. Nothing between them ever looked INSIDE the bytes:
 * a tarball carrying a stray dotfile, a test fixture, an install script, a
 * floating first-party pin, a broken bin or a credential-shaped value would be
 * published with provenance attached — provenance proves where bytes came
 * from, not that they should ship. This script is that look. release.yml runs
 * it once per manifest entry (`--tarball <path>`) in a job holding
 * `contents: read` and nothing else; any non-zero exit blocks `publish`.
 *
 * Verdict discipline (QGF OPA-04): every check lands on exactly one of
 *   pass          — the check ran and found nothing
 *   fail          — the check ran and found something; the exit names it
 *   precondition  — the check COULD NOT run (missing input, unreachable feed,
 *                   unflagged control). Reported and non-zero, never a pass:
 *                   an unmeasured tarball is not a reviewed tarball.
 *   skip          — the check does not apply to this tarball by construction
 *                   (only `global-install-smoke`, which needs the CLI's bin).
 * Every check name appears in the closing `census:` line whatever happened,
 * so a reader can tell "passed" from "never ran" without reading the log.
 *
 * The credential scan extracts `package/dist/` entries FLAT — each file at its
 * path relative to `package/dist/`, with no `dist` path component — because
 * the shipped scanner's AST credential walk skips any directory named `dist`
 * (`scanner-bridge.js` SKIP_DIRS; measured on hackmyagent 0.25.0, 0.32.0 and
 * the #731 head). Scanning the tarball's own layout would therefore scan
 * nothing and pass, which is the worst direction to be wrong in. A control
 * file with a credential-named const (value assembled at runtime from parts;
 * no credential-shaped literal exists in this repository) is scanned APART
 * from the shipped files, in its own directory per batch: the scanner reports
 * one location per check id, so a control beside a shipped credential of the
 * same class masks one or the other. If the installed scanner does not flag
 * the control, the scan reports `precondition: control not flagged`, never a
 * pass.
 */
import { execFileSync, spawnSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/**
 * Check names, in census order. This array IS the census contract: a check
 * added to the script but not to this list would run without appearing in the
 * census line, and the census exists so that absence is impossible.
 */
const CHECKS = [
  'entry-allowlist',
  'no-dotfiles',
  'no-test-material',
  'no-install-scripts',
  'pinned-first-party-deps',
  'global-install-smoke',
  'credential-scan',
  'npm-audit',
  'consumer-closure',
];

/**
 * The own-package roster for `consumer-closure`: the FLOOR of
 * todo/scripts/own-package-census.mjs plus the @opena2a scope. A fresh-install
 * closure of the reviewed tarball must not contain a deprecated or advisory-
 * matched copy of any of these, nested or not — GHSA advisories on our own
 * packages describe OUR defects, and shipping a closure that resolves one is
 * shipping the defect regardless of which intermediate pinned it.
 */
const ROSTER_NAMES = [
  'hackmyagent',
  'secretless-ai',
  'ai-trust',
  'opena2a-cli',
  'arp-guard',
  'damn-vulnerable-ai-agent',
  'cryptoserve',
];
const ROSTER_SCOPE = '@opena2a/';

/**
 * Liveness canary for the deprecation feed: a version of an own package that
 * IS deprecated on the registry. If probing it returns empty, the feed is not
 * readable and every "not deprecated" answer this run produced is noise, so
 * the check reports a precondition instead of trusting them.
 * (Verified at authoring time against the registry packument: hackmyagent has
 * 128 deprecated versions and 0.1.0 carries the notice "red-team scored
 * jailbreak text 100% resilient..." (opena2a-org/hackmyagent#369). If upstream
 * ever un-deprecates it, this probe fails LOUD — replace it with another
 * known-deprecated own version.)
 */
const KNOWN_DEPRECATED = { name: 'hackmyagent', version: '0.1.0' };

const isRosterName = (name) => ROSTER_NAMES.includes(name) || name.startsWith(ROSTER_SCOPE);

// ---------------------------------------------------------------------------
// Small machinery.
// ---------------------------------------------------------------------------

function run(cmd, args, opts = {}) {
  return execFileSync(cmd, args, {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 64 * 1024 * 1024,
    ...opts,
  });
}

/** Node stack frame, e.g. "    at foo (/x/y.js:3:7)". */
const STACK_FRAME = /(^|\n)\s+at\s+\S[^\n]*:\d+:\d+/;

const short = (s, n = 300) => String(s ?? '').trim().replace(/\s+/g, ' ').slice(0, n);

class Precondition extends Error {}

// ---------------------------------------------------------------------------
// Tarball reading.
// ---------------------------------------------------------------------------

function listEntries(tarball) {
  return run('tar', ['-tzf', tarball])
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
}

function extractTo(tarball, dir) {
  run('tar', ['-xzf', tarball, '-C', dir]);
}

function readPackedManifest(extractedRoot) {
  const p = path.join(extractedRoot, 'package', 'package.json');
  if (!existsSync(p)) return null;
  return JSON.parse(readFileSync(p, 'utf8'));
}

function* walkFiles(dir, rel = '') {
  for (const name of readdirSync(dir).sort()) {
    const abs = path.join(dir, name);
    const r = rel ? `${rel}/${name}` : name;
    if (statSync(abs).isDirectory()) yield* walkFiles(abs, r);
    else yield { abs, rel: r };
  }
}

// ---------------------------------------------------------------------------
// Structural checks (no network, no execution of tarball content).
// ---------------------------------------------------------------------------

function checkEntryAllowlist(entries) {
  // packages/*/package.json `files` is ["dist", "README.md"] across the
  // workspace, plus what npm always includes (package.json, LICENSE). Anything
  // else in a tarball got there by accident or by attack; either way it does
  // not ship.
  const allowedFile = (e) =>
    e === 'package/README.md' ||
    e === 'package/LICENSE' ||
    e === 'package/package.json' ||
    e.startsWith('package/dist/');
  const allowedDir = (e) => e === 'package/' || e === 'package/dist/' || (e.startsWith('package/dist/') && e.endsWith('/'));
  const bad = entries.filter((e) => (e.endsWith('/') ? !allowedDir(e) : !allowedFile(e)));
  if (bad.length > 0) {
    return {
      status: 'fail',
      detail: bad.slice(0, 20).map((e) => `entry outside the allowlist: ${e}`),
    };
  }
  return { status: 'pass', detail: [`${entries.length} entries, all inside package/dist/ + README.md + LICENSE + package.json`] };
}

function checkNoDotfiles(entries) {
  const bad = entries.filter((e) => e.split('/').some((part) => part.startsWith('.') && part !== ''));
  if (bad.length > 0) {
    return { status: 'fail', detail: bad.slice(0, 20).map((e) => `dotfile entry: ${e}`) };
  }
  return { status: 'pass', detail: ['no dotfile or dot-directory entries'] };
}

function checkNoTestMaterial(entries) {
  const patterns = ['__tests__', 'fixtures', 'test/'];
  const bad = [];
  for (const e of entries) {
    for (const p of patterns) {
      if (e.includes(p)) {
        bad.push(`entry contains "${p}": ${e}`);
        break;
      }
    }
  }
  if (bad.length > 0) return { status: 'fail', detail: bad.slice(0, 20) };
  return { status: 'pass', detail: ['no __tests__, fixtures or test/ entries'] };
}

function checkNoInstallScripts(manifest) {
  if (!manifest) {
    return { status: 'precondition', detail: ['the tarball carries no package/package.json to read scripts from'] };
  }
  const hooks = ['preinstall', 'install', 'postinstall'].filter((h) => manifest.scripts?.[h] != null);
  if (hooks.length > 0) {
    return {
      status: 'fail',
      detail: hooks.map((h) => `packed package.json declares a "${h}" script; nothing that runs on a consumer's install ships from here`),
    };
  }
  return { status: 'pass', detail: ['no preinstall/install/postinstall in the packed package.json'] };
}

function checkPinnedFirstPartyDeps(manifest) {
  if (!manifest) {
    return { status: 'precondition', detail: ['the tarball carries no package/package.json to read dependencies from'] };
  }
  const bad = [];
  // The install-affecting blocks. devDependencies never reach a consumer's
  // resolution, so a caret there is untidy but not a floating first-party pin.
  for (const block of ['dependencies', 'optionalDependencies', 'peerDependencies']) {
    for (const [name, range] of Object.entries(manifest[block] ?? {})) {
      const firstParty = name.startsWith(ROSTER_SCOPE) || name === 'hackmyagent';
      if (firstParty && /^[\^~]/.test(String(range).trim())) {
        bad.push(`${block}: ${name}@"${range}" — first-party dependencies are exact pins, never ranges`);
      }
    }
  }
  if (bad.length > 0) return { status: 'fail', detail: bad };
  return { status: 'pass', detail: ['no caret/tilde range on any @opena2a/* or hackmyagent dependency'] };
}

// ---------------------------------------------------------------------------
// global-install-smoke — install the CLI the way a user does, then run it in
// a world with nothing in it: empty HOME, empty cwd, proxies pointing at a
// closed port so any accidental network call fails instead of quietly
// succeeding. A CLI that only works next to a repo checkout or a warm config
// directory is broken for exactly the user who just installed it.
// ---------------------------------------------------------------------------

function checkGlobalInstallSmoke(tarball, manifest, scratchRoot) {
  if (!manifest) {
    return { status: 'precondition', detail: ['the tarball carries no package/package.json; nothing to install'] };
  }
  if (manifest.name !== 'opena2a-cli') {
    return { status: 'skip', detail: [`packed name is ${manifest.name}; only the opena2a-cli tarball carries the bin this check exercises`] };
  }

  const prefix = mkdtempSync(path.join(scratchRoot, 'smoke-prefix-'));
  const cache = mkdtempSync(path.join(scratchRoot, 'smoke-cache-'));
  const installHome = mkdtempSync(path.join(scratchRoot, 'smoke-install-home-'));
  const detail = [];

  const npmInstallGlobal = (tarballs) =>
    run('npm', [
      'install',
      '-g',
      '--ignore-scripts',
      '--no-audit',
      '--no-fund',
      '--loglevel=error',
      `--prefix=${prefix}`,
      `--cache=${cache}`,
      ...tarballs,
    ], { env: { ...process.env, HOME: installHome } });

  // The sibling workspace tarballs first, from the same directory: at review
  // time the exact versions this tarball pins may not be on the registry yet
  // (publish has not run), so the local packed bytes are the only copy that
  // can satisfy those pins without the registry.
  const dir = path.dirname(tarball);
  const siblings = readdirSync(dir)
    .filter((f) => f.endsWith('.tgz') && path.join(dir, f) !== tarball)
    .sort()
    .map((f) => path.join(dir, f));
  try {
    if (siblings.length > 0) {
      npmInstallGlobal(siblings);
      detail.push(`installed ${siblings.length} sibling workspace tarball(s) first, from ${dir}`);
    } else {
      detail.push('no sibling tarballs found beside the target; first-party pins resolve from the registry');
    }
  } catch (e) {
    return {
      status: 'precondition',
      detail: [`sibling tarball install did not complete, so the CLI was never exercised: ${short(e.stderr || e.message)}`],
    };
  }

  try {
    npmInstallGlobal([tarball]);
  } catch (e) {
    return {
      status: 'precondition',
      detail: [`npm install -g of the tarball did not complete, so the CLI was never exercised: ${short(e.stderr || e.message)}`],
    };
  }

  const bin = path.join(prefix, 'bin', 'opena2a');
  if (!existsSync(bin)) {
    return { status: 'fail', detail: ['global install completed but produced no bin/opena2a — the packed bin map does not ship a working entry point'] };
  }
  const binReal = realpathSync(bin);

  const failures = [];
  for (const args of [['--version'], ['--help'], ['init', '--ci', '--format', 'json']]) {
    const cwd = mkdtempSync(path.join(scratchRoot, 'smoke-cwd-'));
    const emptyHome = mkdtempSync(path.join(scratchRoot, 'smoke-home-'));
    const res = spawnSync(process.execPath, [binReal, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 120_000,
      maxBuffer: 64 * 1024 * 1024,
      env: {
        // Deliberately NOT process.env: an empty HOME and a dead proxy are the
        // point. A closed local port makes any network attempt fail fast and
        // visibly rather than hang or quietly succeed.
        PATH: `${path.join(prefix, 'bin')}:${path.dirname(process.execPath)}`,
        HOME: emptyHome,
        TERM: 'dumb',
        HTTP_PROXY: 'http://127.0.0.1:9',
        HTTPS_PROXY: 'http://127.0.0.1:9',
        http_proxy: 'http://127.0.0.1:9',
        https_proxy: 'http://127.0.0.1:9',
        NO_PROXY: '',
      },
    });
    const label = `opena2a ${args.join(' ')}`;
    const output = `${res.stdout ?? ''}${res.stderr ?? ''}`;
    if (res.error) {
      failures.push(`${label}: did not run (${res.error.message})`);
    } else if (res.status !== 0) {
      failures.push(`${label}: exited ${res.status}${res.signal ? ` (signal ${res.signal})` : ''}: ${short(output, 200)}`);
    } else if (STACK_FRAME.test(output)) {
      failures.push(`${label}: exited 0 but printed a stack trace: ${short(output.match(STACK_FRAME)?.[0], 200)}`);
    } else {
      detail.push(`${label}: exit 0, no stack trace`);
    }
  }
  if (failures.length > 0) return { status: 'fail', detail: [...detail, ...failures] };
  return { status: 'pass', detail };
}

// ---------------------------------------------------------------------------
// credential-scan — see the header for why the extraction is FLAT and why a
// planted control decides whether the scanner's silence means anything.
// ---------------------------------------------------------------------------

function resolveHackmyagent() {
  // Read the installed copy directly rather than through require.resolve: the
  // package's `exports` map does not expose ./package.json, and the .bin shim
  // below points into this same top-level install anyway.
  const pkgPath = path.join(REPO_ROOT, 'node_modules', 'hackmyagent', 'package.json');
  if (!existsSync(pkgPath)) {
    throw new Precondition(
      'hackmyagent is not installed at the repository root — run `npm ci --ignore-scripts` first; the release job does'
    );
  }
  const version = JSON.parse(readFileSync(pkgPath, 'utf8')).version;
  const bin = path.join(REPO_ROOT, 'node_modules', '.bin', 'hackmyagent');
  if (!existsSync(bin)) {
    throw new Precondition('node_modules/.bin/hackmyagent does not exist — run `npm ci --ignore-scripts` first');
  }
  return { bin: realpathSync(bin), version };
}

function checkCredentialScan(extractedRoot, scratchRoot) {
  const distRoot = path.join(extractedRoot, 'package', 'dist');
  if (!existsSync(distRoot)) {
    return { status: 'precondition', detail: ['the tarball has no package/dist/ entries; nothing was scanned, and nothing scanned is not a pass'] };
  }

  let scanner;
  try {
    scanner = resolveHackmyagent();
  } catch (e) {
    if (e instanceof Precondition) return { status: 'precondition', detail: [e.message] };
    throw e;
  }

  // FLAT extraction: each shipped file at its path relative to package/dist/,
  // never under a directory named `dist` (the scanner's AST walk skips those).
  //
  // BATCHED, and the batch size is load-bearing: the scanner caps its compile
  // set at 200 files (MAX_FILES_PER_SCAN, scanner-bridge.js) and the CLI
  // tarball ships 460+. In a single scan the control — deliberately named
  // zz-* so it sorts last — fell off the cap and the control gate correctly
  // reported the scan blind (measured here on the real tarball). 100 shipped
  // files plus one control per batch keeps every batch far under the cap, and
  // every batch carries its OWN control so no batch's silence goes unproven.
  const shippedFiles = [...walkFiles(distRoot)];
  const detail = [];
  for (const f of shippedFiles) {
    if (f.rel.split('/').includes('dist')) {
      // A dist/ directory nested inside dist/ would be skipped by the scanner
      // even after flattening. Say so rather than silently under-scanning.
      detail.push(`warning: ${f.rel} keeps a "dist" path component after flattening; the scanner will skip it`);
    }
  }

  // The planted control: a credential-named const whose value is assembled AT
  // RUNTIME, HERE, from parts (the OpenAI-shaped prefix + 48 repeated
  // characters), so no credential-shaped literal exists in this repository —
  // only the scratch file the scanner is about to read carries the contiguous
  // shape, which is what its format matcher requires of raw bytes.
  // hackmyagent 0.25.0 and 0.32.0 flag this as AST-CRED-001/AST-CRED-003
  // (re-measured on 0.32.0 while building this script); if the installed
  // version does not, the scan has proven itself blind and the verdict below
  // is a precondition, never a pass.
  const CONTROL = 'zz-planted-credential-control.js';
  const controlValue = 'sk-' + 'proj-' + 'A'.repeat(48);
  const controlSource =
    '// Planted control for the release credential scan (OPA-04). If the scanner\n' +
    '// does not flag this file, the scan of everything beside it proves nothing.\n' +
    `const OPENAI_API_KEY = '${controlValue}';\n` +
    'module.exports = { OPENAI_API_KEY };\n';

  const BATCH = 100;
  const isControl = (f) => String(f.file ?? '').endsWith(CONTROL);
  // Only findings that FIRED: the report also carries passed check records.
  const credClass = (f) =>
    f.passed !== true && (/CRED/.test(String(f.checkId ?? '')) || String(f.checkId ?? '') === 'CONFIG-004');

  const hits = new Set();
  const batches = Math.ceil(shippedFiles.length / BATCH);

  // One scan of a directory yields one report; the scanner reports ONE location
  // per check id, so a planted control scanned beside a shipped file that
  // carries the same credential class masks it in either direction: the control
  // wins and the shipped credential is silent, or the shipped file wins and the
  // control reads "not flagged" (measured on the poisoned-dist fixture: census
  // credential-scan=precondition on the very tarball that should FAIL). So two
  // scans per batch, never one: the shipped files alone, the control alone in
  // its own directory. The control scan still runs per batch so every batch's
  // scanner invocation is proven to flag the class it is silent about.
  const scanOnce = (dir, label) => {
    const res = spawnSync(process.execPath, [scanner.bin, 'secure', '--ci', '--format', 'json'], {
      cwd: dir,
      encoding: 'utf8',
      timeout: 300_000,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env },
    });
    if (res.error) {
      return { precondition: [`hackmyagent@${scanner.version} did not run (${label}): ${res.error.message}`] };
    }
    // `--ci` exits non-zero when findings exist — expected on the control scan,
    // the control IS a finding. Only an unparseable report means no scan happened.
    try {
      return { findings: parseScanFindings(res.stdout) };
    } catch {
      return {
        precondition: [
          `hackmyagent@${scanner.version} produced no parseable JSON report (exit ${res.status}, ${label}); the tarball was not scanned`,
          `scanner said: ${short(res.stdout || res.stderr, 300)}`,
        ],
      };
    }
  };

  for (let b = 0; b < batches; b += 1) {
    const scanDir = mkdtempSync(path.join(scratchRoot, `credscan-${b}-`));
    for (const f of shippedFiles.slice(b * BATCH, (b + 1) * BATCH)) {
      const dest = path.join(scanDir, f.rel);
      mkdirSync(path.dirname(dest), { recursive: true });
      copyFileSync(f.abs, dest);
    }
    const controlDir = mkdtempSync(path.join(scratchRoot, `credscan-${b}-control-`));
    writeFileSync(path.join(controlDir, CONTROL), controlSource);

    const control = scanOnce(controlDir, `control, batch ${b + 1}/${batches}`);
    if (control.precondition) return { status: 'precondition', detail: control.precondition };
    if (!control.findings.some((f) => isControl(f) && credClass(f))) {
      return {
        status: 'precondition',
        detail: [`control not flagged by hackmyagent@${scanner.version} (batch ${b + 1}/${batches}) — the credential walk did not see the planted control, so its silence about the shipped files proves nothing`],
      };
    }

    const shipped = scanOnce(scanDir, `shipped files, batch ${b + 1}/${batches}`);
    if (shipped.precondition) return { status: 'precondition', detail: shipped.precondition };
    // Findings on shipped files: named by checkId and file:line, NEVER by the
    // matched text — this log is public CI output and the finding may be real.
    for (const f of shipped.findings) {
      if (!isControl(f) && credClass(f) && f.file != null) hits.add(`${f.checkId} at ${f.file}:${f.line ?? '?'}`);
    }
  }

  if (hits.size > 0) return { status: 'fail', detail: [...hits] };
  return {
    status: 'pass',
    detail: [
      ...detail,
      `hackmyagent@${scanner.version} scanned ${shippedFiles.length} shipped file(s) flat in ${batches} batch(es), the planted control scanned apart from each batch`,
      'every control flagged; zero credential-class findings on shipped files',
    ],
  };
}

/** Accept the report shapes hackmyagent emits: an array, or {findings: []}, or {results: []}. */
function parseScanFindings(stdout) {
  const text = String(stdout ?? '').trim();
  const start = text.search(/[[{]/);
  if (start === -1) throw new Error('no JSON in scanner output');
  const parsed = JSON.parse(text.slice(start));
  const list = Array.isArray(parsed) ? parsed : parsed.findings ?? parsed.results ?? parsed.issues;
  if (!Array.isArray(list)) throw new Error('scanner JSON carries no findings array');
  return list.map((f) => ({
    checkId: f.checkId ?? f.check_id ?? f.ruleId ?? f.id,
    file: f.file ?? f.path ?? f.location?.file,
    line: f.line ?? f.location?.line,
    passed: f.passed,
  }));
}

// ---------------------------------------------------------------------------
// The consumer-resolution pair: one scratch `--package-lock-only` install of
// THIS tarball feeds both `npm-audit` (the public advisory floor) and
// `consumer-closure` (our own packages held to our own advisories and
// deprecations, which npm audit does not check for unpublished-yet closures).
// ---------------------------------------------------------------------------

function resolveClosure(tarball, scratchRoot) {
  const probe = mkdtempSync(path.join(scratchRoot, 'closure-'));
  writeFileSync(
    path.join(probe, 'package.json'),
    JSON.stringify({ name: 'release-artifact-review-probe', version: '1.0.0', private: true }) + '\n'
  );
  // --package-lock-only: resolution without reification — nothing lands in an
  // executable position. --ignore-scripts belt-and-braces on top.
  run('npm', ['install', '--package-lock-only', '--ignore-scripts', '--no-audit', '--no-fund', tarball], { cwd: probe });
  const lockPath = path.join(probe, 'package-lock.json');
  if (!existsSync(lockPath)) throw new Error('npm wrote no package-lock.json, so no closure was resolved');
  return { probe, lock: JSON.parse(readFileSync(lockPath, 'utf8')) };
}

function checkNpmAudit(closure) {
  if (closure.error) {
    return { status: 'precondition', detail: [`the fresh-install closure did not resolve: ${closure.error}`] };
  }
  let raw;
  try {
    raw = run('npm', ['audit', '--omit=dev', '--package-lock-only', '--json'], { cwd: closure.probe });
  } catch (e) {
    // npm audit exits non-zero whenever it finds anything; the report is still
    // on stdout and is the entire point of the call.
    raw = e.stdout ?? '';
  }
  let report;
  try {
    report = JSON.parse(raw);
  } catch {
    return { status: 'precondition', detail: [`npm audit produced no parseable report; the closure was never measured: ${short(raw || '(nothing)')}`] };
  }
  // The advisory-database-unreachable shape parses as JSON but has no
  // vulnerabilities map; reading it as "0 high" would invert the gate
  // (see scripts/audit-consumer-resolution.mjs, which met this live).
  const counts = report.metadata?.vulnerabilities;
  if (!report.vulnerabilities || typeof report.vulnerabilities !== 'object' || !counts || typeof counts.high !== 'number' || typeof counts.critical !== 'number') {
    return { status: 'precondition', detail: [`npm audit returned no usable counts; an unreachable advisory database is not a clean tree: ${short(report?.message ?? raw)}`] };
  }
  if (counts.high + counts.critical > 0) {
    const named = [];
    for (const [name, v] of Object.entries(report.vulnerabilities)) {
      if (v.severity !== 'high' && v.severity !== 'critical') continue;
      const ids = (v.via ?? []).filter((x) => typeof x === 'object' && x.url).map((x) => x.url.split('/').pop());
      named.push(`${name} (${v.severity}${ids.length ? `: ${ids.join(', ')}` : ''})`);
    }
    return { status: 'fail', detail: [`${counts.critical} critical / ${counts.high} high in the consumer closure: ${named.join('; ') || '(unnamed)'}`] };
  }
  return { status: 'pass', detail: [`npm audit --omit=dev: 0 high, 0 critical (${counts.moderate ?? 0} moderate, ${counts.low ?? 0} low)`] };
}

// --- registry + advisories plumbing for consumer-closure --------------------

const npmViewCache = new Map();
function npmView(spec, field) {
  const key = `${spec} ${field}`;
  if (npmViewCache.has(key)) return npmViewCache.get(key);
  let out;
  try {
    out = run('npm', ['view', spec, field]).trim();
  } catch (e) {
    const err = new Error(`npm view ${spec} ${field} errored: ${short(e.stderr || e.message, 200)}`);
    err.notFound = /E404|404 Not Found|No match found/i.test(String(e.stderr ?? '') + String(e.message ?? ''));
    npmViewCache.set(key, { error: err });
    return { error: err };
  }
  const value = { value: out };
  npmViewCache.set(key, value);
  return value;
}

function parseGithubRepo(url) {
  const m = /github\.com[:/]+([^/\s]+)\/([^/\s#?]+?)(?:\.git)?(?:[#?].*)?$/.exec(String(url ?? ''));
  return m ? `${m[1]}/${m[2]}` : null;
}

const advisoryCache = new Map();
async function fetchAdvisories(repo, states) {
  const key = `${repo} ${states}`;
  if (advisoryCache.has(key)) return advisoryCache.get(key);
  const stateParam = states === 'published' ? '&state=published' : '';
  const url = `https://api.github.com/repos/${repo}/security-advisories?per_page=100${stateParam}`;
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'opena2a-release-artifact-review',
  };
  const token = process.env.GH_TOKEN || process.env.GITHUB_TOKEN;
  if (token) headers.Authorization = `Bearer ${token}`;
  let result;
  try {
    const res = await fetch(url, { headers });
    if (!res.ok) {
      const body = short(await res.text().catch(() => ''), 200);
      result = { error: `advisories endpoint for ${repo} returned ${res.status}: ${body}` };
    } else {
      const list = await res.json();
      result = Array.isArray(list) ? { advisories: list } : { error: `advisories endpoint for ${repo} returned a non-list` };
    }
  } catch (e) {
    result = { error: `advisories endpoint for ${repo} unreachable: ${short(e.message, 200)}` };
  }
  advisoryCache.set(key, result);
  return result;
}

async function checkConsumerClosure(closure, packedManifest, advisoryStates) {
  if (closure.error) {
    return { status: 'precondition', detail: [`the fresh-install closure did not resolve: ${closure.error}`] };
  }
  let semver;
  try {
    semver = createRequire(path.join(REPO_ROOT, 'package.json'))('semver');
  } catch {
    return { status: 'precondition', detail: ['the semver package is not resolvable from the repository root — run `npm ci --ignore-scripts` first'] };
  }

  const detail = [`advisory-states read: ${advisoryStates}`];
  const fails = [];
  const preconditions = [];

  // Alias-aware roster rows out of the lockfile: an entry's real name is its
  // `name` field when aliased, else the tail of its node_modules path. The
  // packed package itself is always a row, roster or not — it is the copy the
  // consumer actually asked for.
  const rows = new Map();
  for (const [key, node] of Object.entries(closure.lock.packages ?? {})) {
    if (key === '' || !node?.version) continue;
    const name = node.name ?? key.slice(key.lastIndexOf('node_modules/') + 'node_modules/'.length);
    const isPackedSelf = packedManifest && name === packedManifest.name;
    if (isRosterName(name) || isPackedSelf) rows.set(`${name}@${node.version}`, { name, version: node.version });
  }
  if (packedManifest && !rows.has(`${packedManifest.name}@${packedManifest.version}`)) {
    rows.set(`${packedManifest.name}@${packedManifest.version}`, { name: packedManifest.name, version: packedManifest.version });
  }
  if (rows.size === 0) {
    return { status: 'precondition', detail: [...detail, 'the resolved closure contains no roster package and no packed self — an empty examination is not a pass'] };
  }

  // Liveness canary 1: the deprecation feed must be able to say "deprecated"
  // at all, proven on a version known to be deprecated, or every clean answer
  // below is unfalsifiable.
  const canary = npmView(`${KNOWN_DEPRECATED.name}@${KNOWN_DEPRECATED.version}`, 'deprecated');
  if (canary.error || !canary.value) {
    preconditions.push(
      `deprecation probe on known-deprecated ${KNOWN_DEPRECATED.name}@${KNOWN_DEPRECATED.version} returned ${canary.error ? `an error (${canary.error.message})` : 'empty'} — the deprecation feed is not readable, so "not deprecated" cannot be trusted this run`
    );
  }

  // Repositories to read advisories from: the repos of the closure's roster
  // rows, plus the repos of the full fixed roster. The union exists for the
  // second liveness canary — zero advisories across ALL of these means the
  // feed is silent in a way this repo's history says it never truly is, and a
  // silently empty feed is indistinguishable from a broken one.
  const repoOf = new Map();
  for (const row of rows.values()) {
    const r = npmView(row.name, 'repository.url');
    if (r.error) {
      preconditions.push(
        r.error.notFound && packedManifest && row.name === packedManifest.name
          ? `the packed package ${row.name} has no registry packument yet and its repository cannot be read (first publish?): ${r.error.message}`
          : `packument/npm view for ${row.name} errored: ${r.error.message}`
      );
      continue;
    }
    const repo = parseGithubRepo(r.value);
    if (!repo) {
      preconditions.push(`repository URL for ${row.name} is missing or not a github.com repository ("${r.value}"), so its advisories cannot be read`);
      continue;
    }
    repoOf.set(row.name, repo);
  }
  const canaryRepos = new Set(repoOf.values());
  for (const name of ROSTER_NAMES) {
    if (repoOf.has(name)) continue;
    const r = npmView(name, 'repository.url');
    if (r.error) continue; // canary-only resolution; a roster name absent from the registry is not this closure's problem
    const repo = parseGithubRepo(r.value);
    if (repo) canaryRepos.add(repo);
  }

  let advisoriesRead = 0;
  const advisoriesByRepo = new Map();
  for (const repo of canaryRepos) {
    const res = await fetchAdvisories(repo, advisoryStates);
    if (res.error) {
      // Only load-bearing when a closure row needs this repo; recorded either
      // way so a half-dead feed is visible in the log.
      if ([...repoOf.values()].includes(repo)) preconditions.push(res.error);
      else detail.push(`note: ${res.error} (canary-only repository)`);
      continue;
    }
    advisoriesByRepo.set(repo, res.advisories);
    advisoriesRead += res.advisories.length;
  }
  if (advisoriesRead === 0) {
    preconditions.push(
      "the advisories feed returned zero advisories across the roster's repositories — a silently empty feed is indistinguishable from a broken one, and this roster is measured to carry published advisories"
    );
  }

  // The rows themselves.
  let examined = 0;
  for (const row of [...rows.values()].sort((a, b) => a.name.localeCompare(b.name))) {
    examined += 1;
    const rowNotes = [];

    // Deprecation. `npm view name@version deprecated` E404s on a version that
    // is not on the registry yet — which at review time describes the packed
    // package itself, since publish deliberately has not run. A version the
    // registry has never seen cannot carry a deprecation notice, so that one
    // shape is read as "no notice", provided the packument itself is readable.
    const dep = npmView(`${row.name}@${row.version}`, 'deprecated');
    if (dep.error) {
      const packument = npmView(row.name, 'name');
      if (dep.error.notFound && !packument.error) {
        rowNotes.push('version not on the registry yet (publish runs after this review); no deprecation notice can exist for it');
      } else {
        preconditions.push(`packument/npm view for ${row.name}@${row.version} errored: ${dep.error.message}`);
        detail.push(`examined ${row.name}@${row.version}: UNREADABLE`);
        continue;
      }
    } else if (dep.value) {
      fails.push(`${row.name}@${row.version} is deprecated on the registry: "${short(dep.value, 120)}"`);
      detail.push(`examined ${row.name}@${row.version}: DEPRECATED`);
      continue;
    }

    // Advisories: GitHub joins multiple ranges with ", "; npm semver reads
    // that as a space-separated AND. includePrerelease so a prerelease of a
    // vulnerable line does not slide through the default semver carve-out.
    const repo = repoOf.get(row.name);
    const matched = [];
    if (repo && advisoriesByRepo.has(repo)) {
      for (const adv of advisoriesByRepo.get(repo)) {
        for (const vuln of adv.vulnerabilities ?? []) {
          if (vuln.package?.ecosystem !== 'npm' || vuln.package?.name !== row.name) continue;
          const range = vuln.vulnerable_version_range;
          if (!range) continue;
          let hit = false;
          try {
            hit = semver.satisfies(row.version, range.split(', ').join(' '), { includePrerelease: true });
          } catch {
            preconditions.push(`advisory ${adv.ghsa_id} carries a range for ${row.name} that npm semver cannot parse ("${range}")`);
            continue;
          }
          if (hit) matched.push(`${adv.ghsa_id} (${adv.severity ?? '?'}, "${range}")`);
        }
      }
    }
    if (matched.length > 0) {
      fails.push(`${row.name}@${row.version} inside ${matched.join(' and ')}`);
      detail.push(`examined ${row.name}@${row.version} (${repo}): ADVISORY-MATCHED`);
    } else {
      detail.push(`examined ${row.name}@${row.version}${repo ? ` (${repo})` : ''}: clean${rowNotes.length ? ` — ${rowNotes.join('; ')}` : ''}`);
    }
  }

  detail.push(`advisories read: ${advisoriesRead} across ${advisoriesByRepo.size} repositories (states: ${advisoryStates})`);
  detail.push(`rows: ${examined} own cop${examined === 1 ? 'y' : 'ies'} examined, ${fails.length} fail, ${preconditions.length} precondition`);

  if (fails.length > 0) return { status: 'fail', detail: [...detail, ...fails.map((f) => `FAIL ${f}`), ...preconditions.map((p) => `precondition alongside: ${p}`)] };
  if (preconditions.length > 0) return { status: 'precondition', detail: [...detail, ...preconditions] };
  return { status: 'pass', detail };
}

// ---------------------------------------------------------------------------
// Driver.
// ---------------------------------------------------------------------------

function usage(msg) {
  console.error(msg);
  console.error('usage: node scripts/release-artifact-review.mjs --tarball <path> [--advisory-states published|all]');
  process.exit(2);
}

async function main() {
  const argv = process.argv.slice(2);
  const ti = argv.indexOf('--tarball');
  if (ti === -1 || !argv[ti + 1]) usage('--tarball <path> is required.');
  const tarball = path.resolve(argv[ti + 1]);
  const si = argv.indexOf('--advisory-states');
  const advisoryStates = si === -1 ? 'all' : argv[si + 1];
  if (!['published', 'all'].includes(advisoryStates)) usage(`--advisory-states must be "published" or "all", got "${advisoryStates}".`);
  if (!existsSync(tarball)) usage(`no such tarball: ${tarball}`);

  const scratchRoot = mkdtempSync(path.join(tmpdir(), 'release-artifact-review-'));
  const results = new Map();
  try {
    console.log(`release-artifact-review: ${path.basename(tarball)}`);

    const entries = listEntries(tarball);
    const extracted = mkdtempSync(path.join(scratchRoot, 'extracted-'));
    extractTo(tarball, extracted);
    const manifest = readPackedManifest(extracted);
    if (manifest) console.log(`  packed: ${manifest.name}@${manifest.version} (${entries.length} entries)`);

    const record = (name, result) => {
      results.set(name, result);
      console.log(`  check ${name}: ${result.status}`);
      for (const line of result.detail) console.log(`    ${line}`);
    };

    record('entry-allowlist', checkEntryAllowlist(entries));
    record('no-dotfiles', checkNoDotfiles(entries));
    record('no-test-material', checkNoTestMaterial(entries));
    record('no-install-scripts', checkNoInstallScripts(manifest));
    record('pinned-first-party-deps', checkPinnedFirstPartyDeps(manifest));
    record('global-install-smoke', checkGlobalInstallSmoke(tarball, manifest, scratchRoot));
    record('credential-scan', checkCredentialScan(extracted, scratchRoot));

    let closure;
    try {
      closure = resolveClosure(tarball, scratchRoot);
    } catch (e) {
      closure = { error: short(e.stderr || e.message) };
    }
    record('npm-audit', checkNpmAudit(closure));
    record('consumer-closure', await checkConsumerClosure(closure, manifest, advisoryStates));
  } catch (e) {
    // A crash before the census would be a verdictless exit; convert it into
    // preconditions on everything that never ran, so the census still says so.
    for (const name of CHECKS) {
      if (!results.has(name)) {
        results.set(name, { status: 'precondition', detail: [`never ran: ${short(e.message)}`] });
      }
    }
    console.error(`  review aborted early: ${short(e.stack ?? e.message, 500)}`);
  } finally {
    rmSync(scratchRoot, { recursive: true, force: true });
  }

  // The census: every check, one line, whatever happened.
  console.log(`census: ${CHECKS.map((c) => `${c}=${results.get(c)?.status ?? 'precondition'}`).join(' ')}`);

  const failed = CHECKS.filter((c) => results.get(c)?.status === 'fail');
  const blocked = CHECKS.filter((c) => results.get(c)?.status === 'precondition');
  if (failed.length > 0 || blocked.length > 0) {
    const parts = [];
    if (failed.length > 0) parts.push(`FAIL (${failed.join(', ')})`);
    if (blocked.length > 0) parts.push(`PRECONDITION (${blocked.join(', ')})`);
    console.error(`release-artifact-review: ${parts.join('; ')}`);
    process.exit(1);
  }
  console.log('release-artifact-review: PASS');
}

await main();

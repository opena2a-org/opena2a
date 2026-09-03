/**
 * Behavioural tests for scripts/release-artifact-review.mjs (QGF OPA-04,
 * AC2 + AC3).
 *
 * Red first, per check: every blocking check is proven able to FAIL on a
 * tarball poisoned with exactly the defect it exists to catch, before the
 * clean cases are trusted. A gate that has never been seen red is
 * indistinguishable from a gate that cannot fire.
 *
 * Three kinds of subject:
 *  - poisoned tarballs, built in a temp dir with `tar` so entries npm would
 *    refuse to pack (dotfiles, fixtures/) can exist at all;
 *  - a clean fixture tarball that must come back green on every check;
 *  - the real `opena2a-cli` tarball packed from THIS tree, which must pass
 *    every check whose verdict needs no network reading. Its
 *    `consumer-closure` verdict may honestly be `fail` (a pinned dependency
 *    inside a published advisory blocks the release and is upstream's defect,
 *    not this criterion's) — but it may never be `precondition`: a check that
 *    could not run is not a check that passed.
 *
 * Network: the closure/advisory checks read registry.npmjs.org and
 * api.github.com. In CI a precondition on the own-tarball case is a hard test
 * failure. Outside CI it downgrades to a loud console warning, because a
 * laptop without network must not train people to expect red.
 */
import { describe, expect, it } from 'vitest';
import { execFileSync, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const SCRIPT = path.join(REPO_ROOT, 'scripts', 'release-artifact-review.mjs');
const CLI_DIR = path.join(REPO_ROOT, 'packages', 'cli');

/** Every check AC2 defines, in the script's census order. */
const ALL_CHECKS = [
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

/** The checks whose verdict needs no network reading (AC3's own-tarball list). */
const NETWORK_FREE_CHECKS = [
  'entry-allowlist',
  'no-dotfiles',
  'no-test-material',
  'no-install-scripts',
  'pinned-first-party-deps',
  'global-install-smoke',
  'credential-scan',
];

/**
 * PROVISIONAL CI clause — qgf/refs/rev2-provisional-ci-clause-note.md
 * (OPA-04 contract revision 2). The sentence "under CI=true or
 * GITHUB_ACTIONS=true a precondition in the own-tarball case is a test
 * failure, never a skip" is under CISO review because it collides with
 * hackmyagent's no-CI-reads-in-tests meta-gate (hackmyagent#696). This
 * repository carries no such meta-gate, so the CI read is kept in this ONE
 * helper with this comment, making the eventual amendment a one-line change.
 */
const loudMode = (): boolean => process.env.CI === 'true' || process.env.GITHUB_ACTIONS === 'true';

interface ReviewResult {
  status: number | null;
  out: string;
  census: Record<string, string>;
  failNames: string[];
  preconditionNames: string[];
}

function runReview(tarball: string, extraArgs: string[] = []): ReviewResult {
  const res = spawnSync(process.execPath, [SCRIPT, '--tarball', tarball, ...extraArgs], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 840_000,
    env: { ...process.env },
  });
  const out = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
  const censusLine = out.split('\n').find((l) => l.startsWith('census: '));
  const census: Record<string, string> = {};
  for (const pair of (censusLine ?? '').replace('census: ', '').split(' ')) {
    const [name, status] = pair.split('=');
    if (name && status) census[name] = status;
  }
  const failNames = /FAIL \(([^)]+)\)/.exec(out)?.[1]?.split(', ') ?? [];
  const preconditionNames = /PRECONDITION \(([^)]+)\)/.exec(out)?.[1]?.split(', ') ?? [];
  return { status: res.status, out, census, failNames, preconditionNames };
}

interface FixtureSpec {
  name: string;
  version: string;
  files?: Record<string, string>;
  manifestExtra?: Record<string, unknown>;
}

/**
 * Build a tarball by hand with `tar`, not `npm pack`: half of the poisoned
 * cases are entries npm pack would refuse to produce, which is the point —
 * the review defends against tarballs that did NOT come from a well-behaved
 * pack step.
 */
function buildTarball(scratch: string, spec: FixtureSpec): string {
  const dir = mkdtempSync(path.join(scratch, 'fixture-'));
  const root = path.join(dir, 'package');
  mkdirSync(root, { recursive: true });
  writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name: spec.name, version: spec.version, ...spec.manifestExtra }, null, 2)
  );
  for (const [rel, content] of Object.entries(spec.files ?? {})) {
    const dest = path.join(root, rel);
    mkdirSync(path.dirname(dest), { recursive: true });
    writeFileSync(dest, content);
  }
  const tgz = path.join(dir, `${spec.name.replace('@', '').replace('/', '-')}-${spec.version}.tgz`);
  execFileSync('tar', ['-czf', tgz, '-C', dir, 'package'], { encoding: 'utf8' });
  return tgz;
}

/** A dist/index.js that behaves: exit 0 on anything, JSON for init --ci. */
const WELL_BEHAVED_BIN = [
  '#!/usr/bin/env node',
  "const args = process.argv.slice(2);",
  "if (args[0] === 'init') { console.log(JSON.stringify({ ok: true, checks: [], format: 'json' })); }",
  "else { console.log('0.0.0-fixture'); }",
  '',
].join('\n');

/**
 * A credential-named const carrying a value of the control's class (flagged by
 * hackmyagent's AST credential walk as AST-CRED-001/003). Assembled HERE at
 * test runtime, so the repository carries no credential-shaped literal — the
 * contiguous shape exists only in the poisoned fixture's bytes, where the
 * scanner's raw-content format gate needs it.
 */
const CONTROL_CLASS_LINE = `const OPENAI_API_KEY = '${'sk-' + 'proj-' + 'A'.repeat(48)}';\nmodule.exports = { OPENAI_API_KEY };\n`;

const scratch = mkdtempSync(path.join(tmpdir(), 'opa04-review-tests-'));

/** Memoised heavy runs, so several tests can assert on one invocation. */
let cleanResult: ReviewResult | undefined;
function getCleanResult(): ReviewResult {
  cleanResult ??= runReview(
    buildTarball(scratch, {
      name: 'opena2a-cli',
      version: '0.0.0-qgf-clean',
      manifestExtra: { bin: { opena2a: 'dist/index.js' } },
      files: { 'dist/index.js': WELL_BEHAVED_BIN, 'README.md': '# clean fixture\n' },
    }),
    ['--advisory-states', 'published']
  );
  return cleanResult;
}

let ownResult: ReviewResult | undefined;
function getOwnResult(): ReviewResult {
  if (!ownResult) {
    if (!existsSync(path.join(CLI_DIR, 'dist', 'index.js'))) {
      throw new Error(
        'packages/cli/dist is not built; run `npm run build` first. The own-tarball case reviews the tarball this tree would publish, which does not exist without dist/.'
      );
    }
    const dir = mkdtempSync(path.join(scratch, 'own-pack-'));
    execFileSync('npm', ['pack', '--ignore-scripts', `--pack-destination=${dir}`], {
      cwd: CLI_DIR,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    });
    const tgz = readdirSync(dir).find((f) => f.endsWith('.tgz'));
    if (!tgz) throw new Error('npm pack produced no tarball');
    ownResult = runReview(path.join(dir, tgz));
  }
  return ownResult;
}

// ---------------------------------------------------------------------------
// AC3 — red, one poisoned tarball per check.
// ---------------------------------------------------------------------------

interface PoisonCase {
  title: string;
  check: string;
  spec: FixtureSpec;
}

const POISON_CASES: PoisonCase[] = [
  {
    title: 'OPA-04.AC3 a dotfile entry fails no-dotfiles',
    check: 'no-dotfiles',
    spec: {
      name: 'opena2a-qgf-dotfile',
      version: '0.0.0',
      // Inside dist/, so the entry allowlist stays green and the dotfile rule
      // alone is what fires.
      files: { 'dist/index.js': 'module.exports = {};\n', 'dist/.hidden.js': 'module.exports = {};\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a fixtures/ entry fails no-test-material',
    check: 'no-test-material',
    spec: {
      name: 'opena2a-qgf-fixtures',
      version: '0.0.0',
      files: { 'dist/index.js': 'module.exports = {};\n', 'dist/fixtures/sample.json': '{}\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a postinstall script fails no-install-scripts',
    check: 'no-install-scripts',
    spec: {
      name: 'opena2a-qgf-postinstall',
      version: '0.0.0',
      manifestExtra: { scripts: { postinstall: 'node -e "process.exit(0)"' } },
      files: { 'dist/index.js': 'module.exports = {};\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a caret range on an @opena2a/ dependency fails pinned-first-party-deps',
    check: 'pinned-first-party-deps',
    spec: {
      name: 'opena2a-qgf-caret-scope',
      version: '0.0.0',
      manifestExtra: { dependencies: { '@opena2a/cli-ui': '^0.5.2' } },
      files: { 'dist/index.js': 'module.exports = {};\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a caret range on hackmyagent fails pinned-first-party-deps',
    check: 'pinned-first-party-deps',
    spec: {
      name: 'opena2a-qgf-caret-hma',
      version: '0.0.0',
      manifestExtra: { dependencies: { hackmyagent: '^0.30.0' } },
      files: { 'dist/index.js': 'module.exports = {};\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a dist/index.js that exits 1 on --version fails global-install-smoke',
    check: 'global-install-smoke',
    spec: {
      // Packed name opena2a-cli, because the smoke check only exercises the
      // tarball that ships the bin.
      name: 'opena2a-cli',
      version: '0.0.0-qgf-smokefail',
      manifestExtra: { bin: { opena2a: 'dist/index.js' } },
      files: { 'dist/index.js': '#!/usr/bin/env node\nprocess.exit(1);\n', 'README.md': '# broken\n' },
    },
  },
  {
    title: 'OPA-04.AC3 a dist/ file carrying a value of the control class fails credential-scan',
    check: 'credential-scan',
    spec: {
      name: 'opena2a-qgf-cred',
      version: '0.0.0',
      files: { 'dist/index.js': 'module.exports = {};\n', 'dist/config-helper.js': CONTROL_CLASS_LINE },
    },
  },
];

describe('release-artifact-review: poisoned tarballs go red (OPA-04.AC3)', () => {
  for (const { title, check, spec } of POISON_CASES) {
    it(
      title,
      () => {
        const r = runReview(buildTarball(scratch, spec));
        // The targeted check must report FAIL — a precondition is not a pass,
        // and it is not a red verdict either: it means the check never ran.
        expect(r.census[check], `census: ${JSON.stringify(r.census)}\n${r.out}`).toBe('fail');
        expect(r.status, 'a failing review must exit non-zero').not.toBe(0);
        expect(r.failNames, 'the exit must NAME the failing check').toContain(check);
      },
      600_000
    );
  }

  it(
    'OPA-04.AC3 a dependency on a deprecated hackmyagent version fails consumer-closure',
    (ctx) => {
      const deprecated = findDeprecatedHackmyagentVersion();
      if (!deprecated && !loudMode()) {
        // Offline laptop: the registry probe itself is unreachable. In CI this
        // is a hard failure below — the red case must actually run there.
        console.warn('[consumer-closure red] registry unreachable; skipped outside CI');
        ctx.skip();
        return;
      }
      expect(
        deprecated,
        'no deprecated hackmyagent version discoverable on the registry; this red case cannot run without one'
      ).not.toBeNull();
      const { version, notice } = deprecated!;
      // The version this test used, named in the output as the contract asks.
      console.log(`consumer-closure red case uses hackmyagent@${version} (deprecated: ${notice.slice(0, 100)})`);

      const r = runReview(
        buildTarball(scratch, {
          name: 'opena2a-qgf-deprecated-dep',
          version: '0.0.0',
          // An exact pin, so pinned-first-party-deps stays green and the
          // deprecation row alone is what fires.
          manifestExtra: { dependencies: { hackmyagent: version } },
          files: { 'dist/index.js': 'module.exports = {};\n' },
        })
      );
      expect(r.census['consumer-closure'], r.out).toBe('fail');
      expect(r.status).not.toBe(0);
      expect(r.failNames).toContain('consumer-closure');
      expect(r.out).toContain(`hackmyagent@${version}`);
      expect(r.out.toLowerCase()).toContain('deprecated');
    },
    600_000
  );

  it(
    'OPA-04.AC3 a tarball with no dist/ exits non-zero with a precondition',
    () => {
      const r = runReview(
        buildTarball(scratch, {
          name: 'opena2a-qgf-nodist',
          version: '0.0.0',
          files: { 'README.md': '# nothing shipped\n' },
        })
      );
      expect(r.status).not.toBe(0);
      expect(r.out).toContain('precondition');
      // Specifically: nothing was scanned, and nothing scanned is not a pass.
      expect(r.census['credential-scan']).toBe('precondition');
    },
    600_000
  );
});

function findDeprecatedHackmyagentVersion(): { version: string; notice: string } | null {
  // `npm view 'pkg@*' deprecated --json` answers per-version for every
  // version carrying the field; fall back to probing the oldest few.
  try {
    const raw = execFileSync('npm', ['view', 'hackmyagent@*', 'deprecated', '--json'], {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    }).trim();
    if (raw) {
      const parsed = JSON.parse(raw);
      if (typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)) {
        for (const [version, notice] of Object.entries(parsed)) {
          if (typeof notice === 'string' && notice) return { version, notice };
        }
      }
    }
  } catch {
    // fall through to the probe below
  }
  try {
    const versions: string[] = JSON.parse(
      execFileSync('npm', ['view', 'hackmyagent', 'versions', '--json'], { encoding: 'utf8' })
    );
    for (const version of versions.slice(0, 15)) {
      try {
        const notice = execFileSync('npm', ['view', `hackmyagent@${version}`, 'deprecated'], {
          encoding: 'utf8',
        }).trim();
        if (notice) return { version, notice };
      } catch {
        // unreadable version — keep probing
      }
    }
  } catch {
    return null;
  }
  return null;
}

// ---------------------------------------------------------------------------
// AC3 — green: the clean fixture, then the tarball this tree would publish.
// ---------------------------------------------------------------------------

describe('release-artifact-review: clean subjects go green (OPA-04.AC2/AC3)', () => {
  it(
    'OPA-04.AC3 a clean fixture tarball exits 0 with every check pass',
    () => {
      const r = getCleanResult();
      for (const check of NETWORK_FREE_CHECKS) {
        expect(r.census[check], `${check} on the clean fixture\n${r.out}`).toBe('pass');
      }
      // The two feed-reading checks: pass, with the usual offline downgrade —
      // outside CI an unreachable registry reads as `precondition`, which the
      // script correctly refuses to call a pass; in CI it must BE a pass.
      for (const check of ['npm-audit', 'consumer-closure']) {
        if (r.census[check] === 'precondition' && !loudMode()) {
          console.warn(`[clean-fixture] ${check} = precondition (tolerated outside CI)`);
        } else {
          expect(r.census[check], `${check} on the clean fixture\n${r.out}`).toBe('pass');
        }
      }
      // Exit 0 exactly when every check passed.
      const allPass = ALL_CHECKS.every((c) => r.census[c] === 'pass');
      expect(r.status === 0, `exit ${r.status} vs census ${JSON.stringify(r.census)}`).toBe(allPass);
      if (loudMode()) expect(r.status, r.out).toBe(0);
    },
    840_000
  );

  it(
    'OPA-04.AC2 the census line names every check, whatever its verdict',
    () => {
      const r = getCleanResult();
      expect(Object.keys(r.census).sort()).toEqual([...ALL_CHECKS].sort());
    },
    840_000
  );

  it('OPA-04.AC2 --advisory-states is honoured and the states read are printed', { timeout: 840_000 }, () => {
    // The clean run above passed `--advisory-states published`.
    expect(getCleanResult().out).toContain('advisory-states read: published');
    // And an unknown value is refused rather than silently defaulted.
    const bogus = spawnSync(process.execPath, [SCRIPT, '--tarball', 'x.tgz', '--advisory-states', 'draft'], {
      encoding: 'utf8',
    });
    expect(bogus.status).toBe(2);
  });

  it(
    'OPA-04.AC3 the opena2a-cli tarball packed from this tree passes every network-free check',
    (ctx) => {
      if (!existsSync(path.join(CLI_DIR, 'dist', 'index.js')) && !loudMode()) {
        // ci.yml runs `npm run build` before `npm run test`, so in CI dist/
        // always exists and this skip arm is unreachable there.
        console.warn('[own-tarball] packages/cli/dist not built; skipped outside CI (run npm run build first)');
        ctx.skip();
        return;
      }
      const r = getOwnResult();

      for (const check of NETWORK_FREE_CHECKS) {
        expect(r.census[check], `${check} must never FAIL on our own tarball\n${r.out}`).not.toBe('fail');
        if (r.census[check] !== 'pass') {
          if (loudMode()) {
            expect.fail(`${check} = ${r.census[check]} on the own tarball; in CI a check that could not run is a failure, never a skip.\n${r.out}`);
          } else {
            console.warn(`[own-tarball] ${check} = ${r.census[check]} (tolerated outside CI)\n${r.out}`);
          }
        }
      }

      // The exit code is 0 exactly when no check is fail or precondition.
      const bad = ALL_CHECKS.filter((c) => r.census[c] === 'fail' || r.census[c] === 'precondition');
      expect(r.status === 0, `exit ${r.status} vs census ${JSON.stringify(r.census)}`).toBe(bad.length === 0);

      // consumer-closure and npm-audit may be pass or an HONEST fail (a
      // pinned dependency inside a published advisory blocks the release and
      // is quoted below for the delivery report) — but never a precondition.
      for (const check of ['npm-audit', 'consumer-closure']) {
        if (r.census[check] === 'precondition') {
          if (loudMode()) {
            expect.fail(`${check} = precondition on the own tarball; the advisory feeds were not read, and unread is not clean.\n${r.out}`);
          } else {
            console.warn(`[own-tarball] ${check} = precondition (tolerated outside CI)\n${r.out}`);
          }
        } else {
          expect(['pass', 'fail']).toContain(r.census[check]);
        }
      }

      if (r.census['consumer-closure'] === 'fail' || r.census['npm-audit'] === 'fail') {
        // Verbatim, for the delivery report and for whoever unblocks the
        // release: the census line plus every FAIL row.
        console.log('[own-tarball verbatim]');
        for (const line of r.out.split('\n')) {
          if (line.startsWith('census: ') || line.includes('FAIL')) console.log(line);
        }
      }
    },
    840_000
  );
});

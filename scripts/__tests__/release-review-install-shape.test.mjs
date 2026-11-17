/**
 * The release review's credential scan works in the release job's install
 * shape, and only from the pinned scanner.
 *
 * release.yml's `review` job installs the workspace with
 * `npm ci --ignore-scripts` and builds nothing. In that tree npm links four of
 * hackmyagent 0.30.0's dependencies to unbuilt workspace packages, so a
 * scanner loaded from the repository's node_modules stopped on
 * node_modules/@opena2a/registry-client/dist/index.js, and the credential-scan
 * row read `precondition` on every tarball of every tag. Nothing in CI ran the
 * review in that shape; ci.yml's `test` job now runs this file right after the
 * same install, before anything is built.
 *
 *   T0  the committed scanner lockfile resolves every package from the
 *       registry, by integrity, with no link, and pins hackmyagent exactly;
 *   T1  a fixture tarball reviewed with --scanner-root reads
 *       credential-scan=pass;
 *   T2  every way a scanner root can differ from the pinned install reads
 *       credential-scan=precondition, naming its cause;
 *   T3  no byte of the scanner's stdout reaches the review's output, and from
 *       stderr only a missing module under the scanner or repository root;
 *   T4  the scanner child's environment is exactly the declared list, plus
 *       only what the host's Node runtime sets in every process it starts;
 *   T5  the installer refuses a relative path, a path inside the repository
 *       and a directory that already holds anything.
 *
 * Never skips. With RELEASE_SCANNER_ROOT unset it installs a scanner with
 * scripts/install-release-scanner.mjs into a fresh temporary directory; a
 * missing prerequisite is a failure. Only the credential-scan row is asserted:
 * each review runs with npm offline and an empty npm cache, so the rows that
 * read the registry report `precondition` quickly instead of reading it.
 */
import { after, before, test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import {
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  readlinkSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const REVIEW = path.join(REPO_ROOT, 'scripts', 'release-artifact-review.mjs');
const INSTALL = path.join(REPO_ROOT, 'scripts', 'install-release-scanner.mjs');
const SCANNER_MANIFEST_DIR = path.join(REPO_ROOT, '.github', 'release-scanner');
const PINNED = '0.30.0';

/** The scanner child's environment, by name: release-artifact-review.mjs declares exactly these. */
const DECLARED_ENV = [
  'HOME',
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_COLOR',
  'NO_PROXY',
  'OPENA2A_TELEMETRY',
  'PATH',
  'TMPDIR',
  'USERPROFILE',
  'http_proxy',
  'https_proxy',
].sort();

const scratch = mkdtempSync(path.join(tmpdir(), 'release-review-install-shape-'));
let scannerRoot;
let copyBase;
let fixture;

before(() => {
  scannerRoot = process.env.RELEASE_SCANNER_ROOT;
  if (!scannerRoot) {
    scannerRoot = path.join(scratch, 'scanner');
    const res = spawnSync(process.execPath, [INSTALL, scannerRoot], { encoding: 'utf8', timeout: 600_000 });
    assert.equal(
      res.status,
      0,
      `installing the pinned scanner is this file's prerequisite and it failed:\n${res.stdout}${res.stderr}`
    );
    assert.match(
      res.stdout,
      /^release scanner: hackmyagent@\S+, \d+ packages, lockfile sha256 [0-9a-f]{64}, \S.*\n$/,
      'the installer prints exactly one line'
    );
  }
  assert.ok(
    path.isAbsolute(scannerRoot) && existsSync(path.join(scannerRoot, 'node_modules', 'hackmyagent', 'package.json')),
    `RELEASE_SCANNER_ROOT=${scannerRoot} holds no installed scanner; install one with node scripts/install-release-scanner.mjs <dir>`
  );
  // Beside the installed root, so the hard links below stay on its filesystem.
  copyBase = mkdtempSync(path.join(path.dirname(scannerRoot), 'release-review-root-copies-'));
  fixture = fixtureTarball();
});

after(() => {
  rmSync(scratch, { recursive: true, force: true });
  if (copyBase) rmSync(copyBase, { recursive: true, force: true });
});

/** The tarball every case reviews: a package that is never published, with benign contents. */
function fixtureTarball() {
  const dir = mkdtempSync(path.join(scratch, 'fixture-'));
  const root = path.join(dir, 'package');
  mkdirSync(path.join(root, 'dist'), { recursive: true });
  writeFileSync(
    path.join(root, 'package.json'),
    JSON.stringify({ name: '@opena2a/release-review-install-shape-fixture', version: '0.0.0-install-shape', main: 'dist/index.js' }, null, 2) + '\n'
  );
  writeFileSync(path.join(root, 'dist', 'index.js'), "module.exports = { greeting: 'hello' };\n");
  writeFileSync(path.join(root, 'README.md'), '# install-shape fixture\n\nNever published.\n');
  const tgz = path.join(dir, 'opena2a-release-review-install-shape-fixture-0.0.0-install-shape.tgz');
  execFileSync('tar', ['-czf', tgz, '-C', dir, 'package']);
  return tgz;
}

/**
 * A copy of the installed scanner root built from hard links, so the closure
 * is not duplicated per case; links are recreated with their own targets.
 * Edit a file in a copy only through replaceFile, which unlinks it first, so
 * the installed root is never written.
 */
let copies = 0;
function copyRoot() {
  const dest = path.join(copyBase, `root-${(copies += 1)}`);
  const walk = (from, to) => {
    mkdirSync(to);
    for (const ent of readdirSync(from, { withFileTypes: true })) {
      const a = path.join(from, ent.name);
      const b = path.join(to, ent.name);
      if (ent.isSymbolicLink()) symlinkSync(readlinkSync(a), b);
      else if (ent.isDirectory()) walk(a, b);
      else {
        try {
          linkSync(a, b);
        } catch (e) {
          if (e.code !== 'EXDEV') throw e;
          copyFileSync(a, b);
        }
      }
    }
  };
  walk(scannerRoot, dest);
  return dest;
}

function replaceFile(file, content) {
  rmSync(file, { force: true });
  writeFileSync(file, content);
}

/** hackmyagent's bin target in a scanner root: the file the review runs. */
function binTarget(root) {
  const pkgDir = path.join(root, 'node_modules', 'hackmyagent');
  const { bin } = JSON.parse(readFileSync(path.join(pkgDir, 'package.json'), 'utf8'));
  return path.join(pkgDir, typeof bin === 'string' ? bin : bin.hackmyagent);
}

// The review's own environment: no token (this file reads no advisory), npm
// offline with an empty cache so the registry rows fail fast.
const inherited = { ...process.env };
delete inherited.GH_TOKEN;
delete inherited.GITHUB_TOKEN;

function review(args, env = {}) {
  const res = spawnSync(process.execPath, [REVIEW, '--tarball', fixture, '--advisory-states', 'published', ...args], {
    encoding: 'utf8',
    timeout: 600_000,
    maxBuffer: 64 * 1024 * 1024,
    env: {
      ...inherited,
      npm_config_offline: 'true',
      npm_config_cache: mkdtempSync(path.join(scratch, 'npm-cache-')),
      ...env,
    },
  });
  const out = `${res.stdout ?? ''}\n${res.stderr ?? ''}`;
  const census = {};
  const censusLine = out.split('\n').find((l) => l.startsWith('census: ')) ?? '';
  for (const pair of censusLine.replace('census: ', '').split(' ')) {
    const [name, status] = pair.split('=');
    if (name && status) census[name] = status;
  }
  const lines = out.split('\n');
  const start = lines.findIndex((l) => l.startsWith('  check credential-scan: '));
  const rest = start === -1 ? [] : lines.slice(start + 1);
  const end = rest.findIndex((l) => l.startsWith('  check ') || l.startsWith('census: '));
  const row = start === -1 ? '' : [lines[start], ...(end === -1 ? rest : rest.slice(0, end))].join('\n');
  return { status: res.status, out, census, row };
}

/**
 * Names a Node process reports when it is started with an empty environment.
 * None on Linux; on macOS the runtime sets __CF_USER_TEXT_ENCODING in every
 * process itself. Measured on this host, never listed, so no name the review
 * passes is excused.
 */
function runtimeAddedNames() {
  const res = spawnSync(process.execPath, ['-e', 'process.stdout.write(JSON.stringify(Object.keys(process.env)))'], {
    env: {},
    encoding: 'utf8',
  });
  assert.equal(res.status, 0, `could not start node with an empty environment: ${res.stderr}`);
  return JSON.parse(res.stdout);
}

/** The arm the review must name: a network namespace where this host allows one. */
const expectedArm = () =>
  spawnSync('unshare', ['-rn', 'true'], { stdio: 'ignore' }).status === 0
    ? 'network cut via unshare -rn'
    : 'no netns available; proxy-poisoned env only';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const randomAlnum = (n) => [...randomBytes(n)].map((b) => ALNUM[b % ALNUM.length]).join('');

/** Every 8-character window of `secret` that appears in `out`. */
const leakedWindows = (secret, out) => {
  const found = [];
  for (let i = 0; i + 8 <= secret.length; i += 1) if (out.includes(secret.slice(i, i + 8))) found.push(i);
  return found;
};

// ---------------------------------------------------------------------------

test('T0 the scanner lockfile resolves every package from the registry by integrity, with no link', () => {
  const manifest = JSON.parse(readFileSync(path.join(SCANNER_MANIFEST_DIR, 'package.json'), 'utf8'));
  assert.deepEqual(manifest.dependencies, { hackmyagent: PINNED }, 'package.json pins hackmyagent exactly and nothing else');
  assert.deepEqual(Object.keys(manifest), ['dependencies'], 'the scanner manifest carries its dependency map and nothing else');
  assert.equal(manifest.scripts, undefined, 'the scanner manifest carries no scripts');

  const lock = JSON.parse(readFileSync(path.join(SCANNER_MANIFEST_DIR, 'package-lock.json'), 'utf8'));
  assert.equal(lock.lockfileVersion, 3);
  const entries = Object.entries(lock.packages ?? {});
  for (const [key, entry] of entries) {
    assert.ok(!('link' in entry), `${key || '(root)'} carries "link"`);
    if (key === '') continue;
    assert.ok(String(entry.resolved ?? '').startsWith('https://registry.npmjs.org/'), `${key} resolves from ${entry.resolved}`);
    assert.ok(entry.integrity, `${key} carries no integrity`);
  }
  assert.ok(entries.length > 1, 'the lockfile resolves no package');
  assert.equal(lock.packages['node_modules/hackmyagent']?.version, PINNED);
});

test('T1 a fixture tarball reviewed in the install shape reads credential-scan=pass from the pinned scanner', (t) => {
  const r = review(['--scanner-root', scannerRoot]);
  t.diagnostic(r.row);
  assert.equal(r.census['credential-scan'], 'pass', r.out);
  assert.match(r.row, new RegExp(`hackmyagent@${PINNED.replaceAll('.', '\\.')}`), r.row);
  assert.match(r.row, /every control flagged/, r.row);
});

test('T2 a scanner root that is not the pinned install reads precondition naming its cause', async (t) => {
  const cases = [
    {
      name: 'lockfile edited',
      root: () => {
        const root = copyRoot();
        const lock = path.join(root, 'package-lock.json');
        replaceFile(lock, readFileSync(lock, 'utf8') + '\n');
        return root;
      },
      cause: /package-lock\.json has sha256 [0-9a-f]{64}, which differs from \.github\/release-scanner\/package-lock\.json/,
    },
    {
      name: 'hackmyagent version edited',
      root: () => {
        const root = copyRoot();
        const manifest = path.join(root, 'node_modules', 'hackmyagent', 'package.json');
        replaceFile(manifest, JSON.stringify({ ...JSON.parse(readFileSync(manifest, 'utf8')), version: '0.30.1' }, null, 2));
        return root;
      },
      cause: /installed hackmyagent is 0\.30\.1, which differs from the lockfile's 0\.30\.0/,
    },
    {
      name: '@opena2a/registry-client replaced by a link to the workspace package',
      root: () => {
        const root = copyRoot();
        const dir = path.join(root, 'node_modules', '@opena2a', 'registry-client');
        rmSync(dir, { recursive: true, force: true });
        symlinkSync(path.join(REPO_ROOT, 'packages', 'registry-client'), dir, 'dir');
        return root;
      },
      cause: /package directory is a symbolic link: node_modules\/@opena2a\/registry-client/,
    },
    {
      name: 'a link to a directory outside the root',
      root: () => {
        const root = copyRoot();
        symlinkSync(mkdtempSync(path.join(scratch, 'outside-')), path.join(root, 'node_modules', 'hackmyagent', 'dist', 'outside-link'), 'dir');
        return root;
      },
      cause: /symbolic link resolves outside the scanner root: node_modules\/hackmyagent\/dist\/outside-link -> /,
    },
    { name: 'flag absent', args: () => [], cause: /no --scanner-root given/ },
    { name: 'relative path', args: () => ['--scanner-root', path.join('relative', 'scanner')], cause: /is a relative path/ },
    {
      name: 'missing path',
      args: () => ['--scanner-root', path.join(scratch, 'no-such-scanner')],
      cause: /no-such-scanner does not exist/,
    },
    {
      name: 'root inside the repository',
      args: () => ['--scanner-root', SCANNER_MANIFEST_DIR],
      cause: /lies inside the repository/,
    },
  ];
  for (const c of cases) {
    await t.test(c.name, () => {
      const args = c.args ? c.args() : ['--scanner-root', c.root()];
      const r = review(args);
      assert.equal(r.census['credential-scan'], 'precondition', r.out);
      assert.match(r.row, c.cause, r.row);
      assert.match(r.row, /node scripts\/install-release-scanner\.mjs/, 'the precondition names the install command');
      assert.notEqual(r.status, 0);
    });
  }
});

test('T3 no byte of scanner stdout reaches the output; stderr yields only module paths under the roots and ERR_ codes', async (t) => {
  const root = copyRoot();
  const bin = binTarget(root);
  // Credential-shaped, assembled here; it exists only in the stub's bytes.
  const body = ['s', 'k-', 'pro', 'j-'].join('') + randomAlnum(48);
  assert.ok(body.length >= 40);
  const stub = (source) => replaceFile(bin, `'use strict';\n${source}\n`);

  await t.test('(i) a credential-shaped body then invalid JSON on stdout: counted, never printed', () => {
    const stdout = `${body}\n{"findings": [\n`;
    stub(`process.stdout.write(${JSON.stringify(stdout)});\nprocess.exitCode = 1;`);
    const r = review(['--scanner-root', root]);
    assert.equal(r.census['credential-scan'], 'precondition', r.row);
    assert.deepEqual(leakedWindows(body, r.out), [], 'an 8-character window of scanner stdout reached the review output');
    assert.ok(r.row.includes(`stdout: ${Buffer.byteLength(stdout)} bytes`), `the stdout byte count is printed\n${r.row}`);
  });

  await t.test('(ii, iii) a parse error carrying the body on stderr is dropped; a missing module under the root is named', () => {
    const missing = path.join(root, 'node_modules', 'x', 'dist', 'index.js');
    const stderr =
      `SyntaxError: Unexpected token 's', "${body}" is not valid JSON\n    at JSON.parse (<anonymous>)\n` +
      `Error: Cannot find module '${missing}'\n`;
    stub(`process.stderr.write(${JSON.stringify(stderr)});\nprocess.exitCode = 1;`);
    const r = review(['--scanner-root', root]);
    assert.equal(r.census['credential-scan'], 'precondition', r.row);
    assert.deepEqual(leakedWindows(body, r.out), [], 'an 8-character window of the stderr body reached the review output');
    assert.ok(r.row.includes(missing), `the module path under the scanner root is printed\n${r.row}`);
    assert.ok(r.row.includes(`stderr: ${Buffer.byteLength(stderr)} bytes`), r.row);
  });

  await t.test('(iv) a module path inside the scratch extraction directory: its byte count only', () => {
    const record = path.join(scratch, 'extraction-module-path.txt');
    rmSync(record, { force: true });
    stub(
      [
        "const fs = require('fs');",
        "const path = require('path');",
        'const parent = path.dirname(process.cwd());',
        "const extracted = fs.readdirSync(parent).find((n) => n.startsWith('extracted-'));",
        "const p = path.join(parent, extracted, 'package', 'dist', 'index.js');",
        `fs.writeFileSync(${JSON.stringify(record)}, p);`,
        "process.stderr.write(`Error [ERR_MODULE_NOT_FOUND]: Cannot find module '${p}' imported from ${p}\\n`);",
        'process.exitCode = 1;',
      ].join('\n')
    );
    const r = review(['--scanner-root', root]);
    assert.equal(r.census['credential-scan'], 'precondition', r.row);
    assert.ok(existsSync(record), `the stub never ran\n${r.out}`);
    const p = readFileSync(record, 'utf8');
    assert.ok(!r.out.includes(p), 'the extraction-directory path reached the review output');
    assert.ok(
      r.row.includes(`module path outside the scanner and repository roots (${Buffer.byteLength(p)} bytes)`),
      `the path's byte count is printed in its place\n${r.row}`
    );
    assert.match(r.row, /stderr error codes: ERR_MODULE_NOT_FOUND/, r.row);
  });
});

test('T4 the scanner child receives exactly the declared environment', () => {
  const root = copyRoot();
  const record = path.join(scratch, 'scanner-env-names.jsonl');
  rmSync(record, { force: true });
  // Answers as the real scanner does: the planted control is a finding,
  // anything else is clean. Records variable NAMES, never values.
  replaceFile(
    binTarget(root),
    [
      "'use strict';",
      "const fs = require('fs');",
      `fs.appendFileSync(${JSON.stringify(record)}, JSON.stringify(Object.keys(process.env).sort()) + '\\n');`,
      "const control = fs.readdirSync(process.cwd()).includes('zz-planted-credential-control.js');",
      "const findings = control ? [{ checkId: 'AST-CRED-001', file: 'zz-planted-credential-control.js', line: 3, passed: false }] : [];",
      'process.stdout.write(JSON.stringify({ findings }) + "\\n");',
      'process.exitCode = control ? 1 : 0;',
      '',
    ].join('\n')
  );
  const sentinel = ['release', 'review', 'sentinel', randomAlnum(12)].join('-');
  const r = review(['--scanner-root', root], {
    RELEASE_REVIEW_ENV_SENTINEL: sentinel,
    GH_TOKEN: ['not', 'a', 'credential', randomAlnum(12)].join('-'),
  });
  assert.equal(r.census['credential-scan'], 'pass', r.out);
  assert.ok(existsSync(record), `the stub never ran\n${r.out}`);
  const runs = readFileSync(record, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.ok(runs.length >= 2, `expected a control scan and a shipped-files scan, got ${runs.length}`);
  const expected = [...new Set([...DECLARED_ENV, ...runtimeAddedNames()])].sort();
  for (const names of runs) assert.deepEqual(names, expected);
  assert.ok(r.row.includes(expectedArm()), `the row names the network arm\n${r.row}`);
});

test('T5 the installer refuses a relative path, a path inside the repository and a directory that holds anything', () => {
  // Each refusal comes before npm runs, so nothing here reads the registry.
  const install = (dir) => spawnSync(process.execPath, [INSTALL, dir], { encoding: 'utf8', timeout: 60_000 });

  const relative = install(path.join('relative', 'scanner'));
  assert.notEqual(relative.status, 0);
  assert.match(relative.stderr, /refused: relative[/\\]scanner is a relative path/);

  const insideTarget = path.join(REPO_ROOT, 'node_modules', '.release-scanner-refused');
  const inside = install(insideTarget);
  assert.notEqual(inside.status, 0);
  assert.match(inside.stderr, /refused: .* lies inside the repository/);
  assert.equal(existsSync(insideTarget), false, 'a refused install writes nothing');

  const held = mkdtempSync(path.join(scratch, 'held-'));
  writeFileSync(path.join(held, 'left-behind'), '');
  const nonEmpty = install(held);
  assert.notEqual(nonEmpty.status, 0);
  assert.match(nonEmpty.stderr, /refused: .* already holds 1 entry; give a new or empty directory/);
  assert.deepEqual(readdirSync(held), ['left-behind']);
});

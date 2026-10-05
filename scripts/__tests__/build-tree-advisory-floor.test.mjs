/**
 * The committed lockfile does not walk back into an advisory it already left.
 *
 * `build-tree-audit` in `.github/workflows/security.yml` runs
 * `npm ci --ignore-scripts && npm audit --audit-level=high` over this
 * workspace. It has gone red on `main` more than once (#249) because the
 * lockfile kept transitive versions with published fixes, and because it is
 * not a required check nothing stopped a merge in the meantime. The remedy is a lockfile
 * refresh, and a lockfile refresh is the kind of change that quietly comes
 * undone: a rebase that resolves a `package-lock.json` conflict by taking the
 * other side, or a regeneration from a stale checkout, restores the old pins
 * without touching any manifest.
 *
 * This test reads the committed lockfile offline and fails if any copy of a
 * package listed below resolves inside the range `npm audit` reported for it.
 * Each range is copied from `npm audit` output at the time it was cleared, as
 * the union over that package's advisories. It does not replace the audit: a
 * newly published advisory is still `npm audit`'s to find, and an entry here
 * only records a floor this repository has already reached.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const LOCKFILE = path.join(REPO_ROOT, 'package-lock.json');

// `introduced` and `lastAffected` are both inclusive, as `npm audit` prints
// them; `introduced: null` stands for an open lower bound (`<=x.y.z`).
const CLEARED = [
  {
    name: 'brace-expansion',
    introduced: '4.0.0',
    lastAffected: '5.0.11',
    advisories: ['GHSA-q2hr-2g5m-vwhr', 'GHSA-qhr7-859c-m2p7', 'GHSA-6j4f-fj2g-mc7p'],
  },
  {
    name: 'hono',
    introduced: null,
    lastAffected: '4.13.6',
    advisories: ['GHSA-gqvv-2mrq-wpjv', 'GHSA-g6gw-c38x-mqfc', 'GHSA-crvj-82cr-hjcx', 'GHSA-hxh3-vqpv-xpqv'],
  },
  {
    name: 'ip-address',
    introduced: null,
    lastAffected: '10.7.0',
    advisories: ['GHSA-rpw4-54j3-4h4q', 'GHSA-2vr4-cq9g-pvrc', 'GHSA-j6r3-76f7-8jcv', 'GHSA-h3mg-xc3c-68pw'],
  },
  {
    name: 'fast-uri',
    introduced: '3.0.0',
    lastAffected: '3.1.7',
    advisories: ['GHSA-hrr3-gc8f-f4qj'],
  },
  {
    name: '@vitest/mocker',
    introduced: '2.1.0',
    lastAffected: '4.1.10',
    advisories: ['GHSA-82fw-gwwq-j7x9'],
  },
];

function parseVersion(version) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(version);
  if (!m) return null;
  return { core: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? null };
}

// Semver precedence, close enough for exact lockfile versions: a prerelease
// sorts below its own release, and two prereleases of one core compare
// field-wise with numeric awareness.
function compareVersions(a, b) {
  const pa = parseVersion(a);
  const pb = parseVersion(b);
  for (let i = 0; i < 3; i++) {
    if (pa.core[i] !== pb.core[i]) return pa.core[i] - pb.core[i];
  }
  if (pa.pre === pb.pre) return 0;
  if (pa.pre === null) return 1;
  if (pb.pre === null) return -1;
  return pa.pre.localeCompare(pb.pre, 'en', { numeric: true });
}

function inRange(version, { introduced, lastAffected }) {
  if (introduced !== null && compareVersions(version, introduced) < 0) return false;
  return compareVersions(version, lastAffected) <= 0;
}

// Every installed copy of `name`, keyed by its lockfile path. Workspace links
// carry no version of their own and name a directory, not a registry package.
function lockedCopies(lock, name) {
  const suffix = `node_modules/${name}`;
  return Object.entries(lock.packages ?? {})
    .filter(([key, entry]) => (key === suffix || key.endsWith(`/${suffix}`)) && !entry.link)
    .map(([key, entry]) => ({ key, version: entry.version }));
}

const LOCK = JSON.parse(readFileSync(LOCKFILE, 'utf8'));

test('the lockfile is a v2+ lockfile with a packages map', () => {
  assert.ok(LOCK.lockfileVersion >= 2, `lockfileVersion is ${LOCK.lockfileVersion}`);
  assert.equal(typeof LOCK.packages, 'object');
});

for (const entry of CLEARED) {
  test(`${entry.name}: no locked copy resolves inside ${entry.advisories.join(', ')}`, () => {
    const copies = lockedCopies(LOCK, entry.name);
    for (const { key, version } of copies) {
      assert.ok(parseVersion(version), `${key} has a version this test cannot order: ${version}`);
    }
    const affected = copies.filter(({ version }) => inRange(version, entry));
    const range =
      entry.introduced === null ? `<=${entry.lastAffected}` : `${entry.introduced} - ${entry.lastAffected}`;
    assert.deepEqual(
      affected,
      [],
      `package-lock.json pins ${entry.name} inside ${range} again. ` +
        `Verify: npm audit --audit-level=high. Fix: npm audit fix --package-lock-only.`
    );
  });
}

test('the range check itself: bounds are inclusive and prereleases sort below their release', () => {
  const r = { introduced: '4.0.0', lastAffected: '5.0.11' };
  assert.equal(inRange('3.9.9', r), false);
  assert.equal(inRange('4.0.0', r), true);
  assert.equal(inRange('5.0.11', r), true);
  assert.equal(inRange('5.0.12', r), false);
  assert.equal(inRange('4.0.0-rc.1', r), false);
  assert.equal(inRange('5.0.11-rc.1', r), true);
  assert.equal(inRange('5.0.12-rc.1', r), false);
  assert.equal(inRange('1.0.0', { introduced: null, lastAffected: '4.13.6' }), true);
  assert.ok(compareVersions('1.0.0-rc.2', '1.0.0-rc.10') < 0);
});

#!/usr/bin/env node
/**
 * Install the release review's credential scanner apart from the workspace.
 *
 * release.yml's `review` job installs the workspace with
 * `npm ci --ignore-scripts` and builds nothing. In that tree npm links
 * hackmyagent's first-party dependencies (@opena2a/registry-client,
 * check-core, telemetry, shared) to the unbuilt workspace packages, so a
 * scanner loaded from the repository's node_modules stops on a missing
 * dist/index.js and the credential scan of every tarball reads
 * `precondition`. The scanner therefore installs from its own committed
 * manifest and lockfile (.github/release-scanner/) into a directory outside
 * the repository, where every package comes from the registry by integrity
 * and none is a link to a workspace.
 *
 *   node scripts/install-release-scanner.mjs <absolute directory outside the repository>
 *
 * Refuses a relative path, a path inside the repository and a directory that
 * already holds anything; installs with `npm ci --ignore-scripts`, so no
 * dependency's install script runs; refuses an installed hackmyagent whose
 * version is not the lockfile's. On success it prints exactly one line,
 *
 *   release scanner: hackmyagent@<version>, <n> packages, lockfile sha256 <hex>, <dir>
 *
 * and scripts/release-artifact-review.mjs takes <dir> as `--scanner-root`.
 * Every refusal exits non-zero and names its cause.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const MANIFEST_DIR = path.join(REPO_ROOT, '.github', 'release-scanner');
const MANIFEST_FILES = ['package.json', 'package-lock.json'];
const USAGE = 'usage: node scripts/install-release-scanner.mjs <absolute directory outside the repository>';

function refuse(cause, code = 1) {
  console.error(`install-release-scanner: refused: ${cause}`);
  process.exit(code);
}

const isInside = (child, parent) => {
  const rel = path.relative(parent, child);
  return rel === '' || (!path.isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${path.sep}`));
};

/** The real path `p` will have: its nearest existing ancestor resolved, the rest appended. */
function realTarget(p) {
  let existing = p;
  const rest = [];
  while (!existsSync(existing)) {
    const parent = path.dirname(existing);
    if (parent === existing) break;
    rest.unshift(path.basename(existing));
    existing = parent;
  }
  return path.join(realpathSync(existing), ...rest);
}

const sha256 = (file) => createHash('sha256').update(readFileSync(file)).digest('hex');

const args = process.argv.slice(2);
if (args.length !== 1 || !args[0]) refuse(`expected exactly one target directory, got ${args.length}. ${USAGE}`, 2);
const given = args[0];
if (!path.isAbsolute(given)) refuse(`${given} is a relative path; give an absolute directory outside the repository`);
const dir = path.resolve(given);
if (isInside(dir, REPO_ROOT) || isInside(realTarget(dir), realpathSync(REPO_ROOT))) {
  refuse(`${dir} lies inside the repository (${REPO_ROOT}); the scanner installs outside the workspace so no workspace link can reach it`);
}
if (existsSync(dir)) {
  if (!lstatSync(dir).isDirectory()) refuse(`${dir} exists and is not a directory`);
  const held = readdirSync(dir);
  if (held.length > 0) refuse(`${dir} already holds ${held.length} entr${held.length === 1 ? 'y' : 'ies'}; give a new or empty directory`);
}
for (const f of MANIFEST_FILES) {
  if (!existsSync(path.join(MANIFEST_DIR, f))) refuse(`${path.join(MANIFEST_DIR, f)} does not exist`);
}

try {
  mkdirSync(dir, { recursive: true });
  for (const f of MANIFEST_FILES) copyFileSync(path.join(MANIFEST_DIR, f), path.join(dir, f));
} catch (e) {
  refuse(`could not write ${dir}: ${e.message}`);
}

// --ignore-scripts: no dependency's install script runs (release.yml explains
// why for the workspace install; the same holds here). npm ci installs exactly
// the lockfile and checks every tarball against its integrity.
const res = spawnSync('npm', ['ci', '--ignore-scripts', '--no-audit', '--no-fund'], {
  cwd: dir,
  encoding: 'utf8',
  stdio: ['ignore', 'pipe', 'pipe'],
  timeout: 600_000,
  maxBuffer: 64 * 1024 * 1024,
});
if (res.error) refuse(`npm ci did not run in ${dir}: ${res.error.message}`);
if (res.status !== 0) {
  const npmErrors = String(res.stderr ?? '')
    .split('\n')
    .filter((l) => /^npm (error|ERR!)/.test(l))
    .slice(0, 20);
  refuse(
    [`npm ci exited ${res.status}${res.signal ? ` (signal ${res.signal})` : ''} in ${dir}`, ...npmErrors].join('\n  ')
  );
}

const lockPath = path.join(dir, 'package-lock.json');
const lock = JSON.parse(readFileSync(lockPath, 'utf8'));
const pinned = lock.packages?.['node_modules/hackmyagent']?.version;
if (!pinned) refuse(`${lockPath} names no node_modules/hackmyagent`);
const installedManifest = path.join(dir, 'node_modules', 'hackmyagent', 'package.json');
if (!existsSync(installedManifest)) refuse(`npm ci left no ${installedManifest}`);
const installed = JSON.parse(readFileSync(installedManifest, 'utf8')).version;
if (installed !== pinned) refuse(`installed hackmyagent is ${installed}; the lockfile pins ${pinned}`);

const packages = Object.keys(lock.packages ?? {}).filter((k) => k !== '').length;
console.log(`release scanner: hackmyagent@${installed}, ${packages} packages, lockfile sha256 ${sha256(lockPath)}, ${dir}`);

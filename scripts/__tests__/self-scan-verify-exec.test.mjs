/**
 * Keeps the self-scan clear of NEMO-008 (issue #388).
 *
 * The pinned scanner (`hackmyagent secure`) reports NEMO-008 HIGH, "TOCTOU
 * race between verify and apply", per directory: it takes any line that
 * reads like an integrity step (a word of VERIFY_WORDS followed on the same
 * line by a word of ARTIFACT_WORDS, below) in one file, and any line calling
 * spawn, exec, execSync or execFile in another file of the same directory,
 * and pairs them. It reads lines, not data flow, so a one-line dynamic
 * import from src/shield/integrity.js, destructuring runIntegrityChecks, in
 * a shield test was paired with an unrelated child process in the
 * concurrent-write test, and the same import in src/commands/shield.ts with
 * one in claim.ts. Neither path verifies an artifact and then runs it.
 *
 * Those lines are now split so no single line matches, and the root
 * .hmaignore rule that hid the test-directory hit is retired. This walks
 * every JS/TS file in the repository with the scanner's predicates, so a new
 * pairing fails `npm run test:scripts` instead of the scan. The scanner
 * stops after 200 files, so a pairing outside that window passes today and
 * fires after an unrelated file is added; the walk here has no cap.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');

const SKIP_DIRS = new Set(['node_modules', 'dist', '.git', '.turbo', 'coverage']);
const EXTENSIONS = new Set(['.ts', '.tsx', '.js', '.mjs', '.cjs']);

// NEMO-008's two line predicates, as the pinned scanner applies them. The
// first is assembled from word lists kept on separate lines so this file's
// own lines never match it; the words pair up by position.
const VERIFY_WORDS = ['verify', 'validate', 'check'];
const ARTIFACT_WORDS = ['digest', 'hash', 'integrity'];
const READS_AS_VERIFY = new RegExp(
  VERIFY_WORDS.map((word, i) => `${word}.*${ARTIFACT_WORDS[i]}`).join('|'),
  'i',
);
const CALLS_EXEC = /\bspawn\s*\(|\bexec\s*\(|\bexecSync\s*\(|\bexecFile\s*\(/;

function walk(dir, out) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) walk(path.join(dir, entry.name), out);
    } else if (entry.isFile() && EXTENSIONS.has(path.extname(entry.name))) {
      out.push(path.join(dir, entry.name));
    }
  }
}

/** Every cross-file pairing the scanner could report, as "verify-site with exec-site". */
function pairings(files) {
  // dir -> (file -> first matching line) for each predicate
  const verifyByDir = new Map();
  const execByDir = new Map();
  const note = (byDir, file, line) => {
    const dir = path.dirname(file);
    const inDir = byDir.get(dir) ?? new Map();
    if (!inDir.has(file)) inDir.set(file, line);
    byDir.set(dir, inDir);
  };

  for (const file of files) {
    readFileSync(file, 'utf8')
      .split('\n')
      .forEach((line, i) => {
        if (READS_AS_VERIFY.test(line)) note(verifyByDir, file, i + 1);
        if (CALLS_EXEC.test(line)) note(execByDir, file, i + 1);
      });
  }

  // The scanner keeps the first file of each kind in directory read order,
  // which differs across filesystems, so any cross-file pair is a hit.
  const hits = [];
  for (const [dir, verifiers] of verifyByDir) {
    const execs = execByDir.get(dir);
    if (!execs) continue;
    for (const [vFile, vLine] of verifiers) {
      for (const [eFile, eLine] of execs) {
        if (vFile === eFile) continue;
        hits.push(
          `${path.relative(REPO_ROOT, vFile)}:${vLine} with ${path.relative(REPO_ROOT, eFile)}:${eLine}`,
        );
      }
    }
  }
  return hits;
}

test('no directory pairs a verify-like line in one file with an exec line in another', () => {
  const files = [];
  walk(REPO_ROOT, files);
  assert.ok(files.length > 200, `walked only ${files.length} files`);
  assert.deepEqual(pairings(files), []);
});

test('the root .hmaignore carries no NEMO-008 exclusion', () => {
  const rules = readFileSync(path.join(REPO_ROOT, '.hmaignore'), 'utf8')
    .split('\n')
    .map((line) => line.trim());
  assert.equal(rules.some((line) => line.includes('NEMO-008')), false);
  assert.equal(rules.includes('packages/cli/__tests__/shield/events.test.ts'), false);
});

test('the predicates still recognise the lines the scanner paired', () => {
  // Assembled from parts so this file's own lines never match the predicate.
  const flagged = [
    'const { runIntegrityCheck',
    "s } = await import('../../src/shield/integrity.js');",
  ].join('');
  assert.equal(READS_AS_VERIFY.test(flagged), true);
  assert.equal(CALLS_EXEC.test(['const child = spawn', '(process.execPath, [script]);'].join('')), true);

  // The split form now used at each import site matches on neither line.
  assert.equal(READS_AS_VERIFY.test('const { runIntegrityChecks } ='), false);
  assert.equal(READS_AS_VERIFY.test("  await import('../../src/shield/integrity.js');"), false);
});

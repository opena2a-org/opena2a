/**
 * `opena2a init` says "No files were scanned for credentials" only when the
 * credential check found nothing (issue #400). A key file is flagged by its
 * name, without being opened, so a directory holding only `.certs/server.key`
 * or `.server.key` has a credential finding over zero files scanned; the
 * paragraph calling that "not a clean result" because nothing was read
 * contradicts the finding printed above it.
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * HOME and OPENA2A_HOME point into a temporary directory, so no file of the
 * user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'index.js');

const NO_FILES_SCANNED = 'No files were scanned for credentials';

function runInit(root, target, extraArgs = []) {
  const home = path.join(root, 'home');
  mkdirSync(home, { recursive: true });
  const res = spawnSync(process.execPath, [CLI, 'init', '--dir', target, ...extraArgs], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: home,
      OPENA2A_HOME: path.join(root, 'opena2a-home'),
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
      CI: '1',
    },
    timeout: 60_000,
  });
  return `${res.stdout}\n${res.stderr}`;
}

function tempRoot(t, prefix) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

const KEY_FILE_LAYOUTS = [
  { name: '.certs/server.key', files: [['.certs', 'server.key']] },
  { name: '.server.key', files: [['.server.key']] },
];

for (const layout of KEY_FILE_LAYOUTS) {
  test(`init on a directory holding only ${layout.name} prints the finding without the no-files-scanned paragraph`, (t) => {
    const root = tempRoot(t, 'init-keyfile-');
    const target = path.join(root, 'project');
    mkdirSync(target);
    for (const parts of layout.files) {
      const file = path.join(target, ...parts);
      mkdirSync(path.dirname(file), { recursive: true });
      // init flags key files by name alone; the content is never read.
      writeFileSync(file, 'placeholder\n');
    }

    const output = runInit(root, target);
    assert.match(output, /Private key file/, `no key-file finding in the output:\n${output}`);
    assert.ok(!output.includes(NO_FILES_SCANNED), `the no-files-scanned paragraph was printed:\n${output}`);
  });
}

test('init on a directory with nothing to scan and no finding still prints the no-files-scanned paragraph', (t) => {
  const root = tempRoot(t, 'init-noscan-');
  const target = path.join(root, 'project');
  mkdirSync(target);
  writeFileSync(path.join(target, 'logo.png'), 'PNG');

  const output = runInit(root, target);
  assert.ok(output.includes(NO_FILES_SCANNED), `the no-files-scanned paragraph is missing:\n${output}`);
});

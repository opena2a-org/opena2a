/**
 * `opena2a init` counts an MCP config in credentialFilesScanned only when it
 * read the file (issue #400). A `.mcp.json` that is a directory, or a file
 * it may not open (mode 000), was not scanned, so a project holding nothing
 * else reports zero files scanned and "no files scanned", not "no findings".
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * HOME and OPENA2A_HOME point into a temporary directory, so no file of the
 * user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI = path.join(REPO_ROOT, 'packages', 'cli', 'dist', 'index.js');

function runInitJson(root, target) {
  const home = path.join(root, 'home');
  mkdirSync(home, { recursive: true });
  const res = spawnSync(process.execPath, [CLI, 'init', '--dir', target, '--json'], {
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
  assert.ok(res.stdout, `init --json printed nothing:\n${res.stderr}`);
  return JSON.parse(res.stdout);
}

function tempRoot(t, prefix) {
  const root = mkdtempSync(path.join(os.tmpdir(), prefix));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  return root;
}

function assertNothingScanned(report) {
  assert.equal(report.credentialFilesScanned, 0);
  assert.equal(report.credentialFindings, 0);
  const credCheck = report.hygieneChecks.find(c => c.label === 'Credential scan');
  assert.ok(credCheck, 'no Credential scan hygiene check in the report');
  assert.equal(credCheck.detail, 'no files scanned');
}

test('init --json does not count a .mcp.json that is a directory', (t) => {
  const root = tempRoot(t, 'init-mcpdir-');
  const target = path.join(root, 'project');
  mkdirSync(path.join(target, '.mcp.json'), { recursive: true });

  assertNothingScanned(runInitJson(root, target));
});

const canTestMode000 = process.platform !== 'win32' && process.getuid?.() !== 0;

test('init --json does not count a .mcp.json it cannot read', { skip: !canTestMode000 && 'mode 000 is readable here' }, (t) => {
  const root = tempRoot(t, 'init-mcp000-');
  const target = path.join(root, 'project');
  mkdirSync(target);
  const config = path.join(target, '.mcp.json');
  writeFileSync(config, '{"mcpServers":{}}\n');
  chmodSync(config, 0o000);
  let report;
  try {
    report = runInitJson(root, target);
  } finally {
    chmodSync(config, 0o644);
  }
  assertNothingScanned(report);
});

test('init --json still counts a readable .mcp.json', (t) => {
  const root = tempRoot(t, 'init-mcpok-');
  const target = path.join(root, 'project');
  mkdirSync(target);
  writeFileSync(path.join(target, '.mcp.json'), '{"mcpServers":{}}\n');

  const report = runInitJson(root, target);
  assert.equal(report.credentialFilesScanned, 1);
  const credCheck = report.hygieneChecks.find(c => c.label === 'Credential scan');
  assert.equal(credCheck?.detail, 'no findings');
});

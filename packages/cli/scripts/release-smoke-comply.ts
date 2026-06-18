#!/usr/bin/env tsx
/**
 * release-smoke-comply.ts — `opena2a comply` dispatch + masking smoke.
 *
 * Why this exists:
 *   `opena2a comply` is a new dispatch surface (0.10.10) that delegates to the
 *   @opena2a/aicomply engine. Per the org "End-to-End Smoke after dispatch
 *   changes" rule, every routing change must be exercised end-to-end through
 *   the BUILT `dist/index.js` (not the source), because a broken Commander
 *   registration or a regressed mask helper is invisible to unit tests that
 *   import the handler directly.
 *
 *   It asserts the four invariants a user (and a CI gate) depends on:
 *     1. Benign content  -> exit 0, verdict CLEAN.
 *     2. PII content      -> exit 1, verdict VIOLATION, and the RAW secret
 *        never appears in stdout (mask integrity — the security invariant).
 *     3. --json           -> parseable array, maskedValue masked, no raw leak.
 *     4. Unreadable path   -> exit 2 (usage error), not a crash.
 *
 * Exit code 0 = green, 1 = assertion failure, 2 = setup error.
 */
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const CLI = resolve(__dirname, '..', 'dist', 'index.js');

const SSN = '123-45-6789';
let failures = 0;

function fail(msg: string): void {
  process.stderr.write(`  FAIL: ${msg}\n`);
  failures++;
}

function pass(msg: string): void {
  process.stdout.write(`  ok: ${msg}\n`);
}

interface Run {
  status: number;
  stdout: string;
  stderr: string;
}

function runComply(args: string[], input: string): Run {
  const r = spawnSync('node', [CLI, 'comply', ...args], {
    input,
    encoding: 'utf8',
    // Deny the daemon so the smoke is deterministic and offline.
    env: { ...process.env, OPENA2A_TELEMETRY: 'off' },
  });
  return { status: r.status ?? -1, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

function main(): void {
  if (!existsSync(CLI)) {
    process.stderr.write(`setup error: ${CLI} not found — run \`npm run build\` first.\n`);
    process.exit(2);
  }

  process.stdout.write('opena2a comply — dispatch + masking smoke\n');

  // 1. Benign stdin -> exit 0, CLEAN.
  const benign = runComply([], 'hello world, nothing sensitive here');
  if (benign.status === 0 && /CLEAN/.test(benign.stdout)) pass('benign content -> exit 0, CLEAN');
  else fail(`benign expected exit 0 + CLEAN, got exit ${benign.status}`);

  // 2. PII stdin -> exit 1, VIOLATION, raw secret NEVER in stdout.
  const pii = runComply([], `My SSN is ${SSN}`);
  if (pii.status === 1 && /VIOLATION/.test(pii.stdout)) pass('PII content -> exit 1, VIOLATION');
  else fail(`PII expected exit 1 + VIOLATION, got exit ${pii.status}`);
  if (!pii.stdout.includes(SSN)) pass('mask integrity: raw secret absent from text output');
  else fail('mask integrity BREACH: raw secret leaked to stdout');

  // 3. --json -> parseable, masked, no raw leak.
  const json = runComply(['--json'], `SSN ${SSN}`);
  let parsed: unknown;
  try {
    parsed = JSON.parse(json.stdout);
  } catch {
    parsed = undefined;
  }
  if (
    json.status === 1 &&
    Array.isArray(parsed) &&
    (parsed as { verdict: string }[])[0]?.verdict === 'VIOLATION'
  ) {
    pass('--json -> parseable array, verdict VIOLATION');
  } else {
    fail(`--json expected exit 1 + parseable VIOLATION array, got exit ${json.status}`);
  }
  if (!json.stdout.includes(SSN)) pass('mask integrity: raw secret absent from JSON output');
  else fail('mask integrity BREACH: raw secret leaked to JSON');

  // 4. Unreadable path -> exit 2 (usage), not a crash.
  const tmp = mkdtempSync(join(tmpdir(), 'comply-smoke-'));
  try {
    const bad = runComply([join(tmp, 'nope.txt')], '');
    if (bad.status === 2 && /cannot read/.test(bad.stderr)) pass('unreadable path -> exit 2, usage error');
    else fail(`unreadable path expected exit 2 + 'cannot read', got exit ${bad.status}`);
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  if (failures > 0) {
    process.stderr.write(`\ncomply smoke: ${failures} assertion(s) failed — release-blocker.\n`);
    process.exit(1);
  }
  process.stdout.write('\ncomply smoke: all assertions passed.\n');
  process.exit(0);
}

main();

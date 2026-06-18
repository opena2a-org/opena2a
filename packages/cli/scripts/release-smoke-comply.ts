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

/**
 * The mask must not reveal a meaningful slice of the secret. Assert no run of
 * 4+ consecutive SSN digits survives in the output (a weaker "is the literal
 * dashed string present" check would pass even if the mask leaked most digits).
 */
function maskIntegrityHolds(output: string): boolean {
  const digits = SSN.replace(/-/g, '');
  for (let i = 0; i + 4 <= digits.length; i++) {
    if (output.includes(digits.slice(i, i + 4))) return false;
  }
  return true;
}

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
  if (maskIntegrityHolds(pii.stdout)) pass('mask integrity: no 4-digit SSN window in text output');
  else fail('mask integrity BREACH: too much of the SSN leaked to stdout');

  // 2b. Bare provider API key (regression for the 0.10.10 gap: comply scanned
  //     a bare sk-ant key CLEAN until @opena2a/aicomply 2.2.0). The literal
  //     word FAKE keeps this out of any real-secret scanner. Asserts the key is
  //     flagged AND never echoed raw.
  const PROVIDER_KEY = `sk-ant-api03-FAKE${'0'.repeat(91)}`;
  const cred = runComply([], `the agent leaked ${PROVIDER_KEY} in its output`);
  if (cred.status === 1 && /VIOLATION/.test(cred.stdout) && /CREDENTIAL/.test(cred.stdout)) {
    pass('bare provider key (sk-ant) -> exit 1, VIOLATION, CREDENTIAL');
  } else {
    fail(`provider key expected exit 1 + VIOLATION + CREDENTIAL, got exit ${cred.status}`);
  }
  if (!cred.stdout.includes(PROVIDER_KEY)) pass('mask integrity: raw provider key not in text output');
  else fail('mask integrity BREACH: raw provider key leaked to stdout');

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
  if (maskIntegrityHolds(json.stdout)) pass('mask integrity: no 4-digit SSN window in JSON output');
  else fail('mask integrity BREACH: too much of the SSN leaked to JSON');

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

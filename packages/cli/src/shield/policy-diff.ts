/**
 * Shield: how the policy differs from the policy as last recorded, and
 * recording it as it is now.
 *
 * `shield policy diff` compares ~/.opena2a/shield/policy.yaml, the file
 * selfcheck verifies, with the policy as last recorded, and changes no file.
 * `shield policy accept <hash>` prints the same comparison and then records
 * the policy from the one read it compared: the hash selfcheck checks, a copy
 * of the bytes (so the next comparison is line by line), the policy.yaml entry
 * of signatures.json, and a policy.accepted event. The hash named must be the
 * policy's own, so what is recorded is what was shown. There is no prompt and
 * no flag in place of the hash.
 */

import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import type { EnvironmentScan } from './types.js';
import { SHIELD_POLICY_FILE, SHIELD_SCAN_FILE } from './types.js';
import { getShieldDir, writeEvent } from './events.js';
import { generatePolicyFromScan } from './policy.js';
import {
  POLICY_RECORDED_FILE,
  isLockdown,
  readPolicyRecord,
  recordPolicyContent,
  shellQuote,
  type PolicyRecord,
} from './integrity.js';
import { resignArtifact } from './signing.js';
import { bold, gray, green, red, yellow } from '../util/colors.js';

/** The file both commands act on, as their messages name it. */
const POLICY_DISPLAY_PATH = '~/.opena2a/shield/policy.yaml';
/** The hex characters of a hash that diff prints, and the fewest accept takes. */
const HASH_PREFIX_LENGTH = 12;
const DIVIDER = '-'.repeat(40);
const POLICY_MODES = ['adaptive', 'monitor', 'enforce'];
const RULE_CATEGORIES = ['credentials', 'processes', 'network', 'filesystem', 'mcpServers'];
const RULE_LISTS = ['allow', 'deny'];

/** Why both commands refuse --dir. */
export const POLICY_DIR_REFUSAL =
  'shield policy diff and accept act on ~/.opena2a/shield/policy.yaml, the policy shield selfcheck verifies; --dir is not used here.';

// ---------------------------------------------------------------------------
// The comparison
// ---------------------------------------------------------------------------

export type PolicyBaseline = 'recordedCopy' | 'generatedFromScan' | 'none';

/**
 * One path whose value differs: entries added to and removed from a list, or
 * a value replaced (`from` is absent for a value added, `to` for one removed).
 */
export interface PolicyChange {
  path: string;
  added?: unknown[];
  removed?: unknown[];
  from?: unknown;
  to?: unknown;
}

/** The comparison, as `--format json` prints it. */
export interface PolicyDiffResult {
  status: 'changed' | 'unchanged' | 'unrecorded';
  recordedAt: string | null;
  recordedHash: string | null;
  currentHash: string;
  baseline: PolicyBaseline;
  /** null when there is nothing to compare with (baseline `none`). */
  changes: PolicyChange[] | null;
  acceptCommand: string | null;
}

type RecordedCopy =
  | { state: 'usable'; policy: unknown }
  | { state: 'missing' }
  | { state: 'unusable'; reason: string };

interface Comparison {
  result: PolicyDiffResult;
  record: PolicyRecord | 'unreadable' | null;
  copy: RecordedCopy | null;
  scanTime: string | null;
  current: Record<string, unknown>;
}

type PolicyRead =
  | { ok: true; buffer: Buffer; hash: string; policy: Record<string, unknown> }
  | { ok: false; missing: boolean; problem: string };

function sha256(content: Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isStringList(value: unknown): boolean {
  return Array.isArray(value) && value.every((entry) => typeof entry === 'string');
}

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/** Why `value` is not a Shield policy, or null when it is one. */
function shapeProblem(value: unknown): string | null {
  if (!isObject(value)) return 'it is not a JSON object';
  if (typeof value.mode !== 'string' || !POLICY_MODES.includes(value.mode)) {
    return `mode is ${JSON.stringify(value.mode) ?? 'missing'}, not adaptive, monitor or enforce`;
  }
  const rules = value.default;
  if (!isObject(rules)) return 'it has no default rules';
  for (const category of RULE_CATEGORIES) {
    for (const list of RULE_LISTS) {
      const entries = isObject(rules[category]) ? (rules[category] as Record<string, unknown>)[list] : undefined;
      if (!isStringList(entries)) return `default.${category}.${list} is not a list of strings`;
    }
  }
  if (!isObject(value.agents)) return 'agents is not an object';
  for (const [name, overrides] of Object.entries(value.agents)) {
    if (!isObject(overrides)) return `agents.${name} is not an object`;
    for (const category of RULE_CATEGORIES) {
      const override = overrides[category];
      if (override === undefined) continue;
      if (!isObject(override)) return `agents.${name}.${category} is not an object`;
      for (const list of RULE_LISTS) {
        if (override[list] !== undefined && !isStringList(override[list])) {
          return `agents.${name}.${category}.${list} is not a list of strings`;
        }
      }
    }
  }
  return null;
}

/** One read of the policy, parsed as loadPolicy parses it and checked for shape. */
function readPolicy(policyPath: string): PolicyRead {
  if (!existsSync(policyPath)) {
    return { ok: false, missing: true, problem: 'no policy is loaded. Run: opena2a shield init' };
  }
  let buffer: Buffer;
  try {
    buffer = readFileSync(policyPath);
  } catch (err) {
    return {
      ok: false,
      missing: false,
      problem: `${POLICY_DISPLAY_PATH} cannot be read (${escapeInvisible(errorMessage(err))}). ` +
        `Check it: ls -l ${shellQuote(policyPath)}`,
    };
  }
  let parsed: unknown;
  let problem: string | null;
  try {
    parsed = JSON.parse(buffer.toString('utf-8'));
    problem = shapeProblem(parsed);
  } catch (err) {
    problem = errorMessage(err);
  }
  if (problem !== null) {
    return {
      ok: false,
      missing: false,
      problem: `${POLICY_DISPLAY_PATH} does not parse as a Shield policy (${escapeInvisible(problem)}). ` +
        `Review it: cat ${shellQuote(policyPath)}`,
    };
  }
  return { ok: true, buffer, hash: sha256(buffer), policy: parsed as Record<string, unknown> };
}

/** The copy of the recorded policy, usable only while its sha256 is the recorded hash. */
function readRecordedCopy(record: PolicyRecord): RecordedCopy {
  const copyPath = join(getShieldDir(), POLICY_RECORDED_FILE);
  if (!existsSync(copyPath)) return { state: 'missing' };
  let bytes: Buffer;
  try {
    bytes = readFileSync(copyPath);
  } catch {
    return { state: 'unusable', reason: 'cannot be read' };
  }
  if (sha256(bytes) !== record.hash) return { state: 'unusable', reason: 'does not match the recorded hash' };
  try {
    return { state: 'usable', policy: JSON.parse(bytes.toString('utf-8')) };
  } catch {
    return { state: 'unusable', reason: 'does not parse' };
  }
}

/** The policy this version of shield init generates from the last scan, or null without a usable scan. */
function generatedFromLastScan(): { policy: unknown; scanTime: string } | null {
  const scanPath = join(getShieldDir(), SHIELD_SCAN_FILE);
  if (!existsSync(scanPath)) return null;
  try {
    const scan = JSON.parse(readFileSync(scanPath, 'utf-8')) as EnvironmentScan;
    return {
      policy: generatePolicyFromScan(scan),
      scanTime: typeof scan.timestamp === 'string' ? scan.timestamp : 'time not recorded',
    };
  } catch {
    return null;
  }
}

function compare(read: Extract<PolicyRead, { ok: true }>): Comparison {
  const record = readPolicyRecord();
  const recorded = record !== null && record !== 'unreadable' ? record : null;
  const base = {
    recordedAt: recorded?.recordedAt ?? null,
    recordedHash: recorded?.hash ?? null,
    currentHash: read.hash,
  };

  if (recorded !== null && recorded.hash === read.hash) {
    const copy = readRecordedCopy(recorded);
    return {
      result: {
        status: 'unchanged',
        ...base,
        baseline: copy.state === 'usable' ? 'recordedCopy' : 'none',
        changes: [],
        acceptCommand: null,
      },
      record,
      copy,
      scanTime: null,
      current: read.policy,
    };
  }

  const copy = recorded !== null ? readRecordedCopy(recorded) : null;
  let baseline: PolicyBaseline = 'none';
  let changes: PolicyChange[] | null = null;
  let scanTime: string | null = null;
  if (copy?.state === 'usable') {
    baseline = 'recordedCopy';
    changes = diffPolicies(copy.policy, read.policy);
  } else {
    const generated = generatedFromLastScan();
    if (generated !== null) {
      baseline = 'generatedFromScan';
      changes = diffPolicies(generated.policy, read.policy);
      scanTime = generated.scanTime;
    }
  }

  return {
    result: {
      status: recorded !== null ? 'changed' : 'unrecorded',
      ...base,
      baseline,
      changes,
      acceptCommand: `opena2a shield policy accept ${read.hash.slice(0, HASH_PREFIX_LENGTH)}`,
    },
    record,
    copy,
    scanTime,
    current: read.policy,
  };
}

// ---------------------------------------------------------------------------
// The difference between two parsed policies
// ---------------------------------------------------------------------------

/** A value as text with object keys sorted, so equal values compare equal. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    isObject(v) ? Object.fromEntries(Object.keys(v).sort().map((k) => [k, v[k]])) : v,
  ) ?? 'undefined';
}

function same(a: unknown, b: unknown): boolean {
  return a === b || canonical(a) === canonical(b);
}

function distinct(values: unknown[]): unknown[] {
  const seen = new Set<string>();
  return values.filter((value) => {
    const key = canonical(value);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function own(object: Record<string, unknown>, key: string): unknown {
  return Object.hasOwn(object, key) ? object[key] : undefined;
}

/**
 * The paths at which two parsed policies differ. Objects are compared key by
 * key; a list is compared as a set of entries, so its order and repeats are
 * not a change; any other value is compared whole.
 */
export function diffPolicies(before: unknown, after: unknown): PolicyChange[] {
  const changes: PolicyChange[] = [];
  walk('', before, after, changes);
  return changes;
}

function walk(path: string, before: unknown, after: unknown, out: PolicyChange[]): void {
  if ((before === undefined || isObject(before)) && (after === undefined || isObject(after))) {
    const b = (before ?? {}) as Record<string, unknown>;
    const a = (after ?? {}) as Record<string, unknown>;
    const keys = [...Object.keys(b), ...Object.keys(a).filter((key) => !Object.hasOwn(b, key))];
    for (const key of keys) walk(path ? `${path}.${key}` : key, own(b, key), own(a, key), out);
    return;
  }
  if ((before === undefined || Array.isArray(before)) && (after === undefined || Array.isArray(after))) {
    const b = (before ?? []) as unknown[];
    const a = (after ?? []) as unknown[];
    const removed = distinct(b.filter((x) => !a.some((y) => same(x, y))));
    const added = distinct(a.filter((x) => !b.some((y) => same(x, y))));
    if (removed.length > 0 || added.length > 0) out.push({ path, added, removed });
    return;
  }
  if (same(before, after)) return;
  const change: PolicyChange = { path };
  if (before !== undefined) change.from = before;
  if (after !== undefined) change.to = after;
  out.push(change);
}

/** The entries a set of changes adds or removes, one per path and entry. */
function entriesOf(
  changes: PolicyChange[] | null,
  side: 'added' | 'removed',
): Array<{ path: string; entry: unknown }> | null {
  if (changes === null) return null;
  return changes.flatMap((change) => {
    const scalarKey = side === 'added' ? 'to' : 'from';
    const entries = change[side] ?? (scalarKey in change ? [change[scalarKey]] : []);
    return entries.map((entry) => ({ path: change.path, entry }));
  });
}

// ---------------------------------------------------------------------------
// Printing
// ---------------------------------------------------------------------------

const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|[^\S ]/u;
const INVISIBLE_ALL = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]|[^\S ]/gu;

/**
 * Text read from a file, made safe to print: every control, format or
 * whitespace character other than a space is written as an escape, so a
 * value can neither move the cursor or erase a line the diff printed, nor
 * look like another value.
 */
function escapeInvisible(text: string): string {
  return text.replace(INVISIBLE_ALL, (c) => `\\u{${c.codePointAt(0)!.toString(16)}}`);
}

/** An entry as printed: as it is when it is plain text, else its JSON text, escaped. */
function entryText(entry: unknown): string {
  if (typeof entry === 'string' && entry !== '' && entry.trim() === entry && !entry.startsWith('"') && !INVISIBLE.test(entry)) {
    return entry;
  }
  return escapeInvisible(JSON.stringify(entry) ?? String(entry));
}

/** A path as printed: the default rules are named by category alone. */
function pathText(path: string): string {
  return escapeInvisible(path.startsWith('default.') ? path.slice('default.'.length) : path);
}

function changeLines(change: PolicyChange): string[] {
  const removed = change.removed ?? ('from' in change ? [change.from] : []);
  const added = change.added ?? ('to' in change ? [change.to] : []);
  return [
    `  ${pathText(change.path)}`,
    ...removed.map((entry) => red(`    - ${entryText(entry)}`)),
    ...added.map((entry) => green(`    + ${entryText(entry)}`)),
  ];
}

/** Every value of the policy but its version, under its path. */
function policyLines(value: unknown, path = ''): string[] {
  if (isObject(value)) {
    return Object.keys(value)
      .filter((key) => path !== '' || key !== 'version')
      .flatMap((key) => policyLines(value[key], path ? `${path}.${key}` : key));
  }
  const entries = Array.isArray(value) ? value : [value];
  return [
    `  ${pathText(path)}`,
    ...(entries.length === 0 ? ['    (none)'] : entries.map((entry) => `    ${entryText(entry)}`)),
  ];
}

function header(c: Comparison): string {
  const recordedAt = escapeInvisible(c.result.recordedAt ?? '');
  const generated = 'Changes compared with the policy this version of shield init generates from the last scan ' +
    `(${escapeInvisible(c.scanTime ?? '')}):`;
  const asItIs = 'The policy as it is now:';
  const unusable = c.copy?.state === 'unusable' ? c.copy.reason : null;

  if (c.result.status === 'unrecorded') {
    const first = c.record === 'unreadable'
      ? 'Shield Policy: the hash recorded for this policy cannot be read from policy-hash.json.'
      : 'Shield Policy: no hash has been recorded for this policy.';
    return `${first}\n${c.result.baseline === 'generatedFromScan' ? generated : asItIs}`;
  }
  if (c.result.baseline === 'recordedCopy') {
    return `Shield Policy: changes since it was recorded (${recordedAt})`;
  }
  if (c.result.baseline === 'generatedFromScan') {
    return unusable !== null
      ? `Shield Policy: the copy kept of the policy as recorded ${unusable}, so it is not used. ${generated}`
      : `Shield Policy: no copy of the policy as recorded exists (it was recorded by an earlier version). ${generated}`;
  }
  return unusable !== null
    ? `Shield Policy: the policy has changed since it was recorded (${recordedAt}), and the copy kept of the ` +
      `recorded policy ${unusable}, so the change cannot be shown line by line. ${asItIs}`
    : `Shield Policy: the policy has changed since it was recorded (${recordedAt}), and no copy of the ` +
      `recorded policy exists, so the change cannot be shown line by line. ${asItIs}`;
}

function bodyLines(c: Comparison): string[] {
  const { changes, baseline } = c.result;
  if (changes === null) return policyLines(c.current);
  if (changes.length === 0) {
    return [baseline === 'recordedCopy'
      ? '  Only formatting differs; no rule, mode or agent changed.'
      : '  No rule, mode or agent differs from the generated policy.'];
  }
  return changes.flatMap(changeLines);
}

/** The comparison as `shield policy diff` prints it. */
function comparisonText(c: Comparison): string {
  const { result } = c;
  if (result.status === 'unchanged') {
    return bold(`Shield Policy: no changes since it was recorded (${escapeInvisible(result.recordedAt ?? '')}).`) + '\n';
  }
  const lines = [bold(header(c)), gray(DIVIDER), ...bodyLines(c), gray(DIVIDER)];
  if (result.recordedHash !== null) {
    const note = result.baseline === 'recordedCopy' ? ''
      : c.copy?.state === 'unusable' ? ' (kept copy not used)'
      : ' (content not kept)';
    lines.push(`  Recorded  ${escapeInvisible(result.recordedHash.slice(0, HASH_PREFIX_LENGTH))}${note}`);
  }
  lines.push(`  Now       ${result.currentHash.slice(0, HASH_PREFIX_LENGTH)}`);
  lines.push(`  To record the policy as it is now: ${result.acceptCommand}`);
  return lines.join('\n') + '\n';
}

function writeJson(value: unknown): void {
  process.stdout.write(JSON.stringify(value, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// The commands
// ---------------------------------------------------------------------------

function policyFilePath(): string {
  return join(getShieldDir(), SHIELD_POLICY_FILE);
}

/**
 * `opena2a shield policy diff`: print how the policy differs from the policy
 * as last recorded. Exits 0 when it printed, and 1 when policy.yaml is
 * missing or does not parse.
 */
export function policyDiff(options: { json: boolean }): number {
  const read = readPolicy(policyFilePath());
  if (!read.ok) {
    if (read.missing) {
      if (options.json) writeJson({ error: 'No policy loaded' });
      else process.stderr.write(yellow('No policy loaded. Run: opena2a shield init\n'));
    } else if (options.json) {
      writeJson({ error: read.problem });
    } else {
      process.stderr.write(red(read.problem) + '\n');
    }
    return 1;
  }

  const comparison = compare(read);
  if (options.json) writeJson(comparison.result);
  else process.stdout.write(comparisonText(comparison));
  return 0;
}

/**
 * `opena2a shield policy accept <hash>`: print the comparison, then record
 * the policy as it is now, when `hash` is at least 12 hex characters of the
 * sha256 of the bytes compared. Every refusal records nothing.
 */
export function policyAccept(hash: string | undefined, options: { json: boolean }): number {
  const refuse = (reason: string): number => {
    if (options.json) writeJson({ recorded: false, reason });
    else process.stderr.write(red(reason) + '\n');
    return 1;
  };

  // 1. Lockdown is lifted only by recover --verify.
  if (isLockdown()) {
    return refuse('Nothing recorded: Shield is in lockdown. Verify before unlocking: opena2a shield recover --verify');
  }

  // 2. One read of the file: everything after this uses these bytes.
  const policyPath = policyFilePath();
  const read = readPolicy(policyPath);
  if (!read.ok) return refuse(`Nothing recorded: ${read.problem}`);

  // 3. The comparison, exactly as diff prints it.
  const comparison = compare(read);
  if (!options.json) process.stdout.write(comparisonText(comparison));

  const notRecorded = (reason: string, rc: number): number => {
    if (options.json) writeJson({ ...comparison.result, recorded: false, reason });
    else process.stdout.write((rc === 0 ? `  ${reason}` : yellow(`  ${reason}`)) + '\n');
    return rc;
  };
  const shown = read.hash.slice(0, HASH_PREFIX_LENGTH);
  const nameIt = `To record this exact policy, name its hash: opena2a shield policy accept ${shown}`;

  // 4. No hash named.
  if (hash === undefined || hash === '') return notRecorded(`Nothing recorded. ${nameIt}`, 1);

  // 5. A hash that is not the policy's.
  const given = hash.toLowerCase();
  if (!/^[0-9a-f]{12,64}$/.test(given)) {
    return notRecorded(
      `Nothing recorded: a policy hash is at least ${HASH_PREFIX_LENGTH} hex characters, as shield policy diff ` +
        `prints it, and ${escapeInvisible(hash)} is not one. ${nameIt}`,
      1,
    );
  }
  if (!read.hash.startsWith(given)) {
    return notRecorded(
      `Nothing recorded: the policy's hash is ${shown}, not ${escapeInvisible(hash)}. ` +
        'It has changed since it was shown; see what changed: opena2a shield policy diff',
      1,
    );
  }

  // 6. Already the record.
  if (comparison.result.status === 'unchanged') {
    return notRecorded('The policy matches the recorded policy; nothing to record.', 0);
  }

  // 7. Record the bytes compared: the hash and its copy, the policy.yaml
  // signature entry alone, then the event.
  recordPolicyContent(read.buffer);
  resignArtifact(SHIELD_POLICY_FILE, read.buffer);
  let eventError: string | null = null;
  try {
    writeEvent({
      source: 'shield',
      category: 'integrity',
      severity: 'medium',
      agent: null,
      sessionId: null,
      action: 'policy.accepted',
      target: policyPath,
      outcome: 'allowed',
      detail: {
        previousHash: comparison.result.recordedHash,
        hash: read.hash,
        baseline: comparison.result.baseline,
        added: entriesOf(comparison.result.changes, 'added'),
        removed: entriesOf(comparison.result.changes, 'removed'),
      },
      orgId: null,
      managed: false,
      agentId: null,
    });
  } catch (err) {
    eventError = errorMessage(err);
  }

  if (options.json) {
    writeJson({ ...comparison.result, recorded: true });
  } else {
    process.stdout.write(green(`  Recorded the policy as it is now (${shown}) and re-signed policy.yaml.`) + '\n');
    process.stdout.write('  Verify: opena2a shield selfcheck\n');
  }
  if (eventError !== null) {
    process.stderr.write(red(`  The policy.accepted event was not written to the event log: ${escapeInvisible(eventError)}`) + '\n');
    return 1;
  }
  return 0;
}

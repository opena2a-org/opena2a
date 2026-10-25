/**
 * An edited Shield policy is recorded only after the change is shown.
 *
 * `opena2a shield policy diff` shows how ~/.opena2a/shield/policy.yaml differs
 * from the policy as last recorded, and changes no file. `opena2a shield
 * policy accept <hash>` prints that difference and then records the policy as
 * it is now (the recorded hash, a copy of its bytes, the policy.yaml signature
 * entry and a policy.accepted event), and only when <hash> is the policy's
 * own. `opena2a shield init` keeps a policy that changed since it was recorded
 * and leaves its record and signature as they are, also under --ci.
 * `opena2a shield selfcheck` names `opena2a shield policy diff` as the next
 * step of its policy row, and of its artifact-signatures row when the policy
 * is a failing artifact.
 *
 * Every case runs in a scratch HOME whose policy, recorded hash and signatures
 * are written by the CLI's own functions (createDefaultPolicy, savePolicy,
 * recordPolicyHash, signAllArtifacts). shield init runs with its environment
 * scan and credential audit replaced, and with no credential store, identity
 * module, config signing or runtime setup reachable: only its policy and
 * signing steps are under test.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';

import type { ShieldSignature } from '../../src/shield/types.js';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

vi.mock('secretless-ai', () => {
  throw new Error('Cannot find module secretless-ai');
});

vi.mock('@opena2a/aim-core', () => {
  throw new Error('Cannot find module @opena2a/aim-core');
});

vi.mock('../../src/shield/detect.js', () => ({
  detectEnvironment: vi.fn(() => ({
    timestamp: '2026-10-24T12:00:00.000Z',
    hostname: 'test-host',
    platform: 'darwin',
    shell: '/bin/zsh',
    clis: [],
    knownClis: [],
    assistants: [],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'node',
    projectName: 'test-project',
  })),
}));

vi.mock('../../src/util/credential-patterns.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/credential-patterns.js')>();
  return { ...actual, scanCredentialsWithCoverage: vi.fn(async () => ({ matches: [], filesScanned: 1 })) };
});

vi.mock('../../src/commands/guard.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/commands/guard.js')>();
  return { ...actual, signConfigFilesSilent: vi.fn(async () => ({ signed: 0, files: [] })) };
});

vi.mock('../../src/commands/runtime.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/commands/runtime.js')>();
  return { ...actual, runtimeInitSilent: vi.fn(async () => ({ created: false, path: 'arp.yaml' })) };
});

vi.mock('../../src/util/spinner.js', () => ({
  Spinner: class {
    start(): void {}
    stop(): void {}
  },
}));

const shieldCommand = await import('../../src/commands/shield.js');
const { shield } = shieldCommand;
const { shieldInit } = await import('../../src/shield/init.js');
const { createDefaultPolicy, savePolicy } = await import('../../src/shield/policy.js');
const { recordPolicyHash, runIntegrityChecks, enterLockdown } = await import('../../src/shield/integrity.js');
const { signAllArtifacts, loadSignatures } = await import('../../src/shield/signing.js');

const SHIELD_CMD_SRC = path.resolve(__dirname, '../../src/commands/shield.ts');
const INDEX_SRC = path.resolve(__dirname, '../../src/index.ts');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const SCAN_TIME = '2026-10-20T09:30:00.000Z';

let home: string;
let project: string;
let shieldDir: string;
let policyPath: string;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(tmpdir(), 'shield-policy-accept-'));
  project = fs.mkdtempSync(path.join(tmpdir(), 'shield-policy-accept-project-'));
  _mockHomeDir = home;
  shieldDir = path.join(home, '.opena2a', 'shield');
  fs.mkdirSync(shieldDir, { recursive: true });
  policyPath = path.join(shieldDir, 'policy.yaml');
  // selfcheck reads the rc file of $SHELL; none exists, so its row is a WARN.
  vi.stubEnv('SHELL', '/bin/zsh');
  vi.stubEnv('OPENA2A_TELEMETRY', 'off');
  vi.stubEnv('DO_NOT_TRACK', '1');
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(project, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// Fixtures, written by the CLI's own functions
// ---------------------------------------------------------------------------

function sha256(content: string | Buffer): string {
  return createHash('sha256').update(content).digest('hex');
}

function shieldFile(name: string): string {
  return path.join(shieldDir, name);
}

/** The policy's sha256, cut to the 12 hex characters diff prints. */
function policyHash12(): string {
  return sha256(fs.readFileSync(policyPath)).slice(0, 12);
}

/** A policy written, recorded and signed as init leaves it: deny holds aws, gcloud, az, ... */
function recordPolicy(): void {
  savePolicy(createDefaultPolicy('enforce'), policyPath);
  recordPolicyHash(policyPath);
  signAllArtifacts();
}

/** The scan init saved last: the generated-policy baseline is built from it. */
function writeScan(): void {
  const scan = {
    timestamp: SCAN_TIME,
    hostname: 'test-host',
    platform: 'darwin',
    shell: '/bin/zsh',
    clis: [],
    knownClis: [],
    assistants: [],
    mcpServers: [],
    oauthSessions: [],
    projectType: 'node',
    projectName: 'test-project',
  };
  fs.writeFileSync(shieldFile('scan.json'), JSON.stringify(scan, null, 2) + '\n', { mode: 0o600 });
}

/** Delete one entry's line from processes.deny, as an editor deleting `"aws",` does. */
function deleteDenyEntry(entry: string): void {
  const text = fs.readFileSync(policyPath, 'utf-8');
  const edited = text.replace(new RegExp(`^ *"${entry}",\\n`, 'm'), '');
  expect(edited).not.toBe(text);
  fs.writeFileSync(policyPath, edited);
}

/** Every file under `dir`, by content. */
function snapshot(dir: string, out: Record<string, string> = {}): Record<string, string> {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out[`${full}/`] = 'dir';
      snapshot(full, out);
    } else {
      out[full] = sha256(fs.readFileSync(full));
    }
  }
  return out;
}

function signatureOf(file: string): ShieldSignature | undefined {
  return loadSignatures()?.signatures.find((s) => s.filePath === file);
}

function lastEvent(): Record<string, unknown> {
  const lines = fs.readFileSync(shieldFile('events.jsonl'), 'utf-8').trim().split('\n');
  return JSON.parse(lines[lines.length - 1]) as Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Running the commands
// ---------------------------------------------------------------------------

interface Run {
  rc: number;
  out: string;
  err: string;
}

async function capture(fn: () => Promise<number>): Promise<Run> {
  let out = '';
  let err = '';
  const stdout = vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
    out += String(chunk);
    return true;
  }) as never);
  const stderr = vi.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown) => {
    err += String(chunk);
    return true;
  }) as never);
  try {
    const rc = await fn();
    return { rc, out: out.replace(STRIP_ANSI, ''), err: err.replace(STRIP_ANSI, '') };
  } finally {
    stdout.mockRestore();
    stderr.mockRestore();
  }
}

/** `opena2a shield <subcommand> [args...]`, routed as Commander routes it. */
function run(args: string[], options: { format?: string; dir?: string } = {}): Promise<Run> {
  const [subcommand, ...rest] = args;
  return capture(() => shield({ subcommand, args: rest, ...options }));
}

function runInit(options: { ci?: boolean; format?: string }): Promise<Run> {
  return capture(async () => (await shieldInit({ targetDir: project, ...options })).exitCode);
}

/** The printed selfcheck line of one check. */
function rowLine(out: string, name: string): string {
  const line = out.split('\n').find((l) => l.trim().split(/\s+/)[1] === name);
  expect(line, `no ${name} row in:\n${out}`).toBeDefined();
  return line!;
}

function check(name: string) {
  return runIntegrityChecks({ shell: 'zsh' }).checks.find((c) => c.name === name)!;
}

// ---------------------------------------------------------------------------
// (g) The edit that deletes an entry from deny, end to end
// ---------------------------------------------------------------------------

describe('(g) a deny entry deleted from a recorded policy', () => {
  it('fails both selfcheck rows until accept <hash> records the policy as shown, then both pass', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const hash = policyHash12();

    const failing = await run(['selfcheck']);
    expect(failing.rc).toBe(1);
    expect(failing.out).toContain('Overall: COMPROMISED');
    for (const name of ['policy', 'artifact-signatures']) {
      const line = rowLine(failing.out, name);
      expect(line).toMatch(/^\s*FAIL\s/);
      expect(line.trimEnd().endsWith('See what changed: opena2a shield policy diff')).toBe(true);
    }
    expect(rowLine(failing.out, 'policy')).toContain('Policy file has changed since it was recorded at ');

    const record = JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8'));
    const diff = await run(['policy', 'diff']);
    expect(diff.rc).toBe(0);
    expect(diff.out).toBe([
      `Shield Policy: changes since it was recorded (${record.recordedAt})`,
      '----------------------------------------',
      '  processes.deny',
      '    - aws',
      '----------------------------------------',
      `  Recorded  ${record.hash.slice(0, 12)}`,
      `  Now       ${hash}`,
      `  To record the policy as it is now: opena2a shield policy accept ${hash}`,
      '',
    ].join('\n'));

    const accept = await run(['policy', 'accept', hash]);
    expect(accept.rc).toBe(0);
    expect(accept.out).toContain('  processes.deny\n    - aws\n');
    expect(accept.out).toContain(`  Recorded the policy as it is now (${hash}) and re-signed policy.yaml.\n`);
    expect(accept.out).toContain('  Verify: opena2a shield selfcheck\n');

    const passing = await run(['selfcheck']);
    expect(rowLine(passing.out, 'policy')).toMatch(/^\s*PASS\s/);
    expect(rowLine(passing.out, 'artifact-signatures')).toMatch(/^\s*PASS\s/);
    // The only remaining WARN is the missing rc file.
    expect(passing.out).toContain('Overall: DEGRADED');
    expect(passing.rc).toBe(0);

    const event = lastEvent();
    expect(event.action).toBe('policy.accepted');
    expect(event.source).toBe('shield');
    expect(event.category).toBe('integrity');
    expect(event.severity).toBe('medium');
    expect(event.outcome).toBe('allowed');
    const detail = event.detail as Record<string, unknown>;
    expect(detail.hash).toBe(sha256(fs.readFileSync(policyPath)));
    expect(detail.previousHash).toBe(sha256(JSON.stringify(createDefaultPolicy('enforce'), null, 2) + '\n'));
    expect(detail.baseline).toBe('recordedCopy');
    expect(detail.removed).toEqual([{ path: 'default.processes.deny', entry: 'aws' }]);
    expect(detail.added).toEqual([]);
  });

  it('records the bytes it compared: hash, recorded copy (mode 0600) and the policy.yaml signature agree', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const bytes = fs.readFileSync(policyPath);

    expect((await run(['policy', 'accept', policyHash12()])).rc).toBe(0);

    const record = JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8'));
    expect(record.hash).toBe(sha256(bytes));
    expect(typeof record.recordedAt).toBe('string');
    expect(fs.readFileSync(shieldFile('policy.recorded.yaml'))).toEqual(bytes);
    expect(fs.statSync(shieldFile('policy.recorded.yaml')).mode & 0o777).toBe(0o600);
    expect(signatureOf('policy.yaml')?.hash).toBe(`sha256:${sha256(bytes)}`);
    expect(signatureOf('policy.yaml')?.fileSize).toBe(bytes.length);
  });
});

// ---------------------------------------------------------------------------
// (h) to (k): accept records nothing unless the hash named is the policy's
// ---------------------------------------------------------------------------

describe('(h) accept with no hash', () => {
  it('prints the change, records nothing and exits 1', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const hash = policyHash12();
    const before = snapshot(home);

    const result = await run(['policy', 'accept']);

    expect(result.rc).toBe(1);
    expect(result.out).toContain('  processes.deny\n    - aws\n');
    expect(result.out).toContain(
      `  Nothing recorded. To record this exact policy, name its hash: opena2a shield policy accept ${hash}\n`,
    );
    expect(snapshot(home)).toEqual(before);
  });
});

describe('(i) accept with a hash the policy no longer has', () => {
  it('records nothing, exits 1 and names policy diff when the policy was edited again after diff', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const shown = (await run(['policy', 'diff'])).out.match(/opena2a shield policy accept ([0-9a-f]{12})/)?.[1];
    expect(shown).toBe(policyHash12());

    deleteDenyEntry('gcloud');
    const now = policyHash12();
    const before = snapshot(home);

    const result = await run(['policy', 'accept', shown!]);

    expect(result.rc).toBe(1);
    expect(result.out).toContain(
      `  Nothing recorded: the policy's hash is ${now}, not ${shown}. ` +
        'It has changed since it was shown; see what changed: opena2a shield policy diff\n',
    );
    expect(snapshot(home)).toEqual(before);
  });

  it('records nothing for a hash shorter than 12 hex characters, even one the policy starts with', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const before = snapshot(home);

    const result = await run(['policy', 'accept', policyHash12().slice(0, 6)]);

    expect(result.rc).toBe(1);
    expect(result.out).toContain('  Nothing recorded: ');
    expect(result.out).toContain(`opena2a shield policy accept ${policyHash12()}`);
    expect(snapshot(home)).toEqual(before);
  });
});

describe('(j) accept with a policy.yaml that does not parse as a Shield policy', () => {
  const unparseable: Array<[string, (valid: Record<string, unknown>) => string]> = [
    ['text that is not JSON', () => '{"version": 1, "mode": '],
    ['an unknown mode', (valid) => JSON.stringify({ ...valid, mode: 'lenient' }, null, 2) + '\n'],
    [
      'a missing rule list',
      (valid) => {
        const rules = JSON.parse(JSON.stringify(valid.default)) as Record<string, Record<string, unknown>>;
        delete rules.processes.deny;
        return JSON.stringify({ ...valid, default: rules }, null, 2) + '\n';
      },
    ],
    ['a rule list holding a number', (valid) => {
      const rules = JSON.parse(JSON.stringify(valid.default)) as Record<string, Record<string, unknown>>;
      rules.network.allow = [443];
      return JSON.stringify({ ...valid, default: rules }, null, 2) + '\n';
    }],
  ];

  for (const [label, write] of unparseable) {
    it(`records nothing and exits 1 for ${label}`, async () => {
      recordPolicy();
      const valid = JSON.parse(fs.readFileSync(policyPath, 'utf-8')) as Record<string, unknown>;
      fs.writeFileSync(policyPath, write(valid));
      const before = snapshot(home);

      const result = await run(['policy', 'accept', policyHash12()]);

      expect(result.rc).toBe(1);
      expect(result.err).toContain(
        'Nothing recorded: ~/.opena2a/shield/policy.yaml does not parse as a Shield policy (',
      );
      expect(result.err).toContain(`). Review it: cat '${policyPath}'`);
      expect(snapshot(home)).toEqual(before);
    });
  }

  it('control: a valid edited policy records', async () => {
    recordPolicy();
    deleteDenyEntry('aws');

    const result = await run(['policy', 'accept', policyHash12()]);

    expect(result.rc).toBe(0);
    expect(JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8')).hash)
      .toBe(sha256(fs.readFileSync(policyPath)));
  });
});

describe('(k) accept re-signs the policy.yaml entry only', () => {
  it('leaves the scan.json and llm-cache.json entries as they are, so an edited scan.json still fails', async () => {
    writeScan();
    fs.writeFileSync(shieldFile('llm-cache.json'), '{}\n', { mode: 0o600 });
    recordPolicy();
    expect(loadSignatures()?.signatures.map((s) => s.filePath).sort())
      .toEqual(['llm-cache.json', 'policy.yaml', 'scan.json']);
    const scanEntry = signatureOf('scan.json');
    const cacheEntry = signatureOf('llm-cache.json');
    const policyEntry = signatureOf('policy.yaml');

    deleteDenyEntry('aws');
    fs.appendFileSync(shieldFile('scan.json'), '\n');

    const result = await run(['policy', 'accept', policyHash12()]);

    expect(result.rc).toBe(0);
    expect(signatureOf('scan.json')).toEqual(scanEntry);
    expect(signatureOf('llm-cache.json')).toEqual(cacheEntry);
    expect(signatureOf('policy.yaml')).not.toEqual(policyEntry);
    expect(signatureOf('policy.yaml')?.hash).toBe(`sha256:${sha256(fs.readFileSync(policyPath))}`);

    expect(check('policy').status).toBe('pass');
    const artifacts = check('artifact-signatures');
    expect(artifacts.status).toBe('fail');
    expect(artifacts.detail).toContain('scan.json has been modified');
    expect(artifacts.detail).not.toContain('policy.yaml');
    expect(artifacts.nextStep).toBe(`ls -l '${shieldDir}'`);
  });
});

// ---------------------------------------------------------------------------
// (l), (m): shield init keeps a changed policy and does not sign it
// ---------------------------------------------------------------------------

const KEPT_LINES =
  '  Existing policy kept. It has changed since it was recorded.\n' +
  '  See what changed: opena2a shield policy diff\n';

describe('(l) shield init with a policy edited since it was recorded', () => {
  it('keeps policy.yaml, its signature entry and policy-hash.json byte for byte, and says so', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const policyBytes = fs.readFileSync(policyPath);
    const recordBytes = fs.readFileSync(shieldFile('policy-hash.json'));
    const policyEntry = signatureOf('policy.yaml');

    const result = await runInit({ format: 'text' });

    expect(fs.readFileSync(policyPath)).toEqual(policyBytes);
    expect(fs.readFileSync(shieldFile('policy-hash.json'))).toEqual(recordBytes);
    expect(signatureOf('policy.yaml')).toEqual(policyEntry);
    expect(result.out).toContain(KEPT_LINES);
    expect(result.out).toContain('  To regenerate: delete ~/.opena2a/shield/policy.yaml and re-run init\n');
    expect(result.out).not.toContain('Existing policy found. Preserving current policy.');
    // The other artifacts are signed as before: the scan init just wrote.
    expect(signatureOf('scan.json')?.hash).toBe(`sha256:${sha256(fs.readFileSync(shieldFile('scan.json')))}`);
    // Both rows still fail: init showed nobody the change, so it recorded none.
    expect(check('policy').status).toBe('fail');
    expect(check('artifact-signatures').status).toBe('fail');
  });

  it('control: an unedited recorded policy is kept with the lines init printed before', async () => {
    recordPolicy();
    const policyBytes = fs.readFileSync(policyPath);

    const result = await runInit({ format: 'text' });

    expect(fs.readFileSync(policyPath)).toEqual(policyBytes);
    expect(result.out).toContain('  Existing policy found. Preserving current policy.\n');
    expect(result.out).not.toContain('Existing policy kept.');
    expect(check('policy').status).toBe('pass');
    expect(check('artifact-signatures').status).toBe('pass');
  });
});

describe('(m) shield init --ci with a policy edited since it was recorded', () => {
  it('keeps the policy instead of replacing it, and prints the two lines without breaking the JSON', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const policyBytes = fs.readFileSync(policyPath);
    const recordBytes = fs.readFileSync(shieldFile('policy-hash.json'));
    const policyEntry = signatureOf('policy.yaml');

    const result = await runInit({ ci: true });

    expect(fs.readFileSync(policyPath)).toEqual(policyBytes);
    expect(fs.readFileSync(shieldFile('policy-hash.json'))).toEqual(recordBytes);
    expect(signatureOf('policy.yaml')).toEqual(policyEntry);
    expect(result.err).toContain(KEPT_LINES);
    expect(() => JSON.parse(result.out)).not.toThrow();
  });

  it('control: an unedited recorded policy is regenerated, recorded and copied, as before', async () => {
    recordPolicy();
    expect(JSON.parse(fs.readFileSync(policyPath, 'utf-8')).mode).toBe('enforce');

    await runInit({ ci: true });

    const bytes = fs.readFileSync(policyPath);
    expect(JSON.parse(bytes.toString('utf-8')).mode).toBe('adaptive');
    expect(JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8')).hash).toBe(sha256(bytes));
    expect(fs.readFileSync(shieldFile('policy.recorded.yaml'))).toEqual(bytes);
    expect(check('policy').status).toBe('pass');
    expect(check('artifact-signatures').status).toBe('pass');
  });
});

// ---------------------------------------------------------------------------
// (n) The recorded copy is the baseline only while it matches the record
// ---------------------------------------------------------------------------

describe('(n) the recorded-copy baseline', () => {
  it('after an accept, a second edit is shown line by line against the copy', async () => {
    writeScan();
    recordPolicy();
    deleteDenyEntry('aws');
    expect((await run(['policy', 'accept', policyHash12()])).rc).toBe(0);
    deleteDenyEntry('gcloud');

    const text = await run(['policy', 'diff']);
    expect(text.rc).toBe(0);
    expect(text.out).toContain('Shield Policy: changes since it was recorded (');
    expect(text.out).toContain('  processes.deny\n    - gcloud\n');
    expect(text.out).not.toContain('- aws');

    const json = await run(['policy', 'diff'], { format: 'json' });
    const parsed = JSON.parse(json.out);
    expect(parsed.baseline).toBe('recordedCopy');
    expect(parsed.changes).toEqual([{ path: 'default.processes.deny', added: [], removed: ['gcloud'] }]);
  });

  it('with one byte of the copy changed, diff falls back to the generated policy and labels it', async () => {
    writeScan();
    recordPolicy();
    deleteDenyEntry('aws');
    const copyPath = shieldFile('policy.recorded.yaml');
    const copy = fs.readFileSync(copyPath, 'utf-8');
    expect(copy).toContain('"gcloud"');
    fs.writeFileSync(copyPath, copy.replace('"gcloud"', '"gclouD"'));

    const text = await run(['policy', 'diff']);
    expect(text.rc).toBe(0);
    expect(text.out).toContain(
      `Changes compared with the policy this version of shield init generates from the last scan (${SCAN_TIME}):`,
    );
    expect(text.out).not.toContain('Shield Policy: changes since it was recorded');
    // The generated policy is adaptive; the recorded one was enforce.
    expect(text.out).toContain('  mode\n    - adaptive\n    + enforce\n');
    expect(JSON.parse((await run(['policy', 'diff'], { format: 'json' })).out).baseline).toBe('generatedFromScan');

    fs.rmSync(shieldFile('scan.json'));
    const none = await run(['policy', 'diff']);
    expect(none.rc).toBe(0);
    expect(none.out).toContain('so the change cannot be shown line by line. The policy as it is now:');
    expect(none.out).toContain('  processes.deny\n    gcloud\n');
    expect(JSON.parse((await run(['policy', 'diff'], { format: 'json' })).out).baseline).toBe('none');
  });

  it('a record written without a copy compares with the generated policy, labelled as such', async () => {
    writeScan();
    recordPolicy();
    fs.rmSync(shieldFile('policy.recorded.yaml'), { force: true });
    deleteDenyEntry('aws');
    const recorded = JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8')).hash as string;

    const text = await run(['policy', 'diff']);

    expect(text.out).toContain(
      'Shield Policy: no copy of the policy as recorded exists (it was recorded by an earlier version). ' +
        `Changes compared with the policy this version of shield init generates from the last scan (${SCAN_TIME}):`,
    );
    expect(text.out).toContain(`  Recorded  ${recorded.slice(0, 12)} (content not kept)\n`);
  });
});

// ---------------------------------------------------------------------------
// diff: the other states it reports
// ---------------------------------------------------------------------------

describe('policy diff', () => {
  it('says so when the policy matches its record, and changes no file', async () => {
    recordPolicy();
    const recordedAt = JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8')).recordedAt;
    const before = snapshot(home);

    const result = await run(['policy', 'diff']);

    expect(result.rc).toBe(0);
    expect(result.out).toBe(`Shield Policy: no changes since it was recorded (${recordedAt}).\n`);
    expect(snapshot(home)).toEqual(before);
  });

  it('names a change in formatting only as that', async () => {
    recordPolicy();
    const policy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    fs.writeFileSync(policyPath, JSON.stringify(policy, null, 4) + '\n');

    const result = await run(['policy', 'diff']);

    expect(result.rc).toBe(0);
    expect(result.out).toContain('  Only formatting differs; no rule, mode or agent changed.\n');
  });

  it('with no hash recorded, says so and compares with the generated policy', async () => {
    writeScan();
    savePolicy(createDefaultPolicy('adaptive'), policyPath);
    const policy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    policy.default.network.allow.push('api.example.test');
    fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');

    const result = await run(['policy', 'diff']);

    expect(result.rc).toBe(0);
    expect(result.out).toContain('Shield Policy: no hash has been recorded for this policy.\n');
    expect(result.out).toContain('  network.allow\n    + api.example.test\n');
    expect(result.out).toContain(`  To record the policy as it is now: opena2a shield policy accept ${policyHash12()}\n`);
    expect(JSON.parse((await run(['policy', 'diff'], { format: 'json' })).out).status).toBe('unrecorded');
  });

  it('prints its JSON with camelCase keys, the change per path and the accept command', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const policy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    policy.mode = 'monitor';
    fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');
    const record = JSON.parse(fs.readFileSync(shieldFile('policy-hash.json'), 'utf-8'));

    const result = await run(['policy', 'diff'], { format: 'json' });

    expect(result.rc).toBe(0);
    expect(JSON.parse(result.out)).toEqual({
      status: 'changed',
      recordedAt: record.recordedAt,
      recordedHash: record.hash,
      currentHash: sha256(fs.readFileSync(policyPath)),
      baseline: 'recordedCopy',
      changes: [
        { path: 'mode', from: 'enforce', to: 'monitor' },
        { path: 'default.processes.deny', added: [], removed: ['aws'] },
      ],
      acceptCommand: `opena2a shield policy accept ${policyHash12()}`,
    });
  });

  it('exits 1 when there is no policy, or when it does not parse', async () => {
    expect((await run(['policy', 'diff'])).rc).toBe(1);

    fs.writeFileSync(policyPath, '{not json');
    const broken = await run(['policy', 'diff']);
    expect(broken.rc).toBe(1);
    expect(broken.err).toContain('~/.opena2a/shield/policy.yaml does not parse as a Shield policy (');
  });

  it('prints control characters in a policy entry as escapes, never to the terminal', async () => {
    recordPolicy();
    const policy = JSON.parse(fs.readFileSync(policyPath, 'utf-8'));
    // An entry that would erase the line above it, and one with a zero-width space.
    policy.default.processes.allow.push('ok\x1b[1A\x1b[2Kgit', 'aws\u200b');
    fs.writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');

    let raw = '';
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      raw += String(chunk);
      return true;
    }) as never);
    vi.spyOn(process.stderr, 'write').mockReturnValue(true);
    const rc = await shield({ subcommand: 'policy', args: ['diff'] });
    vi.restoreAllMocks();

    expect(rc).toBe(0);
    expect(raw.replace(STRIP_ANSI, '')).not.toMatch(/[\x00-\x09\x0b-\x1f\x7f-\x9f\u200b]/);
    expect(raw).toContain('+ "ok\\u001b[1A\\u001b[2Kgit"');
    expect(raw).toContain('+ "aws\\u{200b}"');
  });
});

// ---------------------------------------------------------------------------
// Refusals that come before anything is compared
// ---------------------------------------------------------------------------

describe('policy diff and accept refusals', () => {
  it('both refuse --dir: they act on the policy selfcheck verifies', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const before = snapshot(home);
    for (const verb of [['diff'], ['accept', policyHash12()]]) {
      const result = await run(['policy', ...verb], { dir: project });
      expect(result.rc).toBe(1);
      expect(result.err).toContain(
        'shield policy diff and accept act on ~/.opena2a/shield/policy.yaml, the policy shield selfcheck verifies; --dir is not used here.',
      );
    }
    expect(snapshot(home)).toEqual(before);
  });

  it('accept records nothing in lockdown and names recover --verify', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    enterLockdown('policy tampered');
    const before = snapshot(home);

    const result = await run(['policy', 'accept', policyHash12()]);

    expect(result.rc).toBe(1);
    expect(result.err).toContain(
      'Nothing recorded: Shield is in lockdown. Verify before unlocking: opena2a shield recover --verify',
    );
    expect(snapshot(home)).toEqual(before);
  });

  it('a policy action that does not exist is refused, not answered with the summary', async () => {
    recordPolicy();
    const result = await run(['policy', 'acept', policyHash12()]);
    expect(result.rc).toBe(1);
    expect(result.err).toContain('Unknown policy action: acept');
    expect(result.out).not.toContain('Shield Policy');
  });

  it('accept --format json reports recorded false with the reason, and true once recorded', async () => {
    recordPolicy();
    deleteDenyEntry('aws');

    const refused = JSON.parse((await run(['policy', 'accept'], { format: 'json' })).out);
    expect(refused.recorded).toBe(false);
    expect(refused.reason).toContain('Nothing recorded.');
    expect(refused.status).toBe('changed');

    const recorded = await run(['policy', 'accept', policyHash12()], { format: 'json' });
    expect(recorded.rc).toBe(0);
    const parsed = JSON.parse(recorded.out);
    expect(parsed.recorded).toBe(true);
    expect(parsed.reason).toBeUndefined();
    expect(parsed.changes).toEqual([{ path: 'default.processes.deny', added: [], removed: ['aws'] }]);
  });

  it('accept on a policy that matches its record records nothing and exits 0', async () => {
    recordPolicy();
    const before = snapshot(home);

    const result = await run(['policy', 'accept', policyHash12()]);

    expect(result.rc).toBe(0);
    expect(result.out).toContain('  The policy matches the recorded policy; nothing to record.\n');
    expect(snapshot(home)).toEqual(before);
  });
});

// ---------------------------------------------------------------------------
// (o) Every command these print parses as registered, and does what it says
// ---------------------------------------------------------------------------

/** `shield` subcommands the dispatcher routes, the `shield policy` verbs, and the flags `shield` registers. */
function shieldSurface(): { registered: boolean; subcommands: Set<string>; verbs: Set<string>; flags: Set<string> } {
  const dispatch = fs.readFileSync(SHIELD_CMD_SRC, 'utf-8');
  const start = dispatch.indexOf('export async function shield(');
  const body = dispatch.slice(start, dispatch.indexOf('default:', start));
  const subcommands = new Set([...body.matchAll(/case '([a-z-]+)':/g)].map((m) => m[1]));
  const verbs = new Set<string>((shieldCommand as { SHIELD_POLICY_VERBS?: readonly string[] }).SHIELD_POLICY_VERBS ?? []);
  const index = fs.readFileSync(INDEX_SRC, 'utf-8');
  const at = index.indexOf(".command('shield [subcommand] [args...]')");
  const block = index.slice(at, index.indexOf('.action(', at));
  const flags = new Set([...block.matchAll(/\.option\('(--[a-z-]+)/g)].map((m) => m[1]));
  return { registered: at >= 0, subcommands, verbs, flags };
}

/** Parse one printed `opena2a shield ...` command as Commander and the dispatchers route it. */
function parseRegistered(command: string): { subcommand: string; args: string[]; flags: Record<string, true> } {
  const surface = shieldSurface();
  const [bin, parent, subcommand, ...rest] = command.split(/\s+/);
  expect(bin, command).toBe('opena2a');
  expect(parent, command).toBe('shield');
  expect(surface.registered, 'shield is not registered in index.ts').toBe(true);
  expect(surface.subcommands.has(subcommand), `unrouted subcommand in "${command}"`).toBe(true);
  const args: string[] = [];
  const flags: Record<string, true> = {};
  for (const token of rest) {
    if (token.startsWith('--')) {
      expect(surface.flags.has(token), `unregistered flag in "${command}"`).toBe(true);
      flags[token.slice(2).replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase())] = true;
    } else {
      args.push(token);
    }
  }
  if (args.length > 0) {
    expect(subcommand, `"${command}" passes a positional to a subcommand that takes none`).toBe('policy');
    expect(surface.verbs.has(args[0]), `unrouted policy action in "${command}"`).toBe(true);
    if (args[0] === 'accept') {
      expect(args, command).toHaveLength(2);
      expect(args[1], command).toMatch(/^[0-9a-f]{12,64}$/);
    } else {
      expect(args, command).toHaveLength(1);
    }
  }
  return { subcommand, args, flags };
}

/** Every `opena2a ...` command an output names, to the end of its line. */
function commandsIn(output: string): string[] {
  return [...output.matchAll(/(?:^|\s)(opena2a\s[^\n]*?)\s*$/gm)].map((m) => m[1].trim());
}

describe('(o) the commands selfcheck, init and diff print', () => {
  it('parse as registered commands, and run in a fixture to the outcome their text states', async () => {
    writeScan();
    recordPolicy();
    deleteDenyEntry('aws');
    const hash = policyHash12();

    const printed = new Set<string>();
    for (const output of [
      (await run(['selfcheck'])).out,
      (await runInit({ format: 'text' })).out,
      (await run(['policy', 'diff'])).out,
    ]) {
      for (const command of commandsIn(output)) printed.add(command);
    }
    expect(printed).toContain('opena2a shield policy diff');
    expect(printed).toContain(`opena2a shield policy accept ${hash}`);
    for (const command of printed) {
      expect(command).not.toMatch(/\bshield\s+init\b/);
      parseRegistered(command);
    }

    // diff, run as printed, changes no file.
    const diff = parseRegistered('opena2a shield policy diff');
    const before = snapshot(home);
    const shown = await capture(() => shield({ subcommand: diff.subcommand, args: diff.args, ...diff.flags }));
    expect(shown.rc).toBe(0);
    expect(shown.out).toContain('    - aws\n');
    expect(snapshot(home)).toEqual(before);

    // accept <hash>, run as printed, turns both rows PASS.
    const accept = parseRegistered(`opena2a shield policy accept ${hash}`);
    const accepted = await capture(() => shield({ subcommand: accept.subcommand, args: accept.args, ...accept.flags }));
    expect(accepted.rc).toBe(0);
    expect(check('policy').status).toBe('pass');
    expect(check('artifact-signatures').status).toBe('pass');

    // What accept prints parses too.
    for (const command of commandsIn(accepted.out)) parseRegistered(command);
  });

  it('accept prints only commands that parse, when it refuses too', async () => {
    recordPolicy();
    deleteDenyEntry('aws');
    const shown = policyHash12();
    deleteDenyEntry('gcloud');
    const outputs = [
      await run(['policy', 'accept']),
      await run(['policy', 'accept', shown]),
      await run(['policy', 'accept', 'abc']),
    ];
    enterLockdown('policy tampered');
    outputs.push(await run(['policy', 'accept', policyHash12()]));
    for (const { rc, out, err } of outputs) {
      expect(rc).toBe(1);
      const commands = commandsIn(out + '\n' + err);
      // Each refusal names the command to run next.
      expect(commands.length, out + err).toBeGreaterThan(0);
      for (const command of commands) parseRegistered(command);
    }
  });
});

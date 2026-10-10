/**
 * Every Shield Fix line runs as printed and reaches the state its text states.
 *
 * The structural guard in findings.test.ts proves each remediation names
 * registered commands and flags. It cannot see a chain that dead-ends:
 * `opena2a guard diff && opena2a guard resign` was printed for SHIELD-INT-001,
 * but `guard diff` exits 1 whenever a signed file changed -- the exact state
 * the finding reports -- so the shell never reached `resign`.
 *
 * The walk below puts each chained remediation in a fixture where its own
 * finding fires and runs every segment before an `&&` in-process. A chain
 * whose earlier segment exits non-zero there fails. A chain added without a
 * fixture fails too, so a new `&&` cannot land unwalked.
 *
 * The credential findings are held to a second rule: an exposed key stays
 * live until the provider revokes it, so the Fix leads with revoking it in
 * words (no opena2a command does that), and never offers a history rewrite or
 * local cleanup as the fix.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { FINDING_CATALOG } = await import('../../src/shield/findings.js');
const { toSarif } = await import('../../src/shield/sarif.js');
const { writeEvent, getEventsPath } = await import('../../src/shield/events.js');
const { runShieldPhase, generateActionItems, scoreReview, CRITICAL_BAND } = await import('../../src/commands/review.js');
const { buildReviewFindings } = await import('../../src/commands/review-findings.js');
const { guard } = await import('../../src/commands/guard.js');
const { shield } = await import('../../src/commands/shield.js');

type GuardSub = Parameters<typeof guard>[0]['subcommand'];
type ShieldSub = Parameters<typeof shield>[0]['subcommand'];

let tempHome: string;
let targetDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'shield-walk-home-'));
  targetDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-walk-target-'));
  _mockHomeDir = tempHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(targetDir, { recursive: true, force: true });
});

async function quietly<T>(fn: () => Promise<T>): Promise<T> {
  const out = vi.spyOn(process.stdout, 'write').mockReturnValue(true);
  const err = vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    return await fn();
  } finally {
    out.mockRestore();
    err.mockRestore();
  }
}

/** Supply one typed line to the shared confirm prompt. */
function withStdinAnswer(answer: string): () => void {
  const fake = new PassThrough();
  // guard resign accepts a confirmation only at a terminal, which is where
  // the Fix's reader types it.
  Object.assign(fake, { isTTY: true });
  fake.end(answer + '\n');
  const original = Object.getOwnPropertyDescriptor(process, 'stdin')!;
  Object.defineProperty(process, 'stdin', { value: fake, configurable: true, enumerable: true, writable: true });
  return () => { Object.defineProperty(process, 'stdin', original); };
}

/** `--archive-log` -> `archiveLog`, the property Commander exposes it as. */
function optionProperty(flag: string): string {
  return flag.replace(/^--/, '').replace(/-([a-z])/g, (_m, c: string) => c.toUpperCase());
}

/**
 * Run one `opena2a <command> <subcommand> [--flag ...]` segment in-process,
 * the way Commander routes it. A segment this runner cannot execute throws,
 * so a chain is never passed by skipping a step.
 */
async function runSegment(segment: string, dir: string): Promise<number> {
  const [exe, command, sub, ...rest] = segment.split(/\s+/);
  if (exe !== 'opena2a') throw new Error(`no in-process runner for "${segment}"`);
  const flags: Record<string, boolean> = {};
  for (const token of rest) {
    if (!token.startsWith('--')) throw new Error(`no in-process runner for "${token}" in "${segment}"`);
    flags[optionProperty(token)] = true;
  }
  if (command === 'guard') {
    return quietly(() => guard({ subcommand: sub as GuardSub, targetDir: dir, ...flags }));
  }
  if (command === 'shield') {
    return quietly(() => shield({ subcommand: sub as ShieldSub, ...flags }));
  }
  throw new Error(`no in-process runner for "${segment}"`);
}

/**
 * Walk every segment that a later `&&` depends on. Returns the first segment
 * that exits non-zero (the chain stops there), or null when the shell would
 * reach the last segment.
 */
async function walkChain(remediation: string, dir: string): Promise<{ segment: string; code: number } | null> {
  const segments = remediation.split(/\s*&&\s*/).map(s => s.trim()).filter(Boolean);
  for (const segment of segments.slice(0, -1)) {
    const code = await runSegment(segment, dir);
    if (code !== 0) return { segment, code };
  }
  return null;
}

function findingIds(): string[] {
  return runShieldPhase(targetDir).classifiedFindings.map(f => f.finding.id);
}

/** A signed config file that has since changed, and the event review reads. */
async function int001Fires(dir: string): Promise<string> {
  const file = path.join(dir, 'mcp.json');
  fs.writeFileSync(file, '{"servers":{}}\n');
  expect(await quietly(() => guard({ subcommand: 'sign', targetDir: dir, format: 'json' }))).toBe(0);
  fs.writeFileSync(file, '{"servers":{"added":{"command":"node"}}}\n');
  writeEvent({
    source: 'configguard', category: 'config.tampered', severity: 'critical',
    agent: null, sessionId: null, action: 'tamper-detected', target: file,
    outcome: 'monitored', detail: {}, orgId: null, managed: false, agentId: null,
  });
  return file;
}

/** A Shield event log whose hash chain breaks after two genuine events. */
async function int002Fires(): Promise<void> {
  for (const action of ['first', 'second']) {
    writeEvent({
      source: 'shield', category: 'posture-assessment', severity: 'info',
      agent: null, sessionId: null, action, target: 'walk', outcome: 'allowed',
      detail: {}, orgId: null, managed: false, agentId: null,
    });
  }
  const forged = {
    id: '00000000-0000-7000-8000-000000000000',
    timestamp: new Date().toISOString(),
    version: 1,
    source: 'shield', category: 'posture-assessment', severity: 'info',
    agent: null, sessionId: null, action: 'forged', target: 'walk', outcome: 'allowed',
    detail: {}, orgId: null, managed: false, agentId: null,
    prevHash: 'f0'.repeat(32),
    eventHash: '0f'.repeat(32),
  };
  fs.appendFileSync(getEventsPath(), JSON.stringify(forged) + '\n', 'utf-8');
}

/**
 * For each finding whose remediation chains with `&&`: put the machine in the
 * state where that finding fires. A new chain needs an entry here.
 */
const FIRING_FIXTURES: Partial<Record<string, (dir: string) => Promise<unknown>>> = {
  'SHIELD-INT-001': int001Fires,
  'SHIELD-INT-002': int002Fires,
};

const CHAINED = Object.values(FINDING_CATALOG).filter(def => def.remediation.includes('&&'));

describe('the catalog walk', () => {
  it('reports a dead end: `guard diff` exits 1 in the state SHIELD-INT-001 reports', async () => {
    await int001Fires(targetDir);
    expect(findingIds()).toContain('SHIELD-INT-001');
    expect(await walkChain('opena2a guard diff && opena2a guard resign', targetDir))
      .toEqual({ segment: 'opena2a guard diff', code: 1 });
  });

  it('refuses a segment it cannot run instead of passing it', async () => {
    await expect(walkChain('opena2a protect --dir . && opena2a guard verify', targetDir))
      .rejects.toThrow(/no in-process runner/);
  });

  it('has a firing fixture for every chained remediation', () => {
    const missing = CHAINED.map(def => def.id).filter(id => !FIRING_FIXTURES[id]);
    expect(missing, `chained remediations with no fixture where the finding fires: ${missing.join(', ')}`)
      .toEqual([]);
  });

  for (const def of CHAINED) {
    it(`${def.id}: every segment before an && exits 0 where the finding fires`, async () => {
      const fire = FIRING_FIXTURES[def.id];
      expect(fire, `${def.id} chains "${def.remediation}" with no firing fixture`).toBeDefined();
      await fire!(targetDir);
      expect(findingIds()).toContain(def.id);
      expect(
        await walkChain(def.remediation, targetDir),
        `${def.id}: "${def.remediation}" stops before its last step in the state the finding reports`,
      ).toBeNull();
    });
  }

  it('SHIELD-INT-002: the walked chain ends with the finding cleared', async () => {
    await int002Fires();
    expect(findingIds()).toContain('SHIELD-INT-002');
    const segments = FINDING_CATALOG['SHIELD-INT-002'].remediation.split(/\s*&&\s*/);
    for (const segment of segments) expect(await runSegment(segment, targetDir)).toBe(0);
    expect(findingIds()).not.toContain('SHIELD-INT-002');
  });
});

describe('SHIELD-INT-001 Fix', () => {
  const def = FINDING_CATALOG['SHIELD-INT-001'];

  it('prints the inspect step alone and never chains resign onto it', () => {
    expect(def.remediation).toBe('opena2a guard diff');
    expect(def.remediation).not.toContain('&&');
    expect(def.remediationNote).toMatch(/only if every change .* yours/i);
    expect(def.remediationNote).toContain('opena2a guard resign');
    expect(def.remediationNote).toContain('opena2a guard verify');
  });

  it('reaches the stated outcome: diff, then a typed-y resign, then guard verify exits 0', async () => {
    await int001Fires(targetDir);
    expect(await runSegment(def.remediation, targetDir)).toBe(1);

    const restore = withStdinAnswer('y');
    try {
      expect(await quietly(() => guard({ subcommand: 'resign', targetDir }))).toBe(0);
    } finally {
      restore();
    }
    expect(await runSegment('opena2a guard verify', targetDir)).toBe(0);
  });

  it('does not claim the finding leaves review, which reads 7 days of events', async () => {
    await int001Fires(targetDir);
    const restore = withStdinAnswer('y');
    try {
      await quietly(() => guard({ subcommand: 'resign', targetDir }));
    } finally {
      restore();
    }
    expect(findingIds()).toContain('SHIELD-INT-001');
    expect(def.remediationNote).toMatch(/opena2a review .*7 days/);
  });

  it('agrees with the review action item for changed config files', () => {
    const items = generateActionItems(
      { totalFindings: 0 } as never,
      { signatureStatus: 'tampered', tamperedFiles: ['mcp.json'] } as never,
      { policyLoaded: true } as never,
      { hygieneChecks: [] } as never,
    );
    const item = items.find(i => i.tab === 'hygiene');
    expect(item?.command).toBe(def.remediation);
    expect(item?.description).toContain(def.remediationNote!);
    expect(item?.description).not.toMatch(/tamper/i);
  });
});

describe('SHIELD-CRED-001 to -004 Fix', () => {
  const PROVIDERS: Record<string, RegExp> = {
    'SHIELD-CRED-001': /Anthropic/,
    'SHIELD-CRED-002': /OpenAI/,
    'SHIELD-CRED-003': /GitHub/,
    'SHIELD-CRED-004': /service that issued it/,
  };

  for (const [id, provider] of Object.entries(PROVIDERS)) {
    describe(id, () => {
      const def = FINDING_CATALOG[id];

      it('leads with revoking the key at the provider, in words', () => {
        const note = def.remediationNote ?? '';
        const first = note.split(/(?<=\.)\s/)[0];
        expect(first).toMatch(/^Revoke /);
        expect(first).toMatch(provider);
        // No opena2a command revokes a key; the first step must not imply one does.
        expect(first).not.toContain('opena2a');
      });

      it('prints one runnable storing step with no placeholder', () => {
        expect(def.remediation).toBe('opena2a protect --dir .');
        expect(def.remediation).not.toMatch(/<[^>]+>/);
      });

      it('offers no history rewrite or gh login refresh as the fix', () => {
        const text = `${def.remediation} ${def.remediationNote ?? ''}`;
        expect(text).not.toMatch(/filter-repo|gh auth refresh/);
        // History cleanup may be mentioned only as optional, after revoking.
        if (/history/i.test(text)) expect(text).toMatch(/optional/i);
      });

      it('states the revocation step in the review report finding, ahead of its Fix command', () => {
        const shieldData = { classifiedFindings: [{ finding: def, count: 1, firstSeen: '', lastSeen: '', examples: [] }], policyLoaded: true, eventCount: 1 } as never;
        const guardData = { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'valid', candidates: [] } as never;
        const credentialData = { matches: [], totalFindings: 0, bySeverity: {} } as never;
        const detectData = { mcpServers: [], aiConfigs: [] } as never;
        const { reportFindings } = buildReviewFindings({
          targetDir: '/tmp/x',
          initData: { projectType: 'Node.js', hygieneChecks: [], envFiles: [], advisories: [], matchedPackages: [] } as never,
          credentialData, guardData, shieldData, detectData, findings: [],
          hmaData: { available: false, score: null, allFailedFindings: [] } as never,
          state: { hygieneChecks: [], credentials: credentialData, guard: guardData, shield: shieldData, hma: { available: false, score: null }, detect: detectData } as never,
          score: scoreReview,
          floorBand: CRITICAL_BAND,
        });
        const found = reportFindings.find(f => f.foundBy.some(b => b.source === 'shield' && b.checkId === id));
        expect(found?.reason).toContain(def.remediationNote!);
        expect(found?.fix?.command).toBe(def.remediation);
      });

      it('leads the SARIF help text with the revocation step', () => {
        const sarif = toSarif([{ finding: def, count: 1, firstSeen: '', lastSeen: '', examples: [] }], '0.0.0');
        const help = sarif.runs[0].tool.driver.rules[0].help.text;
        expect(help.indexOf('Revoke')).toBe(help.indexOf('Remediation: ') + 'Remediation: '.length);
        expect(help).toContain(def.remediation);
      });
    });
  }
});

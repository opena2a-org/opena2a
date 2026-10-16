import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { CRITICAL_BAND, scoreReview, type DetectPhaseData, type HmaFinding, type InitPhaseData } from '../../src/commands/review.js';
import { buildReviewFindings, maskEvidenceLine } from '../../src/commands/review-findings.js';
import type { EnvFileFact } from '../../src/commands/review-facts.js';
import type { CredentialMatch } from '../../src/util/credential-patterns.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const SECRET = 'q7Zr2Lw9Kx4Vb8Nm3Tc6'; // synthetic; must never reach the output
const MASK = '••••'; // what the report prints in place of a value

const hma = (checkId: string, severity: string, category: string, file?: string, extra: Partial<HmaFinding> = {}): HmaFinding => ({
  checkId, name: checkId, description: '', category, severity, passed: false, message: '', file,
  fixable: true, fix: 'opena2a secure --fix', guidance: '', count: 1, sampleFiles: [], ...extra,
});

const checks = (warn: string[]): InitPhaseData['hygieneChecks'] => ['.gitignore', '.env protection', 'Lock file', 'Security config']
  .map(label => ({ label, status: warn.includes(label) ? 'warn' : label === 'Security config' ? 'info' : 'pass', detail: '' }));

/** Built-in credential scan matches in src/config.ts, one per line, none of them reported by HMA. */
const credentialMatches = (severity: string, count: number): CredentialMatch[] => Array.from({ length: count }, (_, i) => ({
  value: MASK, filePath: '/tmp/x/src/config.ts', line: i + 1, findingId: 'CRED-010', envVar: `SERVICE_KEY_${i + 1}`, severity, title: 'Service key',
}));

function build(o: { warn: string[]; envFiles?: EnvFileFact[]; hmaScore: number; hmaFindings: HmaFinding[]; guard: 'unsigned' | 'valid'; detect?: Partial<DetectPhaseData>; credentials?: CredentialMatch[] }) {
  const hygieneChecks = checks(o.warn);
  const guardData = { filesMonitored: 0, tamperedFiles: [], signatureStatus: o.guard, candidates: ['package.json'] };
  const matches = o.credentials ?? [];
  const bySeverity: Record<string, number> = {};
  for (const m of matches) bySeverity[m.severity] = (bySeverity[m.severity] ?? 0) + 1;
  const credentialData = { matches, totalFindings: matches.length, bySeverity } as never;
  const shieldData = { classifiedFindings: [], policyLoaded: false, eventCount: 0 } as never;
  const detectData = { mcpServers: [], aiConfigs: [], ...o.detect } as DetectPhaseData;
  return buildReviewFindings({
    targetDir: '/tmp/x',
    initData: { projectType: 'Node.js', hygieneChecks, envFiles: o.envFiles ?? [], advisories: [], matchedPackages: [] } as never,
    credentialData, guardData, shieldData, detectData,
    findings: matches.map(m => ({ id: m.findingId, title: m.title, severity: m.severity, source: 'credential-scan', detail: `src/config.ts:${m.line}`, remediation: '' })),
    hmaData: { available: true, score: o.hmaScore, allFailedFindings: o.hmaFindings } as never,
    state: { hygieneChecks, credentials: credentialData, guard: guardData, shield: shieldData, hma: { available: true, score: o.hmaScore }, detect: detectData },
    score: scoreReview,
    floorBand: CRITICAL_BAND,
  });
}

// The measured envcase tree (composite 88): tiny-clean-repo without its .env
// ignore rules, a .env setting three values, and HMA 0.30.0's results on it.
const envcase = () => build({
  warn: ['.env protection', 'Lock file'],
  envFiles: [{ path: '.env', assignments: 3, gitIgnored: false, gitTracked: false, stagedByAddAll: true, mode: '-rw-r--r--' }],
  hmaScore: 61,
  guard: 'unsigned',
  hmaFindings: [
    hma('PERM-001', 'high', 'permissions', '.env'),
    hma('GIT-002', 'low', 'git', '.gitignore'),
    hma('GIT-003', 'critical', 'git', '.env'),
    hma('SEM-CRED-001', 'high', 'Credential Protection', '.env', {
      line: 1, fix: 'opena2a protect .  — migrates hardcoded secrets into the vault',
      evidence: { kind: 'positive', lines: [{ n: 1, content: `DATABASE_URL=postgres://app:${SECRET}@localhost:5432/app` }] },
    }),
    hma('SEM-CRED-002', 'medium', 'Credential Protection', '.env', { line: 2, fix: 'Add .env to .gitignore' }),
    hma('SEM-CRED-002', 'medium', 'Credential Protection', '.env', { line: 3, fix: 'Add .env to .gitignore' }),
  ],
});

// test/hma's shape: HMA 0/100 plus in-repo critical MCP and AI config signals.
const hmaFixture = () => build({
  warn: ['Lock file'],
  hmaScore: 0,
  guard: 'valid',
  detect: {
    mcpServers: [{ name: 'shell', transport: 'stdio', source: 'mcp.json (project)', verified: false, capabilities: ['shell:execute'], risk: 'critical' }],
    aiConfigs: [{ file: '.cursorrules', tool: 'Cursor', risk: 'critical', details: 'Cursor config contains credential references' }],
  },
  hmaFindings: [
    hma('SKILL-001', 'critical', 'skill', 'SKILL.md', { fix: 'hackmyagent check SKILL.md' }),
    hma('SOUL-001', 'high', 'soul-governance', 'SOUL.md', { fix: 'hackmyagent harden-soul .  — adds SOUL.md' }),
    hma('AIM-001', 'medium', 'identity-spoofing', undefined, { fix: 'hackmyagent fix-all --with-aim  — signs each skill' }),
    hma('CRED-001', 'high', 'credentials', '.env', { fix: 'npx secretless-ai init' }),
    hma('HMA-000', 'low', 'scan', undefined, { fix: 'npm install -g hackmyagent' }),
    hma('GW-001', 'high', 'gateway', 'gateway.json', { fix: 'hackmyagent secure --fix' }),
  ],
});

const commandsOf = (r: ReturnType<typeof build>) => [
  ...r.reportFindings.flatMap(f => [f.fix, f.then, f.verify]), ...r.optionalHardening.map(h => h.fix),
].filter((c): c is NonNullable<typeof c> => c !== null);

describe('review findings on the envcase tree', () => {
  it('merges the .env exposure into one first finding listing every check that found it', () => {
    const r = envcase();
    expect(r.scoreModel).toMatchObject({ weightSet: 'withHma', weightedScore: 88, floorHeldBy: [] });
    const [env, second, third] = r.reportFindings;
    expect(env).toMatchObject({
      title: '.env is not ignored by git and sets 3 values', severity: 'critical', confidence: 'confirmed',
      fix: { command: "printf '\\n.env\\n' >> .gitignore", tool: 'shell' },
      verify: { command: 'git check-ignore -v -- .env', tool: 'git' },
      recovery: { kind: 'atLeast', points: 3, from: 88, to: 91 },
    });
    expect(env.foundBy.map(b => [b.checkId, b.lines])).toEqual([['.env protection', []], ['GIT-003', []], ['SEM-CRED-002', [2, 3]]]);
    expect([second.foundBy[0].checkId, third.foundBy[0].checkId]).toEqual(['SEM-CRED-001', 'PERM-001']);
    expect(third).toMatchObject({ fix: { command: 'chmod 600 .env' }, verify: { command: 'ls -l .env' } });
    expect(r.fixFirst).toEqual([env, second, third].map(f => f.fingerprint));
  });

  it('re-scores signing at +3, gives a Shield policy no score change, and names no read-only command', () => {
    const r = envcase();
    expect(r.optionalHardening.map(h => [h.id, h.recovery.kind, h.recovery.points])).toEqual([['guard-sign', 'computed', 3], ['shield-policy', 'none', 0]]);
    expect(r.recoverySummary).toEqual({
      currentScore: 88, potentialScore: 91, totalRecoverable: 3,
      opportunities: [{ dimension: 'Config integrity', pointsRecoverable: 3, action: 'opena2a guard sign' }],
    });
  });

  it('masks the secret in evidence and fingerprints are unique and stable', () => {
    const r = envcase();
    expect(JSON.stringify(r)).not.toContain(SECRET);
    expect(r.reportFindings[1].evidence[0].text).toBe(`DATABASE_URL=postgres://app:${MASK}@localhost:5432/app`);
    const fps = r.reportFindings.map(f => f.fingerprint);
    expect(new Set(fps).size).toBe(fps.length);
    expect(fps.every(fp => /^[0-9a-f]{8}$/.test(fp))).toBe(true);
    expect(envcase().reportFindings.map(f => f.fingerprint)).toEqual(fps);
  });
});

describe('maskEvidenceLine on one long line', () => {
  /** A line of `size` characters built from `unit`, then a secret. */
  const lineOf = (unit: string, size: number) => unit.repeat(Math.ceil(size / unit.length)).slice(0, size) + ' api_key=' + SECRET;

  /** The processor time of one masking of `line`, in milliseconds; the output is checked on every run. */
  const cpuMs = (line: string) => {
    const before = process.cpuUsage();
    const out = maskEvidenceLine(line, true);
    const used = process.cpuUsage(before);
    expect(out).not.toContain(SECRET);
    expect(out.length).toBeLessThanOrEqual(160);
    return (used.user + used.system) / 1000;
  };
  const fastestMs = (line: string) => Math.min(cpuMs(line), cpuMs(line), cpuMs(line));
  const median = (values: number[]) => [...values].sort((a, b) => a - b)[values.length >> 1];

  // Processor time, not elapsed time, so time the process spends waiting for a CPU is not
  // counted. The line is doubled from 1 KB until the fastest of three maskings takes at least
  // 0.25 ms (or the line is 512 KB); then that line and one 8 times as long are masked in turn,
  // nine times each. Linear work grows 8 times and quadratic work 64 times, so the median of
  // the nine ratios must be under 24; a few ratios that another thread or a slower core
  // distorts do not carry the median. The bound guards against a super-linear regression, not
  // against a larger constant.
  it.each(['a', '-', 'key', 'a-', 'key=', 'http://u:FAKE@h/', '"key":"v",', 'http://u:p/', 'x://y:'])(
    'masks a line of repeated %s in time linear in its length', unit => {
      let size = 1_000;
      while (size < 512_000 && fastestMs(lineOf(unit, size)) < 0.25) size *= 2;
      const lineN = lineOf(unit, size), line8N = lineOf(unit, size * 8);
      const msN: number[] = [], ms8N: number[] = [];
      for (let pair = 0; pair < 9; pair++) {
        msN.push(cpuMs(lineN));
        ms8N.push(cpuMs(line8N));
      }
      const ratio = median(ms8N.map((ms, i) => ms / msN[i]));
      const times = `${JSON.stringify(unit)}: ${median(msN).toFixed(2)} ms at ${size / 1000} KB, ${median(ms8N).toFixed(2)} ms at ${(size * 8) / 1000} KB`;
      expect(ratio, `${times}, median ratio ${ratio.toFixed(1)}`).toBeLessThan(24);
    }, 60_000);
});

describe('review findings while HMA holds the floor', () => {
  it('names HMA as holding the score and gives every other finding 0', () => {
    const r = hmaFixture();
    expect(r.scoreModel.floorHeldBy).toContain('HMA Scan');
    // No re-scored gain exists, so the total is not reported as 0; the holders are named instead.
    expect(r.recoverySummary.totalRecoverable).toBeNull();
    expect(r.recoverySummary.opportunities.map(o => o.dimension)).toEqual(r.scoreModel.floorHeldBy);
    const others = r.reportFindings.filter(f => !f.foundBy.some(b => b.source === 'hma'));
    expect(others.length).toBe(3);
    for (const f of others) expect(f.recovery.points).toBe(0);
  });

  it('rewrites bundled-tool citations and drops those with no opena2a command', () => {
    const r = hmaFixture();
    for (const c of commandsOf(r)) expect(c.command).not.toMatch(/hackmyagent|npx secretless-ai|npm install -g/);
    for (const f of r.reportFindings) expect(f.advice ?? '').not.toMatch(/hackmyagent|secretless-ai|npm install -g/);
    const fixOf = (id: string) => r.reportFindings.find(f => f.foundBy[0].checkId === id)?.fix?.command ?? null;
    expect(['SKILL-001', 'AIM-001', 'GW-001', 'CRED-001', 'SOUL-001', 'HMA-000'].map(fixOf)).toEqual([
      'opena2a check SKILL.md', 'opena2a fix-all --with-aim', 'opena2a secure --fix', 'opena2a secrets init', null, null,
    ]);
  });
});

describe('recovery while a floor holder pins the score', () => {
  // HMA at 0 holds the floor. Five critical credentials keep the credential
  // dimension at 0 after any one of them is moved, so it holds the floor too.
  const heldTree = () => build({
    warn: ['Lock file'],
    hmaScore: 0,
    guard: 'valid',
    credentials: credentialMatches('critical', 5),
    hmaFindings: [
      hma('SKILL-001', 'critical', 'skill', 'SKILL.md', { fix: 'hackmyagent check SKILL.md' }),
      hma('SOUL-001', 'high', 'soul-governance', 'SOUL.md'),
    ],
  });
  // HMA at 0 alone; one high credential sits below the critical band but above 0.
  const hmaOnly = () => build({
    warn: ['Lock file'],
    hmaScore: 0,
    guard: 'valid',
    credentials: credentialMatches('high', 1),
    hmaFindings: [
      hma('SKILL-001', 'critical', 'skill', 'SKILL.md', { fix: 'hackmyagent check SKILL.md' }),
      hma('GW-001', 'critical', 'gateway', 'gateway.json', { fix: 'hackmyagent secure --fix' }),
    ],
  });

  it('names each floor holder and what moves it, and computes no potential score', () => {
    const r = heldTree();
    expect(r.scoreModel.floorHeldBy).toEqual(['Credentials', 'HMA Scan']);
    expect(r.recoverySummary).toEqual({
      currentScore: 0, potentialScore: null, totalRecoverable: null,
      opportunities: [
        { dimension: 'Credentials', pointsRecoverable: null, action: 'opena2a protect', kind: 'nextRun' },
        { dimension: 'HMA Scan', pointsRecoverable: null, action: 'address the 1 critical finding under HMA Scan', kind: 'nextRun' },
      ],
    });
  });

  it('gives HMA as the one holder when no other dimension is at the floor', () => {
    const r = hmaOnly();
    expect(r.scoreModel.floorHeldBy).toEqual(['HMA Scan']);
    expect(r.recoverySummary).toEqual({
      currentScore: 0, potentialScore: null, totalRecoverable: null,
      opportunities: [{ dimension: 'HMA Scan', pointsRecoverable: null, action: 'address the 2 critical findings under HMA Scan', kind: 'nextRun' }],
    });
  });

  it('marks a fix that moves its own dimension but not the composite as floorPinned, naming the holder', () => {
    const r = heldTree();
    const credential = r.reportFindings.find(f => f.foundBy[0].source === 'credential-scan')!;
    expect(credential.recovery).toEqual({ kind: 'floorPinned', points: 0, from: 0, to: 0, holder: ['Credentials'] });
    const lockFile = r.reportFindings.find(f => f.foundBy[0].checkId === 'Lock file')!;
    expect(lockFile.recovery).toEqual({ kind: 'floorPinned', points: 0, from: 0, to: 0, holder: ['Credentials', 'HMA Scan'] });
    const only = hmaOnly();
    expect(only.reportFindings.find(f => f.foundBy[0].checkId === 'Lock file')!.recovery)
      .toEqual({ kind: 'floorPinned', points: 0, from: 0, to: 0, holder: ['HMA Scan'] });
    // A fix that may also move the one holder cannot be re-scored here.
    expect(only.reportFindings.find(f => f.foundBy[0].source === 'credential-scan')!.recovery.kind).toBe('nextRun');
  });

  it('keeps none for a fix that changes no score input', () => {
    const r = heldTree();
    expect(r.optionalHardening.map(h => [h.id, h.recovery])).toEqual([['shield-policy', { kind: 'none', points: 0, from: 0, to: 0 }]]);
  });

  it('keeps a computed opportunity numeric when the floor holder is the dimension the action moves', () => {
    // One critical credential holds the floor at 20; opena2a protect lifts it.
    const r = build({ warn: [], hmaScore: 90, guard: 'valid', credentials: credentialMatches('critical', 1), hmaFindings: [] });
    expect(r.scoreModel.floorHeldBy).toEqual(['Credentials']);
    expect(r.recoverySummary.potentialScore).toBeGreaterThan(r.recoverySummary.currentScore);
    expect(r.recoverySummary.totalRecoverable).toBe(r.recoverySummary.potentialScore! - r.recoverySummary.currentScore);
    expect(r.recoverySummary.opportunities).toEqual([
      { dimension: 'Credentials', pointsRecoverable: r.recoverySummary.totalRecoverable, action: 'opena2a protect' },
    ]);
  });
});

describe('every cited opena2a command parses in the built CLI', () => {
  const cited = [...new Set([envcase(), hmaFixture()].flatMap(commandsOf).map(c => c.command))].filter(c => c.startsWith('opena2a '));
  // An unregistered verb falls back to the root usage; an unknown subcommand exits 1.
  it.each(cited)('%s', command => {
    const args = command.split(' ').slice(1);
    const res = spawnSync(process.execPath, [CLI_PATH, ...args, '--help'], { encoding: 'utf8', timeout: 60_000 });
    expect(res.status).toBe(0);
    expect(res.stdout).not.toContain('Usage: opena2a [options] [command]');
    if (['guard', 'shield', 'mcp'].includes(args[0])) expect(res.stdout).toContain(`Usage: opena2a ${args[0]} ${args[1]}`);
  });
});

it.each([
  ['"apiToken": "abc123", run --auth-token abc123', false, '"apiToken": ••••, run --auth-token ••••'],
  [`curl -H ${SECRET}`, true, 'curl -H ••••'],
])('maskEvidenceLine(%s)', (line, secret, masked) => {
  expect(maskEvidenceLine(line, secret)).toBe(masked);
});

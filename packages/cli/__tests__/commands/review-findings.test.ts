import { describe, it, expect } from 'vitest';
import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { CRITICAL_BAND, scoreReview, type DetectPhaseData, type HmaFinding, type InitPhaseData } from '../../src/commands/review.js';
import { buildReviewFindings, maskEvidenceLine } from '../../src/commands/review-findings.js';
import type { EnvFileFact } from '../../src/commands/review-facts.js';

const CLI_PATH = resolve(__dirname, '../../dist/index.js');
const SECRET = 'q7Zr2Lw9Kx4Vb8Nm3Tc6'; // synthetic; must never reach the output
const MASK = '••••'; // what the report prints in place of a value

const hma = (checkId: string, severity: string, category: string, file?: string, extra: Partial<HmaFinding> = {}): HmaFinding => ({
  checkId, name: checkId, description: '', category, severity, passed: false, message: '', file,
  fixable: true, fix: 'opena2a secure --fix', guidance: '', count: 1, sampleFiles: [], ...extra,
});

const checks = (warn: string[]): InitPhaseData['hygieneChecks'] => ['.gitignore', '.env protection', 'Lock file', 'Security config']
  .map(label => ({ label, status: warn.includes(label) ? 'warn' : label === 'Security config' ? 'info' : 'pass', detail: '' }));

function build(o: { warn: string[]; envFiles?: EnvFileFact[]; hmaScore: number; hmaFindings: HmaFinding[]; guard: 'unsigned' | 'valid'; detect?: Partial<DetectPhaseData> }) {
  const hygieneChecks = checks(o.warn);
  const guardData = { filesMonitored: 0, tamperedFiles: [], signatureStatus: o.guard, candidates: ['package.json'] };
  const credentialData = { matches: [], totalFindings: 0, bySeverity: {} } as never;
  const shieldData = { classifiedFindings: [], policyLoaded: false, eventCount: 0 } as never;
  const detectData = { mcpServers: [], aiConfigs: [], ...o.detect } as DetectPhaseData;
  return buildReviewFindings({
    targetDir: '/tmp/x',
    initData: { projectType: 'Node.js', hygieneChecks, envFiles: o.envFiles ?? [], advisories: [], matchedPackages: [] } as never,
    credentialData, guardData, shieldData, detectData, findings: [],
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

describe('review findings while HMA holds the floor', () => {
  it('names HMA as holding the score and gives every other finding 0', () => {
    const r = hmaFixture();
    expect(r.scoreModel.floorHeldBy).toContain('HMA Scan');
    expect(r.recoverySummary.totalRecoverable).toBe(0);
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

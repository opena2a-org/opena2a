/**
 * shield report: a Shield-source `command.blocked` record gets no finding in
 * the HTML violations list, and its recommendation says that Shield did not
 * stop the command and to check whether it ran.
 *
 * The record keeps its stored action and outcome: the JSON byOutcome and the
 * text report's Top Actions line read as before, and the Blocked card still
 * counts only records from other sources. In the same report run, a blocked
 * record from another source keeps its finding and "Already blocked by
 * policy", a `command.blocked` record from another source keeps its own row,
 * and a Shield record of another action keeps its finding.
 *
 * Every record is written through the build's own event writer
 * (dist/shield/events.js writeEvent) into a scratch HOME. Every run starts
 * node under env -i from an empty working directory; on macOS it runs inside
 * sandbox-exec with network access denied.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { pathToFileURL } from 'node:url';
import { runInNewContext } from 'node:vm';

const CLI_PATH = path.resolve(__dirname, '../../dist/index.js');
const EVENTS_JS = path.resolve(__dirname, '../../dist/shield/events.js');

const DID_NOT_STOP =
  'Shield did not stop this. An earlier version recorded the policy deny as blocked; check whether the command ran.';
const ALREADY_BLOCKED = 'Already blocked by policy';

/** The shape of a Shield `command.blocked` record (0.10.13 and earlier). */
const SHIELD_COMMAND_BLOCKED = {
  source: 'shield',
  category: 'enforcement',
  severity: 'high',
  agent: null,
  sessionId: null,
  action: 'command.blocked',
  target: 'aws s3 ls',
  outcome: 'blocked',
  detail: { rule: 'processes.deny:aws', mode: 'enforce' },
  orgId: null,
  managed: false,
  agentId: null,
};

/** A config guard record in the shape `guard verify --enforce` writes. */
const GUARD_BLOCKED = {
  source: 'configguard',
  category: 'config.tampered',
  severity: 'high',
  agent: null,
  sessionId: null,
  action: 'guard.verify',
  target: '/srv/agent',
  outcome: 'blocked',
  detail: {
    tamperedCount: 1,
    missingCount: 0,
    files: [{ path: 'package.json', status: 'tampered', diff: null }],
  },
  orgId: null,
  managed: false,
  agentId: null,
};

/** A `command.blocked` record from another source, with the same target and agent. */
const ARP_COMMAND_BLOCKED = {
  ...SHIELD_COMMAND_BLOCKED,
  source: 'arp',
  category: 'process.spawn',
  detail: {},
};

/** A Shield record of another action, in the shape `init` writes for a credential it finds. */
const SHIELD_CREDENTIAL_FINDING = {
  source: 'shield',
  category: 'shield.credential',
  severity: 'high',
  agent: null,
  sessionId: null,
  action: 'credential-finding',
  target: '/srv/agent/config.js',
  outcome: 'monitored',
  detail: { findingId: 'CRED-004', title: 'Credential in source', line: 3 },
  orgId: null,
  managed: false,
  agentId: null,
};

// Network access is denied and the keychain tool cannot start.
const SANDBOX_PROFILE =
  '(version 1)(allow default)(deny network*)(deny process-exec (literal "/usr/bin/security"))';

interface Run { status: number | null; stdout: string; stderr: string }

let scratch: string;

function runNode(home: string, cwd: string, args: string[]): Run {
  const argv = [
    '/usr/bin/env', '-i',
    'PATH=/opt/homebrew/bin:/usr/bin:/bin',
    `HOME=${home}`,
    'OPENA2A_TELEMETRY=off',
    'DO_NOT_TRACK=1',
    'NO_COLOR=1',
    'HARNESS_NO_LIVE_TRANSPORT=1',
    'OPENA2A_AUTH_FORCE_FILE=1',
    process.execPath,
    ...args,
  ];
  const [cmd, ...rest] = process.platform === 'darwin'
    ? ['/usr/bin/sandbox-exec', '-p', SANDBOX_PROFILE, ...argv]
    : argv;
  const res = spawnSync(cmd, rest, { cwd, encoding: 'utf8', timeout: 60000 });
  return { status: res.status, stdout: res.stdout, stderr: res.stderr };
}

/** A scratch HOME, an empty working directory and an output directory. */
function scratchSet(name: string): { home: string; cwd: string; out: string } {
  const base = path.join(scratch, name);
  const dirs = { home: path.join(base, 'home'), cwd: path.join(base, 'cwd'), out: path.join(base, 'out') };
  for (const dir of Object.values(dirs)) fs.mkdirSync(dir, { recursive: true });
  return dirs;
}

const WRITER = [
  'const { writeEvent } = await import(process.argv[1]);',
  'for (const record of JSON.parse(process.argv[2])) writeEvent(record);',
].join('\n');

function writeRecords(home: string, cwd: string, records: object[]): void {
  const res = runNode(home, cwd, [
    '--input-type=module', '-e', WRITER, pathToFileURL(EVENTS_JS).href, JSON.stringify(records),
  ]);
  if (res.status !== 0) throw new Error(`event writer exited ${String(res.status)}: ${res.stderr}`);
}

function shieldReport(home: string, cwd: string, extra: string[]): Run {
  const res = runNode(home, cwd, [CLI_PATH, 'shield', 'report', ...extra]);
  if (res.status !== 0) {
    throw new Error(`shield report ${extra.join(' ')} exited ${String(res.status)}: ${res.stderr}`);
  }
  return res;
}

function htmlReport(home: string, cwd: string, out: string): string {
  const file = path.join(out, 'report.html');
  shieldReport(home, cwd, ['--report', file]);
  return fs.readFileSync(file, 'utf-8');
}

function embeddedPayload(html: string): string {
  const start = html.indexOf('>', html.indexOf('<script id="report-data"')) + 1;
  return html.slice(start, html.indexOf('</script>', start));
}

interface Violation {
  action: string;
  target: string;
  count: number;
  recommendation: string;
  findingId?: string;
  remediationCommand?: string;
  compliance?: string[];
}

function embeddedReport(html: string): {
  policyEvaluation: { blocked: number; topViolations: Violation[] };
} {
  return JSON.parse(embeddedPayload(html)).report;
}

/** The violations page as the report's own script writes it. */
function violationsPage(html: string): string {
  const script = html.slice(html.lastIndexOf('<script>') + '<script>'.length, html.lastIndexOf('</script>'));
  const payload = embeddedPayload(html);
  const nodes = new Map<string, any>();
  const handlers = new Map<string, (e: any) => void>();
  const node = (id: string) => {
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        innerHTML: '',
        classList: { toggle: () => {}, add: () => {}, remove: () => {} },
        addEventListener: (type: string, fn: (e: any) => void) => handlers.set(`${id}:${type}`, fn),
      });
    }
    return nodes.get(id);
  };
  const escapeText = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const documentStub = {
    getElementById: (id: string) => (id === 'report-data' ? { textContent: payload } : node(id)),
    querySelectorAll: () => [] as any[],
    querySelector: () => null,
    addEventListener: () => {},
    createElement: () => {
      let text = '';
      return {
        set textContent(v: string) { text = v; },
        get innerHTML() { return escapeText(text); },
      };
    },
  };
  // The evaluated string is the report the built CLI just wrote.
  runInNewContext(script, { document: documentStub, window: {} });
  const onNavClick = handlers.get('main-nav:click');
  if (!onNavClick) throw new Error('report script did not register the nav listener');
  onNavClick({ target: { closest: () => ({ dataset: { page: 'violations' } }) } });
  return node('page-violations').innerHTML;
}

/**
 * The cells of each violations-table row, keyed by the Action cell:
 * Finding, Action, Target, Agent, Count, Severity, Compliance, Remediation.
 */
function violationRows(page: string): Map<string, string[]> {
  const rows = new Map<string, string[]>();
  for (const row of page.matchAll(/<tr class="violation-row"[^>]*>(.*?)<\/tr>/g)) {
    const cells = [...row[1].matchAll(/<td[^>]*>(.*?)<\/td>/g)].map(cell => cell[1]);
    rows.set(cells[1], cells);
  }
  return rows;
}

function blockedCard(page: string): string | undefined {
  return page.match(/<div class="stat-value"[^>]*>([^<]*)<\/div><div class="stat-label">Blocked<\/div>/)?.[1];
}

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

beforeAll(() => {
  scratch = fs.mkdtempSync(path.join(tmpdir(), 'shield-report-command-blocked-'));
});

afterAll(() => {
  fs.rmSync(scratch, { recursive: true, force: true });
});

describe('shield report over one Shield command.blocked record', () => {
  let html = '';
  let json: Record<string, any> = {};
  let text = '';

  beforeAll(() => {
    const { home, cwd, out } = scratchSet('shield-only');
    writeRecords(home, cwd, [SHIELD_COMMAND_BLOCKED]);
    json = JSON.parse(shieldReport(home, cwd, ['--format', 'json']).stdout);
    text = shieldReport(home, cwd, []).stdout;
    html = htmlReport(home, cwd, out);
  }, 120000);

  it('dist/index.js and dist/shield/events.js exist (run `npm run build` first)', () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
    expect(fs.existsSync(EVENTS_JS)).toBe(true);
  });

  it('reads the record through an intact chain', () => {
    expect(json.totalEvents).toBe(1);
    expect(json.logIntegrity.chainIntact).toBe(true);
    expect(embeddedReport(html).policyEvaluation.topViolations).toHaveLength(1);
  });

  it('gives the violation the recommendation that Shield did not stop it, and no finding', () => {
    const [violation] = embeddedReport(html).policyEvaluation.topViolations;
    expect(violation.action).toBe('command.blocked');
    expect(violation.target).toBe('aws s3 ls');
    expect(violation.recommendation).toBe(DID_NOT_STOP);
    expect(violation).not.toHaveProperty('findingId');
    expect(violation).not.toHaveProperty('remediationCommand');
    expect(violation).not.toHaveProperty('compliance');
  });

  it('writes that recommendation into the row Remediation cell, with no finding id in the row', () => {
    const row = violationRows(violationsPage(html)).get('command.blocked');
    expect(row).toBeDefined();
    const [finding, , , , , , compliance, remediation] = row!;
    expect(finding).toBe('<span style="color:var(--dim)">--</span>');
    expect(compliance).toBe('--');
    expect(remediation).toBe(DID_NOT_STOP);
  });

  it('names neither SHIELD-POL-002 nor "Already blocked by policy" anywhere in the file', () => {
    expect(occurrences(html, 'SHIELD-POL-002')).toBe(0);
    expect(occurrences(html, ALREADY_BLOCKED)).toBe(0);
  });

  it('keeps the stored outcome in the JSON byOutcome and topActions', () => {
    expect(json.byOutcome).toEqual({ blocked: 1 });
    expect(json.topActions).toEqual([{ name: 'command.blocked', count: 1 }]);
  });

  it('keeps the text report Top Actions line command.blocked 1', () => {
    const lines = text.split('\n');
    const header = lines.findIndex(line => line.trim() === 'Top Actions');
    expect(header).toBeGreaterThanOrEqual(0);
    expect(lines[header + 1]).toBe(`    ${'command.blocked'.padEnd(30)} 1`);
  });

  it('leaves the record off the Blocked card', () => {
    expect(embeddedReport(html).policyEvaluation.blocked).toBe(0);
    expect(blockedCard(violationsPage(html))).toBe('0');
  });
});

describe('the same report run over a Shield command.blocked record and a config guard blocked record', () => {
  let html = '';

  beforeAll(() => {
    const { home, cwd, out } = scratchSet('shield-and-guard');
    writeRecords(home, cwd, [SHIELD_COMMAND_BLOCKED, GUARD_BLOCKED]);
    html = htmlReport(home, cwd, out);
  }, 120000);

  function violation(action: string): Violation {
    const found = embeddedReport(html).policyEvaluation.topViolations.filter(v => v.action === action);
    expect(found).toHaveLength(1);
    return found[0];
  }

  it('lists both records as violations', () => {
    expect(embeddedReport(html).policyEvaluation.topViolations).toHaveLength(2);
  });

  it('keeps "Already blocked by policy" and the finding for the guard record', () => {
    const guard = violation('guard.verify');
    expect(guard.recommendation).toBe(ALREADY_BLOCKED);
    expect(guard.findingId).toBe('SHIELD-POL-002');
    expect(guard.remediationCommand).toBe('opena2a shield policy');
    expect(guard.compliance?.length ?? 0).toBeGreaterThan(0);
  });

  it('writes the guard row with its finding id and its remediation command', () => {
    const row = violationRows(violationsPage(html)).get('guard.verify');
    expect(row).toBeDefined();
    const [finding, , , , , , , remediation] = row!;
    expect(finding).toContain('>SHIELD-POL-002</span>');
    expect(remediation).toContain('<code class="remediation-code" title="opena2a shield policy">opena2a shield policy</code>');
  });

  it('gives the Shield record the did-not-stop recommendation and no finding in the same file', () => {
    const shield = violation('command.blocked');
    expect(shield.recommendation).toBe(DID_NOT_STOP);
    expect(shield).not.toHaveProperty('findingId');
    expect(shield).not.toHaveProperty('remediationCommand');
    expect(shield).not.toHaveProperty('compliance');
    const row = violationRows(violationsPage(html)).get('command.blocked');
    expect(row?.[7]).toBe(DID_NOT_STOP);
  });

  it('counts the guard record, and not the Shield record, on the Blocked card', () => {
    expect(embeddedReport(html).policyEvaluation.blocked).toBe(1);
    expect(blockedCard(violationsPage(html))).toBe('1');
  });
});

describe('the same report run over a Shield command.blocked record, one from another source, and a Shield record of another action', () => {
  let html = '';

  beforeAll(() => {
    const { home, cwd, out } = scratchSet('shield-arp-credential');
    writeRecords(home, cwd, [SHIELD_COMMAND_BLOCKED, ARP_COMMAND_BLOCKED, SHIELD_CREDENTIAL_FINDING]);
    html = htmlReport(home, cwd, out);
  }, 120000);

  it('keeps the command.blocked record from another source in its own row, with "Already blocked by policy" and its finding', () => {
    const rows = embeddedReport(html).policyEvaluation.topViolations.filter(v => v.action === 'command.blocked');
    expect(rows).toHaveLength(2);
    const shield = rows.find(v => v.recommendation === DID_NOT_STOP);
    const other = rows.find(v => v.recommendation === ALREADY_BLOCKED);
    expect(shield?.count).toBe(1);
    expect(shield).not.toHaveProperty('findingId');
    expect(other?.count).toBe(1);
    expect(other?.findingId).toBe('SHIELD-POL-002');
    expect(other?.remediationCommand).toBe('opena2a shield policy');
  });

  it('keeps the finding and the recommendation of the Shield record of another action', () => {
    const found = embeddedReport(html).policyEvaluation.topViolations.filter(v => v.action === 'credential-finding');
    expect(found).toHaveLength(1);
    expect(found[0].findingId).toBe('SHIELD-CRED-004');
    expect(found[0].recommendation).toBe('Review and consider blocking');
  });
});

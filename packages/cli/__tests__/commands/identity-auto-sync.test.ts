import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// `identity integrate` wrote bridging.autoSync into the manifest, but nothing
// read it: integrated tool events reached the audit log only through a manual
// `identity sync`. With autoSync set, `identity trust` and `identity audit`
// now import them first.

interface Logged {
  action: string;
  target: string;
  result: string;
  plugin: string;
  metadata?: Record<string, unknown>;
  timestamp: string;
}

const aimState = vi.hoisted(() => ({
  log: [] as Logged[],
  logCountAtTrust: -1,
}));

vi.mock('../../src/util/report-submission.js', () => ({
  recordScanAndMaybePrompt: async () => undefined,
  isContributeEnabled: async () => false,
  getRegistryUrl: async () => null,
  submitScanReport: async () => true,
}));

vi.mock('../../src/util/identity-auth-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/identity-auth-lookup.js')>();
  return { ...actual, storedServerUrl: () => undefined };
});

vi.mock('@opena2a/aim-core', () => ({
  AIMCore: class {
    getIdentity(): object { return { agentId: 'agent-1', agentName: 'default' }; }
    setTrustHints(): void {}
    logEvent(event: Omit<Logged, 'timestamp'>): void {
      aimState.log.push({ ...event, timestamp: new Date().toISOString() });
    }
    readAuditLog(opts?: { limit?: number }): Logged[] {
      return opts?.limit ? aimState.log.slice(-opts.limit) : [...aimState.log];
    }
    calculateTrust(): object {
      aimState.logCountAtTrust = aimState.log.length;
      return { score: 40, grade: 'moderate', factors: {} };
    }
  },
}));

const { identity } = await import('../../src/commands/identity.js');
const { readManifest } = await import('../../src/identity/manifest.js');

let dir: string;
let stdout: string;

function writeManifestFile(autoSync: boolean): void {
  fs.mkdirSync(path.join(dir, '.opena2a', 'guard'), { recursive: true });
  fs.writeFileSync(path.join(dir, '.opena2a', 'agent.yaml'), [
    'version: "1"',
    'agent:',
    '  name: "default"',
    '  agentId: "agent-1"',
    '  publicKey: "pk"',
    '  created: "2026-01-01T00:00:00.000Z"',
    'tools:',
    '  secretless: false',
    '  configguard: true',
    '  arp: false',
    '  hma: false',
    '  shield: false',
    'bridging:',
    `  autoSync: ${autoSync}`,
    '  lastSyncAt: null',
    'registry:',
    '  contribute: false',
    '  gtin: false',
    '  sensorToken: null',
    '',
  ].join('\n'));
  fs.writeFileSync(path.join(dir, '.opena2a', 'guard', 'signatures.json'), JSON.stringify({
    signatures: [{ filePath: 'mcp.json', hash: 'abc', signedAt: '2026-01-02T00:00:00.000Z', signedBy: 'me' }],
  }));
}

function guardEvents(): Logged[] {
  return aimState.log.filter(e => e.action === 'configguard.sign');
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-autosync-'));
  aimState.log = [];
  aimState.logCountAtTrust = -1;
  stdout = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
    stdout += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('identity autoSync', () => {
  it('imports integrated tool events before trust is calculated', async () => {
    writeManifestFile(true);

    const code = await identity({ subcommand: 'trust', dir, format: 'json' });

    expect(code).toBe(0);
    expect(guardEvents()).toHaveLength(1);
    expect(aimState.logCountAtTrust).toBe(1);
    expect(readManifest(dir)?.bridging.lastSyncAt).not.toBeNull();
  });

  it('imports integrated tool events before the audit log is read', async () => {
    writeManifestFile(true);

    const code = await identity({ subcommand: 'audit', dir, format: 'json' });

    expect(code).toBe(0);
    const shown = JSON.parse(stdout) as Logged[];
    expect(shown.map(e => e.action)).toEqual(['configguard.sign']);
  });

  it('does not import an event twice across reads', async () => {
    writeManifestFile(true);

    await identity({ subcommand: 'audit', dir, format: 'json' });
    await identity({ subcommand: 'trust', dir, format: 'json' });

    expect(guardEvents()).toHaveLength(1);
  });

  it('leaves the audit log alone when autoSync is off', async () => {
    writeManifestFile(false);

    await identity({ subcommand: 'trust', dir, format: 'json' });
    await identity({ subcommand: 'audit', dir, format: 'json' });

    expect(guardEvents()).toHaveLength(0);
    expect(readManifest(dir)?.bridging.lastSyncAt).toBeNull();
  });
});

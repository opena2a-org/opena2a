import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// Regression (#410): `identity trust` contributed its summary with scanner
// version 0.6.3, the CLI's version when the value was written, whatever
// version of the CLI ran it; the Registry publishes it as the tool version.

const submission = vi.hoisted(() => ({
  submitScanReport: vi.fn(async () => true),
}));

vi.mock('../../src/util/report-submission.js', () => ({
  recordScanAndMaybePrompt: async () => undefined,
  isContributeEnabled: async () => true,
  getRegistryUrl: async () => 'https://api.oa2a.org',
  submitScanReport: submission.submitScanReport,
}));

vi.mock('../../src/util/identity-auth-lookup.js', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../src/util/identity-auth-lookup.js')>();
  return { ...actual, storedServerUrl: () => undefined };
});

vi.mock('@opena2a/aim-core', () => ({
  AIMCore: class {
    getIdentity(): object { return { agentId: 'agent-1' }; }
    calculateTrust(): object {
      return { score: 40, grade: 'D', factors: { secretsManaged: 0, configSigned: 1 } };
    }
  },
}));

const { identity } = await import('../../src/commands/identity.js');

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-identity-trust-'));
  submission.submitScanReport.mockClear();
  vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
});

describe('identity trust contribution', () => {
  it('is sent with the version of the CLI that ran it', async () => {
    const cliVersion = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf-8')).version;

    const code = await identity({ subcommand: 'trust', dir });

    expect(code).toBe(0);
    expect(submission.submitScanReport).toHaveBeenCalledTimes(1);
    const [, report] = submission.submitScanReport.mock.calls[0] as unknown as [string, Record<string, unknown>];
    expect(report.scannerName).toBe('opena2a-identity');
    expect(report.scannerVersion).toBe(cliVersion);
    expect(report.findings).toEqual([
      expect.objectContaining({ category: 'trust', title: 'secrets Managed not active' }),
    ]);
  });
});

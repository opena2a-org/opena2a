/**
 * protect's completion message (#270): after a migration whose re-scan finds
 * nothing, protect states how many credentials it migrated and how many
 * credential types detection covers. It must never claim that no credentials
 * remain — the scan only finds the types it knows.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { protect } from '../../src/commands/protect.js';
import {
  CREDENTIAL_PATTERNS,
  credentialTypeCount,
  describeMigrationOutcome,
  loadCanonicalPatterns,
  type CanonicalCredentialPattern,
} from '../../src/util/credential-patterns.js';

// Keep the migration off the operator's real vault: the store accepts every
// secret in memory.
vi.mock('secretless-ai', () => {
  class SecretStore {
    async setSecret(): Promise<void> { /* stored in memory */ }
  }
  return { SecretStore, readBackendConfig: () => 'local' };
});

const ABSENCE_CLAIM = /no credentials remain|credentials? (?:are|is) gone|source is clean/i;

describe('describeMigrationOutcome', () => {
  it('states the migrated count, the detected count and the detection coverage', () => {
    const line = describeMigrationOutcome(3, 3, 42);
    expect(line).toBe(
      'Migrated 3 of 3 detected credentials. ' +
      'Detection covers 42 credential types; review the source for credentials of other types.',
    );
  });

  it('uses the singular for one credential and one type', () => {
    expect(describeMigrationOutcome(1, 1, 1)).toBe(
      'Migrated 1 of 1 detected credential. ' +
      'Detection covers 1 credential type; review the source for credentials of other types.',
    );
  });

  it('never asserts that no credentials remain', () => {
    for (const [m, d, t] of [[0, 0, 0], [1, 1, 7], [2, 5, 60]]) {
      expect(describeMigrationOutcome(m, d, t)).not.toMatch(ABSENCE_CLAIM);
    }
  });
});

describe('credentialTypeCount', () => {
  it('is the local pattern count when the catalog is unavailable', () => {
    expect(credentialTypeCount([])).toBe(CREDENTIAL_PATTERNS.length);
  });

  it('counts a type the catalog shares with the local patterns once', () => {
    const shared: CanonicalCredentialPattern = {
      id: 'x', name: CREDENTIAL_PATTERNS[0].title.toUpperCase(), regex: /x/, envPrefix: 'X',
    };
    const extra: CanonicalCredentialPattern = {
      id: 'y', name: 'Some Other Token', regex: /y/, envPrefix: 'Y',
    };
    expect(credentialTypeCount([shared, extra])).toBe(CREDENTIAL_PATTERNS.length + 1);
  });
});

describe('protect completion output', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-protect-claim-'));
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name": "test"}');
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 403 }));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
  });

  it('reports the migrated count and detection coverage, not an absence claim', async () => {
    const fakeKey = 'AIza' + 'Q'.repeat(35);
    fs.writeFileSync(path.join(tempDir, 'api.ts'), `const key = "${fakeKey}";\n`);

    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    }) as typeof process.stdout.write;
    try {
      await protect({ targetDir: tempDir, ci: true, skipSign: true, skipLiveness: true });
    } finally {
      process.stdout.write = origWrite;
    }

    // Strip ANSI colour codes before matching.
    // eslint-disable-next-line no-control-regex
    const out = chunks.join('').replace(/\x1b\[[0-9;]*m/g, '');
    expect(fs.readFileSync(path.join(tempDir, 'api.ts'), 'utf-8')).not.toContain(fakeKey);

    const types = credentialTypeCount(await loadCanonicalPatterns());
    expect(out).toContain(
      `Migrated 1 of 1 detected credential. Detection covers ${types} credential types;`,
    );
    expect(out).not.toMatch(ABSENCE_CLAIM);
    expect(out).not.toContain('Verification passed');
  });
});

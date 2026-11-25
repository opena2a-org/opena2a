import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { formatStatus } from '../../src/shield/status.js';
import type { ShieldStatus } from '../../src/shield/types.js';

// Printed next steps must be commands that run. `opena2a guard init` is an
// unknown subcommand, `opena2a self-register` takes no argument, and the
// secretless package installs a `secretless-ai` binary, not `secretless`.

const SRC = join(__dirname, '..', '..', 'src');
const read = (rel: string) => readFileSync(join(SRC, rel), 'utf-8');

describe('printed next steps name commands that exist', () => {
  it('shield status suggests guard sign for an inactive ConfigGuard', () => {
    const status: ShieldStatus = {
      timestamp: '2026-01-01T00:00:00Z',
      tools: [{ name: 'ConfigGuard', installed: false, active: false, version: null, keyMetric: '' }],
      policyLoaded: true,
      policyMode: 'enforce',
      shellIntegration: true,
      integrityStatus: 'healthy',
      lastReportScore: null,
      lastReportDate: null,
    };
    const out = formatStatus(status, 'text');
    expect(out).toContain('opena2a guard sign');
    expect(out).not.toContain('guard init');
  });

  it('no source file prints guard init, self-register <pkg>, or a bare secretless binary', () => {
    for (const rel of ['shield/status.ts', 'commands/trust.ts', 'commands/claim.ts', 'commands/protect.ts']) {
      const src = read(rel);
      expect(src, rel).not.toMatch(/guard init/);
      expect(src, rel).not.toMatch(/self-register \$\{/);
      expect(src, rel).not.toMatch(/\bsecretless broker start/);
    }
  });

  it('trust points at claim and protect points at secretless-ai broker start', () => {
    expect(read('commands/trust.ts')).toContain('run: opena2a claim ${packageName}');
    expect(read('commands/protect.ts')).toContain('secretless-ai broker start');
  });
});

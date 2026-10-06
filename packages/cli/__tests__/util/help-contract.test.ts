import { describe, it, expect } from 'vitest';
import { HELP_CONTRACTS, formatHelpContract } from '../../src/util/help-contract.js';
import { HELP_WIDTH } from '../../src/util/subcommand-help.js';
import { ADAPTER_REGISTRY } from '../../src/adapters/registry.js';

describe('formatHelpContract', () => {
  it('prints an exit-code section and an automation section with --json and --ci rows', () => {
    const out = formatHelpContract({
      exit: [['0', 'clean'], ['1', 'findings present']],
      json: 'prints the result as JSON',
      ci: 'no effect',
    });
    expect(out.split('\n')).toEqual([
      'Exit codes:',
      '  0  clean',
      '  1  findings present',
      '',
      'Automation:',
      '  --json  prints the result as JSON',
      '  --ci    no effect',
    ]);
  });

  it('wraps a long meaning under its own column', () => {
    const out = formatHelpContract({
      exit: [['engine', 'word '.repeat(30).trim()], ['1', 'short']],
      json: 'x',
      ci: 'y',
    });
    const lines = out.split('\n');
    expect(lines[1].startsWith('  engine  word')).toBe(true);
    expect(lines[2].startsWith('          word')).toBe(true);
    expect(lines.find((l) => l.startsWith('  1 '))).toBe('  1       short');
    for (const line of lines) expect(line.length).toBeLessThanOrEqual(HELP_WIDTH);
  });
});

describe('HELP_CONTRACTS', () => {
  it('has an entry for every adapter command', () => {
    for (const name of Object.keys(ADAPTER_REGISTRY)) {
      expect(HELP_CONTRACTS[name], name).toBeDefined();
    }
  });

  for (const [name, contract] of Object.entries(HELP_CONTRACTS)) {
    it(`${name}: names at least one exit code and both flags, within ${HELP_WIDTH} columns`, () => {
      expect(contract.exit.length).toBeGreaterThan(0);
      for (const [code, meaning] of contract.exit) {
        expect(code).toMatch(/^(\d+|engine)$/);
        expect(meaning.trim()).not.toBe('');
      }
      expect(contract.json.trim()).not.toBe('');
      expect(contract.ci.trim()).not.toBe('');
      const out = formatHelpContract(contract);
      expect(out).not.toMatch(/\u2014/);
      for (const line of out.split('\n')) expect(line.length).toBeLessThanOrEqual(HELP_WIDTH);
    });
  }
});

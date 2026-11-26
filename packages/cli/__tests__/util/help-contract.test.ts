import { describe, it, expect } from 'vitest';
import { HELP_CONTRACTS, adapterSourceLine, formatHelpContract } from '../../src/util/help-contract.js';
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

  // protect and identity revoke both skip their confirmation under --json, not
  // only under --ci; the Automation section has to say so (#418).
  it('protect: --json says it skips the confirmation prompt, and --ci is still needed off a terminal', () => {
    expect(HELP_CONTRACTS.protect.json).toContain('skips the confirmation prompt');
    expect(HELP_CONTRACTS.protect.json).toContain('when stdin is not a terminal, --ci is still needed');
  });

  it('identity: --json says revoke proceeds without the confirmation step, as --ci does', () => {
    expect(HELP_CONTRACTS.identity.json).toContain('revoke proceeds without the confirmation step');
    expect(HELP_CONTRACTS.identity.ci).toContain('revoke proceeds without the confirmation step');
  });

  // An unscannable benchmark target exits 2 (#507); the help listed only 0 and 1.
  it('benchmark: lists exit codes 0, 1 and 2, with 2 for a target that could not be scanned', () => {
    const exit = HELP_CONTRACTS.benchmark.exit;
    expect(exit.map(([code]) => code)).toEqual(['0', '1', '2']);
    expect(Object.fromEntries(exit)['2']).toBe(
      'the target does not exist, is not a directory or could not be read; nothing was scanned',
    );
    const out = formatHelpContract(HELP_CONTRACTS.benchmark);
    expect(out).toMatch(/^ {2}2 {2}the target does not exist/m);
  });
});

describe('adapterSourceLine', () => {
  const lineFor = (name: string): string => {
    const config = ADAPTER_REGISTRY[name];
    const tool = config.packageName ?? config.command ?? config.image ?? config.pythonModule ?? name;
    return adapterSourceLine(config.method, tool);
  };

  it('states each tool\'s real install path and never calls it bundled', () => {
    expect(lineFor('crypto')).toContain('python3 -m cryptoserve');
    expect(lineFor('crypto')).toContain('pipx run cryptoserve');
    expect(lineFor('train')).toContain('opena2a/dvaa Docker image');
    expect(lineFor('train')).toContain('needs Docker');
    for (const name of ['scan', 'secrets', 'registry']) {
      expect(lineFor(name)).toContain('npm dependency installed with opena2a-cli');
    }
    for (const name of Object.keys(ADAPTER_REGISTRY)) {
      expect(lineFor(name)).not.toMatch(/bundled|first use/i);
    }
  });
});

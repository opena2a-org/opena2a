import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  isHelpRequest,
  printSubcommandHelp,
  GUARD_HELP,
  SHIELD_HELP,
  IDENTITY_HELP,
  RUNTIME_HELP,
  SKILL_HELP,
  MCP_HELP,
} from '../../src/util/subcommand-help.js';

function captureStdout(fn: () => boolean): { result: boolean; output: string } {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
  try {
    const result = fn();
    return { result, output: chunks.join('') };
  } finally {
    process.stdout.write = origWrite;
  }
}

describe('isHelpRequest (#132)', () => {
  it('matches --help in the explicit args array', () => {
    expect(isHelpRequest(['sign', '--help'])).toBe(true);
    expect(isHelpRequest(['--help'])).toBe(true);
    expect(isHelpRequest(['-h'])).toBe(true);
  });

  it('returns false when no help flag present', () => {
    expect(isHelpRequest(['sign'])).toBe(false);
    expect(isHelpRequest(['--verbose'])).toBe(false);
    expect(isHelpRequest([])).toBe(false);
  });

  it('falls back to process.argv when args omitted', () => {
    const origArgv = process.argv;
    try {
      process.argv = ['node', 'cli', 'guard', 'sign', '--help'];
      expect(isHelpRequest()).toBe(true);
      process.argv = ['node', 'cli', 'guard', 'sign'];
      expect(isHelpRequest()).toBe(false);
    } finally {
      process.argv = origArgv;
    }
  });
});

describe('printSubcommandHelp (#132)', () => {
  it('prints a per-subcommand help block for a known subcommand', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'sign', GUARD_HELP));
    expect(result).toBe(true);
    expect(output).toContain('Usage: opena2a guard sign');
    expect(output).toContain('Sign config files for integrity verification');
    expect(output).toContain('--files <files...>');
    expect(output).toContain('Examples:');
  });

  it('returns false for an unknown subcommand without printing', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'unknown-sub', GUARD_HELP));
    expect(result).toBe(false);
    expect(output).toBe('');
  });

  it('prints help without an Options section when none are declared', () => {
    const { result, output } = captureStdout(() => printSubcommandHelp('guard', 'watch', GUARD_HELP));
    expect(result).toBe(true);
    expect(output).toContain('Usage: opena2a guard watch');
    expect(output).not.toContain('Options:');
    expect(output).toContain('Examples:');
  });
});

describe('subcommand help registries (#132)', () => {
  it('GUARD_HELP covers all 10 documented guard subcommands', () => {
    const expected = ['sign', 'verify', 'status', 'watch', 'diff', 'policy', 'hook', 'resign', 'snapshot', 'harden'];
    for (const sub of expected) {
      expect(GUARD_HELP[sub], `missing GUARD_HELP entry for ${sub}`).toBeDefined();
      expect(GUARD_HELP[sub].summary.length).toBeGreaterThan(0);
    }
  });

  it('SHIELD_HELP covers all 13 documented shield subcommands', () => {
    const expected = ['init', 'status', 'log', 'selfcheck', 'policy', 'evaluate', 'recover', 'report', 'session', 'baseline', 'suggest', 'explain', 'triage'];
    for (const sub of expected) {
      expect(SHIELD_HELP[sub], `missing SHIELD_HELP entry for ${sub}`).toBeDefined();
    }
  });

  it('RUNTIME_HELP covers all 4 documented runtime subcommands', () => {
    const expected = ['start', 'status', 'tail', 'init'];
    for (const sub of expected) {
      expect(RUNTIME_HELP[sub]).toBeDefined();
    }
  });

  it('SKILL_HELP covers the create subcommand', () => {
    expect(SKILL_HELP.create).toBeDefined();
  });

  it('MCP_HELP covers audit, sign, verify', () => {
    expect(MCP_HELP.audit).toBeDefined();
    expect(MCP_HELP.sign).toBeDefined();
    expect(MCP_HELP.verify).toBeDefined();
  });

  it('IDENTITY_HELP covers every subcommand listed in the parent description', () => {
    const expected = ['list', 'init', 'create', 'trust', 'audit', 'log', 'policy', 'check', 'sign', 'verify', 'integrate', 'detach', 'sync', 'connect', 'disconnect', 'tag', 'mcp', 'activity', 'suspend', 'reactivate'];
    for (const sub of expected) {
      expect(IDENTITY_HELP[sub], `missing IDENTITY_HELP entry for ${sub}`).toBeDefined();
    }
  });
});

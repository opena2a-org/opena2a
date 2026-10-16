/**
 * A natural-language match is confirmed before it runs, and the
 * prompt's default must not be "yes" for a command that changes the project,
 * the keychain or a running daemon. `opena2a nanomind setup` prompted
 * `Run opena2a shield init?` with the default set to yes, so pressing Enter
 * started the 11-step setup.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

const { confirm } = vi.hoisted(() => ({
  confirm: vi.fn(async (_opts: { message: string; default?: boolean }) => false),
}));
vi.mock('@inquirer/prompts', () => ({ confirm }));
// No NanoMind daemon in a unit test: the classifier gate reports "not blocked".
vi.mock('../../src/natural/nanomind-classifier.js', () => ({
  classifyWithNanoMindDaemon: vi.fn(async () => null),
}));

import { confirmExecution, handleNaturalLanguage } from '../../src/natural/llm-fallback.js';
import { INTENT_MAPPINGS, MUTATING_COMMANDS, isMutatingCommand } from '../../src/natural/intent-map.js';

const SPEC_MUTATING = [
  'protect', 'shield init', 'secrets init', 'guard sign', 'guard resign',
  'harden-soul', 'harden-skill', 'fix-all', 'runtime start', 'identity init', 'identity create',
];

describe('confirmation default for a matched command', () => {
  const origTty = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
  const origCi = process.env.CI;
  let output: string[];

  function setTty(value: boolean): void {
    Object.defineProperty(process.stdin, 'isTTY', { value, configurable: true });
  }

  beforeEach(() => {
    confirm.mockClear();
    delete process.env.CI;
    setTty(true);
    output = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      output.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);
    vi.spyOn(process.stderr, 'write').mockImplementation((() => true) as typeof process.stderr.write);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (origTty) Object.defineProperty(process.stdin, 'isTTY', origTty);
    else delete (process.stdin as { isTTY?: boolean }).isTTY;
    if (origCi === undefined) delete process.env.CI;
    else process.env.CI = origCi;
  });

  it('prompts with default no before the 11-step setup', async () => {
    const result = await handleNaturalLanguage('get started');
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm.mock.calls[0][0].message).toBe('Run opena2a shield init?');
    expect(confirm.mock.calls[0][0].default).toBe(false);
    expect(result).toBeNull();
  });

  it('keeps default yes for a read-only command', async () => {
    await handleNaturalLanguage('find secrets');
    expect(confirm).toHaveBeenCalledTimes(1);
    expect(confirm.mock.calls[0][0].message).toBe('Run opena2a secrets scan?');
    expect(confirm.mock.calls[0][0].default).toBe(true);
  });

  it('every mapping whose command is in the mutating set prompts with default no', async () => {
    const mutating = INTENT_MAPPINGS.filter(m => isMutatingCommand(m.command));
    expect(mutating.map(m => m.command)).toEqual(
      expect.arrayContaining(['opena2a shield init', 'opena2a protect', 'opena2a secrets init', 'opena2a runtime start']),
    );
    for (const mapping of INTENT_MAPPINGS) {
      confirm.mockClear();
      await confirmExecution(mapping.command);
      expect(confirm, mapping.command).toHaveBeenCalledTimes(1);
      expect(confirm.mock.calls[0][0].default, mapping.command).toBe(!isMutatingCommand(mapping.command));
    }
  });

  it('never dispatches without a terminal and prints the command instead', async () => {
    setTty(false);
    expect(await confirmExecution('opena2a shield init')).toBe(false);
    expect(await confirmExecution('opena2a secrets scan')).toBe(false);
    expect(confirm).not.toHaveBeenCalled();
    expect(output.join('')).toContain('Run with:');
  });
});

describe('isMutatingCommand', () => {
  it('holds every command the mutating set is specified to contain', () => {
    for (const command of SPEC_MUTATING) {
      expect(MUTATING_COMMANDS, command).toContain(command);
      expect(isMutatingCommand(`opena2a ${command}`), command).toBe(true);
    }
  });

  it('matches on the command path, ignoring arguments', () => {
    expect(isMutatingCommand('opena2a guard sign config.json')).toBe(true);
    expect(isMutatingCommand('opena2a identity create --name my-agent')).toBe(true);
    expect(isMutatingCommand('opena2a protect ./src')).toBe(true);
  });

  it('treats a dry run and the read-only commands as read-only', () => {
    expect(isMutatingCommand('opena2a protect . --dry-run')).toBe(false);
    expect(isMutatingCommand('opena2a guard verify')).toBe(false);
    expect(isMutatingCommand('opena2a secrets scan')).toBe(false);
    expect(isMutatingCommand('opena2a scan secure')).toBe(false);
    expect(isMutatingCommand('opena2a init')).toBe(false);
    expect(isMutatingCommand('opena2a identity')).toBe(false);
  });

  it('treats --fix as a change to the project', () => {
    expect(isMutatingCommand('opena2a scan secure --fix')).toBe(true);
  });
});

import { describe, it, expect, afterEach } from 'vitest';
import * as os from 'node:os';
import { guard } from '../../src/commands/guard.js';
import { runtime } from '../../src/commands/runtime.js';
import { shield } from '../../src/commands/shield.js';
import { printUnknownSubcommand } from '../../src/util/subcommand-help.js';

// A word that would clear the line, move the cursor and forge a line of its
// own if it reached the terminal as typed.
const CRAFTED = 'signs\x1b[2K\r\x1b]0;title\x07\nOK: all files verified\x9b31m\x7f';

async function captureStderr(fn: () => unknown): Promise<string> {
  const chunks: string[] = [];
  const origErr = process.stderr.write;
  process.stderr.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
  try {
    await fn();
  } finally {
    process.stderr.write = origErr;
  }
  return chunks.join('');
}

function expectNoControlCharacters(stderr: string, parent: string): void {
  // The word stays on the one line that names it as unknown.
  expect(stderr).toMatch(new RegExp(`^Unknown ${parent} subcommand: signs[^\\n]*OK: all files verified31m\\n\\n`));
  // Only the line ends the CLI writes itself remain.
  expect(stderr.replace(/\n/g, '')).not.toMatch(/[\x00-\x1f\x7f-\x9f]/);
}

describe('an unknown subcommand is echoed without control characters', () => {
  const savedExitCode = process.exitCode;
  afterEach(() => { process.exitCode = savedExitCode; });

  it('guard', async () => {
    let code = 0;
    const stderr = await captureStderr(async () => {
      code = await guard({ subcommand: CRAFTED, targetDir: os.tmpdir() } as Parameters<typeof guard>[0]);
    });
    expect(code).toBe(1);
    expectNoControlCharacters(stderr, 'guard');
  });

  it('runtime', async () => {
    let code = 0;
    const stderr = await captureStderr(async () => {
      code = await runtime({ subcommand: CRAFTED, targetDir: os.tmpdir() } as unknown as Parameters<typeof runtime>[0]);
    });
    expect(code).toBe(1);
    expectNoControlCharacters(stderr, 'runtime');
  });

  it('shield', async () => {
    let code = 0;
    const stderr = await captureStderr(async () => {
      code = await shield({ subcommand: CRAFTED });
    });
    expect(code).toBe(1);
    expectNoControlCharacters(stderr, 'shield');
  });

  it('the --help answer', async () => {
    const stderr = await captureStderr(() => printUnknownSubcommand('guard', CRAFTED, () => 'help\n'));
    expect(process.exitCode).toBe(1);
    expect(stderr).toBe('Unknown guard subcommand: signs[2K]0;titleOK: all files verified31m\n\nhelp\n');
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { selfRegister } from '../../src/commands/self-register.js';
import type { SelfRegisterOptions } from '../../src/commands/self-register.js';

// `self-register` writes to the PUBLIC registry (POST
// /api/v1/registry/community/scan-result). Before this gate, the destructive
// path was the default: `--dry-run` was opt-in and nothing else stood between
// an invocation and a production write. A fresh-user release-test subagent ran
// the bare command and submitted scan results for the whole tool manifest to
// https://api.oa2a.org from a developer laptop. A sandboxed HOME did not stop
// it, and OPENA2A_TELEMETRY_URL does not apply — self-register talks to the
// registry directly.
//
// The contract these tests pin: no network WRITE without either an explicit
// `--yes` or an interactive confirmation. Refusal must be non-zero so a script
// that assumed the old behavior fails loudly instead of silently doing nothing.

const mockFetch = vi.fn();

function captureStdout(fn: () => Promise<number>): Promise<{ exitCode: number; output: string }> {
  const chunks: string[] = [];
  const origWrite = process.stdout.write;
  process.stdout.write = ((chunk: any) => {
    chunks.push(String(chunk));
    return true;
  }) as any;

  return fn().then(exitCode => {
    process.stdout.write = origWrite;
    return { exitCode, output: chunks.join('') };
  }).catch(err => {
    process.stdout.write = origWrite;
    throw err;
  });
}

/** Mock that accepts every registry call, so any write attempt is visible. */
function mockAcceptEverything() {
  mockFetch.mockImplementation(async (url: string) => {
    if (String(url).includes('by-name')) {
      return { ok: true, json: async () => ({ data: { id: 'pkg-1' } }) };
    }
    if (String(url).includes('request-scan-token')) {
      return { ok: true, json: async () => ({ scanToken: 'tok-123' }) };
    }
    if (String(url).includes('scan-result')) {
      return { ok: true, json: async () => ({ status: 'accepted' }) };
    }
    return { ok: false, status: 500 };
  });
}

/** Registry calls that mutate state. GETs (existence checks) are harmless. */
function writeCalls(): string[] {
  return mockFetch.mock.calls
    .map(c => String(c[0]))
    .filter(u => u.includes('scan-result') || u.includes('request-scan-token'));
}

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('self-register confirmation gate', () => {
  it('makes NO registry write non-interactively without --yes, and exits non-zero', async () => {
    mockAcceptEverything();

    const options: SelfRegisterOptions = {
      ci: true, // non-interactive: cannot prompt
      format: 'json',
      only: ['hackmyagent'],
    };

    const { exitCode } = await captureStdout(() => selfRegister(options));

    // The load-bearing assertion: nothing was submitted to the registry.
    expect(writeCalls()).toEqual([]);
    // And the refusal is loud, not a silent no-op.
    expect(exitCode).not.toBe(0);
  });

  it('names --yes and --dry-run in the refusal so the user is not left guessing', async () => {
    mockAcceptEverything();

    const { output } = await captureStdout(() => selfRegister({
      ci: true,
      format: 'text',
      only: ['hackmyagent'],
    }));

    expect(output).toContain('--yes');
    expect(output).toContain('--dry-run');
  });

  it('DOES write when --yes is given (gate is not simply blocking everything)', async () => {
    mockAcceptEverything();

    const { exitCode } = await captureStdout(() => selfRegister({
      ci: true,
      yes: true,
      skipScan: true,
      format: 'json',
      only: ['hackmyagent'],
    }));

    // Positive control: without this, a fix that blocks unconditionally passes.
    expect(writeCalls().length).toBeGreaterThan(0);
    expect(exitCode).toBe(0);
  });

  it('still allows --dry-run with no --yes, and makes no request at all', async () => {
    mockAcceptEverything();

    const { exitCode } = await captureStdout(() => selfRegister({
      dryRun: true,
      ci: true,
      format: 'json',
      only: ['hackmyagent'],
    }));

    expect(mockFetch).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
  });

  it('refuses before any per-tool work, not after scanning the whole manifest', async () => {
    mockAcceptEverything();

    // No `only` filter: the full 11-tool manifest. A gate placed inside the
    // per-tool loop would still fire HMA scans and existence checks before
    // refusing; the gate belongs ahead of the loop.
    await captureStdout(() => selfRegister({ ci: true, format: 'json' }));

    expect(mockFetch).not.toHaveBeenCalled();
  });
});

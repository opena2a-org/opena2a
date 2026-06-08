import { describe, it, expect, vi, afterEach } from 'vitest';
import { withRebrandedStdout } from '../../src/adapters/import.js';

/**
 * issue #191 (defense-in-depth): an import-adapter tool that exposes a
 * programmatic `run`/`main` writes its Commander help straight to
 * process.stdout, bypassing the streaming rebrander a spawned child gets.
 * `withRebrandedStdout` intercepts those writes, line-rebrands them, and
 * restores the original writer in `finally`.
 */
describe('withRebrandedStdout — programmatic-path interception', () => {
  const original = process.stdout.write;
  afterEach(() => {
    process.stdout.write = original;
  });

  it('rebrands string writes emitted by the wrapped fn', async () => {
    const spy = vi.fn().mockReturnValue(true);
    process.stdout.write = spy as unknown as typeof process.stdout.write;

    await withRebrandedStdout(async () => {
      process.stdout.write('Usage: cryptoserve <command>\n');
      process.stdout.write('  $ secretless-ai scan\n');
    });

    const written = spy.mock.calls.map((c) => c[0]).join('');
    expect(written).toContain('Usage: opena2a crypto <command>');
    expect(written).toContain('opena2a secrets scan');
    expect(written).not.toContain('cryptoserve <command>');
  });

  it('rebrands Buffer writes too', async () => {
    const spy = vi.fn().mockReturnValue(true);
    process.stdout.write = spy as unknown as typeof process.stdout.write;

    await withRebrandedStdout(async () => {
      process.stdout.write(Buffer.from('hackmyagent secure\n'));
    });

    expect(spy.mock.calls.map((c) => c[0]).join('')).toContain('opena2a secure');
  });

  it('restores the original writer even when the wrapped fn throws', async () => {
    const spy = vi.fn().mockReturnValue(true);
    process.stdout.write = spy as unknown as typeof process.stdout.write;

    await expect(
      withRebrandedStdout(async () => {
        process.stdout.write('cryptoserve login\n');
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');

    // The line written before the throw was still rebranded and emitted...
    expect(spy.mock.calls.map((c) => c[0]).join('')).toContain('opena2a crypto login');

    // ...and the patch was removed: a subsequent write is no longer rebranded
    // (it reaches the underlying writer verbatim).
    spy.mockClear();
    process.stdout.write('cryptoserve login\n');
    expect(spy).toHaveBeenCalledWith('cryptoserve login\n');
  });

  it('is non-reentrant: a nested call does not leak the patch (restores cleanly)', async () => {
    const spy = vi.fn().mockReturnValue(true);
    process.stdout.write = spy as unknown as typeof process.stdout.write;

    await withRebrandedStdout(async () => {
      // Inner call must NOT re-patch / capture the already-patched writer as its
      // "original" -- doing so would restore to a patched fn and leak forever.
      await withRebrandedStdout(async () => {
        process.stdout.write('cryptoserve login\n');
      });
    });

    // After both calls unwind, a fresh write is no longer rebranded -> the
    // process-global was fully restored, not left double-patched.
    spy.mockClear();
    process.stdout.write('cryptoserve login\n');
    expect(spy).toHaveBeenCalledWith('cryptoserve login\n');
  });
});

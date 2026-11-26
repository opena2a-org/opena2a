/**
 * `opena2a identity` with no subcommand prints the usage and exits 1, as
 * guard, runtime and shield do, instead of running `identity list`.
 */
import { describe, it, expect, afterEach, vi } from 'vitest';

import { identity } from '../../src/commands/identity.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('identity with no subcommand', () => {
  it('prints the usage on stderr, nothing on stdout, and exits 1', async () => {
    let out = '';
    let err = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: any) => { out += String(chunk); return true; });
    vi.spyOn(process.stderr, 'write').mockImplementation((chunk: any) => { err += String(chunk); return true; });

    expect(await identity({ subcommand: '', ci: false, format: 'text', verbose: false })).toBe(1);

    expect(out).toBe('');
    expect(err).toContain('Usage: opena2a identity <subcommand>');
    expect(err).not.toContain('Unknown identity subcommand');
  });
});

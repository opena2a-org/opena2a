/**
 * `opena2a config` (#343): the documented `config set contribute false`
 * answered "Unknown config action: set" and exited 1.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { loadUserConfig } from '@opena2a/shared';
import { runConfig, parseToggleValue } from '../../src/commands/config.js';

let home: string;
let savedHome: string | undefined;
let out: string;
let err: string;

async function enabled(key: 'contribute' | 'llm'): Promise<boolean> {
  return loadUserConfig()[key].enabled;
}

beforeEach(() => {
  savedHome = process.env.HOME;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-config-'));
  process.env.HOME = home;
  out = '';
  err = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: any) => { out += String(chunk); return true; });
  vi.spyOn(process.stderr, 'write').mockImplementation((chunk: any) => { err += String(chunk); return true; });
});

afterEach(() => {
  vi.restoreAllMocks();
  process.env.HOME = savedHome;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('config set (#343)', () => {
  it('accepts the documented form `config set contribute false`', async () => {
    await runConfig('set', 'contribute', 'on');
    expect(await enabled('contribute')).toBe(true);
    out = '';

    expect(await runConfig('set', 'contribute', 'false')).toBe(0);
    expect(out).toBe('Community contributions disabled.\n');
    expect(err).toBe('');
    expect(await enabled('contribute')).toBe(false);
  });

  it('accepts on/off and true/false for both keys', async () => {
    expect(await runConfig('set', 'contribute', 'off')).toBe(0);
    expect(await enabled('contribute')).toBe(false);
    expect(await runConfig('set', 'contribute', 'true')).toBe(0);
    expect(await enabled('contribute')).toBe(true);
    expect(await runConfig('set', 'llm', 'on')).toBe(0);
    expect(await enabled('llm')).toBe(true);
    expect(await runConfig('set', 'llm', 'false')).toBe(0);
    expect(await enabled('llm')).toBe(false);
  });

  it('takes --enable / --disable in place of the value', async () => {
    expect(await runConfig('set', 'llm', undefined, { enable: true })).toBe(0);
    expect(await enabled('llm')).toBe(true);
    expect(await runConfig('set', 'llm', undefined, { disable: true })).toBe(0);
    expect(await enabled('llm')).toBe(false);
  });

  it('refuses an unknown key, a missing key and a missing value, and changes nothing', async () => {
    await runConfig('set', 'contribute', 'on');
    err = '';

    expect(await runConfig('set', 'registry', 'off')).toBe(1);
    expect(err).toMatch(/Unknown config key: registry \(expected contribute or llm\)/);
    expect(await runConfig('set', undefined, undefined)).toBe(1);
    expect(err).toMatch(/config set needs a key/);
    expect(await runConfig('set', 'contribute', undefined)).toBe(1);
    expect(err).toMatch(/config set contribute needs a value: on or off/);
    expect(await enabled('contribute')).toBe(true);
  });

  it('refuses a value that is not on or off instead of printing the status and exiting 0', async () => {
    await runConfig('set', 'contribute', 'on');
    expect(await runConfig('set', 'contribute', 'maybe')).toBe(1);
    expect(err).toMatch(/Unknown value for contribute: maybe \(expected on or off\)/);
    expect(await runConfig('contribute', 'banana', undefined)).toBe(1);
    expect(await enabled('contribute')).toBe(true);
  });
});

describe('config contribute / llm (unchanged forms)', () => {
  it('still sets with on/off and --enable/--disable, and prints the status with no value', async () => {
    expect(await runConfig('contribute', 'off', undefined)).toBe(0);
    expect(out).toBe('Community contributions disabled.\n');
    expect(await runConfig('contribute', undefined, undefined, { enable: true })).toBe(0);
    expect(await enabled('contribute')).toBe(true);
    out = '';
    expect(await runConfig('contribute', undefined, undefined)).toBe(0);
    expect(out).toMatch(/^Contribute: enabled\n/);
    expect(await runConfig('llm', 'on', undefined)).toBe(0);
    expect(out).toMatch(/LLM features enabled\.\n$/);
  });

  it('an unknown action exits 1 and the usage names config set', async () => {
    expect(await runConfig('frobnicate', undefined, undefined)).toBe(1);
    expect(err).toMatch(/^Unknown config action: frobnicate\n/);
    expect(err).toMatch(/opena2a config set contribute\|llm on\|off/);
  });
});

describe('parseToggleValue', () => {
  it('reads the on and off words and nothing else', () => {
    for (const v of ['on', 'ON', 'true', 'enable', 'enabled', 'yes', '1']) expect(parseToggleValue(v), v).toBe(true);
    for (const v of ['off', 'false', 'False', 'disable', 'disabled', 'no', '0']) expect(parseToggleValue(v), v).toBe(false);
    for (const v of [undefined, '', 'maybe', 'onn']) expect(parseToggleValue(v), String(v)).toBeNull();
  });
});

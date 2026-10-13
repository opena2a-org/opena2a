/**
 * What the CLI says about checking an installation matches what it checks
 * (#434).
 *
 * The README, and now the "Verifying what was installed" section of
 * docs/verifying-npm-packages.md, said `opena2a status` reports the binary signature state and
 * `opena2a shield selfcheck` attests the install against an embedded
 * manifest. No manifest ships with the package, `status` repeats the
 * selfcheck verdict, and selfcheck reads only Shield's own state. `verify`
 * was described as verifying the binary integrity of installed OpenA2A
 * packages: it hashes one entry file per package, asks the registry about
 * that hash, and its default list leaves out opena2a-cli.
 *
 * The verify help is read from the built `dist/index.js`, as in
 * help-layout.test.ts.
 */
import { describe, it, expect, vi, afterEach } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { SHIELD_HELP } from '../src/util/subcommand-help.js';
import { verify, _internals, VERIFIABLE_PACKAGES } from '../src/commands/verify.js';

const REPO_ROOT = resolve(__dirname, '../../..');
const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;
const PROVENANCE_DOC = 'docs/verifying-npm-packages.md';
// Claims of an install check that no command performs.
const UNBACKED = [/embedded manifest/i, /binary signature/i, /binary integrity/i, /self-attestation/i];

/** The provenance page's "Verifying what was installed" section, up to the next `## `. */
function verifyingSection(): string {
  const page = readFileSync(resolve(REPO_ROOT, PROVENANCE_DOC), 'utf-8');
  const start = page.indexOf('## Verifying what was installed');
  expect(start).toBeGreaterThan(-1);
  const end = page.indexOf('\n## ', start + 1);
  return page.slice(start, end === -1 ? undefined : end);
}

function verifyHelp(): string {
  const res = spawnSync(process.execPath, [CLI_PATH, 'verify', '--help'], {
    encoding: 'utf8',
    timeout: 20000,
    input: '',
    env: { ...process.env, NODE_OPTIONS: '', NO_COLOR: '1', OPENA2A_TELEMETRY: 'off' },
  });
  expect(res.status).toBe(0);
  return (res.stdout ?? '').replace(STRIP_ANSI, '');
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('install-integrity claims (#434)', () => {
  it('the verifying page claims no install check the CLI does not run', () => {
    const section = verifyingSection();
    for (const pattern of UNBACKED) expect(section).not.toMatch(pattern);
    expect(section).toContain('No command compares the installed files of `opena2a-cli` with the published package');
  });

  it('the verifying page names what verify hashes and how to reach opena2a-cli', () => {
    const section = verifyingSection();
    for (const pkg of VERIFIABLE_PACKAGES) expect(section).toContain(`\`${pkg}\``);
    expect(section).toContain('`opena2a verify --package opena2a-cli`');
    // The tarball check is the page's own per-package block, so the section links up to it.
    expect(section).toContain('](#opena2a-cli)');
    expect(readFileSync(resolve(REPO_ROOT, PROVENANCE_DOC), 'utf-8')).toContain('\n## `opena2a-cli`\n');
  });

  it('shield selfcheck --help names Shield state, not binary signatures', () => {
    const summary = SHIELD_HELP.selfcheck.summary;
    for (const pattern of UNBACKED) expect(summary).not.toMatch(pattern);
    expect(summary).toContain("It does not check the CLI's installed files.");
  });

  it('dist/index.js exists', () => {
    expect(existsSync(CLI_PATH)).toBe(true);
  });

  it.runIf(existsSync(CLI_PATH))('verify --help names every default package and says opena2a-cli is not one', () => {
    const help = verifyHelp();
    for (const pattern of UNBACKED) expect(help).not.toMatch(pattern);
    const prose = help.replace(/\s+/g, ' ');
    for (const pkg of VERIFIABLE_PACKAGES) expect(prose).toContain(pkg);
    expect(VERIFIABLE_PACKAGES).not.toContain('opena2a-cli');
    expect(prose).toContain('opena2a-cli is not in that list');
    expect(prose).toContain('"no data" means the registry returned neither a match nor a mismatch; it is not a pass.');
    expect(help).toContain(`https://github.com/opena2a-org/opena2a/blob/main/${PROVENANCE_DOC}`);
  });

  it('the verify text heading does not claim binary integrity', async () => {
    vi.spyOn(_internals, 'resolvePackagePath').mockReturnValue({ mainFile: __filename, version: '0.0.0' });
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 404, json: async () => ({}) }));
    const chunks: string[] = [];
    vi.spyOn(process.stdout, 'write').mockImplementation(((chunk: unknown) => {
      chunks.push(String(chunk));
      return true;
    }) as typeof process.stdout.write);

    const exitCode = await verify({ packageName: 'hackmyagent', registryUrl: 'https://test-registry.example.com' });

    const output = chunks.join('').replace(STRIP_ANSI, '');
    expect(exitCode).toBe(0);
    for (const pattern of UNBACKED) expect(output).not.toMatch(pattern);
    expect(output.split('\n')[0]).toBe('Looking up installed OpenA2A package hashes in the registry');
    expect(output).toContain('no data');
  });
});

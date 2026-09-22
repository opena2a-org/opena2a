/**
 * The model CLI gets a declared contract and keeps working (#246).
 *
 * shield/llm-backend.ts runs `claude --print` for the optional semantic pass.
 * At base it handed that child `{ ...process.env }`. This test runs the REAL
 * `execFileSync` against a stub `claude` placed first on PATH, so it measures
 * what the binary actually receives rather than what a mock was told — the
 * probe that the narrowed environment still carries what the tool needs, and
 * nothing it does not.
 *
 * Enumerated in child-process-audit.ts: the stubs are started by the module
 * under test, one at a time and synchronous, and this file's own static
 * import is for the one-shot probe that checks the stub directory is on a
 * filesystem that permits execution.
 */
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { spawnSync } from 'node:child_process';

import { CHILD_ENV_CONTRACTS } from '../../src/adapters/registry.js';
import { looksLikeCredentialName } from '../../src/util/child-env.js';
import { callClaudeCode, isClaudeCodeAvailable } from '../../src/shield/llm-backend.js';

const REQUIRED_EXACT = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL', 'AWS_BEARER_TOKEN_BEDROCK'];
const REQUIRED_PREFIXES = ['ANTHROPIC_', 'CLAUDE_', 'CLAUDE_CODE_', 'AWS_'];

const REGISTRY_SOURCE = path.resolve(__dirname, '..', '..', 'src', 'adapters', 'registry.ts');

describe('CHILD_ENV_CONTRACTS.claude (#246)', () => {
  it('OPA-14.AC5 declares the four credential names and the four prefixes', () => {
    const contract = CHILD_ENV_CONTRACTS.claude;
    expect(contract.envInherit).toBeUndefined();
    for (const name of REQUIRED_EXACT) expect(contract.envAllow, name).toContain(name);
    for (const prefix of REQUIRED_PREFIXES) expect(contract.envAllowPrefixes, prefix).toContain(prefix);
  });

  it('OPA-14.AC5 the credential entries are exact because the guard blocks them on a prefix match', () => {
    // A prefix match passes through looksLikeCredentialName, so a credential
    // under ANTHROPIC_ / AWS_ reaches the child only as an exact entry. The
    // three credentials in the contract are exactly such names; the endpoint
    // (ANTHROPIC_BASE_URL) is exact because it selects where the credential
    // is sent, not because the guard would drop it.
    for (const name of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'AWS_BEARER_TOKEN_BEDROCK']) {
      expect(looksLikeCredentialName(name), name).toBe(true);
    }
    expect(looksLikeCredentialName('ANTHROPIC_BASE_URL')).toBe(false);
    // And a credential under a declared prefix that is NOT declared exactly
    // stays out — the guard still applies to prefix matches.
    expect(looksLikeCredentialName('AWS_SECRET_ACCESS_KEY')).toBe(true);
  });

  it('OPA-14.AC5 every further exact name carries a comment citing the tool’s published reference', () => {
    const extra = (CHILD_ENV_CONTRACTS.claude.envAllow ?? []).filter(n => !REQUIRED_EXACT.includes(n));
    const lines = fs.readFileSync(REGISTRY_SOURCE, 'utf-8').split('\n');
    for (const name of extra) {
      const idx = lines.findIndex(l => l.includes(`'${name}'`));
      expect(idx, `${name} is declared in registry.ts`).toBeGreaterThanOrEqual(0);
      const context = [lines[idx - 2] ?? '', lines[idx - 1] ?? '', lines[idx]].join('\n');
      expect(context, `${name} must cite the line of the published environment-variable reference`)
        .toMatch(/\/\/.*(reference|docs).*(line|:\d+|#)/i);
    }
  });
});

describe('claude on PATH receives the contract (#246)', () => {
  const posix = process.platform !== 'win32';
  let stubDir = '';
  let savedPath: string | undefined;
  let savedEnv: Record<string, string | undefined> = {};

  /**
   * A directory the stubs can be executed from. `os.tmpdir()` first; if that
   * filesystem is mounted `noexec` (execvp then skips the stub and keeps
   * searching PATH, so a real `claude` elsewhere would answer instead), fall
   * back to a scratch directory inside this package, removed in afterAll.
   */
  function executableScratchDir(): string {
    const candidates = [tmpdir(), path.resolve(__dirname, '..')];
    for (const base of candidates) {
      const dir = fs.mkdtempSync(path.join(base, '.opena2a-claude-stub-'));
      const probe = path.join(dir, 'probe');
      fs.writeFileSync(probe, '#!/bin/sh\nexit 0\n', { mode: 0o755 });
      if (spawnSync(probe, [], { stdio: 'ignore' }).status === 0) return dir;
      fs.rmSync(dir, { recursive: true, force: true });
    }
    throw new Error(`no executable scratch directory among ${candidates.join(', ')}`);
  }

  beforeAll(() => {
    if (!posix) return;
    stubDir = executableScratchDir();
    // `claude` prints its own environment as the `result` field of the JSON
    // callClaudeCode parses; `which` records its environment to a file and
    // prints a path, so both children the backend starts are observed.
    const claudeJs = path.join(stubDir, 'claude-stub.js');
    fs.writeFileSync(claudeJs,
      'process.stdout.write(JSON.stringify({ result: JSON.stringify(process.env) }));\n');
    const whichJs = path.join(stubDir, 'which-stub.js');
    fs.writeFileSync(whichJs,
      `require('node:fs').writeFileSync(${JSON.stringify(path.join(stubDir, 'which-env.json'))}, JSON.stringify(process.env));\n` +
      `process.stdout.write(${JSON.stringify(path.join(stubDir, 'claude'))} + '\\n');\n`);
    // The absolute node path is baked in: the child's PATH is the filtered
    // one, and the stub must not depend on where node lives in it.
    fs.writeFileSync(path.join(stubDir, 'claude'),
      `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(claudeJs)} "$@"\n`, { mode: 0o755 });
    fs.writeFileSync(path.join(stubDir, 'which'),
      `#!/bin/sh\nexec ${JSON.stringify(process.execPath)} ${JSON.stringify(whichJs)} "$@"\n`, { mode: 0o755 });
  });

  afterAll(() => {
    if (stubDir) fs.rmSync(stubDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    savedPath = process.env.PATH;
    savedEnv = {
      ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY,
      GITHUB_TOKEN: process.env.GITHUB_TOKEN,
      CLAUDECODE: process.env.CLAUDECODE,
      CLAUDE_CODE_USE_BEDROCK: process.env.CLAUDE_CODE_USE_BEDROCK,
      AWS_SECRET_ACCESS_KEY: process.env.AWS_SECRET_ACCESS_KEY,
    };
    process.env.PATH = `${stubDir}${path.delimiter}${savedPath ?? ''}`;
    process.env.ANTHROPIC_API_KEY = 'PLANTED-anthropic';
    process.env.GITHUB_TOKEN = 'PLANTED-gh';
    process.env.CLAUDE_CODE_USE_BEDROCK = '1';
    process.env.AWS_SECRET_ACCESS_KEY = 'PLANTED-aws-secret';
    delete process.env.CLAUDECODE;
  });

  afterEach(() => {
    process.env.PATH = savedPath;
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  });

  it.skipIf(!posix)('OPA-14.AC5 the stub claude sees ANTHROPIC_API_KEY and not GITHUB_TOKEN', () => {
    const response = callClaudeCode('system prompt', 'user prompt', 100);
    expect(response, 'callClaudeCode returned a response from the stub').not.toBeNull();
    expect(response!.backend).toBe('claude-code');
    const seen = JSON.parse(response!.text) as Record<string, string>;
    expect(seen.ANTHROPIC_API_KEY).toBe('PLANTED-anthropic');
    expect(seen.GITHUB_TOKEN).toBeUndefined();
    expect(seen).not.toHaveProperty('OPENA2A_CHILD_ENV_ALLOW');
    // Prefix matches carry configuration, and the guard keeps credentials
    // under a prefix out unless declared exactly.
    expect(seen.CLAUDE_CODE_USE_BEDROCK).toBe('1');
    expect(seen.AWS_SECRET_ACCESS_KEY).toBeUndefined();
    expect(seen.PATH).toBe(process.env.PATH);
    expect(seen.HOME).toBe(process.env.HOME);
  });

  it.skipIf(!posix)('OPA-14.AC5 the which-claude probe sees neither ANTHROPIC_API_KEY nor GITHUB_TOKEN', () => {
    const record = path.join(stubDir, 'which-env.json');
    fs.rmSync(record, { force: true });
    expect(isClaudeCodeAvailable()).toBe(true);
    const seen = JSON.parse(fs.readFileSync(record, 'utf-8')) as Record<string, string>;
    expect(seen.ANTHROPIC_API_KEY).toBeUndefined();
    expect(seen.GITHUB_TOKEN).toBeUndefined();
    expect(seen.PATH).toBe(process.env.PATH);
  });
});

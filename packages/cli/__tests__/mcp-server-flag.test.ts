/**
 * `opena2a mcp sign --server X` (#344).
 *
 * `mcp` allows unknown options, so before `--server` was declared the flag
 * was skipped and its value became a third positional: "error: too many
 * arguments for 'mcp'. Expected 2 arguments but got 3." Exercises the built
 * `dist/index.js`, because the defect was in how the command line parsed.
 */
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { resolveMcpServerArg } from '../src/util/mcp-server-arg.js';

const CLI_PATH = resolve(__dirname, '../dist/index.js');
const STRIP_ANSI = /\x1b\[[0-9;]*m/g;

let root: string;
let project: string;
let env: NodeJS.ProcessEnv;

function runCli(args: string[]) {
  const res = spawnSync(process.execPath, [CLI_PATH, ...args], {
    cwd: project,
    encoding: 'utf8',
    timeout: 60_000,
    env,
  });
  return { status: res.status, out: `${res.stdout ?? ''}\n${res.stderr ?? ''}`.replace(STRIP_ANSI, '') };
}

beforeAll(() => {
  root = mkdtempSync(join(tmpdir(), 'opena2a-mcp-server-flag-'));
  project = join(root, 'project');
  const home = join(root, 'home');
  mkdirSync(project);
  mkdirSync(home);
  writeFileSync(
    join(project, '.mcp.json'),
    '{"mcpServers":{"filesystem":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem","/tmp"]}}}\n',
  );
  env = {
    PATH: process.env.PATH,
    HOME: home,
    XDG_CONFIG_HOME: join(home, '.config'),
    OPENA2A_TELEMETRY: 'off',
  };
});

afterAll(() => {
  rmSync(root, { recursive: true, force: true });
});

describe('mcp --server (#344)', () => {
  it('signs and verifies with --server, the same as with the positional', () => {
    const sign = runCli(['mcp', 'sign', '--server', 'filesystem']);
    expect(sign.out).not.toMatch(/too many arguments/);
    expect(sign.status).toBe(0);
    expect(sign.out).toMatch(/MCP server signed successfully/);
    expect(sign.out).toMatch(/Server:\s+filesystem/);

    const verify = runCli(['mcp', 'verify', '--server', 'filesystem']);
    expect(verify.status).toBe(0);
    expect(verify.out).toMatch(/Server:\s+filesystem/);

    const positional = runCli(['mcp', 'sign', 'filesystem']);
    expect(positional.status).toBe(0);
    expect(positional.out).toMatch(/Server:\s+filesystem/);
  }, 120_000);

  it('refuses two different server names', () => {
    const both = runCli(['mcp', 'sign', 'other', '--server', 'filesystem']);
    expect(both.status).toBe(1);
    expect(both.out).toMatch(/Two different servers given: 'other' and --server 'filesystem'/);
  }, 60_000);
});

describe('resolveMcpServerArg', () => {
  it('takes either form, agrees when both name the same server, and refuses a conflict', () => {
    expect(resolveMcpServerArg('a', undefined)).toEqual({ server: 'a' });
    expect(resolveMcpServerArg(undefined, 'a')).toEqual({ server: 'a' });
    expect(resolveMcpServerArg('a', 'a')).toEqual({ server: 'a' });
    expect(resolveMcpServerArg(undefined, undefined)).toEqual({ server: undefined });
    expect(resolveMcpServerArg('a', 'b')).toHaveProperty('error');
  });
});

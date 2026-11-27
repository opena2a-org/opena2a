/**
 * With OPENA2A_HOME set, the aim-core identity lives in
 * $OPENA2A_HOME/aim-core: `guard sign`, `shield status` and the AIM server
 * connection file read and write there, and nothing is created under
 * ~/.opena2a/aim-core. (`shield init` is covered in
 * shield/init-aim-core-home.test.ts.)
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return { ...actual, homedir: () => _mockHomeDir };
});

const { getAimCoreDir, displayAimCoreDir } = await import('../../src/util/aim-core-dir.js');
const { saveServerConfig, loadServerConfig, removeServerConfig } = await import('../../src/util/aim-client.js');
const { getShieldStatus } = await import('../../src/shield/status.js');
const { guard } = await import('../../src/commands/guard.js');

let tempHome: string;
let opena2aHome: string;
let projectDir: string;
let savedEnv: string | undefined;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(tmpdir(), 'aim-core-dir-home-'));
  opena2aHome = fs.mkdtempSync(path.join(tmpdir(), 'aim-core-dir-opena2a-'));
  projectDir = fs.mkdtempSync(path.join(tmpdir(), 'aim-core-dir-project-'));
  _mockHomeDir = tempHome;
  savedEnv = process.env.OPENA2A_HOME;
  process.env.OPENA2A_HOME = opena2aHome;
});

afterEach(() => {
  vi.restoreAllMocks();
  if (savedEnv === undefined) delete process.env.OPENA2A_HOME;
  else process.env.OPENA2A_HOME = savedEnv;
  for (const dir of [tempHome, opena2aHome, projectDir]) fs.rmSync(dir, { recursive: true, force: true });
});

function legacyAimCoreDir(): string {
  return path.join(tempHome, '.opena2a', 'aim-core');
}

function writeIdentity(): void {
  const dir = path.join(opena2aHome, 'aim-core');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'identity.json'), '{}\n');
}

describe('getAimCoreDir', () => {
  it('is $OPENA2A_HOME/aim-core when OPENA2A_HOME is set', () => {
    expect(getAimCoreDir()).toBe(path.join(opena2aHome, 'aim-core'));
  });

  it('follows a change to OPENA2A_HOME after import', () => {
    const other = path.join(opena2aHome, 'nested');
    process.env.OPENA2A_HOME = other;
    expect(getAimCoreDir()).toBe(path.join(other, 'aim-core'));
  });

  it('falls back to ~/.opena2a/aim-core when OPENA2A_HOME is unset', async () => {
    delete process.env.OPENA2A_HOME;
    const actualOs = await vi.importActual<typeof import('node:os')>('node:os');
    expect(getAimCoreDir()).toBe(path.join(actualOs.homedir(), '.opena2a', 'aim-core'));
  });
});

describe('displayAimCoreDir', () => {
  it('prints the absolute OPENA2A_HOME path when it is outside the home directory', () => {
    expect(displayAimCoreDir()).toBe(path.join(opena2aHome, 'aim-core') + path.sep);
  });

  it('abbreviates a path under the home directory with ~', () => {
    process.env.OPENA2A_HOME = path.join(tempHome, 'custom');
    expect(displayAimCoreDir()).toBe(`~${path.sep}${path.join('custom', 'aim-core')}${path.sep}`);
  });
});

describe('AIM server connection file', () => {
  it('is written under $OPENA2A_HOME/aim-core/identities', () => {
    saveServerConfig({ serverUrl: 'http://127.0.0.1:1', agentId: 'a', agentName: 'n' } as never);
    const file = path.join(opena2aHome, 'aim-core', 'identities', 'server.json');
    expect(fs.existsSync(file)).toBe(true);
    expect(loadServerConfig()).not.toBeNull();
    expect(fs.existsSync(legacyAimCoreDir())).toBe(false);
    expect(removeServerConfig()).toBe(true);
    expect(fs.existsSync(file)).toBe(false);
  });
});

describe('shield status', () => {
  function aimCoreTool() {
    const tool = getShieldStatus(projectDir).tools.find(t => t.name === 'AIM Core (Identity)');
    expect(tool).toBeDefined();
    return tool!;
  }

  it('reports the identity in $OPENA2A_HOME/aim-core as active', () => {
    writeIdentity();
    expect(aimCoreTool().active).toBe(true);
    expect(fs.existsSync(legacyAimCoreDir())).toBe(false);
  });

  it('does not count an identity left in ~/.opena2a/aim-core', () => {
    fs.mkdirSync(legacyAimCoreDir(), { recursive: true });
    fs.writeFileSync(path.join(legacyAimCoreDir(), 'identity.json'), '{}\n');
    expect(aimCoreTool().active).toBe(false);
  });
});

describe('guard sign', () => {
  async function sign(): Promise<string> {
    fs.writeFileSync(path.join(projectDir, 'package.json'), '{"name":"x"}\n');
    let out = '';
    vi.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      out += String(chunk);
      return true;
    });
    vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
    const code = await guard({ subcommand: 'sign', targetDir: projectDir, files: ['package.json'] });
    vi.restoreAllMocks();
    expect(code).toBe(0);
    return out;
  }

  it('finds the identity in $OPENA2A_HOME/aim-core and prints no identity tip', async () => {
    writeIdentity();
    const out = await sign();
    expect(out).not.toContain('Create an agent identity');
    expect(fs.existsSync(legacyAimCoreDir())).toBe(false);
  });

  it('prints the identity tip when only ~/.opena2a/aim-core holds one', async () => {
    fs.mkdirSync(legacyAimCoreDir(), { recursive: true });
    fs.writeFileSync(path.join(legacyAimCoreDir(), 'identity.json'), '{}\n');
    const out = await sign();
    expect(out).toContain('Create an agent identity');
  });
});

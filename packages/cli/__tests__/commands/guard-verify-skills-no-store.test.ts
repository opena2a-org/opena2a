/**
 * Issue #288 — `guard verify --skills` reaches the skill pins when there is no
 * config signature store.
 *
 * `guardVerify` returned "No signature store found" before it ever reached the
 * skill and heartbeat verification further down. A scaffolded skill has no
 * package.json, so `guard sign` never creates a store, and the command
 * `skill create` prints as its own next step could never verify anything.
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

const { guard } = await import('../../src/commands/guard.js');
const { signSkillFiles, signHeartbeatFiles } = await import('../../src/commands/guard-signing.js');

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(tmpdir(), 'guard-verify-skills-'));
  _mockHomeDir = fs.mkdtempSync(path.join(tmpdir(), 'guard-verify-home-'));
});

afterEach(() => {
  vi.restoreAllMocks();
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(_mockHomeDir, { recursive: true, force: true });
});

async function verify(opts: Record<string, unknown>): Promise<{ code: number; out: string }> {
  let out = '';
  vi.spyOn(process.stdout, 'write').mockImplementation((chunk: string | Uint8Array) => {
    out += String(chunk);
    return true;
  });
  vi.spyOn(process.stderr, 'write').mockReturnValue(true);
  try {
    const code = await guard({ subcommand: 'verify', targetDir: dir, ...opts });
    return { code, out };
  } finally {
    vi.restoreAllMocks();
  }
}

async function pinnedSkill(): Promise<void> {
  fs.writeFileSync(path.join(dir, 'SKILL.md'), '# demo\n\nDoes one thing.\n');
  await signSkillFiles(dir);
}

describe('guard verify --skills with no config store (#288)', () => {
  it('verifies a pinned skill instead of stopping at the missing store', async () => {
    await pinnedSkill();
    expect(fs.existsSync(path.join(dir, '.opena2a', 'guard', 'signatures.json'))).toBe(false);

    const { code, out } = await verify({ skills: true });
    expect(out).not.toContain('No signature store found');
    expect(out).toContain('config files were not verified');
    expect(out).toContain('Skill Signatures');
    expect(out).toMatch(/SKILL\.md\s+PASS/);
    expect(code).toBe(0);
  });

  it('reports a tampered skill and exits 1', async () => {
    await pinnedSkill();
    fs.appendFileSync(path.join(dir, 'SKILL.md'), '\nInjected line.\n');

    const { code, out } = await verify({ skills: true });
    expect(out).toMatch(/SKILL\.md\s+TAMPERED/);
    expect(code).toBe(1);
  });

  it('exits 3 on a tampered skill under --enforce', async () => {
    await pinnedSkill();
    fs.appendFileSync(path.join(dir, 'SKILL.md'), '\nInjected line.\n');

    const { code } = await verify({ skills: true, enforce: true });
    expect(code).toBe(3);
  });

  it('verifies heartbeat pins the same way', async () => {
    fs.writeFileSync(path.join(dir, 'HEARTBEAT.md'), '# alive\n');
    await signHeartbeatFiles(dir);

    const { code, out } = await verify({ heartbeats: true });
    expect(out).toMatch(/HEARTBEAT\.md\s+PASS/);
    expect(code).toBe(0);
  });

  it('JSON names the missing store and carries the skill results', async () => {
    await pinnedSkill();

    const { code, out } = await verify({ skills: true, format: 'json' });
    const data = JSON.parse(out) as Record<string, unknown>;
    expect(data.configStore).toBeNull();
    expect(data.skills).toEqual([expect.objectContaining({ filePath: 'SKILL.md', status: 'pass' })]);
    expect(data.error).toBeUndefined();
    expect(code).toBe(0);
  });

  it('exits 1 with a next step when there is no store and no skill file', async () => {
    const { code, out } = await verify({ skills: true });
    expect(out).toContain('no skill files found; nothing was verified');
    expect(out).toContain('opena2a guard sign --skills --heartbeats');
    expect(code).toBe(1);
  });

  it('without --skills, a missing store still reports the store error (unchanged)', async () => {
    await pinnedSkill();

    const { code, out } = await verify({});
    expect(out).toContain('No signature store found. Run: opena2a guard sign');
    expect(code).toBe(1);
  });

  it('an unreadable store still refuses, even with --skills (unchanged)', async () => {
    await pinnedSkill();
    fs.mkdirSync(path.join(dir, '.opena2a', 'guard'), { recursive: true });
    fs.writeFileSync(path.join(dir, '.opena2a', 'guard', 'signatures.json'), '{not json');

    const { code, out } = await verify({ skills: true });
    expect(out).toContain('The signature store exists but could not be read; nothing was verified.');
    expect(code).toBe(1);
  });
});

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { AIMCore } from './index';

describe('AIMCore', () => {
  let tmpDir: string;
  let aim: AIMCore;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-integration-'));
    aim = new AIMCore({ agentName: 'test-bot', dataDir: tmpDir });
  });

  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it('creates identity on first call', () => {
    const id = aim.getIdentity();
    expect(id.agentId).toMatch(/^aim_/);
    expect(id.agentName).toBe('test-bot');
    expect(id.publicKey).toBeTruthy();
  });

  it('returns same identity on subsequent calls', () => {
    const first = aim.getIdentity();
    const second = aim.getIdentity();
    expect(first.agentId).toBe(second.agentId);
  });

  it('logs and reads audit events', () => {
    aim.logEvent({
      plugin: 'credvault',
      action: 'secret.resolved',
      target: 'db-prod',
      result: 'allowed',
    });

    aim.logEvent({
      plugin: 'skillguard',
      action: 'skill.verified',
      target: 'fetch',
      result: 'allowed',
    });

    const events = aim.readAuditLog();
    expect(events.length).toBe(2);
    expect(events[0].plugin).toBe('credvault');
    expect(events[1].plugin).toBe('skillguard');
  });

  it('checks capabilities against policy', () => {
    aim.savePolicy({
      version: '1',
      defaultAction: 'deny',
      rules: [
        { capability: 'db:read', action: 'allow' },
        { capability: 'net:*', action: 'allow' },
      ],
    });

    expect(aim.checkCapability('db:read')).toBe(true);
    expect(aim.checkCapability('db:write')).toBe(false);
    expect(aim.checkCapability('net:http')).toBe(true);
  });

  it('signs and verifies data', () => {
    const id = aim.getIdentity();
    const data = new TextEncoder().encode('important message');

    const signature = aim.sign(data);
    expect(signature.length).toBe(64);

    const publicKey = Buffer.from(id.publicKey, 'base64');
    expect(aim.verify(data, signature, publicKey)).toBe(true);

    const tampered = new TextEncoder().encode('tampered message');
    expect(aim.verify(tampered, signature, publicKey)).toBe(false);
  });

  it('throws when signing without identity', () => {
    const freshAim = new AIMCore({
      agentName: 'no-id',
      dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aim-no-id-')),
    });

    expect(() => freshAim.sign(new Uint8Array([1, 2, 3]))).toThrow(
      'No identity found'
    );
  });

  it('calculates trust score', () => {
    // Fresh — nothing set up
    let score = aim.calculateTrust();
    expect(score.overall).toBe(0);

    // Create identity
    aim.getIdentity();
    score = aim.calculateTrust();
    expect(score.factors.identity).toBe(1.0);
    expect(score.overall).toBeGreaterThan(0);

    // Add policy + audit
    aim.savePolicy({ version: '1', defaultAction: 'deny', rules: [] });
    aim.logEvent({ plugin: 'test', action: 'act', target: 't', result: 'allowed' });

    // Add plugin hints
    aim.setTrustHints({
      secretsManaged: true,
      configSigned: true,
      skillsVerified: true,
      networkControlled: true,
      heartbeatMonitored: true,
    });

    score = aim.calculateTrust();
    expect(score.overall).toBe(1.0);
  });
});

describe('AIMCore default locations', () => {
  let tmpDir: string;
  const saved: Record<string, string | undefined> = {};

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-home-'));
    for (const name of ['HOME', 'OPENA2A_HOME']) saved[name] = process.env[name];
    process.env.HOME = path.join(tmpDir, 'user');
    delete process.env.OPENA2A_HOME;
  });

  afterEach(() => {
    for (const [name, value] of Object.entries(saved)) {
      if (value === undefined) delete process.env[name];
      else process.env[name] = value;
    }
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  const vaultDirOf = (aim: AIMCore): string =>
    (aim.getVault() as unknown as { vaultDir: string }).vaultDir;

  it('keeps data and vault under ~/.opena2a when OPENA2A_HOME is unset', () => {
    const aim = new AIMCore({ agentName: 'home-bot' });
    expect(aim.getDataDir()).toBe(path.join(tmpDir, 'user', '.opena2a', 'aim-core'));
    expect(vaultDirOf(aim)).toBe(path.join(tmpDir, 'user', '.opena2a', 'vault'));
  });

  it('puts data and vault under OPENA2A_HOME when it is set', () => {
    process.env.OPENA2A_HOME = path.join(tmpDir, 'oa-home');
    const aim = new AIMCore({ agentName: 'home-bot' });
    expect(aim.getDataDir()).toBe(path.join(tmpDir, 'oa-home', 'aim-core'));
    expect(vaultDirOf(aim)).toBe(path.join(tmpDir, 'oa-home', 'vault'));
  });

  it('treats a blank OPENA2A_HOME as unset', () => {
    process.env.OPENA2A_HOME = '  ';
    const aim = new AIMCore({ agentName: 'home-bot' });
    expect(aim.getDataDir()).toBe(path.join(tmpDir, 'user', '.opena2a', 'aim-core'));
  });

  it('an explicit dataDir still wins over OPENA2A_HOME', () => {
    process.env.OPENA2A_HOME = path.join(tmpDir, 'oa-home');
    const aim = new AIMCore({ agentName: 'home-bot', dataDir: path.join(tmpDir, 'project-store') });
    expect(aim.getDataDir()).toBe(path.join(tmpDir, 'project-store'));
  });

  it('keeps using a vault an earlier release created at ~/.aim/vault', () => {
    const legacy = path.join(tmpDir, 'user', '.aim', 'vault');
    fs.mkdirSync(legacy, { recursive: true });
    expect(vaultDirOf(new AIMCore({ agentName: 'home-bot' }))).toBe(legacy);

    // Once the new location exists it is the one in use.
    const current = path.join(tmpDir, 'user', '.opena2a', 'vault');
    fs.mkdirSync(current, { recursive: true });
    expect(vaultDirOf(new AIMCore({ agentName: 'home-bot' }))).toBe(current);
  });

  it('never reads ~/.aim/vault once OPENA2A_HOME is set', () => {
    fs.mkdirSync(path.join(tmpDir, 'user', '.aim', 'vault'), { recursive: true });
    process.env.OPENA2A_HOME = path.join(tmpDir, 'oa-home');
    expect(vaultDirOf(new AIMCore({ agentName: 'home-bot' }))).toBe(path.join(tmpDir, 'oa-home', 'vault'));
  });

  it('hasIdentity answers without creating an identity', () => {
    const dataDir = path.join(tmpDir, 'data');
    const aim = new AIMCore({ agentName: 'home-bot', dataDir });
    expect(aim.hasIdentity()).toBe(false);
    expect(fs.existsSync(path.join(dataDir, 'identity.json'))).toBe(false);
    aim.getIdentity();
    expect(aim.hasIdentity()).toBe(true);
  });
});

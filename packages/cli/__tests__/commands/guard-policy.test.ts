import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { _internals } from '../../src/commands/guard-policy.js';
import { guard } from '../../src/commands/guard.js';

const {
  loadGuardPolicy, saveGuardPolicy, generateDefaultPolicy,
  checkPolicyCompliance, disableHeartbeat, isHeartbeatDisabled,
  enableHeartbeat, guardPolicy,
  GUARD_DIR, POLICY_FILE, HEARTBEAT_DISABLED_FILE,
} = _internals;

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

describe('guard-policy', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-guard-policy-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  // --- Default policy generation ---

  it('generateDefaultPolicy detects existing config files', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'tsconfig.json'), '{}');

    const policy = generateDefaultPolicy(tempDir);
    expect(policy.version).toBe(1);
    expect(policy.requiredFiles).toContain('package.json');
    expect(policy.requiredFiles).toContain('tsconfig.json');
    expect(policy.requiredFiles).not.toContain('go.mod');
    expect(policy.blockOnUnsigned).toBe(true);
    expect(policy.disableHeartbeatOnTamper).toBe(true);
    expect(policy.autoRemediate).toBe(false);
  });

  it('generateDefaultPolicy returns empty requiredFiles when no config files exist', () => {
    const policy = generateDefaultPolicy(tempDir);
    expect(policy.requiredFiles).toEqual([]);
  });

  // --- Policy loading and saving ---

  it('loadGuardPolicy returns null when no policy exists', () => {
    expect(loadGuardPolicy(tempDir)).toBeNull();
  });

  it('saveGuardPolicy and loadGuardPolicy round-trip correctly', () => {
    const policy = generateDefaultPolicy(tempDir);
    policy.requiredFiles = ['package.json'];
    saveGuardPolicy(tempDir, policy);

    const loaded = loadGuardPolicy(tempDir);
    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.requiredFiles).toEqual(['package.json']);
    expect(loaded!.blockOnUnsigned).toBe(true);
  });

  it('loadGuardPolicy returns null for invalid JSON', () => {
    const dir = path.join(tempDir, GUARD_DIR);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, POLICY_FILE), 'not-json', 'utf-8');
    expect(loadGuardPolicy(tempDir)).toBeNull();
  });

  // --- Compliance checking ---

  it('checkPolicyCompliance reports all signed as compliant', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"test"}');
    // Sign the file using guard
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: true, disableHeartbeatOnTamper: true, autoRemediate: false };
    const result = checkPolicyCompliance(tempDir, policy);

    expect(result.compliant).toBe(true);
    expect(result.requiredSigned).toBe(1);
    expect(result.requiredUnsigned).toEqual([]);
    expect(result.requiredTampered).toEqual([]);
    expect(result.requiredMissing).toEqual([]);
  });

  it('checkPolicyCompliance reports unsigned required files', () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    // No signing -- file is unsigned

    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: true, disableHeartbeatOnTamper: true, autoRemediate: false };
    const result = checkPolicyCompliance(tempDir, policy);

    expect(result.compliant).toBe(false);
    expect(result.requiredUnsigned).toContain('package.json');
  });

  it('checkPolicyCompliance reports tampered required files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"tampered"}');

    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: true, disableHeartbeatOnTamper: true, autoRemediate: false };
    const result = checkPolicyCompliance(tempDir, policy);

    expect(result.compliant).toBe(false);
    expect(result.requiredTampered).toContain('package.json');
  });

  it('checkPolicyCompliance reports missing required files', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });
    fs.unlinkSync(path.join(tempDir, 'package.json'));

    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: true, disableHeartbeatOnTamper: true, autoRemediate: false };
    const result = checkPolicyCompliance(tempDir, policy);

    expect(result.compliant).toBe(false);
    expect(result.requiredMissing).toContain('package.json');
  });

  // --- Heartbeat disable marker ---

  it('disableHeartbeat writes marker file', () => {
    disableHeartbeat(tempDir, 'test reason');
    const markerPath = path.join(tempDir, GUARD_DIR, HEARTBEAT_DISABLED_FILE);
    expect(fs.existsSync(markerPath)).toBe(true);

    const data = JSON.parse(fs.readFileSync(markerPath, 'utf-8'));
    expect(data.disabled).toBe(true);
    expect(data.reason).toBe('test reason');
    expect(data.disabledAt).toBeDefined();
  });

  it('isHeartbeatDisabled returns disabled status when marker exists', () => {
    disableHeartbeat(tempDir, 'tamper detected');
    const status = isHeartbeatDisabled(tempDir);
    expect(status.disabled).toBe(true);
    expect(status.reason).toBe('tamper detected');
    expect(status.disabledAt).toBeDefined();
  });

  it('isHeartbeatDisabled returns not disabled when no marker', () => {
    const status = isHeartbeatDisabled(tempDir);
    expect(status.disabled).toBe(false);
    expect(status.reason).toBeUndefined();
  });

  it('enableHeartbeat removes the marker', () => {
    disableHeartbeat(tempDir, 'test');
    expect(isHeartbeatDisabled(tempDir).disabled).toBe(true);
    enableHeartbeat(tempDir);
    expect(isHeartbeatDisabled(tempDir).disabled).toBe(false);
  });

  // --- guard policy init subcommand ---

  it('guard policy init creates default policy', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{}');
    fs.writeFileSync(path.join(tempDir, 'Dockerfile'), 'FROM node');

    const { exitCode, output } = await captureStdout(() =>
      guardPolicy(tempDir, 'init', { format: 'json' })
    );

    expect(exitCode).toBe(0);
    const policy = JSON.parse(output);
    expect(policy.version).toBe(1);
    expect(policy.requiredFiles).toContain('package.json');
    expect(policy.requiredFiles).toContain('Dockerfile');
    expect(policy.blockOnUnsigned).toBe(true);
    expect(policy.disableHeartbeatOnTamper).toBe(true);

    // Verify file was written
    expect(loadGuardPolicy(tempDir)).not.toBeNull();
  });

  it('guard policy show displays current policy', async () => {
    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: false, disableHeartbeatOnTamper: true, autoRemediate: false };
    saveGuardPolicy(tempDir, policy);

    const { exitCode, output } = await captureStdout(() =>
      guardPolicy(tempDir, 'show', { format: 'json' })
    );

    expect(exitCode).toBe(0);
    const shown = JSON.parse(output);
    expect(shown.requiredFiles).toEqual(['package.json']);
    expect(shown.blockOnUnsigned).toBe(false);
  });

  it('guard policy show returns 1 when no policy exists', async () => {
    const { exitCode, output } = await captureStdout(() =>
      guardPolicy(tempDir, 'show', { format: 'json' })
    );

    expect(exitCode).toBe(1);
    const result = JSON.parse(output);
    expect(result.error).toContain('No guard policy found');
  });

  it('guard policy unknown action returns 1', async () => {
    const stderrChunks: string[] = [];
    const origStderr = process.stderr.write;
    process.stderr.write = ((chunk: any) => { stderrChunks.push(String(chunk)); return true; }) as any;

    const exitCode = await guardPolicy(tempDir, 'invalid', { format: 'text' });

    process.stderr.write = origStderr;
    expect(exitCode).toBe(1);
    expect(stderrChunks.join('')).toContain('Unknown policy action');
  });

  // --- Verify integration with policy ---

  it('verify disables heartbeat when tamper detected and policy requires it', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"original"}');
    await guard({ subcommand: 'sign', targetDir: tempDir, format: 'json' });

    const policy = { version: 1 as const, requiredFiles: ['package.json'], blockOnUnsigned: true, disableHeartbeatOnTamper: true, autoRemediate: false };
    saveGuardPolicy(tempDir, policy);

    // Tamper with file
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name":"tampered"}');

    await captureStdout(() => guard({ subcommand: 'verify', targetDir: tempDir, format: 'json' }));

    // Heartbeat should be disabled
    const hb = isHeartbeatDisabled(tempDir);
    expect(hb.disabled).toBe(true);
    expect(hb.reason).toContain('package.json');
  });
});

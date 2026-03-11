import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { demo } from '../../src/commands/demo.js';

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

describe('demo command', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-demo-test-'));
  });

  afterEach(() => {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // already cleaned up
    }
  });

  describe('AIM demo', () => {
    it('runs successfully in CI mode', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox');
      const { exitCode, output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      expect(exitCode).toBe(0);
      expect(output).toContain('AIM Agent Identity Management Demo');
      expect(output).toContain('Step 1/8');
      expect(output).toContain('Step 8/8');
      expect(output).toContain('Demo Complete');
    });

    it('creates sandbox files', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox');
      await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      // Verify sandbox files were created
      expect(fs.existsSync(path.join(sandboxDir, 'package.json'))).toBe(true);
      expect(fs.existsSync(path.join(sandboxDir, '.opena2a', 'identity.json'))).toBe(true);
      expect(fs.existsSync(path.join(sandboxDir, '.opena2a', 'policy.json'))).toBe(true);
      expect(fs.existsSync(path.join(sandboxDir, '.opena2a', 'guard', 'signatures.json'))).toBe(true);
      expect(fs.existsSync(path.join(sandboxDir, '.opena2a', 'vault', 'manifest.json'))).toBe(true);
    });

    it('cleans up sandbox when --keep is not set', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-cleanup');
      await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
        keep: false,
      }));

      expect(fs.existsSync(sandboxDir)).toBe(false);
    });

    it('preserves sandbox with --keep flag', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-keep');
      await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      expect(fs.existsSync(sandboxDir)).toBe(true);
      expect(fs.existsSync(path.join(sandboxDir, 'package.json'))).toBe(true);
    });

    it('shows before/after scores', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-scores');
      const { output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
      }));

      expect(output).toContain('22/100');
      expect(output).toContain('87/100');
      expect(output).toContain('+65 improvement');
    });

    it('shows audit log entries', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-audit');
      const { output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
      }));

      expect(output).toContain('identity.create');
      expect(output).toContain('policy.apply');
      expect(output).toContain('config.sign');
      expect(output).toContain('credential.migrate');
    });

    it('migrates credentials replacing hardcoded values', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-creds');
      await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      // After migration, .env should have vault references
      const envContent = fs.readFileSync(path.join(sandboxDir, '.env'), 'utf-8');
      expect(envContent).toContain('vault://opena2a/');
      expect(envContent).not.toContain('sk-FAKE');

      // config.js should use process.env
      const configContent = fs.readFileSync(path.join(sandboxDir, 'config.js'), 'utf-8');
      expect(configContent).toContain('process.env.OPENAI_API_KEY');
      expect(configContent).not.toContain('sk-FAKE');
    });

    it('outputs JSON when format is json', async () => {
      const sandboxDir = path.join(tempDir, 'sandbox-json');
      const { exitCode, output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        format: 'json',
        dir: sandboxDir,
      }));

      expect(exitCode).toBe(0);
      // The JSON output is at the end; extract it
      const jsonMatch = output.match(/\{[\s\S]*"scenario"[\s\S]*\}/);
      expect(jsonMatch).not.toBeNull();
      const result = JSON.parse(jsonMatch![0]);
      expect(result.scenario).toBe('aim');
      expect(result.scoreBefore).toBe(22);
      expect(result.scoreAfter).toBe(87);
      expect(result.steps).toHaveLength(8);
      expect(result.auditLog.length).toBeGreaterThan(0);
    });
  });

  describe('DVAA demo', () => {
    it('runs successfully in CI mode', async () => {
      const sandboxDir = path.join(tempDir, 'dvaa-sandbox');
      const { exitCode, output } = await captureStdout(() => demo({
        scenario: 'dvaa',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      expect(exitCode).toBe(0);
      expect(output).toContain('DVAA Attack/Defend Demo');
      expect(output).toContain('Step 1/5');
      expect(output).toContain('Step 5/5');
      expect(output).toContain('Demo Complete');
    });

    it('shows attack simulation results', async () => {
      const sandboxDir = path.join(tempDir, 'dvaa-attacks');
      const { output } = await captureStdout(() => demo({
        scenario: 'dvaa',
        ci: true,
        dir: sandboxDir,
      }));

      expect(output).toContain('prompt-injection');
      expect(output).toContain('credential-theft');
      expect(output).toContain('config-tampering');
      expect(output).toContain('privilege-escalation');
      expect(output).toContain('4/4 attacks blocked');
    });

    it('creates SOUL.md governance file during hardening', async () => {
      const sandboxDir = path.join(tempDir, 'dvaa-soul');
      await captureStdout(() => demo({
        scenario: 'dvaa',
        ci: true,
        dir: sandboxDir,
        keep: true,
      }));

      expect(fs.existsSync(path.join(sandboxDir, 'SOUL.md'))).toBe(true);
      const soulContent = fs.readFileSync(path.join(sandboxDir, 'SOUL.md'), 'utf-8');
      expect(soulContent).toContain('Agent Governance');
    });

    it('shows score improvement', async () => {
      const sandboxDir = path.join(tempDir, 'dvaa-scores');
      const { output } = await captureStdout(() => demo({
        scenario: 'dvaa',
        ci: true,
        dir: sandboxDir,
      }));

      expect(output).toContain('18/100');
      expect(output).toContain('91/100');
      expect(output).toContain('+73 improvement');
    });

    it('outputs JSON for DVAA scenario', async () => {
      const sandboxDir = path.join(tempDir, 'dvaa-json');
      const { exitCode, output } = await captureStdout(() => demo({
        scenario: 'dvaa',
        ci: true,
        format: 'json',
        dir: sandboxDir,
      }));

      expect(exitCode).toBe(0);
      const jsonMatch = output.match(/\{[\s\S]*"scenario"[\s\S]*\}/);
      expect(jsonMatch).not.toBeNull();
      const result = JSON.parse(jsonMatch![0]);
      expect(result.scenario).toBe('dvaa');
      expect(result.scoreBefore).toBe(18);
      expect(result.scoreAfter).toBe(91);
      expect(result.steps).toHaveLength(5);
    });
  });

  describe('error handling', () => {
    it('returns error for unknown scenario', async () => {
      const chunks: string[] = [];
      const origWrite = process.stderr.write;
      process.stderr.write = ((chunk: any) => {
        chunks.push(String(chunk));
        return true;
      }) as any;

      const exitCode = await demo({ scenario: 'unknown', ci: true });
      process.stderr.write = origWrite;

      expect(exitCode).toBe(1);
      expect(chunks.join('')).toContain('Unknown demo scenario');
    });

    it('defaults to aim scenario when no scenario specified', async () => {
      const sandboxDir = path.join(tempDir, 'default-scenario');
      const { exitCode, output } = await captureStdout(() => demo({
        ci: true,
        dir: sandboxDir,
      }));

      expect(exitCode).toBe(0);
      expect(output).toContain('AIM Agent Identity Management Demo');
    });

    it('creates temp directory automatically when no dir specified', async () => {
      const { exitCode, output } = await captureStdout(() => demo({
        ci: true,
        scenario: 'aim',
      }));

      expect(exitCode).toBe(0);
      expect(output).toContain('Demo Complete');
    });
  });

  describe('output quality', () => {
    it('contains no emojis', async () => {
      const sandboxDir = path.join(tempDir, 'no-emoji');
      const { output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
      }));

      // Check for common emoji patterns (unicode emoji ranges)
      const emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{1F1E0}-\u{1F1FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}]/u;
      expect(emojiRegex.test(output)).toBe(false);
    });

    it('shows next steps with runnable commands', async () => {
      const sandboxDir = path.join(tempDir, 'next-steps');
      const { output } = await captureStdout(() => demo({
        scenario: 'aim',
        ci: true,
        dir: sandboxDir,
      }));

      expect(output).toContain('opena2a init');
      expect(output).toContain('opena2a protect');
      expect(output).toContain('opena2a identity create');
    });
  });
});

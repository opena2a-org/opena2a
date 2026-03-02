import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';

import {
  computeFileHash,
  recordPolicyHash,
  verifyPolicyIntegrity,
  getExpectedHookContent,
  verifyShellHookIntegrity,
  verifyProcessIntegrity,
  runIntegrityChecks,
  isLockdown,
  enterLockdown,
  exitLockdown,
  getLockdownReason,
} from '../../src/shield/integrity.js';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// vi.mock hoists automatically in vitest; the factory receives the real module.
// ---------------------------------------------------------------------------

let _mockHomeDir: string | null = null;

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => {
      if (_mockHomeDir !== null) {
        return _mockHomeDir;
      }
      return actual.homedir();
    },
  };
});

// ---------------------------------------------------------------------------
// Test setup / teardown
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-integrity-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  _mockHomeDir = null;
  vi.restoreAllMocks();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ---------------------------------------------------------------------------
// computeFileHash
// ---------------------------------------------------------------------------

describe('computeFileHash', () => {
  it('returns SHA-256 hex digest of file contents', () => {
    const filePath = path.join(tempDir, 'test-file.txt');
    const content = 'hello world\n';
    fs.writeFileSync(filePath, content, 'utf-8');

    const expected = createHash('sha256').update(Buffer.from(content, 'utf-8')).digest('hex');
    const result = computeFileHash(filePath);

    expect(result).toBe(expected);
    expect(result).toMatch(/^[a-f0-9]{64}$/);
  });

  it('returns empty string for non-existent file', () => {
    const result = computeFileHash(path.join(tempDir, 'does-not-exist.txt'));
    expect(result).toBe('');
  });
});

// ---------------------------------------------------------------------------
// recordPolicyHash + verifyPolicyIntegrity
// ---------------------------------------------------------------------------

describe('recordPolicyHash + verifyPolicyIntegrity', () => {
  it('records hash and verifyPolicyIntegrity returns valid=true for unchanged file', () => {
    const policyPath = path.join(tempDir, 'policy.yaml');
    fs.writeFileSync(policyPath, 'mode: enforce\nrules: []\n', 'utf-8');

    recordPolicyHash(policyPath);
    const result = verifyPolicyIntegrity(policyPath);

    expect(result.valid).toBe(true);
    expect(result.detail).toContain('matches');
  });

  it('returns valid=false when policy file is modified after recording', () => {
    const policyPath = path.join(tempDir, 'policy.yaml');
    fs.writeFileSync(policyPath, 'mode: enforce\nrules: []\n', 'utf-8');

    recordPolicyHash(policyPath);

    // Tamper with the policy file
    fs.writeFileSync(policyPath, 'mode: monitor\nrules: [TAMPERED]\n', 'utf-8');

    const result = verifyPolicyIntegrity(policyPath);

    expect(result.valid).toBe(false);
    expect(result.detail).toContain('modified');
  });

  it('returns valid=true when no policy file exists (nothing to verify)', () => {
    const nonExistentPath = path.join(tempDir, 'no-such-policy.yaml');
    const result = verifyPolicyIntegrity(nonExistentPath);

    expect(result.valid).toBe(true);
    expect(result.detail).toContain('No policy file found');
  });
});

// ---------------------------------------------------------------------------
// getExpectedHookContent
// ---------------------------------------------------------------------------

describe('getExpectedHookContent', () => {
  it('zsh content contains opena2a_shield_preexec, add-zsh-hook preexec, and markers', () => {
    const content = getExpectedHookContent('zsh');

    expect(content).toContain('opena2a_shield_preexec');
    expect(content).toContain('add-zsh-hook preexec');
    expect(content).toContain('# >>> opena2a shield hook >>>');
    expect(content).toContain('# <<< opena2a shield hook <<<');
  });

  it('bash content contains opena2a_shield_debug, trap, and markers', () => {
    const content = getExpectedHookContent('bash');

    expect(content).toContain('opena2a_shield_debug');
    expect(content).toContain('trap');
    expect(content).toContain('# >>> opena2a shield hook >>>');
    expect(content).toContain('# <<< opena2a shield hook <<<');
  });

  it('both shells contain start and end markers', () => {
    for (const shell of ['zsh', 'bash'] as const) {
      const content = getExpectedHookContent(shell);
      expect(content).toContain('# >>> opena2a shield hook >>>');
      expect(content).toContain('# <<< opena2a shield hook <<<');
    }
  });
});

// ---------------------------------------------------------------------------
// verifyShellHookIntegrity
// ---------------------------------------------------------------------------

describe('verifyShellHookIntegrity', () => {
  it('returns status=pass when correct hook is installed in .zshrc', () => {
    const zshrcPath = path.join(tempDir, '.zshrc');
    const hookContent = getExpectedHookContent('zsh');
    fs.writeFileSync(zshrcPath, 'existing content\n' + hookContent + '\n', 'utf-8');

    const result = verifyShellHookIntegrity('zsh');

    expect(result.status).toBe('pass');
    expect(result.name).toBe('shell-hook');
    expect(result.detail).toContain('matches expected content');
  });

  it('returns status=fail when hook content is tampered', () => {
    const zshrcPath = path.join(tempDir, '.zshrc');
    const tamperedHook = [
      '# >>> opena2a shield hook >>>',
      'opena2a_shield_preexec() {',
      '  echo "TAMPERED HOOK"',
      '}',
      '# <<< opena2a shield hook <<<',
    ].join('\n');
    fs.writeFileSync(zshrcPath, tamperedHook, 'utf-8');

    const result = verifyShellHookIntegrity('zsh');

    expect(result.status).toBe('fail');
    expect(result.detail).toContain('tampered');
  });

  it('returns status=warn when rc file does not exist', () => {
    // No .zshrc in tempDir (homedir mock)
    const result = verifyShellHookIntegrity('zsh');

    expect(result.status).toBe('warn');
    expect(result.detail).toContain('does not exist');
  });

  it('returns status=warn when no hook markers are found in rc file', () => {
    const zshrcPath = path.join(tempDir, '.zshrc');
    fs.writeFileSync(zshrcPath, '# just a regular zshrc\nexport PATH="/usr/bin"\n', 'utf-8');

    const result = verifyShellHookIntegrity('zsh');

    expect(result.status).toBe('warn');
    expect(result.detail).toContain('markers not found');
  });
});

// ---------------------------------------------------------------------------
// verifyProcessIntegrity
// ---------------------------------------------------------------------------

describe('verifyProcessIntegrity', () => {
  it('returns status=pass with detail containing process.execPath', () => {
    const result = verifyProcessIntegrity();

    expect(result.status).toBe('pass');
    expect(result.name).toBe('process');
    expect(result.detail).toContain(process.execPath);
  });
});

// ---------------------------------------------------------------------------
// lockdown management
// ---------------------------------------------------------------------------

describe('lockdown management', () => {
  it('isLockdown returns false initially', () => {
    expect(isLockdown()).toBe(false);
  });

  it('enterLockdown makes isLockdown return true', () => {
    enterLockdown('test reason');
    expect(isLockdown()).toBe(true);
  });

  it('getLockdownReason returns the reason after entering lockdown', () => {
    enterLockdown('test reason');
    expect(getLockdownReason()).toBe('test reason');
  });

  it('exitLockdown makes isLockdown return false', () => {
    enterLockdown('test reason');
    expect(isLockdown()).toBe(true);

    exitLockdown();
    expect(isLockdown()).toBe(false);
  });

  it('getLockdownReason returns null after exiting lockdown', () => {
    enterLockdown('test reason');
    exitLockdown();
    expect(getLockdownReason()).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// runIntegrityChecks
// ---------------------------------------------------------------------------

describe('runIntegrityChecks', () => {
  it('returns degraded or healthy status when no shield dir exists', () => {
    // With no shield dir and no .zshrc, shell hook check returns warn -> degraded
    const result = runIntegrityChecks({ shell: 'zsh' });

    // Shell hook will warn (no rc file), which makes status degraded.
    // Policy and event chain pass (no files to check), process passes.
    expect(['healthy', 'degraded']).toContain(result.status);
    expect(result.checks.length).toBeGreaterThan(0);
    expect(result.lastVerified).toBeTruthy();
    expect(result.chainHash).toMatch(/^[a-f0-9]{64}$/);
  });

  it('returns status=lockdown when system is in lockdown', () => {
    enterLockdown('integrity test lockdown');

    const result = runIntegrityChecks({ shell: 'zsh' });

    expect(result.status).toBe('lockdown');
    expect(result.checks).toHaveLength(1);
    expect(result.checks[0].name).toBe('lockdown');
    expect(result.checks[0].status).toBe('fail');
    expect(result.checks[0].detail).toContain('integrity test lockdown');
  });
});

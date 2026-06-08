import { describe, it, expect } from 'vitest';
import { execSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { getVerificationCommand } from '../../src/commands/init.js';

// Regression for the 0.10.8 release-test P3 finding: `init` on an empty project
// emitted an ENV-DOTENV Verify command (`cat .gitignore | grep -c '.env'`) that
// errors when no .gitignore exists ("No such file or directory"). The Verify
// command must be runnable on a project with no .gitignore.

function finding(findingId: string) {
  return {
    findingId,
    title: '.env not in .gitignore',
    severity: 'medium',
    count: 1,
    explanation: '',
    businessImpact: '',
    locations: [],
  };
}

describe('getVerificationCommand — ENV-DOTENV (#release-test P3)', () => {
  it('returns a command that suppresses errors and defaults to 0', () => {
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), '/tmp');
    expect(cmd).toBeTruthy();
    expect(cmd).toContain('2>/dev/null');
    expect(cmd).toContain('|| echo 0');
    // The old fragile form piped a bare `cat .gitignore` — must be gone.
    expect(cmd).not.toMatch(/^cat \.gitignore \| grep/);
  });

  it('the emitted command runs cleanly (exit 0) in a dir with no .gitignore', () => {
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), '/tmp')!;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-dotenv-verify-'));
    try {
      // Should print "0" and exit 0, not throw on a missing .gitignore.
      const out = execSync(cmd, { cwd: dir, shell: '/bin/sh', encoding: 'utf-8' });
      expect(out.trim()).toBe('0');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('counts matches when .gitignore exists', () => {
    const cmd = getVerificationCommand(finding('ENV-DOTENV'), '/tmp')!;
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-dotenv-verify-'));
    try {
      fs.writeFileSync(path.join(dir, '.gitignore'), '.env\nnode_modules\n');
      const out = execSync(cmd, { cwd: dir, shell: '/bin/sh', encoding: 'utf-8' });
      expect(Number(out.trim())).toBeGreaterThanOrEqual(1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

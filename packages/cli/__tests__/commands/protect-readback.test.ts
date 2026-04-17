import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// Bug #2: storeInVault must read back what it wrote. If setSecret resolves but
// the value cannot be retrieved, the source MUST NOT be replaced — otherwise
// the credential is lost (gone from source, never landed in vault).
//
// We mock secretless-ai so setSecret resolves (no error) but getSecret returns
// undefined. Then we stub HOME/USERPROFILE empty so the shell-profile fallback
// also fails (returns false). Net effect: stored=false → source untouched.

const mockSetSecret = vi.fn();
const mockGetSecret = vi.fn();

vi.mock('secretless-ai', () => {
  return {
    SecretStore: class {
      setSecret = mockSetSecret;
      getSecret = mockGetSecret;
    },
    readBackendConfig: () => 'local',
  };
});

import { protect } from '../../src/commands/protect.js';

describe('protect — vault read-back verification (bug #2)', () => {
  let tempDir: string;
  let originalHome: string | undefined;
  let originalUserProfile: string | undefined;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-readback-'));
    fs.writeFileSync(path.join(tempDir, 'package.json'), '{"name": "test"}');
    mockSetSecret.mockReset();
    mockGetSecret.mockReset();
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ status: 403 }));
    // Disable shell-profile fallback so vault failure cannot be papered over.
    originalHome = process.env.HOME;
    originalUserProfile = process.env.USERPROFILE;
    delete process.env.HOME;
    delete process.env.USERPROFILE;
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    vi.unstubAllGlobals();
    if (originalHome !== undefined) process.env.HOME = originalHome;
    if (originalUserProfile !== undefined) process.env.USERPROFILE = originalUserProfile;
  });

  it('does NOT replace source when vault read-back returns undefined and shell fallback unavailable', async () => {
    // setSecret "succeeds" (resolves) but getSecret returns undefined,
    // simulating a vault that silently dropped the write.
    mockSetSecret.mockResolvedValue(undefined);
    mockGetSecret.mockResolvedValue(undefined);

    const fakeKey = 'AIza' + 'Y'.repeat(35);
    const original = `const k = "${fakeKey}";\n`;
    const sourcePath = path.join(tempDir, 'app.ts');
    fs.writeFileSync(sourcePath, original);

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    // Assertion: source untouched. Without read-back verification + the
    // shell-fallback guard, the credential would have been wiped from the
    // file even though no vault holds it.
    const after = fs.readFileSync(sourcePath, 'utf-8');
    expect(after).toBe(original);

    // setSecret was called (write attempted)
    expect(mockSetSecret).toHaveBeenCalledWith('GOOGLE_API_KEY', fakeKey);
    // getSecret was called (read-back happened)
    expect(mockGetSecret).toHaveBeenCalledWith('GOOGLE_API_KEY');
  });

  it('DOES replace source when vault read-back confirms the value', async () => {
    // Happy path: setSecret resolves, getSecret returns the same value.
    const fakeKey = 'AIza' + 'W'.repeat(35);
    mockSetSecret.mockResolvedValue(undefined);
    mockGetSecret.mockResolvedValue(fakeKey);

    // Restore HOME so shell fallback is available, but we shouldn't need it.
    process.env.HOME = tempDir;

    const sourcePath = path.join(tempDir, 'app.ts');
    fs.writeFileSync(sourcePath, `const k = "${fakeKey}";\n`);

    await protect({
      targetDir: tempDir,
      ci: true,
      skipVerify: true,
      skipSign: true,
      skipGit: true,
    });

    const after = fs.readFileSync(sourcePath, 'utf-8');
    expect(after).not.toContain(fakeKey);
    expect(after).toContain('process.env.GOOGLE_API_KEY');
    expect(mockGetSecret).toHaveBeenCalled();
  });
});

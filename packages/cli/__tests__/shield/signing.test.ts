import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { tmpdir } from 'node:os';

// ---------------------------------------------------------------------------
// Mock node:os so that homedir() returns our temp directory.
// ---------------------------------------------------------------------------

let _mockHomeDir = '';

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => _mockHomeDir,
  };
});

// Import after mocks
const {
  signArtifact,
  verifyArtifact,
  signAllArtifacts,
  loadSignatures,
  saveSignatures,
  verifyAllArtifacts,
} = await import('../../src/shield/signing.js');

const { getShieldDir } = await import('../../src/shield/events.js');

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(tmpdir(), 'shield-signing-test-'));
  _mockHomeDir = tempDir;
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ===========================================================================
// 1. signArtifact
// ===========================================================================

describe('signArtifact', () => {
  it('produces a valid signature for a file', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'test-file.json');
    fs.writeFileSync(filePath, '{"data": "test"}');

    const sig = signArtifact(filePath);

    expect(sig.filePath).toBe('test-file.json');
    expect(sig.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(sig.signedAt).toBeTruthy();
    expect(sig.signedBy).toContain('@opena2a-cli');
    expect(sig.fileSize).toBeGreaterThan(0);
  });

  it('produces deterministic hash for same content', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'deterministic.json');
    fs.writeFileSync(filePath, '{"stable": true}');

    const sig1 = signArtifact(filePath);
    const sig2 = signArtifact(filePath);

    expect(sig1.hash).toBe(sig2.hash);
  });
});

// ===========================================================================
// 2. verifyArtifact
// ===========================================================================

describe('verifyArtifact', () => {
  it('returns valid when no signatures file exists', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'no-sigs.json');
    fs.writeFileSync(filePath, '{"data": "test"}');

    const result = verifyArtifact(filePath);
    expect(result.valid).toBe(true);
    expect(result.detail).toContain('No signatures file');
  });

  it('returns valid when file has no stored signature', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'untracked.json');
    fs.writeFileSync(filePath, '{"data": "test"}');

    // Create empty signature store
    saveSignatures({ version: 1, signatures: [], updatedAt: new Date().toISOString() });

    const result = verifyArtifact(filePath);
    expect(result.valid).toBe(true);
    expect(result.detail).toContain('No signature recorded');
  });

  it('returns valid when hash matches', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'good-file.json');
    fs.writeFileSync(filePath, '{"data": "verified"}');

    // Sign then verify
    const sig = signArtifact(filePath);
    saveSignatures({
      version: 1,
      signatures: [sig],
      updatedAt: new Date().toISOString(),
    });

    const result = verifyArtifact(filePath);
    expect(result.valid).toBe(true);
    expect(result.detail).toContain('integrity verified');
  });

  it('detects tampering when hash mismatches', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'tampered.json');
    fs.writeFileSync(filePath, '{"original": true}');

    // Sign it
    const sig = signArtifact(filePath);
    saveSignatures({
      version: 1,
      signatures: [sig],
      updatedAt: new Date().toISOString(),
    });

    // Tamper with the file
    fs.writeFileSync(filePath, '{"tampered": true}');

    const result = verifyArtifact(filePath);
    expect(result.valid).toBe(false);
    expect(result.detail).toContain('has been modified');
  });

  it('detects missing file that was signed', () => {
    const shieldDir = getShieldDir();
    const filePath = path.join(shieldDir, 'deleted.json');
    fs.writeFileSync(filePath, '{"data": "exists"}');

    const sig = signArtifact(filePath);
    saveSignatures({
      version: 1,
      signatures: [sig],
      updatedAt: new Date().toISOString(),
    });

    // Delete the file
    fs.unlinkSync(filePath);

    const result = verifyArtifact(filePath);
    expect(result.valid).toBe(false);
    expect(result.detail).toContain('missing');
  });
});

// ===========================================================================
// 3. signAllArtifacts
// ===========================================================================

describe('signAllArtifacts', () => {
  it('signs all existing shield artifacts', () => {
    const shieldDir = getShieldDir();

    // Create policy.yaml and scan.json (the artifacts that typically exist)
    fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), 'mode: adaptive\n');
    fs.writeFileSync(path.join(shieldDir, 'scan.json'), '{"timestamp": "now"}');

    signAllArtifacts();

    const store = loadSignatures();
    expect(store).not.toBeNull();
    expect(store!.signatures.length).toBe(2);

    const filePaths = store!.signatures.map(s => s.filePath);
    expect(filePaths).toContain('policy.yaml');
    expect(filePaths).toContain('scan.json');
  });

  it('only signs files that exist', () => {
    // Shield dir created but no files
    getShieldDir();

    signAllArtifacts();

    const store = loadSignatures();
    expect(store).not.toBeNull();
    expect(store!.signatures.length).toBe(0);
  });
});

// ===========================================================================
// 4. loadSignatures / saveSignatures
// ===========================================================================

describe('loadSignatures / saveSignatures', () => {
  it('returns null when no signatures file exists', () => {
    getShieldDir(); // ensure dir exists
    const store = loadSignatures();
    expect(store).toBeNull();
  });

  it('round-trips correctly', () => {
    getShieldDir();
    const store = {
      version: 1 as const,
      signatures: [{
        filePath: 'test.json',
        hash: 'sha256:abc123',
        signedAt: new Date().toISOString(),
        signedBy: 'test@opena2a-cli',
        fileSize: 42,
      }],
      updatedAt: new Date().toISOString(),
    };

    saveSignatures(store);
    const loaded = loadSignatures();

    expect(loaded).not.toBeNull();
    expect(loaded!.version).toBe(1);
    expect(loaded!.signatures).toHaveLength(1);
    expect(loaded!.signatures[0].filePath).toBe('test.json');
  });

  it('returns null for corrupt signatures file', () => {
    const shieldDir = getShieldDir();
    fs.writeFileSync(path.join(shieldDir, 'signatures.json'), 'not json');

    const store = loadSignatures();
    expect(store).toBeNull();
  });
});

// ===========================================================================
// 5. verifyAllArtifacts
// ===========================================================================

describe('verifyAllArtifacts', () => {
  it('returns valid when no signatures exist', () => {
    getShieldDir();
    const result = verifyAllArtifacts();
    expect(result.valid).toBe(true);
  });

  it('returns valid when all artifacts are intact', () => {
    const shieldDir = getShieldDir();
    fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), 'mode: monitor\n');
    fs.writeFileSync(path.join(shieldDir, 'scan.json'), '{}');

    signAllArtifacts();

    const result = verifyAllArtifacts();
    expect(result.valid).toBe(true);
    expect(result.detail).toContain('verified');
  });

  it('returns invalid when any artifact is tampered', () => {
    const shieldDir = getShieldDir();
    fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), 'mode: monitor\n');
    fs.writeFileSync(path.join(shieldDir, 'scan.json'), '{}');

    signAllArtifacts();

    // Tamper with policy
    fs.writeFileSync(path.join(shieldDir, 'policy.yaml'), 'mode: EVIL\n');

    const result = verifyAllArtifacts();
    expect(result.valid).toBe(false);
    expect(result.detail).toContain('has been modified');
  });
});

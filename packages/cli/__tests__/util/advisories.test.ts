import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

// The advisory list is cached in the user's home, so each test gets its own.
const mockHome = vi.hoisted(() => ({ dir: '' }));

vi.mock('node:os', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:os')>();
  return {
    ...actual,
    homedir: () => mockHome.dir || actual.homedir(),
  };
});

import { checkAdvisories, printAdvisoryWarnings } from '../../src/util/advisories.js';

const mockFetch = vi.fn();

beforeEach(() => {
  vi.stubGlobal('fetch', mockFetch);
  mockFetch.mockReset();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('advisories', () => {
  let tempDir: string;
  let tempHome: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-advisory-test-'));
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-advisory-home-'));
    mockHome.dir = tempHome;
  });

  afterEach(() => {
    mockHome.dir = '';
    fs.rmSync(tempDir, { recursive: true, force: true });
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  it('returns empty when no advisories exist', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(result.advisories).toHaveLength(0);
    expect(result.matchedPackages).toHaveLength(0);
  });

  it('matches advisories against project dependencies', async () => {
    // Create a package.json with a dependency that has an advisory
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
      name: 'test-project',
      dependencies: { 'vulnerable-package': '1.0.0', 'safe-package': '2.0.0' },
    }));

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        advisories: [
          {
            id: 'OA2A-2026-0001',
            summary: 'Critical vulnerability in vulnerable-package',
            severity: [{ type: 'ADVISORY', score: 'CRITICAL' }],
            affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' } }],
            published: '2026-03-01T00:00:00Z',
          },
          {
            id: 'OA2A-2026-0002',
            summary: 'Issue in unrelated-package',
            severity: [{ type: 'ADVISORY', score: 'HIGH' }],
            affected: [{ package: { name: 'unrelated-package', ecosystem: 'npm' } }],
            published: '2026-03-01T00:00:00Z',
          },
        ],
        total: 2,
        format: 'osv',
      }),
    });

    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(result.advisories).toHaveLength(1);
    expect(result.advisories[0].id).toBe('OA2A-2026-0001');
    expect(result.matchedPackages).toContain('vulnerable-package');
    expect(result.matchedPackages).not.toContain('unrelated-package');
  });

  it('handles network errors gracefully', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));

    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(result.advisories).toHaveLength(0);
    expect(result.total).toBe(0);
  });

  it('handles non-200 responses gracefully', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 500 });

    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(result.advisories).toHaveLength(0);
  });

  it('caches advisory results', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    // First call fetches
    await checkAdvisories(tempDir, 'https://registry.test');
    expect(mockFetch).toHaveBeenCalledTimes(1);

    // Second call uses cache
    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(mockFetch).toHaveBeenCalledTimes(1); // Not called again
    expect(result.fromCache).toBe(true);
  });

  it('detects Python dependencies from requirements.txt', async () => {
    fs.writeFileSync(path.join(tempDir, 'requirements.txt'), 'flask==2.0.0\nrequests>=2.25\n');

    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({
        advisories: [
          {
            id: 'OA2A-2026-0003',
            summary: 'Flask vulnerability',
            severity: [{ type: 'ADVISORY', score: 'HIGH' }],
            affected: [{ package: { name: 'flask', ecosystem: 'pypi' } }],
            published: '2026-03-01T00:00:00Z',
          },
        ],
        total: 1,
        format: 'osv',
      }),
    });

    const result = await checkAdvisories(tempDir, 'https://registry.test');
    expect(result.advisories).toHaveLength(1);
    expect(result.matchedPackages).toContain('flask');
  });

  // Regression (#420): review and init called the check with no Registry URL,
  // so the request never left the process and the empty result read as
  // "no matching advisories found". The result now says whether a list was
  // read at all.
  it('requests the list from the Registry URL it is given', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    await checkAdvisories(tempDir, 'https://registry.test');

    expect(mockFetch).toHaveBeenCalledTimes(1);
    expect(String(mockFetch.mock.calls[0][0])).toMatch(/^https:\/\/registry\.test\/api\/v1\/trust\/advisories\?/);
  });

  it('is checked when a list was read, including an empty one', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    expect((await checkAdvisories(tempDir, 'https://registry.test')).checked).toBe(true);
    // The second read comes from the cache: still a list that was read.
    const cached = await checkAdvisories(tempDir, 'https://registry.test');
    expect(cached.fromCache).toBe(true);
    expect(cached.checked).toBe(true);
  });

  it('is not checked when no list was read', async () => {
    mockFetch.mockRejectedValue(new Error('Network error'));
    expect((await checkAdvisories(tempDir, 'https://registry.test')).checked).toBe(false);

    mockFetch.mockReset();
    mockFetch.mockResolvedValue({ ok: false, status: 503 });
    expect((await checkAdvisories(tempDir, 'https://registry.test')).checked).toBe(false);

    mockFetch.mockReset();
    mockFetch.mockResolvedValue({ ok: true, json: async () => ({ error: 'maintenance' }) });
    expect((await checkAdvisories(tempDir, 'https://registry.test')).checked).toBe(false);
  });

  it('an empty Registry URL is not checked and sends nothing', async () => {
    const result = await checkAdvisories(tempDir, '');
    expect(result.checked).toBe(false);
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('caches the list in the home directory and writes nothing into the scanned tree', async () => {
    fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({ name: 'test' }));
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    await checkAdvisories(tempDir, 'https://registry.test');

    expect(fs.readdirSync(tempDir)).toEqual(['package.json']);
    expect(fs.existsSync(path.join(tempHome, '.opena2a', 'cache', 'advisories.json'))).toBe(true);
  });

  // Regression: on a first review or init the cache write is the first write
  // under ~/.opena2a, so it sets that directory's mode. It used the default
  // mode, 755 under a umask of 022, where the other writers there create the
  // directory 700, and files below it became readable by other local users.
  it('creates ~/.opena2a, the cache directory and the cache file for the owner only', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });
    const stateDir = path.join(tempHome, '.opena2a');
    expect(fs.existsSync(stateDir)).toBe(false);

    // Checked under the usual umask, whatever the runner's own is.
    const umask = process.umask(0o022);
    try {
      await checkAdvisories(tempDir, 'https://registry.test');
    } finally {
      process.umask(umask);
    }

    const mode = (p: string) => fs.statSync(p).mode & 0o777;
    expect(mode(stateDir)).toBe(0o700);
    expect(mode(path.join(stateDir, 'cache'))).toBe(0o700);
    expect(mode(path.join(stateDir, 'cache', 'advisories.json'))).toBe(0o600);
  });

  it('does not answer from a list cached for another Registry', async () => {
    mockFetch.mockResolvedValue({
      ok: true,
      json: async () => ({ advisories: [], total: 0, format: 'osv' }),
    });

    await checkAdvisories(tempDir, 'https://registry.test');
    const other = await checkAdvisories(tempDir, 'https://other-registry.test');

    expect(mockFetch).toHaveBeenCalledTimes(2);
    expect(String(mockFetch.mock.calls[1][0])).toMatch(/^https:\/\/other-registry\.test\//);
    expect(other.fromCache).toBe(false);
  });

  it('printAdvisoryWarnings outputs to stdout', () => {
    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;

    printAdvisoryWarnings({
      advisories: [
        {
          id: 'OA2A-2026-0001',
          summary: 'Test advisory',
          severity: [{ type: 'ADVISORY', score: 'CRITICAL' }],
          affected: [{ package: { name: 'test-pkg', ecosystem: 'npm' } }],
          published: '2026-03-01T00:00:00Z',
        },
      ],
      matchedPackages: ['test-pkg'],
      total: 1,
      fromCache: false,
      checked: true,
    });

    process.stdout.write = origWrite;
    const output = chunks.join('');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('Test advisory');
  });
});

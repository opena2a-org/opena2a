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

import { checkAdvisories, fixedVersions, printAdvisoryWarnings, readAdvisories } from '../../src/util/advisories.js';

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

  // Regression (#464): the advisory text is the Registry's, and init printed
  // it as received, so an ESC sequence reached the terminal and the text
  // after a newline printed as a line of its own.
  it('printAdvisoryWarnings removes control characters from Registry text', () => {
    const chunks: string[] = [];
    const origWrite = process.stdout.write;
    process.stdout.write = ((chunk: any) => { chunks.push(String(chunk)); return true; }) as any;
    try {
      printAdvisoryWarnings({
        advisories: [{
          id: 'OA2A-2026-0001\x1b]0;title\x07',
          summary: 'Bad thing\x1b[31mRED\nFORGED LINE',
          severity: [{ type: 'ADVISORY', score: 'HIGH' }],
          affected: [{ package: { name: 'test-pkg\r\nFORGED PKG', ecosystem: 'npm' } }],
          published: '2026-10-01T00:00:00Z',
        }],
        matchedPackages: ['test-pkg\nFORGED MATCH'],
        total: 1,
        listed: 1,
        fromCache: false,
        checked: true,
        reason: null,
        turnedOff: false,
      });
    } finally {
      process.stdout.write = origWrite;
    }
    const output = chunks.join('');
    expect(output).not.toContain('\x1b');
    expect(output).not.toContain('\x07');
    expect(output).not.toContain('\r');
    expect(output).toContain('Bad thing[31mREDFORGED LINE');
    expect(output.split('\n').some(l => /^\s*FORGED/.test(l))).toBe(false);
  });

  // Regression (#464): a registry.url ending in "/" requested
  // "//api/v1/trust/advisories".
  it('joins a Registry URL that ends in "/" with one slash', async () => {
    mockFetch.mockResolvedValue({ ok: true, json: async () => ({ advisories: [], total: 0, format: 'osv' }) });

    await checkAdvisories(tempDir, 'https://registry.test/');

    expect(String(mockFetch.mock.calls[0][0])).toMatch(/^https:\/\/registry\.test\/api\/v1\/trust\/advisories\?/);
  });

  it('reads the window and limit it states, and reports a total above the list it read', async () => {
    mockFetch.mockResolvedValue({ ok: true, json: async () => ({ advisories: [], total: 250, format: 'osv' }) });

    const result = await checkAdvisories(tempDir, 'https://registry.test');

    const url = new URL(String(mockFetch.mock.calls[0][0]));
    expect(url.searchParams.get('limit')).toBe('100');
    const days = (Date.now() - Date.parse(url.searchParams.get('since') as string)) / 86_400_000;
    expect(days).toBeGreaterThanOrEqual(29);
    expect(days).toBeLessThanOrEqual(31);
    expect(result.checked).toBe(true);
    expect(result.listed).toBe(0);
    expect(result.total).toBe(250);
  });

  // Regression (#464): a refused registry.url left the advisories "not
  // checked" with nothing that named the URL or the refusal.
  it('names the refusal of a configured Registry URL and sends nothing', async () => {
    const direct = await checkAdvisories(tempDir, 'http://registry.internal.example');
    expect(direct.checked).toBe(false);
    expect(direct.reason).toBe('Registry URL must use HTTPS: http://registry.internal.example');

    // A URL carrying a user and password; the reason names the host only.
    const withUserinfo = 'http://' + ['someone', 'not-a-real-pw'].join(':') + '@registry.internal.example';
    const resolved = await readAdvisories(tempDir, async () => {
      throw new Error(`Registry URL must use HTTPS: ${withUserinfo}\nPlain HTTP is only allowed for localhost development.`);
    });
    expect(resolved.checked).toBe(false);
    expect(resolved.reason).toBe('Registry URL must use HTTPS: http://registry.internal.example');
    expect(mockFetch).not.toHaveBeenCalled();
  });

  it('names why no list was read: an HTTP status, a timeout, an unreachable host', async () => {
    mockFetch.mockResolvedValue({ ok: false, status: 503 });
    expect((await checkAdvisories(tempDir, 'https://registry.test')).reason).toBe('https://registry.test answered HTTP 503');

    mockFetch.mockReset();
    mockFetch.mockRejectedValue(Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }));
    expect((await checkAdvisories(tempDir, 'https://registry.test')).reason).toBe('https://registry.test did not answer within 5 seconds');

    mockFetch.mockReset();
    mockFetch.mockRejectedValue(new TypeError('fetch failed', { cause: new Error('getaddrinfo ENOTFOUND registry.test') }));
    expect((await checkAdvisories(tempDir, 'https://registry.test')).reason).toBe('https://registry.test could not be read (fetch failed: getaddrinfo ENOTFOUND registry.test)');
  });

  // Regression (#464): the request could not be skipped.
  describe('OPENA2A_ADVISORIES=off', () => {
    const saved = process.env.OPENA2A_ADVISORIES;
    afterEach(() => {
      if (saved === undefined) delete process.env.OPENA2A_ADVISORIES;
      else process.env.OPENA2A_ADVISORIES = saved;
    });

    it('skips the request and reports the advisories as not checked', async () => {
      process.env.OPENA2A_ADVISORIES = 'off';
      const resolve = vi.fn(async () => 'https://registry.test');

      const result = await readAdvisories(tempDir, resolve);

      expect(mockFetch).not.toHaveBeenCalled();
      expect(resolve).not.toHaveBeenCalled();
      expect(result.checked).toBe(false);
      expect(result.turnedOff).toBe(true);
      expect(result.reason).toContain('OPENA2A_ADVISORIES=off');
    });

    it('any other value makes the request', async () => {
      process.env.OPENA2A_ADVISORIES = 'on';
      mockFetch.mockResolvedValue({ ok: true, json: async () => ({ advisories: [], total: 0, format: 'osv' }) });

      const result = await readAdvisories(tempDir, async () => 'https://registry.test');

      expect(mockFetch).toHaveBeenCalledTimes(1);
      expect(result.checked).toBe(true);
    });
  });

  it('fixedVersions reads plain fixed versions for the package and drops anything else', () => {
    const advisory = {
      id: 'OA2A-2026-0004',
      summary: 'x',
      severity: [],
      published: '2026-10-01T00:00:00Z',
      affected: [
        { package: { name: 'pkg', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.3.0' }, { fixed: '2.0.1-rc.1' }, { fixed: '1.3.0' }, { fixed: '3.0.0; touch x' }] }] },
        { package: { name: 'other', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: [{ fixed: '9.9.9' }] }] },
      ],
    };
    expect(fixedVersions(advisory, 'pkg')).toEqual(['1.3.0', '2.0.1-rc.1']);
    expect(fixedVersions(advisory, 'missing')).toEqual([]);
  });

  // Regression: the answer was read as received, so a `null` entry or an
  // `affected` object stopped review and init with a TypeError.
  describe('an advisory list of the wrong shape', () => {
    const WELL_FORMED = {
      id: 'OA2A-2026-0005',
      summary: 'Advisory in vulnerable-package',
      severity: [{ type: 'ADVISORY', score: 'HIGH' }],
      published: '2026-10-01T00:00:00Z',
      affected: [{
        package: { name: 'vulnerable-package', ecosystem: 'npm' },
        ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '1.3.0' }] }],
      }],
    };
    const MALFORMED = [
      null,
      'not an advisory',
      { id: 'OA2A-2026-0006', summary: 'affected is an object', affected: { package: { name: 'vulnerable-package' } } },
      { id: 'OA2A-2026-0007', summary: 'affected holds no object', affected: [null, 5] },
      { id: 'OA2A-2026-0008', summary: 'ecosystem and ranges', affected: [{ package: { name: 'vulnerable-package', ecosystem: 7 }, ranges: { events: [] } }] },
      { id: 'OA2A-2026-0009', summary: 'events is an object', affected: [{ package: { name: 'vulnerable-package', ecosystem: 'npm' }, ranges: [{ type: 'SEMVER', events: { fixed: '9.9.9' } }] }] },
    ];

    beforeEach(() => {
      fs.writeFileSync(path.join(tempDir, 'package.json'), JSON.stringify({
        name: 'test-project',
        dependencies: { 'vulnerable-package': '1.0.0' },
      }));
    });

    it('leaves out what is not an advisory, reads the rest, and matches as before', async () => {
      mockFetch.mockResolvedValue({
        ok: true,
        json: async () => ({ advisories: [...MALFORMED, WELL_FORMED], total: 7, format: 'osv' }),
      });

      const result = await checkAdvisories(tempDir, 'https://registry.test');

      expect(result.checked).toBe(true);
      expect(result.listed).toBe(5);
      expect(result.total).toBe(7);
      expect(result.matchedPackages).toEqual(['vulnerable-package']);
      expect(result.advisories.map(a => a.id)).toEqual(['OA2A-2026-0008', 'OA2A-2026-0009', 'OA2A-2026-0005']);
      expect(result.advisories[0].affected[0].package.ecosystem).toBe('');
      expect(fixedVersions(result.advisories[1], 'vulnerable-package')).toEqual([]);
      expect(result.advisories[2]).toEqual(WELL_FORMED);
    });

    it('counts the entries left out in the total when the answer gives none', async () => {
      mockFetch.mockResolvedValue({ ok: true, json: async () => ({ advisories: [null, WELL_FORMED] }) });

      const result = await checkAdvisories(tempDir, 'https://registry.test');

      expect(result.listed).toBe(1);
      expect(result.total).toBe(2);
    });

    it('reads a cached list the same way', async () => {
      const cacheDir = path.join(tempHome, '.opena2a', 'cache');
      fs.mkdirSync(cacheDir, { recursive: true });
      fs.writeFileSync(path.join(cacheDir, 'advisories.json'), JSON.stringify({
        fetchedAt: Date.now(),
        registryUrl: 'https://registry.test',
        data: { advisories: [...MALFORMED, WELL_FORMED], total: 7, format: 'osv' },
      }));

      const result = await checkAdvisories(tempDir, 'https://registry.test');

      expect(mockFetch).not.toHaveBeenCalled();
      expect(result.fromCache).toBe(true);
      expect(result.listed).toBe(5);
      expect(result.advisories.map(a => a.id)).toEqual(['OA2A-2026-0008', 'OA2A-2026-0009', 'OA2A-2026-0005']);
    });
  });
});

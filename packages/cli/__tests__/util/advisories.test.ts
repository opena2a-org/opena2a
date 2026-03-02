import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
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

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-advisory-test-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
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
    });

    process.stdout.write = origWrite;
    const output = chunks.join('');
    expect(output).toContain('CRITICAL');
    expect(output).toContain('Test advisory');
  });
});

/**
 * Advisory check utility -- fetches security advisories from the OpenA2A Registry
 * and warns users about flagged tools in their project.
 *
 * Called during `opena2a init` and `opena2a review` to surface intelligence from
 * community scan reports.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { bold, red, yellow, dim, cyan, orange } from './colors.js';
import { validateRegistryUrl } from './validate-registry-url.js';

// --- Types ---

interface OSVSeverity {
  type: string;
  score: string;
}

interface OSVAffected {
  package: {
    name: string;
    ecosystem: string;
  };
  ranges?: {
    type: string;
    events: { introduced?: string; fixed?: string }[];
  }[];
}

export interface Advisory {
  id: string;
  summary: string;
  severity: OSVSeverity[];
  affected: OSVAffected[];
  published: string;
  details?: string;
  databaseSpecific?: Record<string, any>;
}

interface AdvisoryResponse {
  advisories: Advisory[];
  total: number;
  format: string;
}

export interface AdvisoryCheck {
  advisories: Advisory[];
  matchedPackages: string[];
  total: number;
  fromCache: boolean;
  /** Whether an advisory list was read, from the Registry or the cache. When
   *  false no dependency was compared, so the result is "not checked", not
   *  "no advisories found". */
  checked: boolean;
}

/** The result when no advisory list was read. */
export function advisoriesNotChecked(): AdvisoryCheck {
  return { advisories: [], matchedPackages: [], total: 0, fromCache: false, checked: false };
}

// --- Cache ---

// The advisory list is the Registry's, not the project's, so it is cached in
// the user's home: a review or init of a tree writes no cache into that tree.
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

interface CachedAdvisories {
  fetchedAt: number;
  registryUrl: string;
  data: AdvisoryResponse;
}

function getCachePath(): string {
  return path.join(os.homedir(), '.opena2a', 'cache', 'advisories.json');
}

function readCache(registryUrl: string): CachedAdvisories | null {
  const cachePath = getCachePath();
  if (!fs.existsSync(cachePath)) return null;

  try {
    const raw = fs.readFileSync(cachePath, 'utf-8');
    const cached = JSON.parse(raw) as CachedAdvisories;
    // A list read from another Registry is not this Registry's list.
    if (
      cached.registryUrl === registryUrl
      && Array.isArray(cached.data?.advisories)
      && Date.now() - cached.fetchedAt < CACHE_TTL_MS
    ) {
      return cached;
    }
  } catch {
    // Corrupted cache
  }
  return null;
}

function writeCache(registryUrl: string, data: AdvisoryResponse): void {
  const cachePath = getCachePath();
  const cacheDir = path.dirname(cachePath);
  try {
    // On a first run this write creates ~/.opena2a, so it sets the mode of the
    // directory the other files there rely on: owner only, as their writers do.
    fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    fs.writeFileSync(cachePath, JSON.stringify({
      fetchedAt: Date.now(),
      registryUrl,
      data,
    } as CachedAdvisories), { encoding: 'utf-8', mode: 0o600 });
  } catch {
    // Cache write failure is non-critical
  }
}

// --- Fetch ---

async function fetchAdvisories(registryUrl: string): Promise<AdvisoryResponse | null> {
  // The validator accepts an empty URL, which would build a relative one.
  if (!registryUrl) return null;
  try {
    validateRegistryUrl(registryUrl);
    // Fetch advisories from the last 30 days
    const since = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
    const url = `${registryUrl}/api/v1/trust/advisories?since=${since}&limit=100`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(5_000),
    });

    if (!response.ok) return null;
    const body = await response.json() as Partial<AdvisoryResponse> | null;
    // A body without an advisory list is not a list that was read.
    if (!body || !Array.isArray(body.advisories)) return null;
    return body as AdvisoryResponse;
  } catch {
    return null;
  }
}

// --- Package detection ---

function detectProjectPackages(dir: string): string[] {
  const packages: string[] = [];

  // Read package.json dependencies
  const pkgPath = path.join(dir, 'package.json');
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      const deps = {
        ...pkg.dependencies,
        ...pkg.devDependencies,
        ...pkg.optionalDependencies,
      };
      packages.push(...Object.keys(deps ?? {}));
    } catch {
      // Invalid package.json
    }
  }

  // Read go.mod dependencies
  const goModPath = path.join(dir, 'go.mod');
  if (fs.existsSync(goModPath)) {
    try {
      const content = fs.readFileSync(goModPath, 'utf-8');
      const requireBlock = content.match(/require\s*\(([\s\S]*?)\)/);
      if (requireBlock) {
        const lines = requireBlock[1].split('\n');
        for (const line of lines) {
          const match = line.trim().match(/^(\S+)\s/);
          if (match) packages.push(match[1]);
        }
      }
    } catch {
      // Invalid go.mod
    }
  }

  // Read requirements.txt
  const reqPath = path.join(dir, 'requirements.txt');
  if (fs.existsSync(reqPath)) {
    try {
      const content = fs.readFileSync(reqPath, 'utf-8');
      for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith('#')) {
          const name = trimmed.split(/[=<>!~]/)[0].trim();
          if (name) packages.push(name);
        }
      }
    } catch {
      // Invalid requirements.txt
    }
  }

  return packages;
}

// --- Main check ---

/**
 * Read the Registry's advisory list and match it against the packages `dir`
 * depends on. The Registry URL is required: the caller passes the one
 * `getRegistryUrl()` resolved, so the check cannot run against no Registry
 * and report an empty list as "no advisories".
 */
export async function checkAdvisories(
  dir: string,
  registryUrl: string,
): Promise<AdvisoryCheck> {
  // Check cache first
  const cached = readCache(registryUrl);
  let data: AdvisoryResponse;
  let fromCache = false;

  if (cached) {
    data = cached.data;
    fromCache = true;
  } else {
    const fetched = await fetchAdvisories(registryUrl);
    if (!fetched) return advisoriesNotChecked();
    data = fetched;
    writeCache(registryUrl, data);
  }

  if (data.advisories.length === 0) {
    return { advisories: [], matchedPackages: [], total: 0, fromCache, checked: true };
  }

  // Match advisories against project packages
  const projectPackages = new Set(detectProjectPackages(dir));
  const matched: Advisory[] = [];
  const matchedNames: string[] = [];

  for (const advisory of data.advisories) {
    for (const affected of advisory.affected ?? []) {
      const pkgName = affected.package?.name;
      if (pkgName && projectPackages.has(pkgName)) {
        matched.push(advisory);
        if (!matchedNames.includes(pkgName)) {
          matchedNames.push(pkgName);
        }
        break;
      }
    }
  }

  return {
    advisories: matched,
    matchedPackages: matchedNames,
    total: data.total,
    fromCache,
    checked: true,
  };
}

// --- Output ---

export function printAdvisoryWarnings(check: AdvisoryCheck): void {
  if (check.advisories.length === 0) return;

  process.stdout.write('\n');
  process.stdout.write(red(bold('  Security Advisories')) + '\n');
  process.stdout.write(dim('  ' + '-'.repeat(47)) + '\n');

  for (const advisory of check.advisories) {
    const severity = advisory.severity?.[0]?.score ?? 'UNKNOWN';
    const severityColor = severity === 'CRITICAL' ? red
      : severity === 'HIGH' ? orange
      : severity === 'MODERATE' ? yellow
      : dim;

    const packages = (advisory.affected ?? []).map(a => a.package?.name).filter(Boolean);

    process.stdout.write(`  ${severityColor(`[${severity}]`.padEnd(12))} ${advisory.summary}\n`);
    process.stdout.write(`  ${' '.repeat(12)} ${dim(`ID: ${advisory.id}  Packages: ${packages.join(', ')}`)}\n`);
  }

  process.stdout.write(dim('  ' + '-'.repeat(47)) + '\n');
  process.stdout.write(`  ${yellow(`${check.advisories.length} advisory(ies)`)} affecting ${cyan(check.matchedPackages.join(', '))}\n`);
  // The package is a shell parameter that refuses when unset: pasted before
  // PACKAGE is set, the shell prints the message and runs nothing.
  process.stdout.write(dim('  For details, run: opena2a verify --package "${PACKAGE:?set PACKAGE to a package named above}"\n'));
  process.stdout.write('\n');
}

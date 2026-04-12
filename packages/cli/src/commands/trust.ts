/**
 * opena2a trust -- Look up the trust profile for an AI agent or MCP server.
 * Queries the Agent Trust Protocol (ATP) public API on the OpenA2A Registry.
 *
 * Usage:
 *   opena2a trust @anthropic/mcp-server-fetch
 *   opena2a trust langchain --source pypi
 *   opena2a trust --json
 *   opena2a trust                              # reads package.json in cwd
 */

import { bold, green, yellow, red, dim, cyan, gray } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { validateRegistryUrl } from '../util/validate-registry-url.js';
import type { TrustLookupResponse } from './atp-types.js';

// --- Types ---

export interface TrustOptions {
  packageName?: string;
  source?: string;
  registryUrl?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  json?: boolean;
  verbose?: boolean;
}

// --- Constants ---

const DEFAULT_REGISTRY_URL = 'https://api.oa2a.org';

// --- Testable internals ---

export const _internals = {
  readLocalPackageName(): string | null {
    try {
      const fs = require('node:fs');
      const path = require('node:path');
      const pkgPath = path.join(process.cwd(), 'package.json');
      if (fs.existsSync(pkgPath)) {
        const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
        return pkg.name ?? null;
      }
    } catch { /* ignore */ }
    return null;
  },

  async fetchTrustLookup(
    registryUrl: string,
    packageName: string,
    source?: string,
  ): Promise<{ ok: boolean; status: number; data?: TrustLookupResponse }> {
    const params = new URLSearchParams({ package: packageName });
    if (source) params.set('source', source);
    const url = `${registryUrl}/v1/trust/lookup?${params}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return { ok: false, status: response.status };
    }

    const data = (await response.json()) as TrustLookupResponse;
    return { ok: true, status: response.status, data };
  },

  async fetchRegistrySearch(
    registryUrl: string,
    query: string,
  ): Promise<{ ok: boolean; status: number; data?: any }> {
    const params = new URLSearchParams({ q: query });
    const url = `${registryUrl}/api/v1/registry/search?${params}`;

    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(15_000),
    });

    if (!response.ok) {
      return { ok: false, status: response.status };
    }

    const data = await response.json();
    return { ok: true, status: response.status, data };
  },
};

// --- Core ---

const VALID_SOURCES = ['npm', 'pypi', 'github'] as const;

export async function trust(options: TrustOptions): Promise<number> {
  const registryUrl = await resolveRegistryUrl(options.registryUrl);
  const isJson = options.json || options.format === 'json';
  const isCi = options.ci ?? false;

  // Validate --source
  if (options.source && !VALID_SOURCES.includes(options.source as any)) {
    const msg = `Invalid source '${options.source}'. Valid sources: npm, pypi, github.`;
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: msg }) + '\n');
    } else {
      process.stderr.write(red(msg) + '\n');
    }
    return 1;
  }

  // Resolve package name
  let packageName = options.packageName;

  // Auto-detect GitHub URLs
  if (packageName && packageName.startsWith('https://github.com/')) {
    const match = packageName.match(/github\.com\/([^/]+\/[^/]+)/);
    if (match) {
      packageName = match[1].replace(/\.git$/, '');
      if (!options.source) options.source = 'github';
    }
  }

  // Handle empty/whitespace-only input
  if (packageName !== undefined && packageName.trim() === '') {
    packageName = undefined;
  }

  if (!packageName) {
    packageName = _internals.readLocalPackageName() ?? undefined;
    if (!packageName) {
      const msg = 'No package name provided and no package.json found in current directory.';
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: msg }) + '\n');
      } else {
        process.stderr.write(red(msg) + '\n');
        process.stderr.write('Usage: opena2a trust <package-name> [--source npm|pypi|github]\n');
      }
      return 1;
    }
  }

  // Default source to "npm" -- the most common package source.
  // Without a source the registry API returns 400 "source parameter is required",
  // which would surface as a misleading "not found" error to the user.
  const source = options.source ?? 'npm';

  const spinner = new Spinner(`Looking up trust profile for ${packageName}...`);
  if (!isCi && !isJson) {
    spinner.start();
  }

  const params = new URLSearchParams({ package: packageName });
  params.set('source', source);
  const requestUrl = `${registryUrl}/v1/trust/lookup?${params}`;

  try {
    const startTime = Date.now();

    // Try primary lookup with specified/default source
    let result = await _internals.fetchTrustLookup(registryUrl, packageName, source);

    // If not found and source was defaulted (not user-specified), try alternate sources
    if ((!result.ok || !result.data) && !options.source) {
      const alternateSources = VALID_SOURCES.filter(s => s !== source);
      for (const altSource of alternateSources) {
        const altResult = await _internals.fetchTrustLookup(registryUrl, packageName, altSource);
        if (altResult.ok && altResult.data) {
          result = altResult;
          break;
        }
      }
    }

    // If still not found, try the registry search API as fallback
    let searchResults: any[] | undefined;
    if (!result.ok || !result.data) {
      const searchResult = await _internals.fetchRegistrySearch(registryUrl, packageName);
      if (searchResult.ok && searchResult.data?.packages?.length > 0) {
        const packages = searchResult.data.packages;
        // Check for an exact name match first
        const exactMatch = packages.find((p: any) => p.name === packageName);
        if (exactMatch) {
          // Re-lookup using the exact package name and its source info
          const lookupName = exactMatch.name;
          for (const trySource of VALID_SOURCES) {
            const retryResult = await _internals.fetchTrustLookup(registryUrl, lookupName, trySource);
            if (retryResult.ok && retryResult.data) {
              result = retryResult;
              break;
            }
          }
        }
        // If still no direct match, save search results to show suggestions
        if (!result.ok || !result.data) {
          searchResults = packages.slice(0, 5);
        }
      }
    }

    const elapsed = Date.now() - startTime;

    if (!isCi && !isJson) {
      spinner.stop();
    }

    if (!result.ok || !result.data) {
      const notFoundMsg = `No trust profile found for ${packageName}. It may not have been discovered yet.`;
      const registerHint = `To add this package, run: opena2a self-register ${packageName}`;
      if (isJson) {
        const jsonOut: any = {
          error: 'not_found',
          package: packageName,
          message: notFoundMsg,
          hint: registerHint,
        };
        if (searchResults && searchResults.length > 0) {
          jsonOut.suggestions = searchResults.map((p: any) => ({
            name: p.name,
            version: p.latestVersion,
            description: p.description,
          }));
        }
        process.stdout.write(JSON.stringify(jsonOut) + '\n');
      } else {
        process.stdout.write(yellow(notFoundMsg) + '\n');
        if (searchResults && searchResults.length > 0) {
          process.stdout.write('\n');
          process.stdout.write(bold('Similar packages in registry:') + '\n');
          for (const pkg of searchResults) {
            const desc = pkg.description ? dim(` - ${pkg.description.slice(0, 60)}`) : '';
            process.stdout.write(`  ${cyan(pkg.name)} v${pkg.latestVersion}${desc}\n`);
          }
          process.stdout.write('\n');
        }
        process.stdout.write(dim(registerHint) + '\n');
        process.stdout.write(dim('Learn more: https://opena2a.org/docs/cli/trust') + '\n');
        if (options.verbose) {
          process.stdout.write('\n');
          process.stdout.write(dim(`Request:  GET ${requestUrl}`) + '\n');
          process.stdout.write(dim(`Status:   ${result.status}`) + '\n');
          process.stdout.write(dim(`Time:     ${elapsed}ms`) + '\n');
        }
      }
      return 1;
    }

    if (isJson) {
      const output = options.verbose
        ? { ...result.data, _debug: { requestUrl, responseTime: `${elapsed}ms`, httpStatus: result.status } }
        : result.data;
      process.stdout.write(JSON.stringify(output, null, 2) + '\n');
    } else {
      printTrustProfile(result.data, options.verbose ?? false, requestUrl, elapsed);
      printTrustNextSteps(packageName);
    }

    return 0;
  } catch (err) {
    if (!isCi && !isJson) {
      spinner.stop();
    }

    const errMsg = err instanceof Error ? err.message : String(err);
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'request_failed', message: errMsg }) + '\n');
    } else {
      process.stderr.write(red(`Failed to query trust profile: ${errMsg}`) + '\n');
      process.stderr.write(dim(`Registry: ${registryUrl}`) + '\n');
      process.stderr.write(dim('Check your registry URL in ~/.opena2a/config.json or use --registry-url <url>') + '\n');
      if (options.verbose) {
        process.stderr.write(dim(`Full error: ${err instanceof Error ? err.stack ?? err.message : String(err)}`) + '\n');
      }
    }
    return 1;
  }
}

// --- Output ---

function printTrustProfile(data: TrustLookupResponse, verbose: boolean, requestUrl?: string, elapsed?: number): void {
  const verifiedLabel = data.publisherVerified ? green('verified') : yellow('unverified');
  const scoreDisplay = Math.round(data.trustScore * 100);
  const scoreColor = scoreDisplay >= 70 ? green : scoreDisplay >= 30 ? yellow : red;
  const levelColor = data.trustLevel === 'certified' || data.trustLevel === 'verified' ? green
    : data.trustLevel === 'claimed' || data.trustLevel === 'scanned' ? yellow
    : dim;

  const typeLabel = data.displayType ?? formatPackageType(data.packageType);

  process.stdout.write('\n');
  process.stdout.write(bold(`${data.name} v${data.version}`) + '\n');
  if (typeLabel) {
    process.stdout.write(`Type:      ${typeLabel}\n`);
  }
  process.stdout.write(`Publisher: ${data.publisher} (${verifiedLabel})\n`);
  process.stdout.write(`Trust:     ${scoreColor(`${scoreDisplay}%`)} (${levelColor(data.trustLevel)})\n`);

  // Security Posture
  process.stdout.write('\n');
  process.stdout.write(bold('Security Posture') + '\n');

  if (data.posture) {
    const hardeningPct = Math.round(data.posture.hardeningPassRate * 100);
    process.stdout.write(`  Hardening:    ${hardeningPct}% pass rate\n`);

    const oasbPct = Math.round(data.posture.oasbCompliance * 100);
    const oasbLevel = oasbPct >= 80 ? 'L1 Compliant' : oasbPct >= 50 ? 'Partial' : 'Minimal';
    process.stdout.write(`  OASB:         ${oasbLevel} (${oasbPct}%)\n`);

    process.stdout.write(`  Governance:   ${data.posture.soulConformance} conformance\n`);

    const riskColor = data.posture.attackSurfaceRisk === 'low' ? green
      : data.posture.attackSurfaceRisk === 'medium' ? yellow
      : red;
    process.stdout.write(`  Attack Risk:  ${riskColor(data.posture.attackSurfaceRisk)}\n`);
  } else if (data.scanSummary) {
    const scan = data.scanSummary;
    const statusColor = scan.status === 'clean' ? green
      : scan.status === 'warnings' ? yellow
      : red;
    process.stdout.write(`  Scan Status:  ${statusColor(scan.status)}\n`);
    process.stdout.write(`  Findings:     ${scan.findingsCount ?? 0} (${scan.highCount ?? 0} high)\n`);
    if (scan.actionRequired) {
      process.stdout.write(`  Action:       ${yellow(scan.actionRequired)}\n`);
    }
    process.stdout.write(`  Last Scanned: ${formatRelativeTime(scan.lastScannedAt)}\n`);
  } else {
    process.stdout.write(dim('  No scan data yet. Run: opena2a scan') + '\n');
  }

  // Supply Chain
  process.stdout.write('\n');
  process.stdout.write(bold('Supply Chain') + '\n');

  if (data.supplyChain) {
    const sc = data.supplyChain;
    const critLabel = sc.criticalVulnerabilities === 0
      ? green('0 critical')
      : red(`${sc.criticalVulnerabilities} critical`);
    const highLabel = sc.highVulnerabilities === 0
      ? green('0 high')
      : yellow(`${sc.highVulnerabilities} high`);
    const medLabel = (sc.mediumVulnerabilities ?? 0) === 0
      ? '0 medium'
      : `${sc.mediumVulnerabilities} medium`;
    const lowLabel = (sc.lowVulnerabilities ?? 0) === 0
      ? '0 low'
      : `${sc.lowVulnerabilities} low`;

    if (sc.totalDependencies !== undefined && sc.totalDependencies !== null) {
      process.stdout.write(`  Dependencies: ${sc.totalDependencies}\n`);
    }
    process.stdout.write(`  Vulns:        ${critLabel}, ${highLabel}, ${medLabel}, ${lowLabel}\n`);
    process.stdout.write(`  Published:    ${formatRelativeTime(sc.lastPublished)}\n`);
    if (sc.maintainerCount > 0) {
      process.stdout.write(`  Maintainers:  ${sc.maintainerCount}\n`);
    }
    if (sc.weeklyDownloads !== undefined && sc.weeklyDownloads !== null) {
      process.stdout.write(`  Downloads:    ${formatNumber(sc.weeklyDownloads)}/week\n`);
    }
  } else {
    process.stdout.write(dim('  No supply chain data yet') + '\n');
  }

  // Capabilities
  if (data.capabilities && data.capabilities.length > 0) {
    process.stdout.write('\n');
    process.stdout.write(`Capabilities: ${data.capabilities.join(', ')}\n`);
  }

  // Verbose: factor breakdown, request details, raw metadata
  if (verbose) {
    if (data.factors && Object.keys(data.factors).length > 0) {
      process.stdout.write('\n');
      process.stdout.write(bold('Trust Factors') + '\n');
      for (const [factor, value] of Object.entries(data.factors)) {
        const pct = Math.round((value as number) * 100);
        const label = factor.replace(/([A-Z])/g, ' $1').toLowerCase().trim();
        process.stdout.write(`  ${label.padEnd(20)} ${pct}%\n`);
      }
    }

    process.stdout.write('\n');
    process.stdout.write(bold('Request Details') + '\n');
    if (requestUrl) process.stdout.write(`  URL:      ${dim(requestUrl)}\n`);
    if (elapsed !== undefined) process.stdout.write(`  Time:     ${dim(`${elapsed}ms`)}\n`);
    process.stdout.write(`  Agent ID: ${dim(data.agentId)}\n`);
    process.stdout.write(`  Source:   ${dim(data.source ?? 'npm')}\n`);
    process.stdout.write(`  Version:  ${dim(data.version)}\n`);
    if (data.lastScanned) process.stdout.write(`  Scanned:  ${dim(data.lastScanned)}\n`);
  }

  // Links — the Registry website is not live yet (launches April 2026) and
  // some responses embed legacy hostnames. Suppress the Profile/Badge lines
  // when the host is known-dead so users don't see broken URLs, and show a
  // dim placeholder instead.
  process.stdout.write('\n');
  if (isDeadProfileHost(data.profileUrl)) {
    process.stdout.write(dim('Profile: (Registry launches soon — opena2a.org)') + '\n');
  } else {
    process.stdout.write(`Profile: ${cyan(data.profileUrl)}\n`);
    process.stdout.write(`Badge:   ${dim(`${data.profileUrl.replace('/agents/', '/v1/trust/')}/badge.svg`)}\n`);
  }
  process.stdout.write('\n');
}

/**
 * Return true when a profile URL uses a hostname that is known not to resolve.
 * The Registry backend currently returns URLs under `registry.opena2a.org` and
 * `registry.oa2a.org`, neither of which has a live public endpoint. Until the
 * Registry website ships, we suppress those links client-side. Known-good
 * hosts (opena2a.org, www.opena2a.org, api.oa2a.org) are not considered dead.
 */
function isDeadProfileHost(url: string | undefined | null): boolean {
  if (!url) return true;
  const DEAD_HOSTS = [
    'registry.opena2a.org',
    'registry.oa2a.org',
    'api.opena2a.org',
  ];
  try {
    const host = new URL(url).hostname.toLowerCase();
    return DEAD_HOSTS.includes(host);
  } catch {
    return true;
  }
}

/**
 * Print a next-steps footer after the trust profile. Teaches users that
 * `trust` is a registry-only lookup and that `check` / `review` are the
 * scanning commands — a distinction that is not obvious from the verb alone.
 */
function printTrustNextSteps(packageName: string): void {
  process.stdout.write(`  ${dim(`Run a local scan:      opena2a check ${packageName} --rescan`)}\n`);
  process.stdout.write(`  ${dim('Full security review:  opena2a review')}\n`);
  process.stdout.write(`  ${dim("Note: 'trust' returns registry data only. For a real scan, use 'check'.")}\n`);
  process.stdout.write('\n');
}

function formatRelativeTime(isoDate: string): string {
  try {
    const then = new Date(isoDate).getTime();
    const now = Date.now();
    const diffMs = now - then;
    const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

    if (diffDays < 1) return 'today';
    if (diffDays === 1) return '1 day ago';
    if (diffDays < 7) return `${diffDays} days ago`;
    const weeks = Math.floor(diffDays / 7);
    if (weeks === 1) return '1 week ago';
    if (weeks < 5) return `${weeks} weeks ago`;
    const months = Math.floor(diffDays / 30);
    if (months === 1) return '1 month ago';
    return `${months} months ago`;
  } catch {
    return isoDate;
  }
}

// --- Helpers ---

/** Format large numbers with commas for readability. */
function formatNumber(n: number): string {
  return n.toLocaleString('en-US');
}

/** Map raw packageType slugs to human-friendly labels. */
function formatPackageType(packageType?: string): string | undefined {
  if (!packageType) return undefined;
  const labels: Record<string, string> = {
    mcp_server: 'MCP Server',
    a2a_agent: 'A2A Agent',
    ai_tool: 'AI Tool',
    skill: 'Skill',
    llm: 'LLM',
  };
  return labels[packageType] ?? packageType;
}

async function resolveRegistryUrl(override?: string): Promise<string> {
  if (override) {
    const url = override.replace(/\/$/, '');
    validateRegistryUrl(url);
    return url;
  }

  // Check environment variable
  const envUrl = process.env.OPENA2A_REGISTRY_URL;
  if (envUrl) {
    const url = envUrl.replace(/\/$/, '');
    validateRegistryUrl(url);
    return url;
  }

  try {
    const shared = await import('@opena2a/shared') as any;
    const mod = 'default' in shared ? shared.default : shared;
    const config = mod.loadUserConfig();
    if (config.registry.url) {
      validateRegistryUrl(config.registry.url);
      return config.registry.url;
    }
  } catch { /* not available */ }

  return DEFAULT_REGISTRY_URL;
}

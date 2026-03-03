/**
 * opena2a verify -- Verify binary integrity of installed packages.
 * Computes SHA-256 hashes of local artifacts and compares against
 * registry-published hashes for tamper detection.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { bold, green, yellow, red, dim } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { table } from '../util/format.js';

// --- Types ---

export interface VerifyOptions {
  packageName?: string;
  registryUrl?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

interface VerifyResult {
  packageName: string;
  version: string;
  localHash: string;
  registryStatus: 'verified' | 'tamper_detected' | 'no_data' | 'error' | 'not_installed';
  trustScore: number | null;
  trustVerdict: string | null;
  oracleVerdict: string | null;
  oracleSignatureValid: boolean | null;
  dependencyRiskCount: number | null;
  lastScannedAt: string | null;
  error?: string;
}

export interface ResolvedPackage {
  mainFile: string;
  version: string;
}

// --- Constants ---

const VERIFIABLE_PACKAGES = [
  'hackmyagent', 'secretless-ai', 'aibrowserguard', 'ai-trust',
];

// --- Testable internals ---

/**
 * Exported for testing. Internal code calls these through the object reference
 * so tests can replace individual functions via vi.spyOn.
 */
export const _internals = {
  resolvePackagePath(packageName: string): ResolvedPackage {
    const resolved = require.resolve(packageName);

    const path = require('node:path');
    const fs = require('node:fs');
    let dir = path.dirname(resolved);
    const root = path.parse(dir).root;

    while (dir !== root) {
      const pkgJsonPath = path.join(dir, 'package.json');
      if (fs.existsSync(pkgJsonPath)) {
        const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf-8'));
        if (pkgJson.name === packageName) {
          return {
            mainFile: resolved,
            version: pkgJson.version ?? 'unknown',
          };
        }
      }
      dir = path.dirname(dir);
    }

    return { mainFile: resolved, version: 'unknown' };
  },
};

// --- Core ---

export async function verify(options: VerifyOptions): Promise<number> {
  const registryUrl = await resolveRegistryUrl(options.registryUrl);
  const packages = options.packageName ? [options.packageName] : VERIFIABLE_PACKAGES;
  const isJson = options.format === 'json';
  const isCi = options.ci ?? false;

  if (!isJson && !isCi) {
    process.stdout.write(bold('Verifying binary integrity of OpenA2A packages') + '\n\n');
  }

  const results: VerifyResult[] = [];
  const spinner = new Spinner('');

  for (const pkg of packages) {
    if (!isCi && !isJson) {
      spinner.update(`Verifying ${pkg}...`);
      spinner.start();
    }

    const result = await verifyPackage(pkg, registryUrl, options);
    results.push(result);

    if (!isCi && !isJson) {
      spinner.stop();
    }
  }

  // Output
  if (isJson) {
    const report = {
      registryUrl,
      timestamp: new Date().toISOString(),
      total: results.length,
      verified: results.filter(r => r.registryStatus === 'verified').length,
      tamperDetected: results.filter(r => r.registryStatus === 'tamper_detected').length,
      noData: results.filter(r => r.registryStatus === 'no_data').length,
      notInstalled: results.filter(r => r.registryStatus === 'not_installed').length,
      packages: results.map(r => ({
        ...r,
        trustScore: r.trustScore,
        trustVerdict: r.trustVerdict,
        oracleVerdict: r.oracleVerdict,
        oracleSignatureValid: r.oracleSignatureValid,
        dependencyRiskCount: r.dependencyRiskCount,
        lastScannedAt: r.lastScannedAt,
      })),
    };
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printResults(results, registryUrl);
  }

  const tampered = results.filter(r => r.registryStatus === 'tamper_detected');
  return tampered.length > 0 ? 1 : 0;
}

// --- Trust profile and oracle queries ---

interface TrustProfile {
  trustScore: number;
  verdict: string;
  lastScannedAt: string | null;
  dependencyRiskCount: number;
}

interface OracleVerdict {
  verdict: string;
  signatureValid: boolean;
}

async function queryTrustProfile(registryUrl: string, name: string, type?: string): Promise<TrustProfile | null> {
  try {
    const params = new URLSearchParams({ name, includeProfile: 'true', includeDeps: 'true' });
    if (type) params.set('type', type);
    const url = `${registryUrl}/api/v1/trust/query?${params}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return null;

    const data = await response.json() as any;
    return {
      trustScore: data.trustProfile?.trustScore ?? data.trustScore ?? 0,
      verdict: data.trustProfile?.verdict ?? data.verdict ?? 'unknown',
      lastScannedAt: data.trustProfile?.lastScannedAt ?? data.lastScannedAt ?? null,
      dependencyRiskCount: data.dependencies?.riskCount ?? 0,
    };
  } catch {
    return null;
  }
}

async function queryOracleVerdict(registryUrl: string, component: string): Promise<OracleVerdict | null> {
  try {
    const url = `${registryUrl}/api/v1/oracle/${encodeURIComponent(component)}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });
    if (!response.ok) return null;

    const data = await response.json() as any;
    // Handle both string and nested object forms of verdict
    const rawVerdict = data.verdict;
    const verdictStr = typeof rawVerdict === 'string' ? rawVerdict
      : rawVerdict?.verdict ?? rawVerdict?.trustLevel ?? 'unknown';
    return {
      verdict: String(verdictStr),
      signatureValid: data.signatureValid ?? data.signature?.valid ?? data.verified ?? false,
    };
  } catch {
    return null;
  }
}

// --- Per-package verification ---

async function verifyPackage(
  packageName: string,
  registryUrl: string,
  options: VerifyOptions,
): Promise<VerifyResult> {
  const emptyTrust = {
    trustScore: null,
    trustVerdict: null,
    oracleVerdict: null,
    oracleSignatureValid: null,
    dependencyRiskCount: null,
    lastScannedAt: null,
  };

  // Step 1: Find local installation
  let mainFilePath: string;
  let pkgVersion: string;
  try {
    const resolved = _internals.resolvePackagePath(packageName);
    mainFilePath = resolved.mainFile;
    pkgVersion = resolved.version;
  } catch {
    if (options.verbose) {
      process.stderr.write(dim(`  ${packageName}: not installed locally\n`));
    }
    return {
      packageName,
      version: 'N/A',
      localHash: 'N/A',
      registryStatus: 'not_installed',
      ...emptyTrust,
    };
  }

  // Step 2: Compute SHA-256
  const localHash = computeSha256(mainFilePath);

  // Step 3: Query registry for hash verification
  let registryStatus: VerifyResult['registryStatus'] = 'no_data';
  let error: string | undefined;

  try {
    const url = `${registryUrl}/api/v1/trust/query?name=${encodeURIComponent(packageName)}&hash=${localHash}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok) {
      const data = await response.json() as { contentVerification?: { status?: string } };
      const status = data.contentVerification?.status;
      if (status === 'verified') registryStatus = 'verified';
      else if (status === 'tamper_detected') registryStatus = 'tamper_detected';
    }
  } catch (err) {
    registryStatus = 'error';
    error = err instanceof Error ? err.message : String(err);
  }

  // Step 4: Query trust profile and oracle verdict (parallel, non-blocking)
  const type = packageName.startsWith('@') ? 'mcp_server' : 'ai_tool';
  const [trustProfile, oracle] = await Promise.all([
    queryTrustProfile(registryUrl, packageName, type),
    queryOracleVerdict(registryUrl, packageName),
  ]);

  return {
    packageName,
    version: pkgVersion,
    localHash,
    registryStatus,
    trustScore: trustProfile?.trustScore ?? null,
    trustVerdict: trustProfile?.verdict ?? null,
    oracleVerdict: oracle?.verdict ?? null,
    oracleSignatureValid: oracle?.signatureValid ?? null,
    dependencyRiskCount: trustProfile?.dependencyRiskCount ?? null,
    lastScannedAt: trustProfile?.lastScannedAt ?? null,
    error,
  };
}

// --- Helpers ---

function computeSha256(filePath: string): string {
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

async function resolveRegistryUrl(override?: string): Promise<string> {
  if (override) return override.replace(/\/$/, '');

  try {
    const shared = await (Function('return import("@opena2a/shared")')() as Promise<any>);
    const mod = 'default' in shared ? shared.default : shared;
    const config = mod.loadUserConfig();
    return config.registry.url;
  } catch {
    return 'https://registry.opena2a.org';
  }
}

// --- Output ---

function printResults(results: VerifyResult[], registryUrl: string): void {
  // Detailed per-package output
  for (const r of results) {
    if (r.registryStatus === 'not_installed') {
      process.stdout.write(dim(`  ${r.packageName}: not installed\n`));
      continue;
    }

    const statusLabel = r.registryStatus === 'verified' ? green('PASS')
      : r.registryStatus === 'tamper_detected' ? red('TAMPER DETECTED')
      : r.registryStatus === 'error' ? red('error')
      : yellow('no data');

    const hashDisplay = r.localHash.slice(0, 16) + '...';

    process.stdout.write('\n');
    process.stdout.write(`  ${dim('Package')}          ${bold(r.packageName)}\n`);
    process.stdout.write(`  ${dim('Version')}          ${r.version}\n`);
    process.stdout.write(`  ${dim('Hash Check')}       ${statusLabel} ${dim('(SHA-256 ' + hashDisplay + ')')}\n`);

    if (r.trustScore !== null) {
      // API returns 0-1 scale; display as 0-100
      const displayScore = r.trustScore <= 1 ? Math.round(r.trustScore * 100) : Math.round(r.trustScore);
      const scoreColor = displayScore >= 80 ? green : displayScore >= 60 ? yellow : red;
      process.stdout.write(`  ${dim('Trust Score')}      ${scoreColor(`${displayScore} / 100`)}\n`);
    }
    if (r.trustVerdict !== null) {
      const verdictColor = r.trustVerdict === 'trusted' ? green
        : r.trustVerdict === 'caution' ? yellow
        : r.trustVerdict === 'untrusted' ? red
        : dim;
      process.stdout.write(`  ${dim('Trust Verdict')}    ${verdictColor(r.trustVerdict)}\n`);
    }
    if (r.oracleVerdict !== null) {
      const oracleLabel = r.oracleSignatureValid ? green('verified (Ed25519)') : yellow(r.oracleVerdict);
      process.stdout.write(`  ${dim('Oracle Signed')}    ${oracleLabel}\n`);
    }
    if (r.lastScannedAt) {
      process.stdout.write(`  ${dim('Last Scanned')}     ${dim(r.lastScannedAt)}\n`);
    }
    if (r.dependencyRiskCount !== null) {
      const depLabel = r.dependencyRiskCount === 0
        ? green('0 risks')
        : yellow(`${r.dependencyRiskCount} risk${r.dependencyRiskCount === 1 ? '' : 's'}`);
      process.stdout.write(`  ${dim('Dependencies')}     ${depLabel}\n`);
    }
  }

  process.stdout.write('\n');

  // Summary
  const verified = results.filter(r => r.registryStatus === 'verified').length;
  const tampered = results.filter(r => r.registryStatus === 'tamper_detected').length;
  const noData = results.filter(r => r.registryStatus === 'no_data' || r.registryStatus === 'error').length;
  const notInstalled = results.filter(r => r.registryStatus === 'not_installed').length;

  process.stdout.write(bold('Summary: '));
  const parts: string[] = [];
  if (verified > 0) parts.push(green(`${verified} verified`));
  if (tampered > 0) parts.push(red(`${tampered} tampered`));
  if (noData > 0) parts.push(yellow(`${noData} no data`));
  if (notInstalled > 0) parts.push(dim(`${notInstalled} not installed`));
  process.stdout.write(parts.join(', ') + '\n');

  process.stdout.write(dim(`Registry: ${registryUrl}\n`));

  if (tampered > 0) {
    process.stdout.write('\n' + red(bold('WARNING: Tamper detected in one or more packages.')) + '\n');
    process.stdout.write(red('Reinstall affected packages from a trusted source.\n'));
  }
}

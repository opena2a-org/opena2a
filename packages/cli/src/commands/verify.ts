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
  error?: string;
}

export interface ResolvedPackage {
  mainFile: string;
  version: string;
}

// --- Constants ---

const VERIFIABLE_PACKAGES = [
  'hackmyagent', 'secretless-ai', 'hma-researcher', 'hma-hunter',
  '@opena2a/arp', '@opena2a/oasb', 'aibrowserguard', 'ai-trust',
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
      packages: results,
    };
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printResults(results, registryUrl);
  }

  const tampered = results.filter(r => r.registryStatus === 'tamper_detected');
  return tampered.length > 0 ? 1 : 0;
}

// --- Per-package verification ---

async function verifyPackage(
  packageName: string,
  registryUrl: string,
  options: VerifyOptions,
): Promise<VerifyResult> {
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
    };
  }

  // Step 2: Compute SHA-256
  const localHash = computeSha256(mainFilePath);

  // Step 3: Query registry
  try {
    const url = `${registryUrl}/api/v1/trust/query?name=${encodeURIComponent(packageName)}&hash=${localHash}`;
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });

    if (!response.ok) {
      return {
        packageName,
        version: pkgVersion,
        localHash,
        registryStatus: 'no_data',
      };
    }

    const data = await response.json() as {
      contentVerification?: { status?: string };
    };

    const status = data.contentVerification?.status;
    if (status === 'verified') {
      return { packageName, version: pkgVersion, localHash, registryStatus: 'verified' };
    } else if (status === 'tamper_detected') {
      return { packageName, version: pkgVersion, localHash, registryStatus: 'tamper_detected' };
    }

    return { packageName, version: pkgVersion, localHash, registryStatus: 'no_data' };
  } catch (err) {
    return {
      packageName,
      version: pkgVersion,
      localHash,
      registryStatus: 'error',
      error: err instanceof Error ? err.message : String(err),
    };
  }
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
  const rows = results.map(r => {
    const statusLabel = r.registryStatus === 'verified' ? green('verified')
      : r.registryStatus === 'tamper_detected' ? red('TAMPER DETECTED')
      : r.registryStatus === 'not_installed' ? dim('not installed')
      : r.registryStatus === 'error' ? red('error')
      : yellow('no data');

    const hashDisplay = r.localHash === 'N/A' ? dim('N/A') : dim(r.localHash.slice(0, 16) + '...');

    return [r.packageName, r.version, hashDisplay, statusLabel];
  });

  process.stdout.write(table(rows, ['Package', 'Version', 'Local Hash', 'Registry Status']) + '\n\n');

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

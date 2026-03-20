/**
 * opena2a baselines -- Collect and submit behavioral observations
 * for crowdsourced agent behavioral profiles. Opt-in only.
 */

import { bold, green, yellow, red, dim, cyan } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { table } from '../util/format.js';
import { validateRegistryUrl } from '../util/validate-registry-url.js';

// --- Types ---

export interface BaselinesOptions {
  packageName: string;
  duration?: number;
  registryUrl?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

interface PackageMetrics {
  fileCount: number;
  totalSizeBytes: number;
  dependencyCount: number;
  hasLockfile: boolean;
  hasTestScript: boolean;
  hasLintScript: boolean;
  hasSuspiciousScripts: boolean;
  hasEnginesField: boolean;
}

interface Observation {
  packageName: string;
  version: string;
  observationType: string;
  timestamp: string;
  metrics: PackageMetrics;
  observer: string;
  observerVersion: string;
}

interface BaselinesResult {
  observation: Observation;
  submitted: boolean;
  submissionStatus: string;
}

// --- Core ---

export async function baselines(options: BaselinesOptions): Promise<number> {
  const isJson = options.format === 'json';
  const isCi = options.ci ?? false;

  // Step 1: Check opt-in
  const optedIn = await checkOptIn();
  if (!optedIn) {
    if (isJson) {
      process.stdout.write(JSON.stringify({
        error: 'Community contributions not enabled',
        hint: 'Run: opena2a config contribute on',
      }) + '\n');
    } else {
      process.stderr.write(yellow('Community contributions are not enabled.\n'));
      process.stderr.write(dim('Enable with: opena2a config contribute on\n'));
    }
    return 1;
  }

  const registryUrl = await resolveRegistryUrl(options.registryUrl);

  if (!isJson && !isCi) {
    process.stdout.write(bold(`Collecting behavioral observations for ${options.packageName}`) + '\n\n');
  }

  // Step 2: Resolve package
  const spinner = new Spinner(`Analyzing ${options.packageName}...`);
  if (!isCi && !isJson) {
    spinner.start();
  }

  let pkgDir: string;
  let pkgJson: any;
  try {
    const resolved = resolvePackage(options.packageName);
    pkgDir = resolved.dir;
    pkgJson = resolved.pkgJson;
  } catch {
    if (!isCi && !isJson) {
      spinner.stop();
    }
    if (isJson) {
      process.stdout.write(JSON.stringify({
        error: `Package not found: ${options.packageName}`,
      }) + '\n');
    } else {
      process.stderr.write(red(`Package not found: ${options.packageName}\n`));
      process.stderr.write(dim('Ensure the package is installed locally.\n'));
    }
    return 1;
  }

  // Step 3: Collect metrics
  const metrics = collectMetrics(pkgDir, pkgJson);
  const pkgVersion = pkgJson.version ?? 'unknown';

  if (!isCi && !isJson) {
    spinner.stop();
  }

  // Step 4: Build observation
  const observation: Observation = {
    packageName: options.packageName,
    version: pkgVersion,
    observationType: 'static_profile',
    timestamp: new Date().toISOString(),
    metrics,
    observer: 'opena2a-cli',
    observerVersion: '0.1.0',
  };

  // Step 5: Submit
  let submitted = false;
  let submissionStatus = 'not_submitted';

  if (!isCi && !isJson) {
    spinner.update('Submitting observation...');
    spinner.start();
  }

  try {
    const response = await fetch(`${registryUrl}/internal/behavioral-observation`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(observation),
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok) {
      submitted = true;
      submissionStatus = 'submitted';
    } else if (response.status === 401 || response.status === 403) {
      // Try community endpoint as fallback
      const fallbackResponse = await fetch(`${registryUrl}/api/v1/registry/community/behavioral-observation`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(observation),
        signal: AbortSignal.timeout(10_000),
      });

      if (fallbackResponse.ok) {
        submitted = true;
        submissionStatus = 'submitted (community)';
      } else {
        submissionStatus = 'collected_locally';
      }
    } else {
      submissionStatus = 'collected_locally';
    }
  } catch {
    submissionStatus = 'collected_locally';
  }

  if (!isCi && !isJson) {
    spinner.stop();
  }

  // Step 6: Output
  const result: BaselinesResult = {
    observation,
    submitted,
    submissionStatus,
  };

  if (isJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    printSummary(result);
  }

  return 0;
}

// --- Helpers ---

async function checkOptIn(): Promise<boolean> {
  try {
    const shared = await import('@opena2a/shared') as any;
    const mod = 'default' in shared ? shared.default : shared;
    const config = mod.loadUserConfig();
    return config.contribute?.enabled === true;
  } catch {
    return false;
  }
}

async function resolveRegistryUrl(override?: string): Promise<string> {
  if (override) {
    const url = override.replace(/\/$/, '');
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
  } catch {
    // not available
  }
  return ''; // registry not yet available
}

interface ResolvedPackageInfo {
  dir: string;
  pkgJson: any;
}

function resolvePackage(packageName: string): ResolvedPackageInfo {
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
        return { dir, pkgJson };
      }
    }
    dir = path.dirname(dir);
  }

  throw new Error(`Could not find package.json for ${packageName}`);
}

function collectMetrics(pkgDir: string, pkgJson: any): PackageMetrics {
  const fs = require('node:fs');
  const path = require('node:path');

  // Count files and total size
  let fileCount = 0;
  let totalSizeBytes = 0;

  function walk(dir: string): void {
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git') continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(fullPath);
      } else if (entry.isFile()) {
        fileCount++;
        try {
          const stat = fs.statSync(fullPath);
          totalSizeBytes += stat.size;
        } catch {
          // skip
        }
      }
    }
  }

  walk(pkgDir);

  // Dependency count
  const deps = pkgJson.dependencies ?? {};
  const dependencyCount = Object.keys(deps).length;

  // Lockfile
  const hasLockfile =
    fs.existsSync(path.join(pkgDir, 'package-lock.json')) ||
    fs.existsSync(path.join(pkgDir, 'yarn.lock')) ||
    fs.existsSync(path.join(pkgDir, 'pnpm-lock.yaml'));

  // Scripts
  const scripts = pkgJson.scripts ?? {};
  const hasTestScript = 'test' in scripts;
  const hasLintScript = 'lint' in scripts;

  // Suspicious scripts: preinstall or postinstall
  const hasSuspiciousScripts =
    'preinstall' in scripts || 'postinstall' in scripts;

  // Engines field
  const hasEnginesField = 'engines' in pkgJson;

  return {
    fileCount,
    totalSizeBytes,
    dependencyCount,
    hasLockfile,
    hasTestScript,
    hasLintScript,
    hasSuspiciousScripts,
    hasEnginesField,
  };
}

// --- Output ---

function printSummary(result: BaselinesResult): void {
  const { observation, submissionStatus } = result;
  const m = observation.metrics;

  process.stdout.write(bold(`Package: ${observation.packageName} v${observation.version}`) + '\n\n');

  const rows: string[][] = [
    ['Files', String(m.fileCount)],
    ['Total size', formatBytes(m.totalSizeBytes)],
    ['Dependencies', String(m.dependencyCount)],
    ['Has lockfile', m.hasLockfile ? green('yes') : yellow('no')],
    ['Has test script', m.hasTestScript ? green('yes') : yellow('no')],
    ['Has lint script', m.hasLintScript ? green('yes') : yellow('no')],
    ['Suspicious scripts', m.hasSuspiciousScripts ? red('yes') : green('no')],
    ['Engines field', m.hasEnginesField ? green('yes') : dim('no')],
  ];

  process.stdout.write(table(rows, ['Metric', 'Value']) + '\n\n');

  const statusColor = result.submitted ? green : yellow;
  process.stdout.write(bold('Submission: ') + statusColor(submissionStatus) + '\n');
  process.stdout.write(dim(`Observation type: ${observation.observationType}\n`));

  if (!result.submitted) {
    process.stdout.write('\n' + cyan('Note: ') + 'Data was collected locally but could not be submitted to the registry.\n');
    process.stdout.write(dim('The observation will be included in the next successful submission.\n'));
  }
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

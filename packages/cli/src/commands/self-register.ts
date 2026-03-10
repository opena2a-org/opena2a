/**
 * opena2a self-register -- Register all OpenA2A tools in the public registry
 * with their security scan results. "Eat your own cooking."
 *
 * Flow:
 * 1. Load tool manifest (13 tools)
 * 2. For each tool: check existence, optionally scan with HMA, publish results
 * 3. Print summary report
 */

import { bold, green, yellow, red, cyan, dim, gray } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { table, formatDuration } from '../util/format.js';

// --- Types ---

export interface ToolManifest {
  name: string;
  displayName: string;
  description: string;
  packageType: 'ai_tool' | 'mcp_server' | 'a2a_agent';
  version: string;
  repositoryUrl: string;
  license: string;
  tags: string[];
  scannable: boolean;
  npmPackage?: string;
}

export interface SelfRegisterOptions {
  registryUrl?: string;
  skipScan?: boolean;
  only?: string[];
  dryRun?: boolean;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
}

interface ToolResult {
  name: string;
  displayName: string;
  status: 'exists' | 'new' | 'error';
  scanStatus: 'passed' | 'warnings' | 'failed' | 'skipped' | 'error';
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  published: boolean;
  publishType: 'scan' | 'metadata' | 'none';
  error?: string;
}

// --- Tool Manifest ---

export const TOOL_MANIFEST: ToolManifest[] = [
  {
    name: 'hackmyagent',
    displayName: 'HackMyAgent',
    description: 'Security scanner for AI agents - hardening checks, attack simulation, CIS benchmarks',
    packageType: 'ai_tool',
    version: '0.7.2',
    repositoryUrl: 'https://github.com/opena2a-org/hackmyagent',
    license: 'Apache-2.0',
    tags: ['security', 'scanner', 'hardening', 'attack'],
    scannable: true,
    npmPackage: 'hackmyagent',
  },
  {
    name: 'secretless-ai',
    displayName: 'Secretless AI',
    description: 'Credential management for AI agents - vault, broker, DLP',
    packageType: 'ai_tool',
    version: '0.8.2',
    repositoryUrl: 'https://github.com/opena2a-org/secretless-ai',
    license: 'Apache-2.0',
    tags: ['credentials', 'vault', 'dlp', 'broker'],
    scannable: true,
    npmPackage: 'secretless-ai',
  },
  {
    name: 'opena2a-arp',
    displayName: 'Agent Runtime Protection',
    description: 'Runtime monitoring and protection for AI agents - process, network, filesystem',
    packageType: 'ai_tool',
    version: '0.8.0',
    repositoryUrl: 'https://github.com/opena2a-org/hackmyagent',
    license: 'Apache-2.0',
    tags: ['runtime', 'monitoring', 'edr'],
    scannable: true,
    npmPackage: 'hackmyagent',
  },
  {
    name: 'opena2a-oasb',
    displayName: 'OASB Benchmark',
    description: 'Open Agent Security Benchmark - standardized security scoring for AI agents',
    packageType: 'ai_tool',
    version: '0.8.0',
    repositoryUrl: 'https://github.com/opena2a-org/hackmyagent',
    license: 'Apache-2.0',
    tags: ['benchmark', 'scoring', 'oasb'],
    scannable: true,
    npmPackage: 'hackmyagent',
  },
  {
    name: 'aibrowserguard',
    displayName: 'BrowserGuard',
    description: 'Browser extension for AI agent security - prompt injection detection, MCP monitoring',
    packageType: 'ai_tool',
    version: '0.1.0-beta',
    repositoryUrl: 'https://github.com/opena2a-org/AI-BrowserGuard',
    license: 'Apache-2.0',
    tags: ['browser', 'extension', 'mcp', 'prompt-injection'],
    scannable: true,
    npmPackage: 'aibrowserguard',
  },
  {
    name: 'ai-trust',
    displayName: 'AI Trust',
    description: 'Trust registry client - query and verify agent trust scores',
    packageType: 'ai_tool',
    version: '0.1.0',
    repositoryUrl: 'https://github.com/opena2a-org/opena2a',
    license: 'Apache-2.0',
    tags: ['trust', 'registry', 'verification'],
    scannable: true,
    npmPackage: 'ai-trust',
  },
  {
    name: 'opena2a-registry',
    displayName: 'OpenA2A Registry',
    description: 'Public trust registry backend - agent identity, trust scoring, community scans',
    packageType: 'a2a_agent',
    version: '0.4.0',
    repositoryUrl: 'https://github.com/opena2a-org/opena2a-registry',
    license: 'Apache-2.0',
    tags: ['registry', 'trust', 'backend', 'go'],
    scannable: false,
  },
  {
    name: 'aim',
    displayName: 'Agent Identity Management',
    description: 'Self-hosted identity and access management platform for AI agents',
    packageType: 'a2a_agent',
    version: '1.23.0',
    repositoryUrl: 'https://github.com/opena2a-org/agent-identity-management',
    license: 'Apache-2.0',
    tags: ['identity', 'iam', 'self-hosted', 'go'],
    scannable: false,
  },
  {
    name: 'dvaa',
    displayName: 'Damn Vulnerable AI Agent',
    description: 'Intentionally vulnerable AI agent for security training and testing',
    packageType: 'a2a_agent',
    version: '0.4.0',
    repositoryUrl: 'https://github.com/opena2a-org/damn-vulnerable-ai-agent',
    license: 'Apache-2.0',
    tags: ['training', 'vulnerable', 'docker', 'ctf'],
    scannable: false,
  },
  {
    name: 'cryptoserve',
    displayName: 'CryptoServe',
    description: 'Cryptographic inventory scanner - PQC readiness, algorithm discovery',
    packageType: 'ai_tool',
    version: '1.8.0',
    repositoryUrl: 'https://github.com/ecolibria/crypto-serve',
    license: 'Apache-2.0',
    tags: ['crypto', 'pqc', 'scanner', 'python'],
    scannable: false,
  },
  {
    name: 'trust-gate',
    displayName: 'Trust Gate',
    description: 'GitHub Action for CI/CD trust verification - block untrusted agent dependencies',
    packageType: 'ai_tool',
    version: '1.0.0',
    repositoryUrl: 'https://github.com/opena2a-org/trust-gate',
    license: 'Apache-2.0',
    tags: ['github-action', 'ci-cd', 'trust', 'gate'],
    scannable: false,
  },
];

// --- Core ---

export async function selfRegister(options: SelfRegisterOptions): Promise<number> {
  const registryUrl = await resolveRegistryUrl(options.registryUrl);
  const tools = filterTools(options.only);
  const isJson = options.format === 'json';
  const isCi = options.ci ?? false;

  if (tools.length === 0) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'No matching tools found', tools: [] }) + '\n');
    } else {
      process.stderr.write(red('No matching tools found.\n'));
      process.stderr.write(`Available: ${TOOL_MANIFEST.map(t => t.name).join(', ')}\n`);
    }
    return 1;
  }

  if (!isJson && !isCi) {
    process.stdout.write(bold(`Registering ${tools.length} OpenA2A tool(s) at ${registryUrl}`) + '\n\n');
  }

  if (options.dryRun && !isJson) {
    process.stdout.write(yellow('[DRY RUN] No HTTP requests will be made.\n\n'));
  }

  const results: ToolResult[] = [];
  const spinner = new Spinner('');

  for (const tool of tools) {
    if (!isCi && !isJson) {
      spinner.update(`Processing ${tool.displayName}...`);
      spinner.start();
    }

    const result = await processTool(tool, registryUrl, options, spinner);
    results.push(result);

    if (!isCi && !isJson) {
      spinner.stop();
    }

    if (options.verbose && !isJson) {
      const statusIcon = result.error ? red('[ERROR]') : result.published ? green('[OK]') : yellow('[SKIP]');
      process.stdout.write(`${statusIcon} ${tool.displayName} -- ${result.status}, scan: ${result.scanStatus}\n`);
    }
  }

  // Summary
  if (isJson) {
    const report = buildJsonReport(results, registryUrl);
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printSummary(results, registryUrl);
  }

  const errors = results.filter(r => r.error);
  return errors.length > 0 ? 1 : 0;
}

// --- Per-tool processing ---

async function processTool(
  tool: ToolManifest,
  registryUrl: string,
  options: SelfRegisterOptions,
  _spinner: Spinner,
): Promise<ToolResult> {
  const result: ToolResult = {
    name: tool.name,
    displayName: tool.displayName,
    status: 'new',
    scanStatus: 'skipped',
    criticalCount: 0,
    highCount: 0,
    mediumCount: 0,
    lowCount: 0,
    published: false,
    publishType: 'none',
  };

  try {
    // Phase 1: Check if tool already exists in registry
    if (!options.dryRun) {
      const existsResult = await checkPackageExists(registryUrl, tool);
      result.status = existsResult.exists ? 'exists' : 'new';
    }

    // Phase 2: Scan (if scannable and not skipped)
    let findings: ScanFinding[] = [];
    if (tool.scannable && !options.skipScan && !options.dryRun) {
      try {
        findings = await scanWithHma(tool);
        const counts = countFindings(findings);
        result.criticalCount = counts.critical;
        result.highCount = counts.high;
        result.mediumCount = counts.medium;
        result.lowCount = counts.low;
        result.scanStatus = counts.critical > 0 || counts.high > 0 ? 'failed' : counts.medium > 0 || counts.low > 0 ? 'warnings' : 'passed';
      } catch {
        result.scanStatus = 'error';
        // Continue -- scan failure should not block registration
      }
    } else if (!tool.scannable) {
      result.scanStatus = 'skipped';
    } else if (options.skipScan) {
      result.scanStatus = 'skipped';
    }

    // Phase 3: Publish results
    if (!options.dryRun) {
      const published = await publishResults(registryUrl, tool, findings, result.scanStatus);
      result.published = published;
      result.publishType = tool.scannable && !options.skipScan ? 'scan' : 'metadata';
    } else {
      result.publishType = tool.scannable && !options.skipScan ? 'scan' : 'metadata';
    }
  } catch (err) {
    result.status = 'error';
    result.error = err instanceof Error ? err.message : String(err);
  }

  return result;
}

// --- Registry interaction ---

interface ExistsResult {
  exists: boolean;
  packageId?: string;
}

export async function checkPackageExists(registryUrl: string, tool: ToolManifest): Promise<ExistsResult> {
  const url = `${registryUrl}/api/v1/registry/packages/by-name/${tool.packageType}/${tool.name}`;

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: { 'Accept': 'application/json' },
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok) {
      const data = await response.json() as { id?: string };
      return { exists: true, packageId: data.id };
    }

    if (response.status === 404) {
      return { exists: false };
    }

    return { exists: false };
  } catch {
    return { exists: false };
  }
}

interface ScanFinding {
  checkId: string;
  name: string;
  severity: string;
  passed: boolean;
  fixed?: boolean;
  message: string;
  description?: string;
}

async function scanWithHma(tool: ToolManifest): Promise<ScanFinding[]> {
  try {
    // Dynamic import of hackmyagent
    const hma = await (Function('return import("hackmyagent")')() as Promise<any>);
    const mod = 'default' in hma ? hma.default : hma;

    // Resolve project path
    const projectPath = resolveProjectPath(tool);
    if (!projectPath) {
      return [];
    }

    // Run hardening scan
    if (typeof mod.runHardeningScan === 'function') {
      const findings = await mod.runHardeningScan(projectPath, { quiet: true });
      return Array.isArray(findings) ? findings : [];
    }

    if (typeof mod.scan === 'function') {
      const result = await mod.scan(projectPath, { mode: 'hardening', quiet: true });
      return Array.isArray(result?.findings) ? result.findings : [];
    }

    return [];
  } catch {
    return [];
  }
}

function resolveProjectPath(tool: ToolManifest): string | null {
  // Check OPENA2A_WORKSPACE env var
  const workspace = process.env.OPENA2A_WORKSPACE;
  if (workspace) {
    const candidate = `${workspace}/${tool.name}`;
    try {
      const fs = require('node:fs');
      if (fs.existsSync(candidate)) return candidate;
    } catch { /* continue */ }
  }

  // Try sibling directories relative to monorepo
  try {
    const path = require('node:path');
    const fs = require('node:fs');
    const monorepoRoot = path.resolve(__dirname, '..', '..', '..', '..');

    // Check direct sibling
    const sibling = path.join(monorepoRoot, '..', tool.name);
    if (fs.existsSync(sibling)) return sibling;

    // Check if it's a monorepo package
    if (tool.npmPackage) {
      const pkgDir = path.join(monorepoRoot, 'packages', tool.name);
      if (fs.existsSync(pkgDir)) return pkgDir;
    }
  } catch { /* continue */ }

  // Fall back to require.resolve
  if (tool.npmPackage) {
    try {
      const resolved = require.resolve(tool.npmPackage);
      const path = require('node:path');
      return path.dirname(resolved);
    } catch { /* not installed */ }
  }

  return null;
}

async function publishResults(
  registryUrl: string,
  tool: ToolManifest,
  findings: ScanFinding[],
  scanStatus: string,
): Promise<boolean> {
  try {
    // Request scan token
    const tokenUrl = `${registryUrl}/api/v1/registry/community/request-scan-token`;
    const tokenResponse = await fetch(tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        packageName: tool.name,
        packageType: tool.packageType,
        version: tool.version,
      }),
      signal: AbortSignal.timeout(10_000),
    });

    let scanToken: string | undefined;
    if (tokenResponse.ok) {
      const tokenData = await tokenResponse.json() as { scanToken?: string };
      scanToken = tokenData.scanToken;
    }

    // Build community report
    const failedFindings = findings.filter(f => !f.passed && !f.fixed);
    const vulnerabilities = failedFindings.map(f => ({
      id: f.checkId,
      severity: f.severity,
      title: f.name,
      description: f.description ?? f.message,
    }));

    const counts = countFindings(findings);
    const payload = {
      packageName: tool.name,
      packageType: tool.packageType,
      version: tool.version,
      scanId: `self-register-${Date.now()}`,
      status: scanStatus === 'skipped' ? 'passed' : scanStatus,
      completedAt: new Date().toISOString(),
      vulnerabilities,
      criticalCount: counts.critical,
      highCount: counts.high,
      mediumCount: counts.medium,
      lowCount: counts.low,
      rawReport: {
        generator: 'opena2a-self-register',
        toolVersion: tool.version,
        repositoryUrl: tool.repositoryUrl,
        license: tool.license,
        tags: tool.tags,
      },
    };

    // Submit results
    const submitUrl = `${registryUrl}/api/v1/registry/community/scan-result`;
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (scanToken) {
      headers['X-Scan-Token'] = scanToken;
    }

    const submitResponse = await fetch(submitUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(10_000),
    });

    if (submitResponse.ok) {
      return true;
    }

    // Handle 429 rate limiting
    if (submitResponse.status === 429) {
      const retryAfter = submitResponse.headers.get('Retry-After');
      const waitMs = retryAfter ? parseInt(retryAfter, 10) * 1000 : 5000;
      await new Promise(resolve => setTimeout(resolve, Math.min(waitMs, 30_000)));

      const retryResponse = await fetch(submitUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(10_000),
      });

      return retryResponse.ok;
    }

    return false;
  } catch {
    return false;
  }
}

// --- Helpers ---

function countFindings(findings: ScanFinding[]): { critical: number; high: number; medium: number; low: number } {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) {
    if (f.passed || f.fixed) continue;
    const sev = f.severity as keyof typeof counts;
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

function filterTools(only?: string[]): ToolManifest[] {
  if (!only || only.length === 0) return TOOL_MANIFEST;
  return TOOL_MANIFEST.filter(t => only.includes(t.name));
}

async function resolveRegistryUrl(override?: string): Promise<string> {
  if (override) return override.replace(/\/$/, '');

  try {
    const shared = await (Function('return import("@opena2a/shared")')() as Promise<any>);
    const mod = 'default' in shared ? shared.default : shared;
    const config = mod.loadUserConfig();
    return config.registry.url;
  } catch {
    return ''; // registry not yet available
  }
}

// --- Output ---

function printSummary(results: ToolResult[], registryUrl: string): void {
  process.stdout.write('\n');

  const rows = results.map(r => {
    const status = r.status === 'error' ? red(r.status) : r.status === 'exists' ? cyan(r.status) : green(r.status);
    const scan = r.scanStatus === 'passed' ? green(r.scanStatus)
      : r.scanStatus === 'warnings' ? yellow(r.scanStatus)
      : r.scanStatus === 'failed' ? red(r.scanStatus)
      : r.scanStatus === 'error' ? red(r.scanStatus)
      : dim(r.scanStatus);
    const crit = r.scanStatus === 'skipped' ? dim('-') : String(r.criticalCount);
    const high = r.scanStatus === 'skipped' ? dim('-') : String(r.highCount);
    const med = r.scanStatus === 'skipped' ? dim('-') : String(r.mediumCount);
    const low = r.scanStatus === 'skipped' ? dim('-') : String(r.lowCount);
    const pub = r.published
      ? (r.publishType === 'metadata' ? green('yes (metadata)') : green('yes'))
      : r.error ? red('no') : dim('dry-run');

    return [r.displayName, status, scan, crit, high, med, low, pub];
  });

  process.stdout.write(table(rows, ['Tool', 'Status', 'Scan', 'Crit', 'High', 'Med', 'Low', 'Published']) + '\n\n');

  // Summary line
  const total = results.length;
  const scanned = results.filter(r => r.scanStatus !== 'skipped').length;
  const metadataOnly = results.filter(r => r.publishType === 'metadata').length;
  const errors = results.filter(r => r.error).length;

  process.stdout.write(bold('Summary: '));
  const parts = [
    `${total} tools`,
    `${scanned} scanned`,
    `${metadataOnly} metadata-only`,
  ];
  if (errors > 0) parts.push(red(`${errors} errors`));
  else parts.push(green('0 errors'));
  process.stdout.write(parts.join(', ') + '\n');
  process.stdout.write(dim(`Registry: ${registryUrl}\n`));
}

function buildJsonReport(results: ToolResult[], registryUrl: string): object {
  return {
    registryUrl,
    timestamp: new Date().toISOString(),
    total: results.length,
    scanned: results.filter(r => r.scanStatus !== 'skipped').length,
    metadataOnly: results.filter(r => r.publishType === 'metadata').length,
    errors: results.filter(r => r.error).length,
    tools: results,
  };
}

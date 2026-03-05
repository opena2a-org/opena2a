/**
 * Scan report submission -- shares detailed scan findings with the OpenA2A Registry
 * when the user has opted in via `opena2a config contribute on`.
 *
 * This enables the community intelligence loop:
 * 1. User scans a tool with HMA
 * 2. Findings are shared (opt-in) with the registry
 * 3. Registry aggregates data and generates advisories
 * 4. Other users see advisories via `opena2a init` and `opena2a verify`
 *
 * Contribution prompting is delayed until after the user has run 3+ scans,
 * so they see value before being asked to share.
 */

import { dim, yellow, cyan } from './colors.js';

// --- Types ---

export interface ScanFinding {
  findingId: string;
  severity: string;
  category: string;
  title: string;
  description?: string;
  cweId?: number;
  filePath?: string;
  lineNumber?: number;
  autoFixable?: boolean;
}

export interface ScanReport {
  /** Package name being scanned */
  packageName: string;
  /** Package version */
  packageVersion?: string;
  /** Package type (npm, pypi, go, mcp_server, a2a_agent) */
  packageType?: string;
  /** Scanner name */
  scannerName: string;
  /** Scanner version */
  scannerVersion: string;
  /** Overall score (0-100) */
  overallScore: number;
  /** Scan duration in ms */
  scanDurationMs: number;
  /** Finding counts by severity */
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  /** Overall verdict */
  verdict: string;
  /** Detailed findings */
  findings: ScanFinding[];
  /** MCP tool names detected */
  mcpTools?: string[];
  /** A2A agent card fields detected */
  a2aCapabilities?: string[];
}

// --- Governance scan normalization ---

/**
 * Normalize a scan-soul governance result into the ScanReport format.
 * Maps control gaps to findings so the registry can aggregate governance data.
 */
export function normalizeGovernanceReport(raw: Record<string, unknown>): ScanReport | null {
  // Detect governance scan by presence of 'domains' array and 'grade' field
  if (!raw.domains || !raw.grade) return null;

  const score = (raw.score as number) ?? 0;
  const grade = (raw.grade as string) ?? 'F';
  const domains = raw.domains as Array<{
    domain: string;
    controls: Array<{ id: string; name: string; passed: boolean }>;
    passed: number;
    total: number;
  }>;

  const findings: ScanFinding[] = [];
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;

  // Severity map for known control IDs (CRITICAL and HIGH controls)
  const severityMap: Record<string, string> = {
    'SOUL-IH-003': 'critical', 'SOUL-HB-001': 'critical',
    'SOUL-TH-001': 'high', 'SOUL-CB-001': 'high', 'SOUL-CB-002': 'high',
    'SOUL-IH-001': 'high', 'SOUL-HB-002': 'high', 'SOUL-HB-003': 'high',
    'SOUL-HO-001': 'high',
  };

  for (const domain of domains) {
    for (const control of domain.controls) {
      if (!control.passed) {
        const severity = severityMap[control.id] ?? 'medium';
        if (severity === 'critical') criticalCount++;
        else if (severity === 'high') highCount++;
        else if (severity === 'medium') mediumCount++;
        else lowCount++;

        findings.push({
          findingId: control.id,
          severity,
          category: 'governance',
          title: `${control.name} not addressed`,
          description: `Control ${control.id} (${control.name}) was not detected in the governance file. Domain: ${domain.domain}.`,
        });
      }
    }
  }

  const verdict = score >= 75 ? 'pass' : score >= 40 ? 'warnings' : 'fail';

  return {
    packageName: (raw.file as string) ?? 'SOUL.md',
    packageType: 'governance',
    scannerName: 'HackMyAgent',
    scannerVersion: '1.0.0',
    overallScore: score,
    scanDurationMs: 0,
    criticalCount,
    highCount,
    mediumCount,
    lowCount,
    infoCount: 0,
    verdict,
    findings,
  };
}

// --- Submission ---

export async function submitScanReport(
  registryUrl: string,
  report: ScanReport,
  verbose?: boolean,
): Promise<boolean> {
  try {
    const url = `${registryUrl}/api/v1/trust/scan-report`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      body: JSON.stringify({
        ...report,
        submittedAt: new Date().toISOString(),
        clientVersion: '0.1.0',
      }),
      signal: AbortSignal.timeout(10_000),
    });

    if (response.ok) {
      if (verbose) {
        process.stderr.write(dim('Scan report shared with OpenA2A community.\n'));
      }
      return true;
    }

    // If the endpoint doesn't exist yet (404), that's fine
    if (response.status === 404) {
      if (verbose) {
        process.stderr.write(dim('Registry scan-report endpoint not available yet.\n'));
      }
      return false;
    }

    return false;
  } catch {
    // Network errors are non-critical
    return false;
  }
}

// --- Config helpers (dynamic import to avoid circular deps) ---

async function loadShared(): Promise<any> {
  const shared = await (Function('return import("@opena2a/shared")')() as Promise<any>);
  return 'default' in shared ? shared.default : shared;
}

export async function isContributeEnabled(): Promise<boolean> {
  try {
    const mod = await loadShared();
    return mod.isContributeEnabled();
  } catch {
    return false;
  }
}

export async function getRegistryUrl(): Promise<string> {
  try {
    const mod = await loadShared();
    const config = mod.loadUserConfig();
    return config.registry?.url ?? '';
  } catch {
    return ''; // registry not yet available
  }
}

/**
 * Record that a scan was completed and conditionally show the contribute prompt.
 * Only prompts after 3+ scans, and not if the user already opted in or recently
 * dismissed the prompt. This lets us demonstrate value first.
 */
export async function recordScanAndMaybePrompt(): Promise<void> {
  try {
    const mod = await loadShared();
    mod.incrementScanCount();

    if (mod.shouldPromptContribute()) {
      printContributePrompt();
      // Mark as shown so it doesn't repeat every scan
      mod.dismissContributePrompt();
    }
  } catch {
    // Non-critical
  }
}

function printContributePrompt(): void {
  process.stderr.write('\n');
  process.stderr.write(cyan('  Your scans help the community detect unsafe tools.\n'));
  process.stderr.write(dim('  Share anonymized scan reports with the OpenA2A registry?\n'));
  process.stderr.write(dim('  Enable:  ') + yellow('opena2a config contribute on') + '\n');
  process.stderr.write(dim('  Details: https://opena2a.org/telemetry\n'));
  process.stderr.write('\n');
}

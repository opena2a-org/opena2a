/**
 * Shield Finding Taxonomy and Classification Engine.
 *
 * Maps Shield events to standardized finding IDs with:
 * - OWASP Agentic Security Index (ASI) compliance references
 * - MITRE ATLAS technique references
 * - Actionable remediation commands
 * - Severity classification
 *
 * Finding ID format: SHIELD-{CATEGORY}-{NUMBER}
 *   Categories: CRED (credential), POL (policy), PROC (process/runtime),
 *               INT (integrity), SUP (supply chain), BAS (behavioral)
 */

import type { ShieldEvent, EventSeverity, PolicyViolation } from './types.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface FindingDefinition {
  id: string;
  title: string;
  severity: EventSeverity;
  category: string;
  owaspAgentic: string;
  mitreAtlas: string;
  remediation: string;
  description: string;
}

export interface ClassifiedFinding {
  finding: FindingDefinition;
  count: number;
  firstSeen: string;
  lastSeen: string;
  examples: ShieldEvent[];
}

// ---------------------------------------------------------------------------
// Finding Catalog
// ---------------------------------------------------------------------------

export const FINDING_CATALOG: Record<string, FindingDefinition> = {
  'SHIELD-CRED-001': {
    id: 'SHIELD-CRED-001',
    title: 'Anthropic API key exposed in source',
    severity: 'critical',
    category: 'cred',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0025',
    remediation: 'opena2a protect --dir . && git filter-repo --path <file> --invert-paths',
    description: 'An Anthropic API key was found hardcoded in source files. This key grants full API access and can result in unauthorized billing.',
  },
  'SHIELD-CRED-002': {
    id: 'SHIELD-CRED-002',
    title: 'OpenAI API key exposed in source',
    severity: 'critical',
    category: 'cred',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0025',
    remediation: 'opena2a protect --dir . && git filter-repo --path <file> --invert-paths',
    description: 'An OpenAI API key was found hardcoded in source files. Exposed keys are exploited within minutes of public disclosure.',
  },
  'SHIELD-CRED-003': {
    id: 'SHIELD-CRED-003',
    title: 'GitHub token exposed in source',
    severity: 'high',
    category: 'cred',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0025',
    remediation: 'opena2a protect --dir . && gh auth refresh',
    description: 'A GitHub token was found hardcoded in source files. This token may grant repository access including private repos and org resources.',
  },
  'SHIELD-CRED-004': {
    id: 'SHIELD-CRED-004',
    title: 'Generic API key or secret exposed',
    severity: 'medium',
    category: 'cred',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0025',
    remediation: 'opena2a protect --dir .',
    description: 'A generic API key or secret was found in a variable assignment. Move it to environment variables or a secrets manager.',
  },
  'SHIELD-POL-001': {
    id: 'SHIELD-POL-001',
    title: 'No security policy defined',
    severity: 'high',
    category: 'pol',
    owaspAgentic: 'ASI03',
    mitreAtlas: 'AML.T0040',
    remediation: 'opena2a shield init',
    description: 'No Shield security policy is configured. Without a policy, all agent actions are unmonitored and unrestricted.',
  },
  'SHIELD-POL-002': {
    id: 'SHIELD-POL-002',
    title: 'Policy violation -- action blocked',
    severity: 'high',
    category: 'pol',
    owaspAgentic: 'ASI02',
    mitreAtlas: 'AML.T0040',
    remediation: 'opena2a shield policy',
    description: 'An agent action was blocked by the security policy. Review the policy to confirm the block is intentional or adjust rules.',
  },
  'SHIELD-POL-003': {
    id: 'SHIELD-POL-003',
    title: 'Policy in monitor-only mode',
    severity: 'medium',
    category: 'pol',
    owaspAgentic: 'ASI03',
    mitreAtlas: 'AML.T0040',
    remediation: 'opena2a shield policy --enforce',
    description: 'The security policy is in monitor-only mode. Violations are logged but not blocked. Consider enabling enforcement.',
  },
  'SHIELD-PROC-001': {
    id: 'SHIELD-PROC-001',
    title: 'Suspicious process spawned by agent',
    severity: 'high',
    category: 'proc',
    owaspAgentic: 'ASI05',
    mitreAtlas: 'AML.T0006',
    remediation: 'opena2a shield evaluate --action process.spawn --target <binary>',
    description: 'An AI agent spawned a process that was flagged as suspicious by the runtime protection engine.',
  },
  'SHIELD-PROC-002': {
    id: 'SHIELD-PROC-002',
    title: 'Network connection anomaly detected',
    severity: 'medium',
    category: 'proc',
    owaspAgentic: 'ASI07',
    mitreAtlas: 'AML.T0007',
    remediation: 'opena2a shield evaluate --action network.connect --target <host>',
    description: 'An anomalous network connection was made by an AI agent. This may indicate data exfiltration or C2 communication.',
  },
  'SHIELD-INT-001': {
    id: 'SHIELD-INT-001',
    title: 'Configuration file tampered',
    severity: 'critical',
    category: 'int',
    owaspAgentic: 'ASI10',
    mitreAtlas: 'AML.T0011',
    remediation: 'opena2a guard diff && opena2a guard resign',
    description: 'A monitored configuration file has been modified without authorization. The file signature no longer matches the stored hash.',
  },
  'SHIELD-INT-002': {
    id: 'SHIELD-INT-002',
    title: 'Event hash chain integrity broken',
    severity: 'critical',
    category: 'int',
    owaspAgentic: 'ASI10',
    mitreAtlas: 'AML.T0006',
    remediation: 'opena2a shield selfcheck && opena2a shield recover --forensic',
    description: 'The tamper-evident event log hash chain has been broken. This indicates log tampering or corruption.',
  },
  'SHIELD-INT-003': {
    id: 'SHIELD-INT-003',
    title: 'Configuration files not signed',
    severity: 'medium',
    category: 'int',
    owaspAgentic: 'ASI09',
    mitreAtlas: 'AML.T0011',
    remediation: 'opena2a guard snapshot',
    description: 'Monitored configuration files do not have cryptographic signatures. Enable ConfigGuard signing to detect unauthorized changes.',
  },
  'SHIELD-SUP-001': {
    id: 'SHIELD-SUP-001',
    title: 'Security advisory found in dependency',
    severity: 'high',
    category: 'sup',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0024',
    remediation: 'npm audit fix || go get -u <package>',
    description: 'A known security vulnerability was found in an installed dependency. Update the package to a patched version.',
  },
  'SHIELD-SUP-002': {
    id: 'SHIELD-SUP-002',
    title: 'Low-trust package installed',
    severity: 'medium',
    category: 'sup',
    owaspAgentic: 'ASI04',
    mitreAtlas: 'AML.T0024',
    remediation: 'opena2a registry check <package>',
    description: 'A package with a low trust score was installed. Review the package for legitimacy before use in production.',
  },
  'SHIELD-BAS-001': {
    id: 'SHIELD-BAS-001',
    title: 'Behavioral anomaly detected',
    severity: 'medium',
    category: 'bas',
    owaspAgentic: 'ASI10',
    mitreAtlas: 'AML.T0043',
    remediation: 'opena2a shield baseline --agent <agent>',
    description: 'An agent exhibited behavior that deviates significantly from its established baseline. Review the agent activity log.',
  },
};

// ---------------------------------------------------------------------------
// Classification Logic
// ---------------------------------------------------------------------------

/**
 * Map a single Shield event to its finding definition.
 * Returns null if the event does not match any known finding pattern.
 */
export function classifyEvent(event: ShieldEvent): FindingDefinition | null {
  // Credential findings
  if (event.source === 'secretless' || event.category === 'credential-finding') {
    const target = (event.target ?? '').toLowerCase();
    const action = (event.action ?? '').toLowerCase();

    if (target.includes('anthropic') || action.includes('anthropic') ||
        (event.detail as Record<string, unknown>)?.findingId === 'CRED-001') {
      return FINDING_CATALOG['SHIELD-CRED-001'];
    }
    if (target.includes('openai') || action.includes('openai') ||
        (event.detail as Record<string, unknown>)?.findingId === 'CRED-002') {
      return FINDING_CATALOG['SHIELD-CRED-002'];
    }
    if (target.includes('github') || action.includes('github') ||
        (event.detail as Record<string, unknown>)?.findingId === 'CRED-003') {
      return FINDING_CATALOG['SHIELD-CRED-003'];
    }
    // Generic credential
    return FINDING_CATALOG['SHIELD-CRED-004'];
  }

  // ConfigGuard integrity findings
  if (event.source === 'configguard') {
    if (event.outcome === 'blocked' || event.action === 'tamper-detected' ||
        (event.detail as Record<string, unknown>)?.outcome === 'tampered') {
      return FINDING_CATALOG['SHIELD-INT-001'];
    }
    if (event.action === 'unsigned' || event.category === 'config-unsigned') {
      return FINDING_CATALOG['SHIELD-INT-003'];
    }
  }

  // Shield diagnostic events: only integrity failures are real findings.
  // All other shield-source events (posture-assessment, credential-finding,
  // shield.init, shield.posture, shield.credential) are internal scans.
  if (event.source === 'shield') {
    if (event.category === 'integrity' && event.severity === 'critical') {
      return FINDING_CATALOG['SHIELD-INT-002'];
    }
    return null; // All other shield events are diagnostic, not findings
  }

  // ARP runtime findings
  if (event.source === 'arp') {
    if (event.category === 'process.spawn' || event.category?.startsWith('process')) {
      return FINDING_CATALOG['SHIELD-PROC-001'];
    }
    if (event.category?.startsWith('network')) {
      return FINDING_CATALOG['SHIELD-PROC-002'];
    }
    if (event.category === 'anomaly' || event.category === 'behavioral-anomaly') {
      return FINDING_CATALOG['SHIELD-BAS-001'];
    }
  }

  // Registry / supply chain findings
  if (event.source === 'registry' || event.category?.includes('supply-chain')) {
    if (event.severity === 'high' || event.severity === 'critical') {
      return FINDING_CATALOG['SHIELD-SUP-001'];
    }
    return FINDING_CATALOG['SHIELD-SUP-002'];
  }

  // Policy findings
  if (event.outcome === 'blocked') {
    return FINDING_CATALOG['SHIELD-POL-002'];
  }
  if (event.outcome === 'monitored' && (event.severity === 'high' || event.severity === 'critical')) {
    return FINDING_CATALOG['SHIELD-POL-003'];
  }

  return null;
}

/**
 * Classify a batch of events into deduplicated findings with counts.
 * Returns findings sorted by severity (critical first), then by count.
 */
export function classifyEvents(events: ShieldEvent[]): ClassifiedFinding[] {
  const map = new Map<string, ClassifiedFinding>();

  for (const event of events) {
    const finding = classifyEvent(event);
    if (!finding) continue;

    const existing = map.get(finding.id);
    if (existing) {
      existing.count += 1;
      if (event.timestamp < existing.firstSeen) existing.firstSeen = event.timestamp;
      if (event.timestamp > existing.lastSeen) existing.lastSeen = event.timestamp;
      if (existing.examples.length < 3) existing.examples.push(event);
    } else {
      map.set(finding.id, {
        finding,
        count: 1,
        firstSeen: event.timestamp,
        lastSeen: event.timestamp,
        examples: [event],
      });
    }
  }

  const severityOrder: Record<EventSeverity, number> = {
    critical: 0, high: 1, medium: 2, low: 3, info: 4,
  };

  return Array.from(map.values()).sort((a, b) => {
    const sevDiff = severityOrder[a.finding.severity] - severityOrder[b.finding.severity];
    if (sevDiff !== 0) return sevDiff;
    return b.count - a.count;
  });
}

/**
 * Map a PolicyViolation to a finding definition.
 * Used to enrich violation data in reports.
 */
export function classifyViolation(violation: PolicyViolation): FindingDefinition | null {
  const action = (violation.action ?? '').toLowerCase();
  const target = (violation.target ?? '').toLowerCase();

  // Credential-related violations
  if (action.includes('credential') || action.includes('secret') || action.includes('key')) {
    if (target.includes('anthropic')) return FINDING_CATALOG['SHIELD-CRED-001'];
    if (target.includes('openai')) return FINDING_CATALOG['SHIELD-CRED-002'];
    if (target.includes('github')) return FINDING_CATALOG['SHIELD-CRED-003'];
    return FINDING_CATALOG['SHIELD-CRED-004'];
  }

  // Process violations
  if (action.includes('process') || action.includes('spawn') || action.includes('exec')) {
    return FINDING_CATALOG['SHIELD-PROC-001'];
  }

  // Network violations
  if (action.includes('network') || action.includes('connect') || action.includes('http')) {
    return FINDING_CATALOG['SHIELD-PROC-002'];
  }

  // Config integrity violations
  if (action.includes('config') || action.includes('tamper')) {
    return FINDING_CATALOG['SHIELD-INT-001'];
  }

  // Supply chain violations
  if (action.includes('install') || action.includes('package') || action.includes('dependency')) {
    return FINDING_CATALOG['SHIELD-SUP-001'];
  }

  // Default: policy violation
  if (violation.severity === 'critical' || violation.severity === 'high') {
    return FINDING_CATALOG['SHIELD-POL-002'];
  }
  return FINDING_CATALOG['SHIELD-POL-003'];
}

/**
 * Get the remediation command for a finding ID.
 */
export function getRemediation(findingId: string): string {
  const finding = FINDING_CATALOG[findingId];
  return finding?.remediation ?? 'opena2a shield selfcheck';
}

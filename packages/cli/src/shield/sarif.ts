/**
 * SARIF 2.1.0 Export for Shield Findings.
 *
 * Produces SARIF (Static Analysis Results Interchange Format) compliant JSON
 * for CI/CD integration with GitHub Code Scanning, Azure DevOps, and other
 * SARIF-consuming tools.
 *
 * Schema: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { ClassifiedFinding, FindingDefinition } from './findings.js';
import type { EventSeverity } from './types.js';

// ---------------------------------------------------------------------------
// SARIF Types (minimal subset for our output)
// ---------------------------------------------------------------------------

interface SarifMessage {
  text: string;
}

interface SarifMultiformatMessage {
  text: string;
}

interface SarifReportingDescriptor {
  id: string;
  shortDescription: SarifMultiformatMessage;
  fullDescription: SarifMultiformatMessage;
  help: SarifMultiformatMessage;
  properties: {
    'security-severity': string;
    tags: string[];
  };
}

interface SarifArtifactLocation {
  uri: string;
}

interface SarifPhysicalLocation {
  artifactLocation: SarifArtifactLocation;
}

interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

interface SarifResult {
  ruleId: string;
  level: 'error' | 'warning' | 'note' | 'none';
  message: SarifMessage;
  locations?: SarifLocation[];
}

interface SarifToolDriver {
  name: string;
  version: string;
  informationUri: string;
  rules: SarifReportingDescriptor[];
}

interface SarifTool {
  driver: SarifToolDriver;
}

interface SarifRun {
  tool: SarifTool;
  results: SarifResult[];
}

export interface SarifLog {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

// ---------------------------------------------------------------------------
// Severity Mapping
// ---------------------------------------------------------------------------

const SEVERITY_SCORES: Record<EventSeverity, string> = {
  critical: '9.5',
  high: '7.5',
  medium: '4.5',
  low: '2.0',
  info: '0.5',
};

function severityToLevel(severity: EventSeverity): 'error' | 'warning' | 'note' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
    default:
      return 'note';
  }
}

// ---------------------------------------------------------------------------
// SARIF Builder
// ---------------------------------------------------------------------------

function buildRule(finding: FindingDefinition): SarifReportingDescriptor {
  return {
    id: finding.id,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.description },
    help: { text: `Remediation: ${finding.remediation}` },
    properties: {
      'security-severity': SEVERITY_SCORES[finding.severity],
      tags: [finding.owaspAgentic, finding.mitreAtlas],
    },
  };
}

function buildResult(classified: ClassifiedFinding): SarifResult {
  const { finding, count, examples } = classified;

  const countLabel = count === 1 ? '1 occurrence' : `${count} occurrences`;
  const message = `${finding.title}: ${countLabel} detected. ${finding.description}`;

  const result: SarifResult = {
    ruleId: finding.id,
    level: severityToLevel(finding.severity),
    message: { text: message },
  };

  // Add locations from example events if they have file-path targets
  const locations: SarifLocation[] = [];
  for (const event of examples) {
    const target = event.target;
    if (target && (target.includes('/') || target.includes('\\'))) {
      // Looks like a file path
      locations.push({
        physicalLocation: {
          artifactLocation: { uri: target },
        },
      });
    }
  }
  if (locations.length > 0) {
    result.locations = locations;
  }

  return result;
}

/**
 * Convert classified findings to a SARIF 2.1.0 log.
 */
export function toSarif(
  findings: ClassifiedFinding[],
  version: string,
): SarifLog {
  // Deduplicate rules by finding ID
  const ruleMap = new Map<string, SarifReportingDescriptor>();
  for (const classified of findings) {
    if (!ruleMap.has(classified.finding.id)) {
      ruleMap.set(classified.finding.id, buildRule(classified.finding));
    }
  }

  const results = findings.map(buildResult);

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'OpenA2A Shield',
            version,
            informationUri: 'https://opena2a.org',
            rules: Array.from(ruleMap.values()),
          },
        },
        results,
      },
    ],
  };
}

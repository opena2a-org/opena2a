import { loadUserConfig } from '@opena2a/shared';
import { loadScanHistory, getLastScan } from '@opena2a/shared';
import { detectProject } from '../util/detect.js';
import { bold, cyan, yellow, gray } from '../util/colors.js';

export interface Suggestion {
  command: string;
  reason: string;
  priority: number;
}

/**
 * Contextual advisor: reads project state, scan history, and config
 * to suggest the most relevant next command. No LLM call -- pure rules engine.
 */
export function getContextualSuggestions(targetDir?: string): Suggestion[] {
  const suggestions: Suggestion[] = [];
  const dir = targetDir ?? process.cwd();
  const project = detectProject(dir);
  const config = loadUserConfig();
  const lastScan = getLastScan();

  // Never scanned? Suggest scan first
  if (!lastScan) {
    suggestions.push({
      command: 'opena2a scan secure',
      reason: 'No scan history found -- run a security scan first',
      priority: 100,
    });
  }

  // Scanned with critical findings but no attack test
  if (lastScan && lastScan.findings.critical > 0) {
    suggestions.push({
      command: 'opena2a scan attack',
      reason: `Last scan found ${lastScan.findings.critical} critical findings -- test with attack mode`,
      priority: 90,
    });
  }

  // Has .env but no protection
  if (project.hasEnv) {
    suggestions.push({
      command: 'opena2a protect',
      reason: '.env file detected -- migrate credentials to encrypted vault',
      priority: 85,
    });
  }

  // MCP project without secrets protection
  if (project.hasMcp) {
    suggestions.push({
      command: 'opena2a secrets init',
      reason: 'MCP configuration detected -- protect credentials from AI tools',
      priority: 80,
    });
  }

  // Not contributing to registry
  if (!config.contribute.enabled && lastScan) {
    suggestions.push({
      command: 'opena2a config contribute on',
      reason: 'Help the community -- share anonymized scan summaries',
      priority: 30,
    });
  }

  // Suggest benchmark after successful scan
  if (lastScan && lastScan.findings.critical === 0 && lastScan.findings.high === 0) {
    suggestions.push({
      command: 'opena2a benchmark',
      reason: 'Clean scan results -- run a full security benchmark',
      priority: 50,
    });
  }

  // Suggest runtime monitoring for agent projects
  if (project.type === 'node' || project.hasMcp) {
    suggestions.push({
      command: 'opena2a runtime start',
      reason: 'Enable runtime monitoring for process, network, and filesystem activity',
      priority: 40,
    });
  }

  // Sort by priority descending
  suggestions.sort((a, b) => b.priority - a.priority);
  return suggestions;
}

export function handleContext(query: string): void {
  const suggestions = getContextualSuggestions();

  if (suggestions.length === 0) {
    process.stdout.write('No contextual suggestions available.\n');
    process.stdout.write('Run: opena2a --help\n');
    return;
  }

  process.stdout.write('\nSuggested next steps:\n\n');

  const limit = query ? suggestions.length : 3;
  for (let i = 0; i < Math.min(limit, suggestions.length); i++) {
    const s = suggestions[i];
    process.stdout.write(`  ${bold(`${i + 1}.`)} ${cyan(s.command)}\n`);
    process.stdout.write(`     ${gray(s.reason)}\n\n`);
  }
}

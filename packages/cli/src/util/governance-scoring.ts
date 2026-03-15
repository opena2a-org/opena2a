/**
 * Shared governance scoring utility.
 *
 * Calculates a governance score (0-100) based on agent governance status,
 * MCP server verification, AI config risk, and identity posture.
 * Used by both `detect` and `review` commands.
 */

export interface GovernanceScoringAgent {
  governanceStatus: string;
  identityStatus: string;
}

export interface GovernanceScoringMcpServer {
  verified: boolean;
  source: string;
  risk: string;
}

export interface GovernanceScoringAiConfig {
  risk: string;
}

export interface GovernanceScoringIdentity {
  aimIdentities: number;
  soulFiles: number;
}

export interface GovernanceScoringInput {
  agents: GovernanceScoringAgent[];
  mcpServers: GovernanceScoringMcpServer[];
  aiConfigs: GovernanceScoringAiConfig[];
  identity: GovernanceScoringIdentity;
}

/**
 * Calculate governance score (0-100, where 100 = fully governed).
 *
 * Internally computes deductions for gaps, then inverts:
 *   governanceScore = 100 - deductions
 *
 * This way users see 100 as the goal and the score goes UP as they fix things.
 */
export function calculateGovernanceScore(input: GovernanceScoringInput): { governanceScore: number; deductions: number } {
  let deductions = 0;

  // Ungoverned agents: 15 points each
  for (const agent of input.agents) {
    if (agent.governanceStatus === 'no governance') deductions += 15;
    if (agent.identityStatus === 'no identity') deductions += 10;
  }

  // Unverified MCP servers -- only project-local servers affect the score.
  // Global/machine-wide servers (Claude plugins, ~/.cursor, etc.) are shown
  // for awareness but don't penalize the project governance score because
  // the user cannot verify them at the project level.
  for (const server of input.mcpServers) {
    if (server.verified) continue;
    const isProjectLocal = server.source.includes('(project)');
    if (!isProjectLocal) continue;
    if (server.risk === 'critical') deductions += 20;
    else if (server.risk === 'high') deductions += 12;
    else if (server.risk === 'medium') deductions += 5;
    else deductions += 2;
  }

  // AI config risk
  for (const config of input.aiConfigs) {
    if (config.risk === 'critical') deductions += 25;
    else if (config.risk === 'high') deductions += 15;
    else if (config.risk === 'medium') deductions += 5;
  }

  // Governance gap: no AIM identity is a multiplier
  if (input.identity.aimIdentities === 0 && input.agents.length > 0) deductions += 20;
  if (input.identity.soulFiles === 0 && input.agents.length > 0) deductions += 10;

  // Cap deductions at 100, round
  deductions = Math.min(Math.round(deductions), 100);

  return { governanceScore: 100 - deductions, deductions };
}

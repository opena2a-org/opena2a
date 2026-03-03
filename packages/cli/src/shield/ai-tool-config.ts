/**
 * AI Tool Configuration for Shield
 *
 * Adds Shield-specific security context to AI coding tool instruction files.
 * Each tool gets its own marker so Secretless and Shield sections coexist
 * without interfering with each other.
 *
 * Secretless owns:  <!-- secretless:managed -->
 * Shield owns:      <!-- opena2a-shield:managed -->
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { join, dirname } from 'node:path';

const SHIELD_MARKER = '<!-- opena2a-shield:managed -->';

const SHIELD_SECTION = `${SHIELD_MARKER}
## Shield Security Context

This project is protected by OpenA2A Shield.

**Security posture:**
- \`opena2a shield status\` -- view protection status
- \`opena2a shield log\` -- query security event log
- \`opena2a shield selfcheck\` -- verify integrity

**Config file changes:**
- Run \`opena2a guard resign\` after intentional config modifications
- Config integrity is monitored -- unauthorized changes trigger alerts

**Agent identity:**
- This session has a local Ed25519 identity (view: \`opena2a shield session\`)
`;

export interface AiToolConfigResult {
  toolsConfigured: string[];
  toolsSkipped: string[];
}

/**
 * Configure Claude Code with Shield context.
 * Appends to CLAUDE.md if marker is not already present.
 */
export function configureClaudeCodeForShield(targetDir: string): boolean {
  const claudeMdPath = join(targetDir, 'CLAUDE.md');
  return appendShieldSection(claudeMdPath);
}

/**
 * Configure Cursor with Shield context.
 * Appends to .cursorrules if marker is not already present.
 */
export function configureCursorForShield(targetDir: string): boolean {
  const cursorPath = join(targetDir, '.cursorrules');
  return appendShieldSection(cursorPath);
}

/**
 * Configure Windsurf with Shield context.
 * Appends to .windsurfrules if marker is not already present.
 */
export function configureWindsurfForShield(targetDir: string): boolean {
  const windsurfPath = join(targetDir, '.windsurfrules');
  return appendShieldSection(windsurfPath);
}

/**
 * Configure GitHub Copilot with Shield context.
 * Appends to .github/copilot-instructions.md if marker is not already present.
 */
export function configureCopilotForShield(targetDir: string): boolean {
  const copilotPath = join(targetDir, '.github', 'copilot-instructions.md');
  return appendShieldSection(copilotPath);
}

/**
 * Configure Cline with Shield context.
 * Appends to .clinerules if marker is not already present.
 */
export function configureClineForShield(targetDir: string): boolean {
  const clinePath = join(targetDir, '.clinerules');
  return appendShieldSection(clinePath);
}

/**
 * Append the Shield section to a file if the marker is not already present.
 * Creates the file if it doesn't exist.
 * Returns true if the section was added, false if already present.
 */
function appendShieldSection(filePath: string): boolean {
  if (existsSync(filePath)) {
    const content = readFileSync(filePath, 'utf-8');
    if (content.includes(SHIELD_MARKER)) {
      return false; // Already configured
    }
    // Append to existing file
    const separator = content.endsWith('\n') ? '\n' : '\n\n';
    writeFileSync(filePath, content + separator + SHIELD_SECTION, { mode: 0o600 });
    return true;
  }

  // Create new file with shield section
  const dir = dirname(filePath);
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }
  writeFileSync(filePath, SHIELD_SECTION, { mode: 0o600 });
  return true;
}

/**
 * Check if the Shield marker exists in a file.
 */
export function hasShieldMarker(filePath: string): boolean {
  if (!existsSync(filePath)) return false;
  try {
    return readFileSync(filePath, 'utf-8').includes(SHIELD_MARKER);
  } catch {
    return false;
  }
}

/**
 * Configure all detected AI tools with Shield context.
 * Only configures tools that have existing config files (except CLAUDE.md which is always created).
 */
export function configureAiTools(targetDir: string, detectedAssistants: string[]): AiToolConfigResult {
  const toolsConfigured: string[] = [];
  const toolsSkipped: string[] = [];

  // Always configure Claude Code (it's the primary target)
  if (configureClaudeCodeForShield(targetDir)) {
    toolsConfigured.push('Claude Code (CLAUDE.md)');
  } else {
    toolsSkipped.push('Claude Code (already configured)');
  }

  // Configure Cursor if detected or .cursorrules exists
  if (detectedAssistants.includes('Cursor') || existsSync(join(targetDir, '.cursorrules'))) {
    if (configureCursorForShield(targetDir)) {
      toolsConfigured.push('Cursor (.cursorrules)');
    } else {
      toolsSkipped.push('Cursor (already configured)');
    }
  }

  // Configure Windsurf if detected or .windsurfrules exists
  if (detectedAssistants.includes('Windsurf') || existsSync(join(targetDir, '.windsurfrules'))) {
    if (configureWindsurfForShield(targetDir)) {
      toolsConfigured.push('Windsurf (.windsurfrules)');
    } else {
      toolsSkipped.push('Windsurf (already configured)');
    }
  }

  // Configure Copilot if .github/copilot-instructions.md exists
  if (existsSync(join(targetDir, '.github', 'copilot-instructions.md'))) {
    if (configureCopilotForShield(targetDir)) {
      toolsConfigured.push('GitHub Copilot (.github/copilot-instructions.md)');
    } else {
      toolsSkipped.push('GitHub Copilot (already configured)');
    }
  }

  // Configure Cline if detected or .clinerules exists
  if (detectedAssistants.includes('Cline') || existsSync(join(targetDir, '.clinerules'))) {
    if (configureClineForShield(targetDir)) {
      toolsConfigured.push('Cline (.clinerules)');
    } else {
      toolsSkipped.push('Cline (already configured)');
    }
  }

  return { toolsConfigured, toolsSkipped };
}

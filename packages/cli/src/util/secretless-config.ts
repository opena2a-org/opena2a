/**
 * Secretless config injection for AI tool config files.
 *
 * After `opena2a protect` migrates credentials to env vars, this module
 * injects a managed section into CLAUDE.md, .cursorrules, etc. so AI
 * coding tools know which env vars to use and which files to avoid.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Types ---

export interface SecretlessConfigItem {
  envVar: string;     // e.g. "ANTHROPIC_API_KEY"
  service: string;    // e.g. "Anthropic Messages API"
  authHeader: string; // e.g. "x-api-key: $ANTHROPIC_API_KEY"
}

export interface SecretlessConfigResult {
  toolsUpdated: string[];   // files that were modified
  toolsSkipped: string[];   // files already up to date
}

// --- Service metadata lookup ---

const SERVICE_METADATA: Record<string, { service: string; authHeader: string }> = {
  ANTHROPIC_API_KEY:  { service: 'Anthropic Messages API', authHeader: 'x-api-key: $ANTHROPIC_API_KEY' },
  OPENAI_API_KEY:     { service: 'OpenAI API', authHeader: 'Authorization: Bearer $OPENAI_API_KEY' },
  GOOGLE_API_KEY:     { service: 'Google API', authHeader: 'X-Goog-Api-Key: $GOOGLE_API_KEY' },
  AWS_ACCESS_KEY_ID:  { service: 'AWS', authHeader: '(AWS Signature V4)' },
  GITHUB_TOKEN:       { service: 'GitHub API', authHeader: 'Authorization: Bearer $GITHUB_TOKEN' },
  API_KEY:            { service: 'API Service', authHeader: '(check service docs)' },
};

const START_MARKER = '<!-- secretless:managed -->';
const END_MARKER = '<!-- /secretless:managed -->';

/** AI tool config files: [relative path, createIfMissing] */
const AI_TOOL_CONFIGS: [string, boolean][] = [
  ['CLAUDE.md', true],
  ['.cursorrules', false],
  ['.windsurfrules', false],
  ['.clinerules', false],
  ['.github/copilot-instructions.md', false],
];

// --- Public API ---

/**
 * Map an env var name to service metadata.
 * Strips numeric suffixes (API_KEY_2 -> API_KEY) for lookup.
 */
export function buildConfigItem(envVar: string): SecretlessConfigItem {
  // Strip trailing _N suffix for lookup
  const baseVar = envVar.replace(/_\d+$/, '');
  const meta = SERVICE_METADATA[baseVar];

  if (meta) {
    return {
      envVar,
      service: meta.service,
      // Replace the base var in the auth header template with the actual var
      authHeader: meta.authHeader.replace(`$${baseVar}`, `$${envVar}`),
    };
  }

  return {
    envVar,
    service: 'API Service',
    authHeader: '(check service docs)',
  };
}

/**
 * Upsert the secretless section into all detected AI tool config files.
 */
export function configureSecretlessForAiTools(
  targetDir: string,
  items: SecretlessConfigItem[],
): SecretlessConfigResult {
  const result: SecretlessConfigResult = {
    toolsUpdated: [],
    toolsSkipped: [],
  };

  if (items.length === 0) return result;

  for (const [relPath, createIfMissing] of AI_TOOL_CONFIGS) {
    const filePath = path.join(targetDir, relPath);

    // Merge with any existing credentials in the file
    const existing = parseExistingCredentials(filePath);
    const merged = mergeCredentials(existing, items);
    const section = generateSecretlessSection(merged);

    const updated = upsertSecretlessSection(filePath, section, createIfMissing);

    if (updated) {
      result.toolsUpdated.push(relPath);
    } else {
      result.toolsSkipped.push(relPath);
    }
  }

  return result;
}

// --- Internal functions ---

/**
 * Build the full markdown section with start/end markers.
 */
export function generateSecretlessSection(items: SecretlessConfigItem[]): string {
  const rows = items
    .map(i => `| \`$${i.envVar}\` | ${i.service} | ${i.authHeader} |`)
    .join('\n');

  return `${START_MARKER}
## Secretless Mode

This project uses Secretless to protect credentials from AI context.

**Available API keys** (set as env vars -- use \`$VAR_NAME\` in commands, never ask for values):

| Env Var | Service | Auth Header |
|---------|---------|-------------|
${rows}

**Blocked file patterns** (never read, write, or reference):
- \`.env\`, \`.env.*\` -- environment variable files
- \`*.key\`, \`*.pem\`, \`*.p12\`, \`*.pfx\` -- private key files
- \`.aws/credentials\`, \`.ssh/*\` -- cloud/SSH credentials
- \`*.tfstate\`, \`*.tfvars\` -- Terraform state with secrets
- \`secrets/\`, \`credentials/\` -- secret directories

**If you need a credential:**
1. Reference it via \`$VAR_NAME\` in shell commands or \`process.env.VAR_NAME\` in code
2. Never hardcode credentials in source files
3. Never print or echo key values -- only reference them as variables

**If you find a hardcoded credential:**
1. Replace it with an environment variable reference
2. Add the variable name to \`.env.example\`
3. Warn the user to rotate the exposed credential

Verify setup: \`npx secretless-ai verify\`

## Transcript Protection
- NEVER ask users to paste API keys, tokens, or passwords into the conversation
- If a user pastes a credential, immediately warn them and suggest using environment variables
- Credentials in this conversation are automatically redacted by Secretless AI
${END_MARKER}`;
}

/**
 * Upsert the secretless section into a file.
 * Returns true if the file was modified, false if skipped or unchanged.
 */
export function upsertSecretlessSection(
  filePath: string,
  section: string,
  createIfMissing: boolean,
): boolean {
  if (!fs.existsSync(filePath)) {
    if (!createIfMissing) return false;

    // Ensure parent directory exists
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    const fd = fs.openSync(filePath, 'w', 0o600);
    fs.writeSync(fd, '\n' + section + '\n');
    fs.closeSync(fd);
    return true;
  }

  const content = fs.readFileSync(filePath, 'utf-8');

  // Check if section already exists
  const startIdx = content.indexOf(START_MARKER);

  if (startIdx === -1) {
    // No existing section -- append with separator
    const separator = content.length > 0 && !content.endsWith('\n') ? '\n' : '';
    const prefix = content.length > 0 ? '\n' : '';
    fs.writeFileSync(filePath, content + separator + prefix + section + '\n', 'utf-8');
    return true;
  }

  // Find end of existing section
  let endIdx = content.indexOf(END_MARKER, startIdx);

  if (endIdx !== -1) {
    // Has proper end marker -- replace from start to end (inclusive)
    endIdx += END_MARKER.length;
  } else {
    // Backward compat: old secretless-ai sections without end marker.
    // Look for next <!-- marker or use EOF.
    const nextMarker = content.indexOf('<!--', startIdx + START_MARKER.length);
    endIdx = nextMarker !== -1 ? nextMarker : content.length;

    // Trim trailing whitespace before the next marker
    while (endIdx > startIdx && content[endIdx - 1] === '\n') {
      endIdx--;
    }
    // Keep one newline
    if (endIdx < content.length) endIdx++;
  }

  const before = content.slice(0, startIdx);
  const after = content.slice(endIdx);

  const newContent = before + section + after;

  // Check if content actually changed
  if (newContent === content) return false;

  fs.writeFileSync(filePath, newContent, 'utf-8');
  return true;
}

/**
 * Extract credential items from an existing secretless section's markdown table.
 */
export function parseExistingCredentials(filePath: string): SecretlessConfigItem[] {
  if (!fs.existsSync(filePath)) return [];

  const content = fs.readFileSync(filePath, 'utf-8');
  const startIdx = content.indexOf(START_MARKER);
  if (startIdx === -1) return [];

  // Find the table rows between start and end markers
  let endIdx = content.indexOf(END_MARKER, startIdx);
  if (endIdx === -1) {
    const nextMarker = content.indexOf('<!--', startIdx + START_MARKER.length);
    endIdx = nextMarker !== -1 ? nextMarker : content.length;
  }

  const sectionContent = content.slice(startIdx, endIdx);
  const items: SecretlessConfigItem[] = [];

  // Match table rows: | `$VAR` | Service | Header |
  const rowPattern = /\|\s*`\$([^`]+)`\s*\|\s*([^|]+)\s*\|\s*([^|]+)\s*\|/g;
  let match: RegExpExecArray | null;

  while ((match = rowPattern.exec(sectionContent)) !== null) {
    const envVar = match[1].trim();
    const service = match[2].trim();
    const authHeader = match[3].trim();

    // Skip the header row
    if (envVar === 'Env Var' || envVar === 'Service') continue;

    items.push({ envVar, service, authHeader });
  }

  return items;
}

/**
 * Merge new credentials with existing ones. Deduplicates by envVar (new takes precedence).
 */
function mergeCredentials(
  existing: SecretlessConfigItem[],
  incoming: SecretlessConfigItem[],
): SecretlessConfigItem[] {
  const map = new Map<string, SecretlessConfigItem>();

  // Add existing first
  for (const item of existing) {
    map.set(item.envVar, item);
  }

  // Incoming overwrites
  for (const item of incoming) {
    map.set(item.envVar, item);
  }

  return Array.from(map.values());
}

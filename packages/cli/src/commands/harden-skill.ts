/**
 * harden-skill -- Analyze a skill file for weaknesses and generate a hardened version.
 *
 * Reads a .skill.md or SKILL.md file, analyzes for missing frontmatter,
 * overprivileged capabilities, and missing integrity pins, then generates
 * a hardened version with complete YAML frontmatter, permission boundaries,
 * and a SHA-256 integrity pin.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { bold, green, yellow, red, dim, cyan } from '../util/colors.js';
import {
  parseFrontmatter,
  scanSkillFile,
  findSkillFiles,
  type SkillFinding,
} from '../scanners/skillguard-checks.js';

// --- Types ---

export interface HardenSkillOptions {
  file?: string;
  dryRun?: boolean;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

interface HardenedResult {
  file: string;
  findings: SkillFinding[];
  changes: string[];
  content: string;
  hash: string;
  written: boolean;
}

// --- Permission boundary defaults ---

const CAPABILITY_BOUNDARIES: Record<string, Record<string, Record<string, string[]>>> = {
  'filesystem:*': {
    filesystem: {
      read: ['./data/**', './config/**'],
      write: ['./output/**'],
    },
  },
  'filesystem:read': {
    filesystem: { read: ['./data/**'] },
  },
  'filesystem:write': {
    filesystem: { write: ['./output/**'] },
  },
  'network:outbound': {
    network: { outbound: ['https://api.example.com'] },
  },
  'credential:read': {
    credential: { read: ['$APPROVED_API_KEY'] },
  },
};

// --- Main ---

export async function hardenSkill(options: HardenSkillOptions): Promise<number> {
  const isJson = options.format === 'json';

  // Find the skill file
  let filePath: string;
  let targetDir: string;
  if (options.file) {
    filePath = path.resolve(options.file);
    targetDir = path.dirname(filePath);
    if (!fs.existsSync(filePath)) {
      const msg = `File not found: ${filePath}\n`;
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: msg.trim() }, null, 2) + '\n');
      } else {
        process.stderr.write(red(msg));
      }
      return 1;
    }
  } else {
    // Auto-detect skill files in current directory
    targetDir = process.cwd();
    const skillFiles = findSkillFiles(targetDir, 0);
    if (skillFiles.length === 0) {
      const msg = 'No skill files found. Specify a file with --file or create one with: opena2a skill create\n';
      if (isJson) {
        process.stdout.write(JSON.stringify({ error: msg.trim() }, null, 2) + '\n');
      } else {
        process.stderr.write(yellow(msg));
      }
      return 1;
    }
    if (skillFiles.length > 1 && !options.ci) {
      process.stdout.write(`Found ${skillFiles.length} skill files. Hardening all:\n`);
      for (const f of skillFiles) {
        process.stdout.write(`  ${path.relative(targetDir, f)}\n`);
      }
      process.stdout.write('\n');
    }
    // Process all found skill files
    const results: HardenedResult[] = [];
    let hasIssues = false;
    for (const sf of skillFiles) {
      const result = hardenSingleFile(sf, targetDir, options);
      results.push(result);
      if (result.findings.length > 0) hasIssues = true;
    }
    if (isJson) {
      process.stdout.write(JSON.stringify(results.length === 1 ? results[0] : results, null, 2) + '\n');
    } else {
      for (const result of results) {
        formatTextResult(result, options);
      }
    }
    return hasIssues ? 0 : 0; // Always succeed; findings are informational
  }

  const result = hardenSingleFile(filePath, targetDir, options);

  if (isJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    formatTextResult(result, options);
  }

  return 0;
}

// --- Core hardening logic ---

function hardenSingleFile(filePath: string, targetDir: string, options: HardenSkillOptions): HardenedResult {
  const relativePath = path.relative(targetDir, filePath);
  const content = fs.readFileSync(filePath, 'utf-8');
  const fm = parseFrontmatter(content);
  const findings = scanSkillFile(filePath, targetDir);
  const changes: string[] = [];

  // Build hardened frontmatter
  const name = (fm.fields.name as string) ?? deriveSkillName(filePath);
  const version = (fm.fields.version as string) ?? '1.0.0';
  const description = (fm.fields.description as string) ?? '';
  const capabilities = Array.isArray(fm.fields.capabilities)
    ? (fm.fields.capabilities as string[])
    : [];

  // Track what we changed
  if (!fm.valid) {
    changes.push('Added YAML frontmatter');
  } else {
    if (!fm.fields.name) changes.push('Added missing name field');
    if (!fm.fields.version) changes.push('Added missing version field');
    if (!fm.fields.capabilities) changes.push('Added missing capabilities field');
  }

  // Build permissions with boundaries
  let permissions: Record<string, Record<string, string[]>> = {};
  if (fm.valid && fm.fields.permissions && typeof fm.fields.permissions === 'object') {
    permissions = fm.fields.permissions as Record<string, Record<string, string[]>>;
  }

  // Add permission boundaries for overprivileged capabilities
  for (const cap of capabilities) {
    if (cap in CAPABILITY_BOUNDARIES && !hasExistingBoundary(permissions, cap)) {
      const boundary = CAPABILITY_BOUNDARIES[cap];
      for (const [domain, perms] of Object.entries(boundary)) {
        if (!permissions[domain]) permissions[domain] = {};
        for (const [action, paths] of Object.entries(perms)) {
          if (!permissions[domain][action]) {
            permissions[domain][action] = paths;
            changes.push(`Added permission boundary: ${domain}.${action}`);
          }
        }
      }
    }
  }

  // Replace filesystem:* with scoped capabilities
  const hardenedCapabilities = capabilities.map(cap => {
    if (cap === 'filesystem:*') {
      changes.push('Replaced filesystem:* with scoped filesystem:read + filesystem:write');
      return null; // Will be replaced
    }
    return cap;
  }).filter(Boolean) as string[];

  if (capabilities.includes('filesystem:*')) {
    if (!hardenedCapabilities.includes('filesystem:read')) hardenedCapabilities.push('filesystem:read');
    if (!hardenedCapabilities.includes('filesystem:write')) hardenedCapabilities.push('filesystem:write');
  }

  // Add maxIterations for tool:chain if missing
  let maxIterations: number | undefined;
  if (hardenedCapabilities.some(c => c.includes('tool:chain'))) {
    const hasLimit = fm.valid && (
      fm.raw.includes('maxIterations') || fm.raw.includes('iterationLimit')
    );
    if (!hasLimit) {
      maxIterations = 10;
      changes.push('Added maxIterations: 10 for tool:chain safety');
    }
  }

  // Generate hardened content
  const hardenedContent = generateHardenedContent({
    name,
    version,
    description,
    capabilities: hardenedCapabilities,
    permissions,
    maxIterations,
    body: fm.body || content.replace(/^---[\s\S]*?---\s*/, ''),
    originalFrontmatter: fm,
  });

  // Compute SHA-256 hash
  const hash = createHash('sha256').update(hardenedContent).digest('hex');
  changes.push(`Integrity pin: SHA-256 ${hash.slice(0, 16)}...`);

  // Write if not dry-run
  let written = false;
  if (!options.dryRun) {
    fs.writeFileSync(filePath, hardenedContent, 'utf-8');
    written = true;
  }

  return {
    file: relativePath,
    findings,
    changes,
    content: options.dryRun ? hardenedContent : '',
    hash,
    written,
  };
}

// --- Content generation ---

interface HardenedContentOptions {
  name: string;
  version: string;
  description: string;
  capabilities: string[];
  permissions: Record<string, Record<string, string[]>>;
  maxIterations?: number;
  body: string;
  originalFrontmatter: ReturnType<typeof parseFrontmatter>;
}

function generateHardenedContent(opts: HardenedContentOptions): string {
  const lines: string[] = ['---'];
  lines.push(`name: ${opts.name}`);
  if (opts.description) {
    lines.push(`description: ${opts.description}`);
  }
  lines.push(`version: ${opts.version}`);

  // Capabilities
  if (opts.capabilities.length > 0) {
    lines.push('capabilities:');
    for (const cap of opts.capabilities) {
      lines.push(`  - ${cap}`);
    }
  } else {
    lines.push('capabilities: []');
  }

  // Permissions
  if (Object.keys(opts.permissions).length > 0) {
    lines.push('permissions:');
    for (const [domain, perms] of Object.entries(opts.permissions)) {
      lines.push(`  ${domain}:`);
      for (const [action, paths] of Object.entries(perms)) {
        lines.push(`    ${action}:`);
        if (Array.isArray(paths)) {
          for (const p of paths) {
            lines.push(`      - "${p}"`);
          }
        }
      }
    }
  } else {
    lines.push('permissions: {}');
  }

  // Max iterations for tool:chain
  if (opts.maxIterations !== undefined) {
    lines.push(`maxIterations: ${opts.maxIterations}`);
  }

  // Preserve extra frontmatter fields from original
  const preserveFields = ['dependencies', 'tools', 'heartbeat', 'author', 'license', 'tags'];
  for (const field of preserveFields) {
    if (opts.originalFrontmatter.valid && field in opts.originalFrontmatter.fields) {
      const val = opts.originalFrontmatter.fields[field];
      if (Array.isArray(val)) {
        if (val.length === 0) {
          lines.push(`${field}: []`);
        } else {
          lines.push(`${field}:`);
          for (const item of val) {
            lines.push(`  - ${item}`);
          }
        }
      } else if (typeof val === 'object' && val !== null) {
        lines.push(`${field}:`);
        for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
          lines.push(`  ${k}: ${v}`);
        }
      } else {
        lines.push(`${field}: ${val}`);
      }
    }
  }

  // Compute and embed integrity hash
  const bodyContent = opts.body.trim();
  const preHashContent = lines.join('\n') + '\n---\n\n' + bodyContent + '\n';
  const hash = createHash('sha256').update(preHashContent).digest('hex');
  lines.push(`integrity: sha256-${hash}`);

  lines.push('---');
  lines.push('');
  lines.push(bodyContent);
  lines.push('');

  return lines.join('\n');
}

// --- Helpers ---

function deriveSkillName(filePath: string): string {
  const basename = path.basename(filePath);
  if (basename === 'SKILL.md') {
    return path.basename(path.dirname(filePath));
  }
  return basename.replace(/\.skill\.md$/, '');
}

function hasExistingBoundary(
  permissions: Record<string, Record<string, string[]>>,
  capability: string,
): boolean {
  const parts = capability.split(':');
  if (parts.length !== 2) return false;
  const domain = parts[0];
  return domain in permissions && Object.keys(permissions[domain]).length > 0;
}

// --- Text output formatting ---

function formatTextResult(result: HardenedResult, options: HardenSkillOptions): void {
  process.stdout.write(bold(`\nHardening: ${result.file}`) + '\n');

  // Show findings
  if (result.findings.length > 0) {
    process.stdout.write('\n  Findings:\n');
    for (const f of result.findings) {
      const sevColor = f.severity === 'critical' ? red : f.severity === 'high' ? yellow : dim;
      const sevLabel = sevColor(f.severity.padEnd(10));
      process.stdout.write(`    ${f.id}  ${sevLabel} ${f.title}\n`);
      if (options.verbose) {
        process.stdout.write(`              ${dim(f.description)}\n`);
      }
    }
  }

  // Show changes
  if (result.changes.length > 0) {
    process.stdout.write('\n  Changes applied:\n');
    for (const change of result.changes) {
      process.stdout.write(`    ${green('+')} ${change}\n`);
    }
  }

  // Show preview or confirmation
  if (options.dryRun) {
    process.stdout.write(`\n  ${dim('[dry-run] No changes written.')}\n`);
    if (options.verbose && result.content) {
      process.stdout.write(`\n  ${dim('--- Preview ---')}\n`);
      const preview = result.content.split('\n').slice(0, 30).join('\n');
      process.stdout.write(dim(preview) + '\n');
      if (result.content.split('\n').length > 30) {
        process.stdout.write(dim('  ... (truncated)') + '\n');
      }
    }
  } else if (result.written) {
    process.stdout.write(`\n  ${green('Written:')} ${result.file}\n`);
    process.stdout.write(`  ${dim('SHA-256:')} ${result.hash}\n`);
  }

  process.stdout.write('\n');
}

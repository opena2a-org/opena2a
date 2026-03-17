/**
 * Skill templates for the `opena2a create skill` wizard.
 *
 * Each template defines default capabilities, permissions, SKILL.md content,
 * and an example code stub.
 */

// --- Types ---

export interface SkillTemplate {
  name: string;
  description: string;
  capabilities: string[];
  permissions: Record<string, Record<string, string[]>>;
  skillMdBody: string;
  exampleCode: string;
}

// --- Templates ---

const basicTemplate: SkillTemplate = {
  name: 'basic',
  description: 'Minimal skill with no external access',
  capabilities: [],
  permissions: {},
  skillMdBody: [
    '## Overview',
    '',
    'A basic skill that processes data locally without external dependencies.',
    '',
    '## Usage',
    '',
    '```',
    'Invoke this skill to perform local data processing.',
    '```',
  ].join('\n'),
  exampleCode: [
    '/**',
    ' * Basic skill entry point.',
    ' *',
    ' * This skill processes data locally without external access.',
    ' */',
    'export async function run(input: Record<string, unknown>): Promise<Record<string, unknown>> {',
    '  // Implement your skill logic here',
    '  return { status: "ok", input };',
    '}',
    '',
  ].join('\n'),
};

const mcpToolTemplate: SkillTemplate = {
  name: 'mcp-tool',
  description: 'MCP-compatible tool with network and filesystem access',
  capabilities: ['filesystem:read', 'network:outbound'],
  permissions: {
    filesystem: {
      read: ['/data/**'],
    },
    network: {
      outbound: ['https://api.example.com'],
    },
  },
  skillMdBody: [
    '## Overview',
    '',
    'An MCP-compatible tool skill that can read local files and call external APIs.',
    '',
    '## Capabilities',
    '',
    '- **filesystem:read** -- reads input data from the local filesystem',
    '- **network:outbound** -- sends requests to approved external endpoints',
    '',
    '## Usage',
    '',
    '```',
    'This skill is designed to be invoked as an MCP tool.',
    '```',
  ].join('\n'),
  exampleCode: [
    'import * as fs from "node:fs";',
    '',
    '/**',
    ' * MCP tool skill entry point.',
    ' *',
    ' * Reads data from the filesystem and can call external APIs.',
    ' */',
    'export async function run(input: { filePath?: string; endpoint?: string }): Promise<Record<string, unknown>> {',
    '  const results: Record<string, unknown> = {};',
    '',
    '  if (input.filePath) {',
    '    results.fileContent = fs.readFileSync(input.filePath, "utf-8");',
    '  }',
    '',
    '  if (input.endpoint) {',
    '    const response = await fetch(input.endpoint);',
    '    results.apiResponse = await response.json();',
    '  }',
    '',
    '  return { status: "ok", ...results };',
    '}',
    '',
  ].join('\n'),
};

const dataProcessorTemplate: SkillTemplate = {
  name: 'data-processor',
  description: 'Data processing pipeline with filesystem read/write access',
  capabilities: ['filesystem:read', 'filesystem:write'],
  permissions: {
    filesystem: {
      read: ['/data/input/**'],
      write: ['/data/output/**'],
    },
  },
  skillMdBody: [
    '## Overview',
    '',
    'A data processing skill that reads input files, transforms data, and writes output.',
    '',
    '## Capabilities',
    '',
    '- **filesystem:read** -- reads input data files',
    '- **filesystem:write** -- writes processed output files',
    '',
    '## Usage',
    '',
    '```',
    'Invoke this skill with an input path and output path.',
    '```',
  ].join('\n'),
  exampleCode: [
    'import * as fs from "node:fs";',
    'import * as path from "node:path";',
    '',
    '/**',
    ' * Data processor skill entry point.',
    ' *',
    ' * Reads input files, transforms data, and writes to output directory.',
    ' */',
    'export async function run(input: { inputPath: string; outputPath: string }): Promise<Record<string, unknown>> {',
    '  const data = fs.readFileSync(input.inputPath, "utf-8");',
    '',
    '  // Transform data',
    '  const processed = data.toUpperCase();',
    '',
    '  const outputFile = path.join(input.outputPath, "output.txt");',
    '  fs.mkdirSync(path.dirname(outputFile), { recursive: true });',
    '  fs.writeFileSync(outputFile, processed, "utf-8");',
    '',
    '  return { status: "ok", outputFile, bytesWritten: processed.length };',
    '}',
    '',
  ].join('\n'),
};

// --- Registry ---

export const TEMPLATES: Record<string, SkillTemplate> = {
  basic: basicTemplate,
  'mcp-tool': mcpToolTemplate,
  'data-processor': dataProcessorTemplate,
};

export const TEMPLATE_NAMES = Object.keys(TEMPLATES);

export function getTemplate(name: string): SkillTemplate | undefined {
  return TEMPLATES[name];
}

// --- Capability definitions ---

export interface CapabilityChoice {
  name: string;
  value: string;
  description: string;
  permissions: string[];
}

export const CAPABILITY_CHOICES: CapabilityChoice[] = [
  {
    name: 'Filesystem',
    value: 'filesystem',
    description: 'Read/write files on the local filesystem',
    permissions: ['read', 'write'],
  },
  {
    name: 'Network',
    value: 'network',
    description: 'Send/receive network requests',
    permissions: ['inbound', 'outbound'],
  },
  {
    name: 'Credential',
    value: 'credential',
    description: 'Access stored credentials or secrets',
    permissions: ['read', 'rotate'],
  },
  {
    name: 'Tool',
    value: 'tool',
    description: 'Invoke other tools or skills',
    permissions: ['invoke', 'chain'],
  },
  {
    name: 'Compute',
    value: 'compute',
    description: 'Execute compute-intensive operations',
    permissions: ['local', 'remote'],
  },
];

// --- Danger patterns for permission boundary validation ---

export interface DangerPattern {
  id: string;
  pattern: RegExp;
  severity: 'high' | 'critical';
  message: string;
}

export const DANGER_PATTERNS: DangerPattern[] = [
  {
    id: 'WILDCARD_FS_WRITE',
    pattern: /filesystem:\s*\n\s*write:\s*\n\s*-\s*["']?\/?\*\*["']?/m,
    severity: 'critical',
    message: 'Wildcard filesystem write access (/**) is overly permissive. Restrict to specific directories.',
  },
  {
    id: 'ROOT_FS_WRITE',
    pattern: /filesystem:\s*\n\s*write:\s*\n\s*-\s*["']?\/["']?\s*$/m,
    severity: 'critical',
    message: 'Root filesystem write access (/) grants full disk write. Restrict to specific directories.',
  },
  {
    id: 'WILDCARD_NETWORK',
    pattern: /network:\s*\n\s*outbound:\s*\n\s*-\s*["']?\*["']?/m,
    severity: 'high',
    message: 'Wildcard network outbound access allows connections to any host. Restrict to specific domains.',
  },
  {
    id: 'CREDENTIAL_ROTATE',
    pattern: /credential:\s*\n\s*rotate:/m,
    severity: 'high',
    message: 'Credential rotation capability should be used sparingly. Ensure this skill genuinely needs to rotate credentials.',
  },
  {
    id: 'TOOL_CHAIN',
    pattern: /tool:\s*\n\s*chain:/m,
    severity: 'high',
    message: 'Tool chaining allows this skill to invoke other skills in sequence. Verify the chain is bounded.',
  },
];

/**
 * Validate SKILL.md content against known danger patterns.
 * Returns an array of matched patterns (empty if safe).
 */
export function validatePermissionBoundaries(skillMdContent: string): DangerPattern[] {
  const matches: DangerPattern[] = [];
  for (const dp of DANGER_PATTERNS) {
    if (dp.pattern.test(skillMdContent)) {
      matches.push(dp);
    }
  }
  return matches;
}

// --- SKILL.md generation ---

export function generateSkillMd(opts: {
  name: string;
  description: string;
  capabilities: string[];
  permissions: Record<string, Record<string, string[]>>;
  bodyContent: string;
}): string {
  const lines: string[] = ['---'];
  lines.push(`name: ${opts.name}`);
  lines.push(`description: ${opts.description}`);
  lines.push('version: 1.0.0');

  if (opts.capabilities.length > 0) {
    lines.push('capabilities:');
    for (const cap of opts.capabilities) {
      lines.push(`  - ${cap}`);
    }
  } else {
    lines.push('capabilities: []');
  }

  if (Object.keys(opts.permissions).length > 0) {
    lines.push('permissions:');
    for (const [domain, perms] of Object.entries(opts.permissions)) {
      lines.push(`  ${domain}:`);
      for (const [action, paths] of Object.entries(perms)) {
        lines.push(`    ${action}:`);
        for (const p of paths) {
          lines.push(`      - "${p}"`);
        }
      }
    }
  } else {
    lines.push('permissions: {}');
  }

  lines.push('dependencies: []');
  lines.push('tools: []');
  lines.push('heartbeat:');
  lines.push('  interval: 7d');
  lines.push('---');
  lines.push('');
  lines.push(`# ${opts.name}`);
  lines.push('');
  lines.push(opts.bodyContent);

  return lines.join('\n') + '\n';
}

// --- HEARTBEAT.md generation ---

export function generateHeartbeatMd(skillName: string): string {
  const now = new Date();
  const lines = [
    `# Heartbeat: ${skillName}`,
    '',
    `Status: active`,
    `Last checked: ${now.toISOString()}`,
    `Interval: 7d`,
    '',
    '## Health',
    '',
    'All systems operational.',
  ];
  return lines.join('\n') + '\n';
}

// --- Test file generation ---

export function generateTestFile(skillName: string, capabilities: string[]): string {
  const safeName = skillName.replace(/[^a-zA-Z0-9]/g, '-');
  const lines: string[] = [
    `import { describe, it, expect } from 'vitest';`,
    '',
    `describe('${skillName}', () => {`,
    `  it('should have a valid SKILL.md', async () => {`,
    `    const fs = await import('node:fs');`,
    `    const content = fs.readFileSync('SKILL.md', 'utf-8');`,
    `    expect(content).toContain('name: ${skillName}');`,
    `    expect(content).toContain('version: 1.0.0');`,
    `  });`,
    '',
  ];

  if (capabilities.includes('filesystem:read') || capabilities.includes('filesystem:write')) {
    lines.push(`  it('declares filesystem capabilities', async () => {`);
    lines.push(`    const fs = await import('node:fs');`);
    lines.push(`    const content = fs.readFileSync('SKILL.md', 'utf-8');`);
    lines.push(`    expect(content).toContain('filesystem');`);
    lines.push(`  });`);
    lines.push('');
  }

  if (capabilities.includes('network:outbound') || capabilities.includes('network:inbound')) {
    lines.push(`  it('declares network capabilities', async () => {`);
    lines.push(`    const fs = await import('node:fs');`);
    lines.push(`    const content = fs.readFileSync('SKILL.md', 'utf-8');`);
    lines.push(`    expect(content).toContain('network');`);
    lines.push(`  });`);
    lines.push('');
  }

  if (capabilities.includes('credential:read') || capabilities.includes('credential:rotate')) {
    lines.push(`  it('declares credential capabilities', async () => {`);
    lines.push(`    const fs = await import('node:fs');`);
    lines.push(`    const content = fs.readFileSync('SKILL.md', 'utf-8');`);
    lines.push(`    expect(content).toContain('credential');`);
    lines.push(`  });`);
    lines.push('');
  }

  lines.push(`  it('has a valid heartbeat file', async () => {`);
  lines.push(`    const fs = await import('node:fs');`);
  lines.push(`    const content = fs.readFileSync('HEARTBEAT.md', 'utf-8');`);
  lines.push(`    expect(content).toContain('Status: active');`);
  lines.push(`    expect(content).toContain('Interval: 7d');`);
  lines.push(`  });`);
  lines.push('');

  lines.push(`  it('has signature block after signing', async () => {`);
  lines.push(`    const fs = await import('node:fs');`);
  lines.push(`    const content = fs.readFileSync('SKILL.md', 'utf-8');`);
  lines.push(`    // After running opena2a guard sign --skills, this should contain a signature`);
  lines.push(`    // This test validates the structure if signed`);
  lines.push(`    if (content.includes('<!-- opena2a-guard')) {`);
  lines.push(`      expect(content).toContain('pinned_hash: sha256:');`);
  lines.push(`      expect(content).toContain('signed_by:');`);
  lines.push(`    }`);
  lines.push(`  });`);

  lines.push('});');
  lines.push('');

  return lines.join('\n');
}

// --- GitHub Action template ---

export function generateGitHubAction(skillName: string): string {
  const lines = [
    `name: Verify ${skillName}`,
    '',
    'on:',
    '  push:',
    '    paths:',
    '      - "SKILL.md"',
    '      - "HEARTBEAT.md"',
    '  pull_request:',
    '    paths:',
    '      - "SKILL.md"',
    '      - "HEARTBEAT.md"',
    '',
    'jobs:',
    '  verify-skill:',
    '    runs-on: ubuntu-latest',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '',
    '      - uses: actions/setup-node@v4',
    '        with:',
    '          node-version: "20"',
    '',
    '      - name: Install OpenA2A CLI',
    '        run: npm install -g opena2a-cli',
    '',
    '      - name: Verify skill signature',
    '        run: opena2a guard verify --skills --ci',
    '',
    '      - name: Verify heartbeat',
    '        run: opena2a guard verify --heartbeats --ci',
    '',
    '      - name: Run security scan',
    '        run: opena2a scan secure --ci',
  ];
  return lines.join('\n') + '\n';
}

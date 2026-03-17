import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';

import { createSkill, _internals } from '../../../src/commands/create/skill.js';
import { create, _internals as createInternals } from '../../../src/commands/create/index.js';
import {
  TEMPLATES,
  TEMPLATE_NAMES,
  getTemplate,
  generateSkillMd,
  generateHeartbeatMd,
  generateTestFile,
  generateGitHubAction,
  validatePermissionBoundaries,
  CAPABILITY_CHOICES,
  DANGER_PATTERNS,
} from '../../../src/commands/create/templates.js';

// ---------------------------------------------------------------------------
// Temp directory setup
// ---------------------------------------------------------------------------

let tempDir: string;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-create-skill-'));
});

afterEach(() => {
  fs.rmSync(tempDir, { recursive: true, force: true });
});

// ===========================================================================
// 1. Template registry
// ===========================================================================

describe('templates', () => {
  it('has three template types', () => {
    expect(TEMPLATE_NAMES).toEqual(['basic', 'mcp-tool', 'data-processor']);
  });

  it('returns template by name', () => {
    const t = getTemplate('basic');
    expect(t).toBeDefined();
    expect(t!.name).toBe('basic');
  });

  it('returns undefined for unknown template', () => {
    expect(getTemplate('nonexistent')).toBeUndefined();
  });

  it('basic template has no capabilities', () => {
    const t = getTemplate('basic')!;
    expect(t.capabilities).toEqual([]);
    expect(t.permissions).toEqual({});
  });

  it('mcp-tool template has filesystem and network capabilities', () => {
    const t = getTemplate('mcp-tool')!;
    expect(t.capabilities).toContain('filesystem:read');
    expect(t.capabilities).toContain('network:outbound');
    expect(t.permissions.filesystem).toBeDefined();
    expect(t.permissions.network).toBeDefined();
  });

  it('data-processor template has filesystem read and write', () => {
    const t = getTemplate('data-processor')!;
    expect(t.capabilities).toContain('filesystem:read');
    expect(t.capabilities).toContain('filesystem:write');
    expect(t.permissions.filesystem?.read).toBeDefined();
    expect(t.permissions.filesystem?.write).toBeDefined();
  });

  it('all templates have example code', () => {
    for (const name of TEMPLATE_NAMES) {
      const t = getTemplate(name)!;
      expect(t.exampleCode.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// 2. SKILL.md generation
// ===========================================================================

describe('generateSkillMd', () => {
  it('generates YAML frontmatter with name and version', () => {
    const md = generateSkillMd({
      name: 'test-skill',
      description: 'A test skill',
      capabilities: [],
      permissions: {},
      bodyContent: '## Overview',
    });

    expect(md).toContain('---');
    expect(md).toContain('name: test-skill');
    expect(md).toContain('description: A test skill');
    expect(md).toContain('version: 1.0.0');
    expect(md).toContain('capabilities: []');
    expect(md).toContain('permissions: {}');
    expect(md).toContain('heartbeat:');
    expect(md).toContain('  interval: 7d');
  });

  it('generates capabilities list', () => {
    const md = generateSkillMd({
      name: 'net-skill',
      description: 'Network skill',
      capabilities: ['filesystem:read', 'network:outbound'],
      permissions: {
        filesystem: { read: ['/data/**'] },
        network: { outbound: ['https://api.example.com'] },
      },
      bodyContent: '## Overview',
    });

    expect(md).toContain('capabilities:');
    expect(md).toContain('  - filesystem:read');
    expect(md).toContain('  - network:outbound');
    expect(md).toContain('  filesystem:');
    expect(md).toContain('    read:');
    expect(md).toContain('      - "/data/**"');
    expect(md).toContain('  network:');
    expect(md).toContain('    outbound:');
  });

  it('includes body content after frontmatter', () => {
    const md = generateSkillMd({
      name: 'body-test',
      description: 'Test',
      capabilities: [],
      permissions: {},
      bodyContent: '## Custom Body\n\nSome content.',
    });

    // Should have two --- separators (frontmatter) followed by content
    const parts = md.split('---');
    expect(parts.length).toBeGreaterThanOrEqual(3);
    expect(md).toContain('## Custom Body');
    expect(md).toContain('Some content.');
  });
});

// ===========================================================================
// 3. HEARTBEAT.md generation
// ===========================================================================

describe('generateHeartbeatMd', () => {
  it('generates heartbeat with skill name and active status', () => {
    const hb = generateHeartbeatMd('my-skill');
    expect(hb).toContain('# Heartbeat: my-skill');
    expect(hb).toContain('Status: active');
    expect(hb).toContain('Interval: 7d');
    expect(hb).toContain('All systems operational.');
  });
});

// ===========================================================================
// 4. Test file generation
// ===========================================================================

describe('generateTestFile', () => {
  it('generates a vitest test file', () => {
    const test = generateTestFile('my-skill', []);
    expect(test).toContain("import { describe, it, expect } from 'vitest'");
    expect(test).toContain("describe('my-skill'");
    expect(test).toContain('SKILL.md');
    expect(test).toContain('HEARTBEAT.md');
  });

  it('includes filesystem test for filesystem capabilities', () => {
    const test = generateTestFile('fs-skill', ['filesystem:read']);
    expect(test).toContain('declares filesystem capabilities');
  });

  it('includes network test for network capabilities', () => {
    const test = generateTestFile('net-skill', ['network:outbound']);
    expect(test).toContain('declares network capabilities');
  });

  it('includes credential test for credential capabilities', () => {
    const test = generateTestFile('cred-skill', ['credential:read']);
    expect(test).toContain('declares credential capabilities');
  });

  it('includes signature block test', () => {
    const test = generateTestFile('sig-skill', []);
    expect(test).toContain('signature block');
    expect(test).toContain('opena2a-guard');
  });
});

// ===========================================================================
// 5. GitHub Action generation
// ===========================================================================

describe('generateGitHubAction', () => {
  it('generates a valid YAML workflow', () => {
    const action = generateGitHubAction('my-skill');
    expect(action).toContain('name: Verify my-skill');
    expect(action).toContain('on:');
    expect(action).toContain('push:');
    expect(action).toContain('pull_request:');
    expect(action).toContain('SKILL.md');
    expect(action).toContain('HEARTBEAT.md');
    expect(action).toContain('opena2a guard verify --skills --ci');
    expect(action).toContain('opena2a guard verify --heartbeats --ci');
    expect(action).toContain('opena2a scan secure --ci');
  });
});

// ===========================================================================
// 6. Permission boundary validation
// ===========================================================================

describe('validatePermissionBoundaries', () => {
  it('returns empty for safe SKILL.md', () => {
    const safe = generateSkillMd({
      name: 'safe',
      description: 'Safe skill',
      capabilities: ['filesystem:read'],
      permissions: { filesystem: { read: ['/data/**'] } },
      bodyContent: '',
    });
    const matches = validatePermissionBoundaries(safe);
    expect(matches).toEqual([]);
  });

  it('detects wildcard filesystem write', () => {
    const dangerous = [
      '---',
      'name: danger',
      'permissions:',
      '  filesystem:',
      '    write:',
      '      - "/**"',
      '---',
    ].join('\n');
    const matches = validatePermissionBoundaries(dangerous);
    const ids = matches.map(m => m.id);
    expect(ids).toContain('WILDCARD_FS_WRITE');
  });

  it('detects credential rotate', () => {
    const content = [
      '---',
      'name: cred-rotator',
      'permissions:',
      '  credential:',
      '    rotate:',
      '      - "vault://default"',
      '---',
    ].join('\n');
    const matches = validatePermissionBoundaries(content);
    const ids = matches.map(m => m.id);
    expect(ids).toContain('CREDENTIAL_ROTATE');
  });

  it('detects tool chaining', () => {
    const content = [
      '---',
      'name: chainer',
      'permissions:',
      '  tool:',
      '    chain:',
      '      - "opena2a/*"',
      '---',
    ].join('\n');
    const matches = validatePermissionBoundaries(content);
    const ids = matches.map(m => m.id);
    expect(ids).toContain('TOOL_CHAIN');
  });

  it('all danger patterns have required fields', () => {
    for (const dp of DANGER_PATTERNS) {
      expect(dp.id).toBeTruthy();
      expect(dp.pattern).toBeInstanceOf(RegExp);
      expect(['high', 'critical']).toContain(dp.severity);
      expect(dp.message.length).toBeGreaterThan(0);
    }
  });
});

// ===========================================================================
// 7. Skill creation (CI mode, non-interactive)
// ===========================================================================

describe('createSkill (CI mode)', () => {
  it('creates all expected files with basic template', async () => {
    const outputDir = path.join(tempDir, 'basic-skill');
    const exitCode = await createSkill({
      name: 'basic-skill',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
    expect(fs.existsSync(path.join(outputDir, 'SKILL.md'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, 'HEARTBEAT.md'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, 'index.ts'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, 'skill.test.ts'))).toBe(true);
    expect(fs.existsSync(path.join(outputDir, '.github', 'workflows', 'skill-verify.yml'))).toBe(true);
  });

  it('creates skill with mcp-tool template', async () => {
    const outputDir = path.join(tempDir, 'mcp-skill');
    const exitCode = await createSkill({
      name: 'mcp-skill',
      template: 'mcp-tool',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);

    const skillMd = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    expect(skillMd).toContain('name: mcp-skill');
    expect(skillMd).toContain('filesystem:read');
    expect(skillMd).toContain('network:outbound');
  });

  it('creates skill with data-processor template', async () => {
    const outputDir = path.join(tempDir, 'data-skill');
    const exitCode = await createSkill({
      name: 'data-skill',
      template: 'data-processor',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);

    const skillMd = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    expect(skillMd).toContain('name: data-skill');
    expect(skillMd).toContain('filesystem:read');
    expect(skillMd).toContain('filesystem:write');
  });

  it('uses default name in CI mode when none provided', async () => {
    const outputDir = path.join(tempDir, 'default-name');
    const exitCode = await createSkill({
      output: outputDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);

    const skillMd = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    expect(skillMd).toContain('name: my-skill');
  });

  it('SKILL.md contains valid YAML frontmatter structure', async () => {
    const outputDir = path.join(tempDir, 'yaml-check');
    await createSkill({
      name: 'yaml-check',
      template: 'mcp-tool',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    const content = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    // Should start with --- and have a closing ---
    expect(content.startsWith('---\n')).toBe(true);
    const secondDash = content.indexOf('---', 4);
    expect(secondDash).toBeGreaterThan(0);

    // Extract frontmatter
    const frontmatter = content.slice(4, secondDash);
    expect(frontmatter).toContain('name:');
    expect(frontmatter).toContain('description:');
    expect(frontmatter).toContain('version:');
    expect(frontmatter).toContain('capabilities:');
    expect(frontmatter).toContain('permissions:');
    expect(frontmatter).toContain('dependencies:');
    expect(frontmatter).toContain('tools:');
    expect(frontmatter).toContain('heartbeat:');
  });

  it('signs skill files by default', async () => {
    const outputDir = path.join(tempDir, 'signed-skill');
    await createSkill({
      name: 'signed-skill',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    const skillMd = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    // After signing, SKILL.md should contain signature block
    expect(skillMd).toContain('<!-- opena2a-guard');
    expect(skillMd).toContain('pinned_hash: sha256:');
    expect(skillMd).toContain('signed_by:');
  });

  it('skips signing with --no-sign', async () => {
    const outputDir = path.join(tempDir, 'unsigned-skill');
    await createSkill({
      name: 'unsigned-skill',
      template: 'basic',
      output: outputDir,
      noSign: true,
      ci: true,
      format: 'json',
    });

    const skillMd = fs.readFileSync(path.join(outputDir, 'SKILL.md'), 'utf-8');
    expect(skillMd).not.toContain('<!-- opena2a-guard');
  });

  it('outputs JSON result in JSON format', async () => {
    const outputDir = path.join(tempDir, 'json-output');

    // Capture stdout
    const chunks: Buffer[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: any) => {
      chunks.push(Buffer.from(chunk));
      return true;
    };

    await createSkill({
      name: 'json-skill',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    process.stdout.write = origWrite;

    const output = Buffer.concat(chunks).toString('utf-8');
    const parsed = JSON.parse(output);
    expect(parsed.directory).toBe(outputDir);
    expect(parsed.files).toContain('SKILL.md');
    expect(parsed.files).toContain('HEARTBEAT.md');
    expect(parsed.files).toContain('index.ts');
    expect(parsed.files).toContain('skill.test.ts');
    expect(parsed.files).toContain('.github/workflows/skill-verify.yml');
    expect(typeof parsed.signed).toBe('boolean');
    expect(Array.isArray(parsed.warnings)).toBe(true);
  });

  it('outputs text format with human-readable output', async () => {
    const outputDir = path.join(tempDir, 'text-output');

    const chunks: Buffer[] = [];
    const origWrite = process.stdout.write.bind(process.stdout);
    process.stdout.write = (chunk: any) => {
      chunks.push(Buffer.from(chunk));
      return true;
    };

    await createSkill({
      name: 'text-skill',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'text',
    });

    process.stdout.write = origWrite;

    const output = Buffer.concat(chunks).toString('utf-8');
    expect(output).toContain('Skill created');
    expect(output).toContain('SKILL.md');
    expect(output).toContain('HEARTBEAT.md');
    expect(output).toContain('Next steps');
  });
});

// ===========================================================================
// 8. Create command (entry point)
// ===========================================================================

describe('create command', () => {
  it('supports skill type', () => {
    expect(createInternals.SUPPORTED_TYPES).toContain('skill');
  });

  it('rejects unknown type', async () => {
    const chunks: Buffer[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = (chunk: any) => {
      chunks.push(Buffer.from(chunk));
      return true;
    };

    const exitCode = await create({
      type: 'unknown-thing',
      ci: true,
      format: 'json',
    });

    process.stderr.write = origWrite;

    expect(exitCode).toBe(1);
    const output = Buffer.concat(chunks).toString('utf-8');
    expect(output).toContain('Unknown type');
  });

  it('delegates skill type to createSkill', async () => {
    const outputDir = path.join(tempDir, 'delegate-test');
    const exitCode = await create({
      type: 'skill',
      name: 'delegated',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    expect(exitCode).toBe(0);
    expect(fs.existsSync(path.join(outputDir, 'SKILL.md'))).toBe(true);
  });
});

// ===========================================================================
// 9. CI defaults
// ===========================================================================

describe('CI defaults', () => {
  it('has sensible default values', () => {
    expect(_internals.CI_DEFAULTS.name).toBe('my-skill');
    expect(_internals.CI_DEFAULTS.template).toBe('basic');
    expect(Array.isArray(_internals.CI_DEFAULTS.capabilities)).toBe(true);
  });
});

// ===========================================================================
// 10. Capability choices
// ===========================================================================

describe('capability choices', () => {
  it('defines five capability categories', () => {
    expect(CAPABILITY_CHOICES).toHaveLength(5);
  });

  it('each choice has required fields', () => {
    for (const choice of CAPABILITY_CHOICES) {
      expect(choice.name).toBeTruthy();
      expect(choice.value).toBeTruthy();
      expect(choice.description).toBeTruthy();
      expect(choice.permissions.length).toBeGreaterThan(0);
    }
  });

  it('covers filesystem, network, credential, tool, compute', () => {
    const values = CAPABILITY_CHOICES.map(c => c.value);
    expect(values).toContain('filesystem');
    expect(values).toContain('network');
    expect(values).toContain('credential');
    expect(values).toContain('tool');
    expect(values).toContain('compute');
  });
});

// ===========================================================================
// 11. Default permission paths
// ===========================================================================

describe('getDefaultPermissionPath', () => {
  it('returns /data/** for filesystem:read', () => {
    expect(_internals.getDefaultPermissionPath('filesystem', 'read')).toBe('/data/**');
  });

  it('returns /data/output/** for filesystem:write', () => {
    expect(_internals.getDefaultPermissionPath('filesystem', 'write')).toBe('/data/output/**');
  });

  it('returns https URL for network:outbound', () => {
    expect(_internals.getDefaultPermissionPath('network', 'outbound')).toMatch(/^https:\/\//);
  });

  it('returns fallback for unknown combination', () => {
    expect(_internals.getDefaultPermissionPath('unknown', 'unknown')).toBe('*');
  });
});

// ===========================================================================
// 12. GitHub Action template content
// ===========================================================================

describe('GitHub Action template', () => {
  it('creates .github/workflows/skill-verify.yml', async () => {
    const outputDir = path.join(tempDir, 'action-test');
    await createSkill({
      name: 'action-test',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    const actionPath = path.join(outputDir, '.github', 'workflows', 'skill-verify.yml');
    expect(fs.existsSync(actionPath)).toBe(true);

    const content = fs.readFileSync(actionPath, 'utf-8');
    expect(content).toContain('actions/checkout@v4');
    expect(content).toContain('actions/setup-node@v4');
    expect(content).toContain('npm install -g opena2a-cli');
  });
});

// ===========================================================================
// 13. Heartbeat file creation
// ===========================================================================

describe('heartbeat file', () => {
  it('is created in the output directory', async () => {
    const outputDir = path.join(tempDir, 'hb-test');
    await createSkill({
      name: 'hb-test',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    const hbPath = path.join(outputDir, 'HEARTBEAT.md');
    expect(fs.existsSync(hbPath)).toBe(true);

    const content = fs.readFileSync(hbPath, 'utf-8');
    expect(content).toContain('Heartbeat: hb-test');
    expect(content).toContain('Status: active');
  });

  it('has expires_at after signing', async () => {
    const outputDir = path.join(tempDir, 'hb-signed');
    await createSkill({
      name: 'hb-signed',
      template: 'basic',
      output: outputDir,
      ci: true,
      format: 'json',
    });

    const content = fs.readFileSync(path.join(outputDir, 'HEARTBEAT.md'), 'utf-8');
    expect(content).toContain('<!-- opena2a-guard');
    expect(content).toContain('expires_at:');
  });
});

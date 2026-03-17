/**
 * Skill creation wizard for `opena2a create skill`.
 *
 * Scaffolds a secure skill directory with SKILL.md (YAML frontmatter),
 * HEARTBEAT.md, example code, vitest test, and GitHub Action template.
 * Signs the skill via ConfigGuard after scaffolding.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, dim } from '../../util/colors.js';
import {
  CAPABILITY_CHOICES,
  TEMPLATE_NAMES,
  getTemplate,
  generateSkillMd,
  generateHeartbeatMd,
  generateTestFile,
  generateGitHubAction,
  validatePermissionBoundaries,
} from './templates.js';

// --- Types ---

export interface SkillCreateOptions {
  name?: string;
  template?: string;
  output?: string;
  noSign?: boolean;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

export interface SkillCreateResult {
  directory: string;
  files: string[];
  signed: boolean;
  warnings: string[];
}

// --- CI defaults ---

const CI_DEFAULTS = {
  name: 'my-skill',
  description: 'A new OpenA2A skill',
  capabilities: [] as string[],
  template: 'basic',
};

// --- Main ---

export async function createSkill(opts: SkillCreateOptions): Promise<number> {
  const isJson = opts.format === 'json';
  const isCi = opts.ci || !!process.env.CI;

  let skillName: string;
  let description: string;
  let selectedCapabilities: string[];
  let selectedPermissions: Record<string, Record<string, string[]>>;
  let templateName: string;

  if (isCi) {
    // Non-interactive mode: use defaults or CLI args
    skillName = opts.name ?? CI_DEFAULTS.name;
    description = CI_DEFAULTS.description;
    selectedCapabilities = CI_DEFAULTS.capabilities;
    selectedPermissions = {};
    templateName = opts.template ?? CI_DEFAULTS.template;
  } else {
    // Interactive wizard
    const prompts = await import('@inquirer/prompts');

    skillName = opts.name ?? await prompts.input({
      message: 'Skill name:',
      default: 'my-skill',
      validate: (v: string) => /^[a-z0-9][a-z0-9-]*$/.test(v) || 'Use lowercase alphanumeric with hyphens',
    });

    description = await prompts.input({
      message: 'Description:',
      default: `A new OpenA2A skill`,
    });

    const capChoices = CAPABILITY_CHOICES.map(c => ({
      name: `${c.name} -- ${c.description}`,
      value: c.value,
    }));

    const selectedCaps = await prompts.checkbox({
      message: 'Capabilities (space to select, enter to confirm):',
      choices: capChoices,
    });

    // Build capability strings and permissions from selections
    selectedCapabilities = [];
    selectedPermissions = {};

    for (const capValue of selectedCaps) {
      const capDef = CAPABILITY_CHOICES.find(c => c.value === capValue);
      if (!capDef) continue;

      const permChoices = capDef.permissions.map(p => ({
        name: `${capValue}:${p}`,
        value: p,
      }));

      const selectedPerms = await prompts.checkbox({
        message: `${capDef.name} permissions:`,
        choices: permChoices,
      });

      for (const perm of selectedPerms) {
        selectedCapabilities.push(`${capValue}:${perm}`);
      }

      if (selectedPerms.length > 0) {
        selectedPermissions[capValue] = {};
        for (const perm of selectedPerms) {
          const defaultPath = getDefaultPermissionPath(capValue, perm);
          const pathInput = await prompts.input({
            message: `${capValue}:${perm} allowed paths/hosts (comma-separated):`,
            default: defaultPath,
          });
          selectedPermissions[capValue][perm] = pathInput.split(',').map((s: string) => s.trim());
        }
      }
    }

    const templateChoices = TEMPLATE_NAMES.map(t => {
      const tmpl = getTemplate(t);
      return { name: `${t} -- ${tmpl?.description ?? ''}`, value: t };
    });

    templateName = opts.template ?? await prompts.select({
      message: 'Template:',
      choices: templateChoices,
    });
  }

  // Apply template defaults for capabilities/permissions if none selected and template has them
  const template = getTemplate(templateName);
  if (template && selectedCapabilities.length === 0 && template.capabilities.length > 0) {
    selectedCapabilities = [...template.capabilities];
    selectedPermissions = JSON.parse(JSON.stringify(template.permissions));
  }

  // Determine output directory
  const outputDir = path.resolve(opts.output ?? path.join(process.cwd(), skillName));

  // Create directory
  fs.mkdirSync(outputDir, { recursive: true });

  const createdFiles: string[] = [];
  const warnings: string[] = [];

  // 1. Generate SKILL.md
  const bodyContent = template?.skillMdBody ?? `## Overview\n\n${description}`;
  const skillMdContent = generateSkillMd({
    name: skillName,
    description,
    capabilities: selectedCapabilities,
    permissions: selectedPermissions,
    bodyContent,
  });

  fs.writeFileSync(path.join(outputDir, 'SKILL.md'), skillMdContent, 'utf-8');
  createdFiles.push('SKILL.md');

  // 2. Generate HEARTBEAT.md
  const heartbeatContent = generateHeartbeatMd(skillName);
  fs.writeFileSync(path.join(outputDir, 'HEARTBEAT.md'), heartbeatContent, 'utf-8');
  createdFiles.push('HEARTBEAT.md');

  // 3. Generate example code
  const exampleCode = template?.exampleCode ?? `export async function run(input: unknown) {\n  return { status: "ok", input };\n}\n`;
  fs.writeFileSync(path.join(outputDir, 'index.ts'), exampleCode, 'utf-8');
  createdFiles.push('index.ts');

  // 4. Generate test file
  const testContent = generateTestFile(skillName, selectedCapabilities);
  fs.writeFileSync(path.join(outputDir, 'skill.test.ts'), testContent, 'utf-8');
  createdFiles.push('skill.test.ts');

  // 5. Generate GitHub Action
  const ghDir = path.join(outputDir, '.github', 'workflows');
  fs.mkdirSync(ghDir, { recursive: true });
  const actionContent = generateGitHubAction(skillName);
  fs.writeFileSync(path.join(ghDir, 'skill-verify.yml'), actionContent, 'utf-8');
  createdFiles.push('.github/workflows/skill-verify.yml');

  // 6. Permission boundary validation
  const dangerMatches = validatePermissionBoundaries(skillMdContent);
  for (const dm of dangerMatches) {
    warnings.push(`[${dm.severity.toUpperCase()}] ${dm.id}: ${dm.message}`);
  }

  // 7. Sign skill files (unless --no-sign)
  let signed = false;
  if (!opts.noSign) {
    try {
      const { signSkillFiles, signHeartbeatFiles } = await import('../guard-signing.js');
      await signSkillFiles(outputDir);
      await signHeartbeatFiles(outputDir);
      signed = true;
    } catch {
      warnings.push('Could not auto-sign skill files. Run: opena2a guard sign --skills --heartbeats');
    }
  }

  // Output results
  const result: SkillCreateResult = {
    directory: outputDir,
    files: createdFiles,
    signed,
    warnings,
  };

  if (isJson) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    process.stdout.write('\n' + bold('Skill created') + '\n\n');
    process.stdout.write(`  ${dim('Directory:')} ${outputDir}\n`);
    process.stdout.write(`  ${dim('Template:')}  ${templateName}\n\n`);

    process.stdout.write(dim('  Files:') + '\n');
    for (const f of createdFiles) {
      process.stdout.write(`    ${green('+')} ${f}\n`);
    }

    if (signed) {
      process.stdout.write(`\n  ${green('Signed')} SKILL.md and HEARTBEAT.md\n`);
    } else if (opts.noSign) {
      process.stdout.write(`\n  ${dim('Signing skipped (--no-sign)')}\n`);
    }

    if (warnings.length > 0) {
      process.stdout.write(`\n  ${yellow('Warnings:')}\n`);
      for (const w of warnings) {
        process.stdout.write(`    ${yellow('!')} ${w}\n`);
      }
    }

    process.stdout.write(`\n  ${dim('Next steps:')}\n`);
    process.stdout.write(`    cd ${skillName}\n`);
    process.stdout.write(`    opena2a guard verify --skills    ${dim('# verify signature')}\n`);
    process.stdout.write(`    opena2a scan secure              ${dim('# security scan')}\n`);
    process.stdout.write('\n');
  }

  return warnings.some(w => w.startsWith('[CRITICAL]')) ? 1 : 0;
}

// --- Helpers ---

function getDefaultPermissionPath(capability: string, permission: string): string {
  switch (`${capability}:${permission}`) {
    case 'filesystem:read': return '/data/**';
    case 'filesystem:write': return '/data/output/**';
    case 'network:outbound': return 'https://api.example.com';
    case 'network:inbound': return 'localhost:8080';
    case 'credential:read': return 'vault://default';
    case 'credential:rotate': return 'vault://default';
    case 'tool:invoke': return 'opena2a/*';
    case 'tool:chain': return 'opena2a/*';
    case 'compute:local': return 'cpu:4,memory:512m';
    case 'compute:remote': return 'https://compute.example.com';
    default: return '*';
  }
}

// --- Testable internals ---

export const _internals = {
  CI_DEFAULTS,
  getDefaultPermissionPath,
};

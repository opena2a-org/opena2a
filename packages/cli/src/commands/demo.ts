/**
 * opena2a demo -- Interactive demonstration of AIM capabilities.
 *
 * Runs a self-contained, narrated walkthrough showing the full AIM lifecycle
 * in a temporary sandbox. No Docker or external services required.
 *
 * Scenarios:
 *   aim  (default) -- Identity, policy, signing, credential migration
 *   dvaa           -- Attack/defend loop against a vulnerable agent config
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import * as readline from 'node:readline';
import { bold, dim, green, yellow, red, cyan, gray } from '../util/colors.js';
import { printFooter } from '../util/footer.js';

// --- Types ---

export interface DemoOptions {
  scenario?: string;
  interactive?: boolean;
  keep?: boolean;
  dir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

interface DemoStep {
  step: number;
  total: number;
  title: string;
  description: string;
}

interface AuditEntry {
  timestamp: string;
  action: string;
  target: string;
  outcome: string;
}

interface DemoResult {
  scenario: string;
  sandboxDir: string;
  kept: boolean;
  steps: { step: number; title: string; status: string }[];
  scoreBefore: number;
  scoreAfter: number;
  findingsBefore: { critical: number; high: number; medium: number; low: number };
  findingsAfter: { critical: number; high: number; medium: number; low: number };
  auditLog: AuditEntry[];
}

// --- Helpers ---

const STEP_DELAY_MS = 300;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function waitForEnter(interactive: boolean): Promise<void> {
  if (!interactive) return;
  const rl = readline.createInterface({ input: process.stdin, output: process.stderr });
  return new Promise((resolve) => {
    process.stderr.write(dim('  [Press Enter to continue]') + '\n');
    rl.once('line', () => {
      rl.close();
      resolve();
    });
  });
}

function printStepHeader(step: DemoStep): void {
  process.stdout.write('\n');
  process.stdout.write(bold(cyan(`Step ${step.step}/${step.total}: ${step.title}`)) + '\n');
  process.stdout.write(dim(`  ${step.description}`) + '\n');
}

function generateDemoId(): string {
  return 'aim_demo_' + crypto.randomBytes(6).toString('hex');
}

function generateKeyPair(): { publicKey: string; privateKeyHex: string } {
  const bytes = crypto.randomBytes(32);
  const hash = crypto.createHash('sha256').update(bytes).digest('hex');
  return {
    publicKey: 'ed25519:' + hash.slice(0, 16) + '...',
    privateKeyHex: hash,
  };
}

function nowISO(): string {
  return new Date().toISOString().replace('T', ' ').slice(0, 19);
}

// --- Sandbox setup ---

function createSandbox(dir?: string): string {
  if (dir) {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  }
  return fs.mkdtempSync(path.join(os.tmpdir(), 'opena2a-demo-'));
}

function cleanupSandbox(sandboxDir: string, keep: boolean): void {
  if (keep) return;
  try {
    fs.rmSync(sandboxDir, { recursive: true, force: true });
  } catch {
    // Best-effort cleanup
  }
}

function writeSandboxFiles(sandboxDir: string): void {
  // package.json
  fs.writeFileSync(
    path.join(sandboxDir, 'package.json'),
    JSON.stringify(
      {
        name: 'demo-ai-agent',
        version: '1.0.0',
        description: 'Sample AI agent for AIM demo',
        main: 'index.js',
        dependencies: { langchain: '^0.1.0', openai: '^4.0.0' },
      },
      null,
      2,
    ),
  );

  // Fake .env with intentionally exposed credentials
  fs.writeFileSync(
    path.join(sandboxDir, '.env'),
    [
      '# Demo credentials (FAKE - for demonstration only)',
      'OPENAI_API_KEY=sk-FAKE-demo-key-1234567890abcdef',
      'DATABASE_URL=postgresql://admin:password123@localhost:5432/mydb',
      '',
    ].join('\n'),
  );

  // MCP config
  const mcpDir = path.join(sandboxDir, '.cursor');
  fs.mkdirSync(mcpDir, { recursive: true });
  fs.writeFileSync(
    path.join(mcpDir, 'mcp.json'),
    JSON.stringify(
      {
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
            env: {},
          },
          database: {
            command: 'npx',
            args: ['-y', 'mcp-server-postgres'],
            env: { DB_URL: 'postgresql://admin:password123@localhost:5432/mydb' },
          },
        },
      },
      null,
      2,
    ),
  );

  // A simple config.js with embedded key
  fs.writeFileSync(
    path.join(sandboxDir, 'config.js'),
    [
      '// Agent configuration',
      'module.exports = {',
      '  apiKey: "sk-FAKE-hardcoded-key-abcdef1234",',
      '  model: "gpt-4",',
      '  maxTokens: 4096,',
      '};',
      '',
    ].join('\n'),
  );
}

function writeDvaaFiles(sandboxDir: string): void {
  // package.json for vulnerable agent
  fs.writeFileSync(
    path.join(sandboxDir, 'package.json'),
    JSON.stringify(
      {
        name: 'vulnerable-ai-agent',
        version: '0.1.0',
        description: 'Intentionally vulnerable AI agent for demo',
        main: 'agent.js',
        dependencies: { openai: '^4.0.0', express: '^4.18.0' },
      },
      null,
      2,
    ),
  );

  // Hardcoded API key in config
  fs.writeFileSync(
    path.join(sandboxDir, 'config.js'),
    [
      '// DVAA agent config',
      'const config = {',
      '  openaiKey: "sk-FAKE-vuln-key-deadbeef1234567890",',
      '  adminToken: "ghp_FAKE_admin_token_1234567890abcdef",',
      '  allowedTools: ["*"],  // overprivileged',
      '  trustAllInputs: true,',
      '};',
      'module.exports = config;',
      '',
    ].join('\n'),
  );

  // Permissive MCP config
  const mcpDir = path.join(sandboxDir, '.cursor');
  fs.mkdirSync(mcpDir, { recursive: true });
  fs.writeFileSync(
    path.join(mcpDir, 'mcp.json'),
    JSON.stringify(
      {
        mcpServers: {
          filesystem: {
            command: 'npx',
            args: ['-y', '@modelcontextprotocol/server-filesystem', '/'],
            env: {},
          },
        },
      },
      null,
      2,
    ),
  );

  // .env with credentials
  fs.writeFileSync(
    path.join(sandboxDir, '.env'),
    [
      'OPENAI_API_KEY=sk-FAKE-vuln-env-key-1234567890',
      'ADMIN_SECRET=FAKE-super-secret-admin-password',
      '',
    ].join('\n'),
  );

  // Overprivileged skill
  fs.writeFileSync(
    path.join(sandboxDir, 'SKILL.md'),
    [
      '---',
      'name: data-exporter',
      'tools: ["read-file", "write-file", "execute-shell", "network-external"]',
      '---',
      '',
      '# Data Exporter Skill',
      'This skill can read, write, execute, and send data externally.',
      '',
    ].join('\n'),
  );
}

// --- AIM Demo ---

async function runAimDemo(opts: DemoOptions): Promise<DemoResult> {
  const isCI = opts.ci ?? false;
  const isInteractive = !isCI && (opts.interactive ?? false);
  const keep = opts.keep ?? false;
  const total = 8;
  const auditLog: AuditEntry[] = [];
  const steps: { step: number; title: string; status: string }[] = [];
  const sandboxDir = createSandbox(opts.dir);

  const delayMs = isCI ? 0 : STEP_DELAY_MS;

  try {
    // Header
    process.stdout.write('\n');
    process.stdout.write(bold('AIM Agent Identity Management Demo') + '\n');
    process.stdout.write(dim('=' .repeat(38)) + '\n');
    process.stdout.write(dim('  Self-contained walkthrough of the AIM lifecycle.') + '\n');
    process.stdout.write(dim('  All operations run in a temporary sandbox.') + '\n');

    // Step 1: Setup sandbox
    printStepHeader({
      step: 1, total,
      title: 'Setting up sandbox',
      description: 'Creating temporary project with sample agent configuration...',
    });
    await sleep(delayMs);
    writeSandboxFiles(sandboxDir);
    process.stdout.write(green('  Created sandbox at: ') + dim(sandboxDir) + '\n');
    process.stdout.write(dim('  Files: package.json, .env, .cursor/mcp.json, config.js') + '\n');
    steps.push({ step: 1, title: 'Setting up sandbox', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 2: Security scan (before AIM)
    printStepHeader({
      step: 2, total,
      title: 'Security scan (before AIM)',
      description: 'Running security assessment of unprotected project...',
    });
    await sleep(delayMs);

    const findingsBefore = { critical: 1, high: 2, medium: 1, low: 0 };
    const scoreBefore = 22;

    process.stdout.write('\n');
    process.stdout.write('  Findings:\n');
    process.stdout.write('    ' + red('CRITICAL') + '  CRED-001  Hardcoded API key in .env\n');
    process.stdout.write('    ' + yellow('HIGH    ') + '  CRED-002  Database password in connection string\n');
    process.stdout.write('    ' + yellow('HIGH    ') + '  CRED-003  Hardcoded API key in config.js\n');
    process.stdout.write('    ' + cyan('MEDIUM  ') + '  MCP-001   MCP server with root filesystem access\n');
    process.stdout.write('\n');
    process.stdout.write('  Result: ' + bold(red('3 findings')) + ' (1 critical, 2 high)\n');
    process.stdout.write('  Score:  ' + bold(red(String(scoreBefore) + '/100')) + '\n');

    auditLog.push({ timestamp: nowISO(), action: 'scan.initial', target: 'project', outcome: 'complete' });
    steps.push({ step: 2, title: 'Security scan (before AIM)', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 3: Create agent identity
    printStepHeader({
      step: 3, total,
      title: 'Creating agent identity',
      description: 'Generating Ed25519 keypair for demo-agent...',
    });
    await sleep(delayMs);

    const agentId = generateDemoId();
    const keyPair = generateKeyPair();

    process.stdout.write('\n');
    process.stdout.write('  Agent ID:    ' + bold(agentId) + '\n');
    process.stdout.write('  Public Key:  ' + dim(keyPair.publicKey) + '\n');
    process.stdout.write('  Algorithm:   Ed25519\n');

    // Write identity file to sandbox
    const opena2aDir = path.join(sandboxDir, '.opena2a');
    fs.mkdirSync(opena2aDir, { recursive: true });
    fs.writeFileSync(
      path.join(opena2aDir, 'identity.json'),
      JSON.stringify({ agentId, publicKey: keyPair.publicKey, algorithm: 'Ed25519', createdAt: new Date().toISOString() }, null, 2),
    );

    auditLog.push({ timestamp: nowISO(), action: 'identity.create', target: 'demo-agent', outcome: 'allowed' });
    steps.push({ step: 3, title: 'Creating agent identity', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 4: Apply capability policy
    printStepHeader({
      step: 4, total,
      title: 'Applying capability policy',
      description: 'Writing capability policy that restricts tool access...',
    });
    await sleep(delayMs);

    const policy = {
      version: 1,
      agentId,
      mode: 'enforce',
      capabilities: {
        allow: ['read-file', 'list-directory', 'search'],
        deny: ['write-file', 'execute-shell', 'network-external'],
      },
      createdAt: new Date().toISOString(),
    };
    fs.writeFileSync(path.join(opena2aDir, 'policy.json'), JSON.stringify(policy, null, 2));

    process.stdout.write('\n');
    process.stdout.write('  Policy applied:\n');
    process.stdout.write('    ' + green('ALLOW') + '  read-file, list-directory, search\n');
    process.stdout.write('    ' + red('DENY ') + '  write-file, execute-shell, network-external\n');
    process.stdout.write('  Mode: enforce\n');

    auditLog.push({ timestamp: nowISO(), action: 'policy.apply', target: 'capability', outcome: 'allowed' });
    steps.push({ step: 4, title: 'Applying capability policy', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 5: Sign configuration files
    printStepHeader({
      step: 5, total,
      title: 'Signing configuration files',
      description: 'Signing package.json and mcp config for tamper detection...',
    });
    await sleep(delayMs);

    const filesToSign = ['package.json', '.cursor/mcp.json'];
    const signatures: Record<string, string> = {};
    for (const f of filesToSign) {
      const content = fs.readFileSync(path.join(sandboxDir, f), 'utf-8');
      const hash = crypto.createHash('sha256').update(content).digest('hex');
      signatures[f] = hash;
    }

    const guardDir = path.join(opena2aDir, 'guard');
    fs.mkdirSync(guardDir, { recursive: true });
    fs.writeFileSync(
      path.join(guardDir, 'signatures.json'),
      JSON.stringify({ version: 1, signatures: Object.entries(signatures).map(([file, hash]) => ({ file, hash, signedAt: new Date().toISOString() })) }, null, 2),
    );

    process.stdout.write('\n');
    for (const f of filesToSign) {
      process.stdout.write('  Signed: ' + bold(f) + ' ' + dim('sha256:' + signatures[f].slice(0, 12) + '...') + '\n');
    }
    process.stdout.write('  Total:  ' + bold('2 files') + ' signed for tamper detection\n');

    auditLog.push({ timestamp: nowISO(), action: 'config.sign', target: 'package.json', outcome: 'allowed' });
    auditLog.push({ timestamp: nowISO(), action: 'config.sign', target: '.cursor/mcp.json', outcome: 'allowed' });
    steps.push({ step: 5, title: 'Signing configuration files', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 6: Migrate credentials
    printStepHeader({
      step: 6, total,
      title: 'Migrating credentials',
      description: 'Moving hardcoded credentials to encrypted vault...',
    });
    await sleep(delayMs);

    const vaultDir = path.join(opena2aDir, 'vault');
    fs.mkdirSync(vaultDir, { recursive: true });

    const migratedCreds = [
      { name: 'OPENAI_API_KEY', source: '.env', status: 'migrated' },
      { name: 'DATABASE_URL', source: '.env', status: 'migrated' },
      { name: 'apiKey', source: 'config.js', status: 'migrated' },
    ];

    // Write a vault manifest
    fs.writeFileSync(
      path.join(vaultDir, 'manifest.json'),
      JSON.stringify({ version: 1, entries: migratedCreds.map((c) => ({ name: c.name, source: c.source, migratedAt: new Date().toISOString() })) }, null, 2),
    );

    // Rewrite .env to use vault references
    fs.writeFileSync(
      path.join(sandboxDir, '.env'),
      [
        '# Credentials migrated to vault',
        'OPENAI_API_KEY=vault://opena2a/OPENAI_API_KEY',
        'DATABASE_URL=vault://opena2a/DATABASE_URL',
        '',
      ].join('\n'),
    );

    // Rewrite config.js to use env var
    fs.writeFileSync(
      path.join(sandboxDir, 'config.js'),
      [
        '// Agent configuration (credentials migrated to vault)',
        'module.exports = {',
        '  apiKey: process.env.OPENAI_API_KEY,',
        '  model: "gpt-4",',
        '  maxTokens: 4096,',
        '};',
        '',
      ].join('\n'),
    );

    process.stdout.write('\n');
    for (const c of migratedCreds) {
      process.stdout.write('  Migrated: ' + bold(c.name) + ' from ' + dim(c.source) + ' to vault\n');
    }
    process.stdout.write('  Total:    ' + bold('3 credentials') + ' moved to encrypted vault\n');

    auditLog.push({ timestamp: nowISO(), action: 'credential.migrate', target: '.env', outcome: 'allowed' });
    auditLog.push({ timestamp: nowISO(), action: 'credential.migrate', target: 'config.js', outcome: 'allowed' });
    steps.push({ step: 6, title: 'Migrating credentials', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 7: Security scan (after AIM)
    printStepHeader({
      step: 7, total,
      title: 'Security scan (after AIM)',
      description: 'Running security assessment of protected project...',
    });
    await sleep(delayMs);

    const findingsAfter = { critical: 0, high: 0, medium: 0, low: 1 };
    const scoreAfter = 87;

    process.stdout.write('\n');
    process.stdout.write('  Findings:\n');
    process.stdout.write('    ' + dim('LOW     ') + '  CONFIG-005  Consider enabling strict mode\n');
    process.stdout.write('\n');
    process.stdout.write('  Result: ' + green('0 critical, 0 high') + '\n');
    process.stdout.write('  Score:  ' + bold(green(String(scoreAfter) + '/100')) + '  ' + green('(+' + String(scoreAfter - scoreBefore) + ' improvement)') + '\n');

    auditLog.push({ timestamp: nowISO(), action: 'scan.final', target: 'project', outcome: 'complete' });
    steps.push({ step: 7, title: 'Security scan (after AIM)', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 8: Audit log
    printStepHeader({
      step: 8, total,
      title: 'Audit log',
      description: 'Reviewing what happened...',
    });
    await sleep(delayMs);

    process.stdout.write('\n');
    for (const entry of auditLog) {
      const action = entry.action.padEnd(20);
      const target = entry.target.padEnd(20);
      process.stdout.write(
        '  ' + dim(entry.timestamp) + '  ' + action + target + green(entry.outcome) + '\n',
      );
    }

    steps.push({ step: 8, title: 'Audit log', status: 'complete' });

    // Summary
    process.stdout.write('\n');
    process.stdout.write(bold('Demo Complete') + '\n');
    process.stdout.write(dim('='.repeat(16)) + '\n');
    process.stdout.write('\n');
    process.stdout.write('  Before AIM:  ' + bold(red(String(scoreBefore) + '/100')) + '  (3 findings, no identity, no governance)\n');
    process.stdout.write('  After AIM:   ' + bold(green(String(scoreAfter) + '/100')) + '  (0 critical findings, identity active, policy enforced)\n');
    process.stdout.write('\n');
    process.stdout.write('  What happened:\n');
    process.stdout.write('    1. Created cryptographic agent identity (Ed25519)\n');
    process.stdout.write('    2. Applied least-privilege capability policy\n');
    process.stdout.write('    3. Signed config files for tamper detection\n');
    process.stdout.write('    4. Migrated hardcoded credentials to encrypted vault\n');
    process.stdout.write('\n');
    process.stdout.write('  Try it on your project:\n');
    process.stdout.write(cyan('    opena2a init') + '              Start security assessment\n');
    process.stdout.write(cyan('    opena2a protect') + '           Detect and migrate credentials\n');
    process.stdout.write(cyan('    opena2a identity create') + '   Create agent identity\n');
    process.stdout.write('\n');

    if (keep) {
      process.stdout.write(dim('  Sandbox preserved at: ' + sandboxDir) + '\n');
    } else {
      process.stdout.write(dim('  Sandbox cleaned up. No files were modified outside the demo.') + '\n');
    }

    return {
      scenario: 'aim',
      sandboxDir,
      kept: keep,
      steps,
      scoreBefore,
      scoreAfter,
      findingsBefore,
      findingsAfter,
      auditLog,
    };
  } finally {
    cleanupSandbox(sandboxDir, keep);
  }
}

// --- DVAA Demo ---

async function runDvaaDemo(opts: DemoOptions): Promise<DemoResult> {
  const isCI = opts.ci ?? false;
  const isInteractive = !isCI && (opts.interactive ?? false);
  const keep = opts.keep ?? false;
  const total = 5;
  const auditLog: AuditEntry[] = [];
  const steps: { step: number; title: string; status: string }[] = [];
  const sandboxDir = createSandbox(opts.dir);

  const delayMs = isCI ? 0 : STEP_DELAY_MS;

  try {
    // Header
    process.stdout.write('\n');
    process.stdout.write(bold('DVAA Attack/Defend Demo') + '\n');
    process.stdout.write(dim('='.repeat(26)) + '\n');
    process.stdout.write(dim('  Shows how AIM protects an agent from common attacks.') + '\n');

    // Step 1: Set up vulnerable agent
    printStepHeader({
      step: 1, total,
      title: 'Setting up vulnerable agent',
      description: 'Creating a simulated vulnerable AI agent configuration...',
    });
    await sleep(delayMs);
    writeDvaaFiles(sandboxDir);
    process.stdout.write(green('  Created vulnerable agent sandbox at: ') + dim(sandboxDir) + '\n');
    process.stdout.write(dim('  Files: package.json, config.js, .env, .cursor/mcp.json, SKILL.md') + '\n');
    steps.push({ step: 1, title: 'Setting up vulnerable agent', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 2: Security scan
    printStepHeader({
      step: 2, total,
      title: 'Running security scan',
      description: 'Scanning for vulnerabilities...',
    });
    await sleep(delayMs);

    const scoreBefore = 18;
    const findingsBefore = { critical: 1, high: 2, medium: 1, low: 0 };

    process.stdout.write('\n');
    process.stdout.write('  Findings:\n');
    process.stdout.write('    ' + red('CRITICAL') + '  CRED-001       Hardcoded API key in config.js\n');
    process.stdout.write('    ' + yellow('HIGH    ') + '  MCP-003        MCP server with root filesystem access\n');
    process.stdout.write('    ' + yellow('HIGH    ') + '  GOVERNANCE-001 No SOUL.md governance file\n');
    process.stdout.write('    ' + cyan('MEDIUM  ') + '  SKILL-002      Overprivileged skill definitions\n');
    process.stdout.write('\n');
    process.stdout.write('  Score: ' + bold(red(String(scoreBefore) + '/100')) + '\n');

    auditLog.push({ timestamp: nowISO(), action: 'scan.initial', target: 'project', outcome: 'complete' });
    steps.push({ step: 2, title: 'Running security scan', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 3: Apply AIM hardening
    printStepHeader({
      step: 3, total,
      title: 'Applying AIM hardening',
      description: 'Creating agent identity, governance, migrating credentials, signing config...',
    });
    await sleep(delayMs);

    const agentId = generateDemoId();
    const opena2aDir = path.join(sandboxDir, '.opena2a');
    fs.mkdirSync(path.join(opena2aDir, 'guard'), { recursive: true });
    fs.mkdirSync(path.join(opena2aDir, 'vault'), { recursive: true });

    // Identity
    process.stdout.write('\n');
    process.stdout.write('  Creating agent identity...       ' + green('done') + '\n');
    fs.writeFileSync(
      path.join(opena2aDir, 'identity.json'),
      JSON.stringify({ agentId, algorithm: 'Ed25519', createdAt: new Date().toISOString() }, null, 2),
    );
    auditLog.push({ timestamp: nowISO(), action: 'identity.create', target: agentId, outcome: 'allowed' });

    // Governance
    process.stdout.write('  Generating governance file...    ' + green('done') + '\n');
    fs.writeFileSync(
      path.join(sandboxDir, 'SOUL.md'),
      [
        '# Agent Governance',
        '',
        '## Identity',
        'This agent operates under AIM identity management.',
        '',
        '## Boundaries',
        '- No external network access without explicit approval',
        '- No shell command execution',
        '- Read-only filesystem access by default',
        '',
        '## Data Handling',
        '- No credential storage in plaintext',
        '- All secrets accessed via vault references',
        '',
      ].join('\n'),
    );
    auditLog.push({ timestamp: nowISO(), action: 'governance.create', target: 'SOUL.md', outcome: 'allowed' });

    // Credential migration
    process.stdout.write('  Migrating credentials...         ' + green('done') + '\n');
    fs.writeFileSync(
      path.join(sandboxDir, 'config.js'),
      [
        '// DVAA agent config (hardened)',
        'const config = {',
        '  openaiKey: process.env.OPENAI_API_KEY,',
        '  adminToken: process.env.ADMIN_TOKEN,',
        '  allowedTools: ["read-file", "search"],',
        '  trustAllInputs: false,',
        '};',
        'module.exports = config;',
        '',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(sandboxDir, '.env'),
      [
        '# Credentials migrated to vault',
        'OPENAI_API_KEY=vault://opena2a/OPENAI_API_KEY',
        'ADMIN_SECRET=vault://opena2a/ADMIN_SECRET',
        '',
      ].join('\n'),
    );
    auditLog.push({ timestamp: nowISO(), action: 'credential.migrate', target: 'config.js', outcome: 'allowed' });

    // Signing
    process.stdout.write('  Signing configuration...         ' + green('done') + '\n');
    const configContent = fs.readFileSync(path.join(sandboxDir, 'config.js'), 'utf-8');
    const configHash = crypto.createHash('sha256').update(configContent).digest('hex');
    fs.writeFileSync(
      path.join(opena2aDir, 'guard', 'signatures.json'),
      JSON.stringify({ version: 1, signatures: [{ file: 'config.js', hash: configHash, signedAt: new Date().toISOString() }] }, null, 2),
    );
    auditLog.push({ timestamp: nowISO(), action: 'config.sign', target: 'config.js', outcome: 'allowed' });

    // Policy
    fs.writeFileSync(
      path.join(opena2aDir, 'policy.json'),
      JSON.stringify({
        version: 1,
        agentId,
        mode: 'enforce',
        capabilities: {
          allow: ['read-file', 'search'],
          deny: ['write-file', 'execute-shell', 'network-external', 'prompt-override'],
        },
      }, null, 2),
    );
    auditLog.push({ timestamp: nowISO(), action: 'policy.apply', target: 'capability', outcome: 'allowed' });

    steps.push({ step: 3, title: 'Applying AIM hardening', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 4: Re-scan
    printStepHeader({
      step: 4, total,
      title: 'Re-scanning after hardening',
      description: 'Running security assessment of hardened project...',
    });
    await sleep(delayMs);

    const scoreAfter = 91;
    const findingsAfter = { critical: 0, high: 0, medium: 0, low: 1 };

    process.stdout.write('\n');
    process.stdout.write('  Findings:\n');
    process.stdout.write('    ' + dim('LOW     ') + '  CONFIG-005  Consider enabling strict mode\n');
    process.stdout.write('\n');
    process.stdout.write('  Score: ' + bold(green(String(scoreAfter) + '/100')) + '  ' + green('(+' + String(scoreAfter - scoreBefore) + ' improvement)') + '\n');

    auditLog.push({ timestamp: nowISO(), action: 'scan.final', target: 'project', outcome: 'complete' });
    steps.push({ step: 4, title: 'Re-scanning after hardening', status: 'complete' });
    await waitForEnter(isInteractive);

    // Step 5: Attack simulation
    printStepHeader({
      step: 5, total,
      title: 'Attack simulation',
      description: 'Running adversarial probes against hardened configuration...',
    });
    await sleep(delayMs);

    const attacks = [
      { name: 'prompt-injection', result: 'BLOCKED', reason: 'capability policy denies prompt override' },
      { name: 'credential-theft', result: 'BLOCKED', reason: 'credentials in vault, not in files' },
      { name: 'config-tampering', result: 'BLOCKED', reason: 'signature verification detects change' },
      { name: 'privilege-escalation', result: 'BLOCKED', reason: 'least-privilege policy enforced' },
    ];

    process.stdout.write('\n');
    for (const attack of attacks) {
      const nameCol = attack.name.padEnd(24);
      process.stdout.write(
        '  ' + nameCol + green('BLOCKED') + '   (' + dim(attack.reason) + ')\n',
      );
      auditLog.push({ timestamp: nowISO(), action: 'attack.' + attack.name, target: 'agent', outcome: 'blocked' });
    }
    process.stdout.write('\n');
    process.stdout.write('  Result: ' + bold(green('4/4 attacks blocked')) + '\n');

    steps.push({ step: 5, title: 'Attack simulation', status: 'complete' });

    // Summary
    process.stdout.write('\n');
    process.stdout.write(bold('Demo Complete') + '\n');
    process.stdout.write(dim('='.repeat(16)) + '\n');
    process.stdout.write('\n');
    process.stdout.write('  Before hardening:  ' + bold(red(String(scoreBefore) + '/100')) + '  (4 findings, no identity, no governance)\n');
    process.stdout.write('  After hardening:   ' + bold(green(String(scoreAfter) + '/100')) + '  (0 critical, identity active, policy enforced)\n');
    process.stdout.write('  Attacks blocked:   ' + bold(green('4/4')) + '\n');
    process.stdout.write('\n');
    process.stdout.write('  What was applied:\n');
    process.stdout.write('    1. Created cryptographic agent identity\n');
    process.stdout.write('    2. Generated SOUL.md governance file\n');
    process.stdout.write('    3. Migrated credentials to encrypted vault\n');
    process.stdout.write('    4. Signed configuration for tamper detection\n');
    process.stdout.write('    5. Applied least-privilege capability policy\n');
    process.stdout.write('\n');
    process.stdout.write('  Try it on your project:\n');
    process.stdout.write(cyan('    opena2a init') + '              Start security assessment\n');
    process.stdout.write(cyan('    opena2a protect') + '           Detect and migrate credentials\n');
    process.stdout.write(cyan('    opena2a harden-soul') + '       Generate governance file\n');
    process.stdout.write('\n');

    if (keep) {
      process.stdout.write(dim('  Sandbox preserved at: ' + sandboxDir) + '\n');
    } else {
      process.stdout.write(dim('  Sandbox cleaned up. No files were modified outside the demo.') + '\n');
    }

    return {
      scenario: 'dvaa',
      sandboxDir,
      kept: keep,
      steps,
      scoreBefore,
      scoreAfter,
      findingsBefore,
      findingsAfter,
      auditLog,
    };
  } finally {
    cleanupSandbox(sandboxDir, keep);
  }
}

// --- Entry point ---

export async function demo(opts: DemoOptions): Promise<number> {
  const scenario = opts.scenario ?? 'aim';
  const format = opts.format ?? 'text';

  let result: DemoResult;

  // In JSON mode, capture the demo silently and only output the JSON result
  const originalWrite = process.stdout.write.bind(process.stdout);
  if (format === 'json') {
    process.stdout.write = (() => true) as typeof process.stdout.write;
  }

  try {
    if (scenario === 'dvaa') {
      result = await runDvaaDemo(opts);
    } else if (scenario === 'aim' || !scenario) {
      result = await runAimDemo(opts);
    } else {
      if (format === 'json') process.stdout.write = originalWrite;
      process.stderr.write(`Unknown demo scenario: ${scenario}\n`);
      process.stderr.write('Available scenarios: aim (default), dvaa\n');
      return 1;
    }
  } catch (err) {
    if (format === 'json') process.stdout.write = originalWrite;
    process.stderr.write(`Demo error: ${err instanceof Error ? err.message : String(err)}\n`);
    return 1;
  }

  // Restore stdout and output JSON if needed
  if (format === 'json') {
    process.stdout.write = originalWrite;
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  }

  printFooter({ ci: opts.ci, json: format === 'json' });
  return 0;
}

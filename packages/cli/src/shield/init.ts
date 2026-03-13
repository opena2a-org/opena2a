import { existsSync, mkdirSync, writeFileSync, appendFileSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type {
  EnvironmentScan,
  ShieldPolicy,
  DetectedCli,
  DetectedAssistant,
  DetectedMcpServer,
  DetectedOAuthSession,
} from './types.js';
import { SHIELD_DIR, SHIELD_SCAN_FILE, SHIELD_POLICY_FILE } from './types.js';
import { detectEnvironment } from './detect.js';
import { generatePolicyFromScan, savePolicy } from './policy.js';
import { writeEvent, getShieldDir } from './events.js';
import { recordPolicyHash, getExpectedHookContent } from './integrity.js';
import { signAllArtifacts } from './signing.js';
import { configureAiTools } from './ai-tool-config.js';
import type { AiToolConfigResult } from './ai-tool-config.js';
import { bold, dim, green, yellow, red, cyan } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { runtimeInitSilent } from '../commands/runtime.js';

interface InitResult {
  scan: EnvironmentScan;
  policy: ShieldPolicy;
  shellHookInstalled: boolean;
  policyPath: string;
  secretlessConfigured: boolean;
  identityCreated: boolean;
  aiToolsConfigured: boolean;
  configSigning: { signed: number; files: string[] } | null;
  arpInit: { created: boolean; path: string; agentName?: string } | null;
  steps: { name: string; status: 'done' | 'skipped' | 'warn' }[];
}

export async function shieldInit(options: {
  targetDir?: string;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
  shellHook?: boolean;
  aiTools?: boolean;
}): Promise<{ exitCode: number; result: InitResult }> {
  const targetDir = options.targetDir ?? process.cwd();
  const ci = options.ci ?? false;
  const format = options.format ?? 'text';
  const isText = format === 'text' && !ci;
  const steps: InitResult['steps'] = [];

  // --- Step 1: Environment Detection ---
  if (isText) process.stdout.write(bold('\nShield Init\n\n'));

  const spinner = isText ? new Spinner('Scanning environment...') : null;
  spinner?.start();

  const scan = detectEnvironment(targetDir);

  spinner?.stop();
  steps.push({ name: 'Environment scan', status: 'done' });

  if (isText) {
    process.stdout.write(bold('Step 1: Environment Detection\n'));
    // CLIs
    if (scan.clis.length > 0) {
      process.stdout.write(`  CLIs found: ${scan.clis.map((c: DetectedCli) => c.name).join(', ')}\n`);
    } else {
      process.stdout.write(`  No cloud CLIs detected\n`);
    }
    // Assistants
    const activeAssistants = scan.assistants.filter((a: DetectedAssistant) => a.detected);
    if (activeAssistants.length > 0) {
      process.stdout.write(`  AI assistants: ${activeAssistants.map((a: DetectedAssistant) => a.name).join(', ')}\n`);
    }
    // MCP servers
    if (scan.mcpServers.length > 0) {
      process.stdout.write(`  MCP servers: ${scan.mcpServers.map((s: DetectedMcpServer) => s.name).join(', ')}\n`);
    }
    // OAuth sessions
    const activeSessions = scan.oauthSessions.filter((s: DetectedOAuthSession) => s.hasActiveSession);
    if (activeSessions.length > 0) {
      process.stdout.write(yellow(`  Active OAuth sessions: ${activeSessions.map((s: DetectedOAuthSession) => s.provider).join(', ')}\n`));
    }
    // Project
    process.stdout.write(`  Project: ${scan.projectName ?? 'unknown'} (${scan.projectType})\n`);
    process.stdout.write('\n');
  }

  // --- Step 2: Credential Audit ---
  if (isText) process.stdout.write(bold('Step 2: Credential Audit\n'));
  let credentialFindings = 0;
  try {
    const { quickCredentialScan } = await import('../util/credential-patterns.js');
    const matches = quickCredentialScan(targetDir);
    credentialFindings = matches.length;
    if (isText) {
      if (matches.length === 0) {
        process.stdout.write(green('  No hardcoded credentials found\n'));
      } else {
        process.stdout.write(yellow(`  ${matches.length} credential${matches.length !== 1 ? 's' : ''} found\n`));
        for (const m of matches.slice(0, 5)) {
          process.stdout.write(`    ${m.severity.toUpperCase()}: ${m.title} in ${m.filePath}:${m.line}\n`);
        }
        if (matches.length > 5) {
          process.stdout.write(dim(`    ... and ${matches.length - 5} more\n`));
        }
        process.stdout.write(dim('  Run: opena2a protect\n'));
      }
    }
  } catch {
    if (isText) process.stdout.write(dim('  Credential scan skipped (module unavailable)\n'));
  }
  steps.push({ name: 'Credential audit', status: credentialFindings > 0 ? 'warn' : 'done' });
  if (isText) process.stdout.write('\n');

  // --- Step 3: Credential Protection (Secretless) ---
  if (isText) process.stdout.write(bold('Step 3: Credential Protection\n'));
  let secretlessConfigured = false;
  try {
    const secretless = await import('secretless-ai');
    if (typeof secretless.init === 'function') {
      const result = secretless.init(targetDir);
      secretlessConfigured = true;
      if (isText) {
        process.stdout.write(green('  Secretless configured\n'));
        if (result && typeof result === 'object') {
          if ('toolsConfigured' in result && Array.isArray(result.toolsConfigured)) {
            process.stdout.write(`  Tools: ${result.toolsConfigured.join(', ')}\n`);
          }
          if ('secretsFound' in result && typeof result.secretsFound === 'number' && result.secretsFound > 0) {
            process.stdout.write(`  Secrets protected: ${result.secretsFound}\n`);
          }
        }
        // Check backend — guide users to authenticate for their configured backend
        try {
          const { readBackendConfig } = await import('secretless-ai');
          if (typeof readBackendConfig === 'function') {
            const backend = readBackendConfig();
            if (backend === '1password') {
              process.stdout.write('\n');
              process.stdout.write(bold('  1Password backend detected.\n'));
              process.stdout.write('  Run once at the start of each session to pre-authenticate\n');
              process.stdout.write('  and avoid repeated Touch ID prompts during development:\n\n');
              process.stdout.write('    ' + cyan('opena2a secrets warm') + '\n\n');
              process.stdout.write(dim('  This loads all secrets into an encrypted local cache.\n'));
              process.stdout.write(dim('  Touch ID is only prompted once per session (default: 8h).\n'));
            } else if (backend === 'gcp-sm') {
              process.stdout.write('\n');
              process.stdout.write(bold('  GCP Secret Manager backend configured.\n'));
              process.stdout.write('  Ensure your GCP credentials are active:\n\n');
              process.stdout.write('    ' + cyan('gcloud auth application-default login') + '\n\n');
              process.stdout.write(dim('  Secrets are stored in GCP Secret Manager and injected at runtime.\n'));
            } else if (backend === 'vault') {
              process.stdout.write('\n');
              process.stdout.write(bold('  HashiCorp Vault backend configured.\n'));
              process.stdout.write('  Ensure VAULT_ADDR and VAULT_TOKEN are set in your shell:\n\n');
              process.stdout.write('    ' + cyan('export VAULT_ADDR=https://vault.example.com') + '\n');
              process.stdout.write('    ' + cyan('export VAULT_TOKEN=<your-token>') + '\n\n');
              process.stdout.write(dim('  Secrets are stored in Vault KV v2 and injected at runtime.\n'));
            }
          }
        } catch {
          // backend check is best-effort
        }
      }
    } else {
      // Secretless module found but no init function -- try CLI fallback
      secretlessConfigured = false;
      if (isText) process.stdout.write(dim('  Secretless module found but init not available\n'));
    }
  } catch {
    if (isText) {
      process.stdout.write(dim('  Secretless not installed (optional)\n'));
      process.stdout.write(dim('  Install: npm install -g secretless-ai\n'));
    }
  }
  steps.push({ name: 'Credential protection', status: secretlessConfigured ? 'done' : 'skipped' });
  if (isText) process.stdout.write('\n');

  // --- Step 4: Agent Identity (aim-core) ---
  if (isText) process.stdout.write(bold('Step 4: Agent Identity\n'));
  let identityCreated = false;
  let identityPublicKey: string | null = null;
  try {
    const aimCore = await import('@opena2a/aim-core');
    if (typeof aimCore.getOrCreateIdentity === 'function') {
      const identity = aimCore.getOrCreateIdentity({
        agentName: 'shield',
        dataDir: join(homedir(), '.opena2a', 'aim-core'),
      });
      identityCreated = true;
      if (identity && typeof identity === 'object' && 'publicKey' in identity) {
        const pk = String(identity.publicKey);
        identityPublicKey = pk.length > 16 ? pk.slice(0, 8) + '...' + pk.slice(-8) : pk;
      }
      if (isText) {
        process.stdout.write(green('  Local Ed25519 identity ready\n'));
        if (identityPublicKey) {
          process.stdout.write(`  Public key: ${identityPublicKey}\n`);
        }
        process.stdout.write(`  Storage: ~/.opena2a/aim-core/\n`);
      }
      // Log identity event
      if (typeof aimCore.logEvent === 'function') {
        aimCore.logEvent({
          type: 'shield.init',
          agent: 'shield',
          detail: { targetDir },
        });
      }
    } else if (typeof aimCore.createIdentity === 'function') {
      // Alternative API shape
      const identity = aimCore.createIdentity('shield');
      identityCreated = true;
      if (isText) {
        process.stdout.write(green('  Local Ed25519 identity created\n'));
        process.stdout.write(`  Storage: ~/.opena2a/aim-core/\n`);
      }
    } else {
      if (isText) process.stdout.write(dim('  aim-core module found but identity API not available\n'));
    }
  } catch {
    if (isText) {
      process.stdout.write(dim('  aim-core not installed (optional)\n'));
      process.stdout.write(dim('  Install: npm install @opena2a/aim-core\n'));
    }
  }
  steps.push({ name: 'Agent identity', status: identityCreated ? 'done' : 'skipped' });
  if (isText) process.stdout.write('\n');

  // --- Step 5: Config Integrity Baseline ---
  if (isText) process.stdout.write(bold('Step 5: Config Integrity Baseline\n'));
  let configSigningResult: { signed: number; files: string[] } | null = null;
  try {
    const { signConfigFilesSilent } = await import('../commands/guard.js');
    configSigningResult = await signConfigFilesSilent(targetDir);
    steps.push({ name: 'Config signing', status: 'done' });
    if (isText) {
      if (configSigningResult.signed > 0) {
        process.stdout.write(green(`  Signed ${configSigningResult.signed} config file${configSigningResult.signed === 1 ? '' : 's'} (${configSigningResult.files.join(', ')})\n`));
      } else {
        process.stdout.write(dim('  No config files found to sign\n'));
      }
    }
  } catch {
    steps.push({ name: 'Config signing', status: 'skipped' });
    if (isText) process.stdout.write(dim('  Config signing skipped\n'));
  }
  if (isText) process.stdout.write('\n');
  // --- Step 6: Generate Policy ---
  if (isText) process.stdout.write(bold('Step 6: Generate Policy\n'));

  const policy = generatePolicyFromScan(scan);
  const shieldDir = getShieldDir();
  const policyPath = join(shieldDir, SHIELD_POLICY_FILE);

  if (existsSync(policyPath) && !ci) {
    if (isText) {
      process.stdout.write(yellow('  Existing policy found. Preserving current policy.\n'));
      process.stdout.write(dim('  To regenerate: delete ~/.opena2a/shield/policy.yaml and re-run init\n'));
    }
  } else {
    savePolicy(policy, policyPath);
    recordPolicyHash(policyPath);
    if (isText) {
      process.stdout.write(green('  Policy generated (adaptive mode)\n'));
      process.stdout.write(`  Shield will learn agent behavior before suggesting rules.\n`);
      const denyProcs = policy.default.processes.deny;
      if (denyProcs.length > 0) {
        process.stdout.write(`  Recommended blocks: ${denyProcs.join(', ')}\n`);
      }
    }
  }
  steps.push({ name: 'Policy generation', status: 'done' });
  if (isText) process.stdout.write('\n');

  // --- Step 7: Shell Integration (opt-in via --shell-hook) ---
  if (isText) process.stdout.write(bold('Step 7: Shell Integration\n'));
  let shellHookInstalled = false;

  const shell = process.env.SHELL?.includes('zsh') ? 'zsh' as const
    : process.env.SHELL?.includes('bash') ? 'bash' as const
    : null;

  if (options.shellHook && shell && !ci) {
    const rcFile = shell === 'zsh'
      ? join(homedir(), '.zshrc')
      : join(homedir(), '.bashrc');

    let rcContent = '';
    if (existsSync(rcFile)) {
      try { rcContent = readFileSync(rcFile, 'utf-8'); } catch {
        if (isText) process.stdout.write(yellow('  Cannot read rc file, skipping shell hooks\n'));
        steps.push({ name: 'Shell integration', status: 'skipped' });
        if (isText) process.stdout.write('\n');
        rcContent = '';
      }
    }

    if (rcContent.includes('opena2a_shield_preexec') || rcContent.includes('opena2a_shield_debug')) {
      shellHookInstalled = true;
      if (isText) process.stdout.write(green('  Shell hooks already installed\n'));
    } else {
      const hookContent = getExpectedHookContent(shell);
      appendFileSync(rcFile, '\n' + hookContent + '\n', { mode: 0o600 });
      shellHookInstalled = true;
      if (isText) process.stdout.write(green(`  Shell hooks installed in ~/.${shell}rc\n`));
    }
  } else if (!options.shellHook) {
    if (isText) process.stdout.write(dim('  Skipped (opt-in: use --shell-hook to install)\n'));
  } else if (ci) {
    if (isText) process.stdout.write(dim('  Shell hooks skipped (CI mode)\n'));
  } else {
    if (isText) process.stdout.write(dim('  Shell not detected (zsh or bash required)\n'));
  }
  steps.push({ name: 'Shell integration', status: shellHookInstalled ? 'done' : 'skipped' });
  if (isText) process.stdout.write('\n');

  // --- Step 8: ARP Initialization ---
  if (isText) process.stdout.write(bold('Step 8: Runtime Protection\n'));
  let arpInitResult: { created: boolean; path: string; agentName?: string } | null = null;
  try {
    arpInitResult = await runtimeInitSilent(targetDir);
    steps.push({ name: 'ARP init', status: 'done' });
    if (isText) {
      if (arpInitResult.created) {
        process.stdout.write(green(`  ARP config created at ${arpInitResult.path}\n`));
      } else {
        process.stdout.write(dim(`  ARP config already exists at ${arpInitResult.path}\n`));
      }
    }
  } catch {
    steps.push({ name: 'ARP init', status: 'skipped' });
    if (isText) process.stdout.write(dim('  ARP initialization skipped\n'));
  }
  if (isText) process.stdout.write('\n');
  // --- Step 9: AI Tool Configuration (opt-in via --ai-tools) ---
  if (isText) process.stdout.write(bold('Step 9: AI Tool Configuration\n'));
  let aiToolsConfigured = false;
  let aiToolResult: AiToolConfigResult | null = null;

  if (options.aiTools && !ci) {
    const detectedAssistants = scan.assistants
      .filter((a: DetectedAssistant) => a.detected)
      .map((a: DetectedAssistant) => a.name);

    aiToolResult = configureAiTools(targetDir, detectedAssistants);
    aiToolsConfigured = aiToolResult.toolsConfigured.length > 0;

    if (isText) {
      if (aiToolResult.toolsConfigured.length > 0) {
        process.stdout.write(green(`  Configured: ${aiToolResult.toolsConfigured.join(', ')}\n`));
      }
      if (aiToolResult.toolsSkipped.length > 0) {
        process.stdout.write(dim(`  Skipped: ${aiToolResult.toolsSkipped.join(', ')}\n`));
      }
      if (aiToolResult.toolsConfigured.length === 0 && aiToolResult.toolsSkipped.length === 0) {
        process.stdout.write(dim('  No AI tools detected\n'));
      }
    }
  } else if (!options.aiTools) {
    if (isText) process.stdout.write(dim('  Skipped (opt-in: use --ai-tools to configure)\n'));
  } else {
    if (isText) process.stdout.write(dim('  AI tool configuration skipped (CI mode)\n'));
  }
  steps.push({ name: 'AI tool config', status: aiToolsConfigured ? 'done' : 'skipped' });
  if (isText) process.stdout.write('\n');

  // --- Step 10: Browser Guard ---
  if (isText) process.stdout.write(bold('Step 10: Browser Guard\n'));
  const hasBrowserGuard = existsSync(join(homedir(), '.config', 'opena2a', 'browser-guard.json')) ||
    existsSync(join(homedir(), '.opena2a', 'browser-guard.json'));
  if (hasBrowserGuard) {
    steps.push({ name: 'Browser Guard', status: 'done' });
    if (isText) process.stdout.write(green('  Browser Guard detected\n'));
  } else {
    steps.push({ name: 'Browser Guard', status: 'skipped' });
    if (isText) {
      process.stdout.write(dim('  Browser Guard not installed\n'));
      process.stdout.write(dim('  Browser session protection is optional.\n'));
    }
  }
  if (isText) process.stdout.write('\n');

  // --- Step 11: Summary ---
  // Save scan results
  const scanPath = join(shieldDir, SHIELD_SCAN_FILE);
  writeFileSync(scanPath, JSON.stringify(scan, null, 2) + '\n', { mode: 0o600 });

  // Sign all Shield artifacts (policy.yaml, scan.json, llm-cache.json)
  signAllArtifacts();

  // Write init event
  writeEvent({
    source: 'shield',
    category: 'shield.init',
    severity: 'info',
    agent: null,
    sessionId: null,
    action: 'shield.init',
    target: targetDir,
    outcome: 'allowed',
    detail: {
      clis: scan.clis.length,
      assistants: scan.assistants.filter((a: DetectedAssistant) => a.detected).length,
      mcpServers: scan.mcpServers.length,
      oauthSessions: scan.oauthSessions.filter((s: DetectedOAuthSession) => s.hasActiveSession).length,
      credentialFindings,
      shellHookInstalled,
      secretlessConfigured,
      identityCreated,
      aiToolsConfigured,
    },
    orgId: null,
    managed: false,
    agentId: null,
  });

  steps.push({ name: 'Summary', status: 'done' });

  if (isText) {
    process.stdout.write(bold('Step 11: Summary\n'));
    const doneCount = steps.filter(s => s.status === 'done').length;
    const warnCount = steps.filter(s => s.status === 'warn').length;
    const skippedCount = steps.filter(s => s.status === 'skipped').length;
    process.stdout.write(`  ${green(`${doneCount} steps completed`)}`);
    if (warnCount > 0) process.stdout.write(`, ${yellow(`${warnCount} warnings`)}`);
    if (skippedCount > 0) process.stdout.write(`, ${dim(`${skippedCount} skipped`)}`);
    process.stdout.write('\n');
    process.stdout.write(`  Policy: ${policyPath}\n`);
    process.stdout.write(`  Events: ${join(shieldDir, 'events.jsonl')}\n`);
    process.stdout.write('\n');
    process.stdout.write(cyan('  Shield is now in adaptive mode. It will learn your agent behavior\n'));
    process.stdout.write(cyan('  and suggest a policy once patterns stabilize.\n'));
    process.stdout.write('\n');
    process.stdout.write(dim('  View status:  opena2a shield status\n'));
    process.stdout.write(dim('  View events:  opena2a shield log\n'));
    process.stdout.write(dim('  Run check:    opena2a shield selfcheck\n'));
    process.stdout.write('\n');
  }

  const result: InitResult = {
    scan,
    policy,
    shellHookInstalled,
    policyPath,
    secretlessConfigured,
    identityCreated,
    aiToolsConfigured,
    configSigning: configSigningResult,
    arpInit: arpInitResult,
    steps,
  };

  if (format === 'json' || ci) {
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  }

  const hasFailure = credentialFindings > 0;
  return { exitCode: hasFailure ? 1 : 0, result };
}

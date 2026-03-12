/**
 * opena2a protect — Detect credentials and migrate to Secretless vault.
 *
 * Flow:
 * 1. Run HMA CRED + DRIFT checks on the target directory
 * 2. For each detected credential with a raw value:
 *    a. Store in Secretless SecretStore
 *    b. Replace in source file with environment variable reference
 *    c. Register broker policy (default: deny-all, must be explicitly allowed)
 *    d. Add to .env.example
 * 3. Re-run scan to verify clean
 * 4. Output migration report
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { bold, green, yellow, red, cyan, dim, gray, white } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';
import { severityLabel, formatDuration, table } from '../util/format.js';

// --- Types ---

interface MigrationResult {
  /** Credential that was migrated */
  credential: CredentialMatch;
  /** Whether the value was stored in Secretless vault */
  stored: boolean;
  /** Where the credential was actually stored */
  storageLocation?: 'vault' | 'shell-profile' | 'none';
  /** Whether the source file was updated */
  replaced: boolean;
  /** Whether a broker policy was created */
  policyCreated: boolean;
  /** Error message if migration failed */
  error?: string;
}

interface ProtectReport {
  /** Target directory */
  targetDir: string;
  /** Total credentials found */
  totalFound: number;
  /** Successfully migrated */
  migrated: number;
  /** Failed migrations */
  failed: number;
  /** Skipped (already using env vars, etc.) */
  skipped: number;
  /** Individual results */
  results: MigrationResult[];
  /** Whether verification scan passed */
  verificationPassed: boolean;
  /** Duration in milliseconds */
  durationMs: number;
  /** Liveness verification results for DRIFT findings (key value -> result) */
  livenessResults?: Record<string, LivenessResult>;
  /** AI tool config files updated with secretless instructions */
  aiToolsUpdated?: string[];
  /** Additional fixes applied beyond credential migration */
  additionalFixes?: AdditionalFixes;
  /** Security score before fixes */
  scoreBefore?: number;
  /** Security score after fixes */
  scoreAfter?: number;
}

interface AdditionalFixes {
  gitignoreFixed?: boolean;
  gitExclusionsAdded?: string[];
  configsSigned?: number;
  configsSignedFiles?: string[];
}

export interface ProtectOptions {
  /** Target directory to scan and protect */
  targetDir: string;
  /** Dry run mode (show what would change, don't modify) */
  dryRun?: boolean;
  /** Verbose output */
  verbose?: boolean;
  /** CI mode (no interactive prompts) */
  ci?: boolean;
  /** Output format */
  format?: 'text' | 'json';
  /** Skip verification re-scan */
  skipVerify?: boolean;
  /** Skip liveness verification for DRIFT findings (offline/CI) */
  skipLiveness?: boolean;
  /** Path to write interactive HTML report */
  report?: string;
  /** Skip config signing phase */
  skipSign?: boolean;
  /** Skip git hygiene fixes (.gitignore, .git/info/exclude) */
  skipGit?: boolean;
}

// --- Credential patterns (shared module) ---

import {
  CREDENTIAL_PATTERNS,
  SKIP_DIRS,
  SKIP_EXTENSIONS,
  walkFiles,
  type CredentialPattern,
  type CredentialMatch,
} from '../util/credential-patterns.js';
import {
  verifyDriftFindings,
  applyLivenessResults,
  type LivenessResult,
} from '../util/drift-verification.js';
import { scanMcpCredentials, scanAiConfigFiles } from '../util/ai-config.js';
import { calculateSecurityScore } from '../util/scoring.js';
import { runScoringChecks } from '../util/hygiene.js';

// --- Core logic ---

/**
 * Main protect command. Scans for credentials, migrates to vault, verifies clean.
 */
export async function protect(options: ProtectOptions): Promise<number> {
  const startTime = Date.now();
  const targetDir = path.resolve(options.targetDir);

  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Target directory not found: ${targetDir}\n`));
    return 1;
  }

  if (options.dryRun) {
    process.stderr.write(yellow('[DRY RUN] No files will be modified.\n\n'));
  }

  // Phase 1: Scan for credentials (source files + MCP configs)
  const spinner = new Spinner('Scanning for credentials...');
  spinner.start();

  let matches = scanForCredentials(targetDir);

  // Also scan MCP config files (skipped by walkFiles due to dot-file/JSON filtering)
  const mcpCreds = scanMcpCredentials(targetDir);
  const seenValues = new Set(matches.map(m => m.value));
  for (const mc of mcpCreds) {
    if (!seenValues.has(mc.value)) {
      matches.push(mc);
      seenValues.add(mc.value);
    }
  }

  spinner.stop();

  const isJson = options.format === 'json';

  // Snapshot the "before" score now, before any filesystem changes.
  // This ensures the score reflects the state init would have seen.
  let scoreBefore: number | undefined;
  try {
    const credsBySeverityBefore: Record<string, number> = {};
    for (const m of matches) {
      credsBySeverityBefore[m.severity] = (credsBySeverityBefore[m.severity] || 0) + 1;
    }
    const checksBefore = runScoringChecks(targetDir, matches.length);
    scoreBefore = calculateSecurityScore(credsBySeverityBefore, checksBefore).score;
  } catch {
    // best-effort
  }

  if (matches.length === 0) {
    if (!isJson) {
      process.stdout.write(green('No hardcoded credentials detected.\n'));
      process.stdout.write(dim('protect also applies git hygiene and config signing.\n'));
    }

    // Even without credentials, apply git hygiene and config signing fixes
    const noCredFixes: AdditionalFixes = {};
    let anyFix = false;

    if (!options.skipGit && !options.dryRun) {
      const gitignoreFixed = fixGitignore(targetDir, false);
      if (gitignoreFixed) {
        noCredFixes.gitignoreFixed = true;
        anyFix = true;
        if (!isJson) process.stdout.write(dim('Added .env exclusion to .gitignore\n'));
      }
      const exclusionsAdded = fixAiConfigExclusion(targetDir, false);
      if (exclusionsAdded.length > 0) {
        noCredFixes.gitExclusionsAdded = exclusionsAdded;
        anyFix = true;
        if (!isJson) process.stdout.write(dim(`Added ${exclusionsAdded.length} AI config file${exclusionsAdded.length === 1 ? '' : 's'} to .git/info/exclude\n`));
      }
    }

    if (!options.skipSign && !options.dryRun) {
      try {
        const { signConfigFilesSilent } = await import('./guard.js');
        const signResult = await signConfigFilesSilent(targetDir);
        if (signResult.signed > 0) {
          noCredFixes.configsSigned = signResult.signed;
          noCredFixes.configsSignedFiles = signResult.files;
          anyFix = true;
          if (!isJson) {
            process.stdout.write(green(`Signed ${signResult.signed} config file${signResult.signed === 1 ? '' : 's'}:\n`));
            for (const f of signResult.files) {
              process.stdout.write(`  ${dim(f)}\n`);
            }
            process.stdout.write(dim('After editing signed files: ') + 'opena2a guard resign\n');
            process.stdout.write(dim('To undo signing:           ') + 'rm .opena2a/guard/signatures.json\n');
          }
        }
      } catch {
        // best-effort
      }
    }

    if (isJson) {
      const report: ProtectReport = {
        targetDir,
        totalFound: 0,
        migrated: 0,
        failed: 0,
        skipped: 0,
        results: [],
        verificationPassed: true,
        durationMs: Date.now() - startTime,
        ...(anyFix ? { additionalFixes: noCredFixes } : {}),
      };
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    } else if (anyFix) {
      process.stdout.write(dim(`Completed in ${formatDuration(Date.now() - startTime)}\n`));
    }
    return 0;
  }

  // Phase 1.5: Liveness verification for DRIFT findings
  let livenessResults: Map<string, LivenessResult> | undefined;
  const hasDriftFindings = matches.some(m => m.findingId.startsWith('DRIFT-'));

  if (hasDriftFindings && !options.skipLiveness) {
    if (!isJson) {
      spinner.update('Verifying credential drift (liveness check)...');
      spinner.start();
    }

    livenessResults = await verifyDriftFindings(matches);
    matches = applyLivenessResults(matches, livenessResults);

    if (!isJson) {
      spinner.stop();
      process.stdout.write('\n' + bold('Drift Verification Results') + '\n');
      process.stdout.write(gray('-'.repeat(50)) + '\n');
      for (const [_key, result] of livenessResults) {
        if (result.live) {
          process.stdout.write(
            red(`${result.findingId}: DRIFT CONFIRMED`) +
            ' -- ' + white(result.detail) + '\n'
          );
          process.stdout.write(
            '  Severity escalated: ' + severityLabel('high') + ' -> ' + severityLabel('critical') + '\n\n'
          );
        } else if (result.checked && !result.error) {
          process.stdout.write(
            yellow(`${result.findingId}: `) + white(result.detail) + '\n\n'
          );
        } else if (result.error) {
          process.stdout.write(
            yellow(`${result.findingId}: `) + white(result.detail) + '\n\n'
          );
        }
      }
    }
  } else if (hasDriftFindings && options.skipLiveness && !isJson) {
    process.stdout.write(yellow('Liveness verification skipped (--skip-liveness)') + '\n\n');
  }

  if (!isJson) {
    process.stdout.write(bold(`Found ${matches.length} credential(s) in ${targetDir}\n\n`));

    // Show findings table
    const findingsRows = matches.map(m => [
      severityLabel(m.severity),
      m.findingId,
      m.title,
      path.relative(targetDir, m.filePath) + ':' + m.line,
      m.envVar,
    ]);
    process.stdout.write(table(findingsRows, ['Severity', 'ID', 'Type', 'Location', 'Env Var']) + '\n\n');

    // Show detailed explanations (non-CI only), deduplicated by finding type
    if (!options.ci) {
      const seenTypes = new Set<string>();
      for (const m of matches) {
        const key = m.findingId + ':' + m.title;
        if (seenTypes.has(key)) continue;
        seenTypes.add(key);
        const count = matches.filter(x => x.findingId === m.findingId && x.title === m.title).length;
        process.stdout.write(bold(`${m.findingId}: ${m.title}`) + (count > 1 ? dim(` (${count} instances)`) : '') + '\n');
        if (m.explanation) {
          process.stdout.write(dim('  Why: ') + m.explanation + '\n');
        }
        if (m.businessImpact) {
          process.stdout.write(dim('  Impact: ') + m.businessImpact + '\n');
        }
        process.stdout.write('\n');
      }
    }
  }

  if (options.dryRun) {
    if (isJson) {
      const report: ProtectReport = {
        targetDir,
        totalFound: matches.length,
        migrated: 0,
        failed: 0,
        skipped: matches.length,
        results: matches.map(m => ({
          credential: m,
          stored: false,
          replaced: false,
          policyCreated: false,
        })),
        verificationPassed: false,
        durationMs: Date.now() - startTime,
        ...(livenessResults ? { livenessResults: Object.fromEntries(livenessResults) } : {}),
      };
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    } else {
      process.stdout.write(yellow('[DRY RUN] Would migrate the above credentials.\n'));
      process.stdout.write(dim('Run without --dry-run to apply changes.\n'));
    }

    // Generate HTML report even in dry-run mode
    if (options.report) {
      await writeHtmlReport(options.report, targetDir, matches, isJson);
    }

    return 0;
  }

  // Confirm before making any changes (interactive mode only)
  if (!isJson && !options.ci) {
    let confirmed = false;
    try {
      const { confirm } = await import('@inquirer/prompts');
      confirmed = await confirm({
        message: `Migrate ${matches.length} credential${matches.length === 1 ? '' : 's'} to Secretless AI vault?`,
        default: true,
      });
    } catch {
      // Ctrl+C or non-interactive — treat as no
      process.stdout.write('\n');
      return 0;
    }
    if (!confirmed) {
      process.stdout.write(dim('No changes made. Run with --dry-run to preview.\n'));
      return 0;
    }
  }

  // Phase 2: Migrate credentials
  if (!isJson) {
    spinner.update('Migrating credentials to Secretless vault...');
    spinner.start();
  }

  const results = await migrateCredentials(matches, targetDir, options);
  if (!isJson) spinner.stop();

  const migrated = results.filter(r => r.stored && r.replaced).length;
  const failed = results.filter(r => r.error).length;
  const skipped = results.filter(r => !r.stored && !r.replaced && !r.error).length;

  // Phase 3: Update .env.example
  updateEnvExample(targetDir, results.filter(r => r.stored), isJson);

  // Phase 3.5: Update AI tool config files with secretless instructions
  let aiToolsUpdated: string[] | undefined;
  if (migrated > 0) {
    try {
      const { configureSecretlessForAiTools, buildConfigItem } = await import('../util/secretless-config.js');
      const configItems = results
        .filter(r => r.stored && r.replaced)
        .map(r => buildConfigItem(r.credential.envVar));
      if (configItems.length > 0) {
        const configResult = configureSecretlessForAiTools(targetDir, configItems);
        aiToolsUpdated = configResult.toolsUpdated;
        if (!isJson && configResult.toolsUpdated.length > 0) {
          process.stdout.write(green(`Updated AI tool configs: ${configResult.toolsUpdated.join(', ')}\n`));
        }
      }
    } catch {
      // AI config injection is best-effort -- don't block migration
    }
  }

  // Phase 4: Fix .gitignore (ENV-DOTENV finding)
  const additionalFixes: AdditionalFixes = {};
  if (!options.skipGit) {
    const gitignoreFixed = fixGitignore(targetDir, options.dryRun);
    if (gitignoreFixed) {
      additionalFixes.gitignoreFixed = true;
      if (!isJson) {
        process.stdout.write(dim('Added .env exclusion to .gitignore\n'));
      }
    }
  }

  // Phase 5: Fix AI config git exclusion (AI-CONFIG finding)
  if (!options.skipGit) {
    const exclusionsAdded = fixAiConfigExclusion(targetDir, options.dryRun);
    if (exclusionsAdded.length > 0) {
      additionalFixes.gitExclusionsAdded = exclusionsAdded;
      if (!isJson) {
        process.stdout.write(dim(`Added ${exclusionsAdded.length} AI config file${exclusionsAdded.length === 1 ? '' : 's'} to .git/info/exclude\n`));
      }
    }
  }

  // Phase 6: Config signing
  if (!options.skipSign && !options.dryRun) {
    try {
      const { signConfigFilesSilent } = await import('./guard.js');
      const signResult = await signConfigFilesSilent(targetDir);
      if (signResult.signed > 0) {
        additionalFixes.configsSigned = signResult.signed;
        additionalFixes.configsSignedFiles = signResult.files;
        if (!isJson) {
          process.stdout.write(green(`Signed ${signResult.signed} config file${signResult.signed === 1 ? '' : 's'}:\n`));
          for (const f of signResult.files) {
            process.stdout.write(`  ${dim(f)}\n`);
          }
          process.stdout.write(dim('After editing signed files: ') + 'opena2a guard resign\n');
          process.stdout.write(dim('To undo signing:           ') + 'rm .opena2a/guard/signatures.json\n');
        }
      }
    } catch {
      // Config signing is best-effort
    }
  }

  // Phase 7: After security score (before score was captured pre-migration)
  let scoreAfter: number | undefined;
  try {
    // After: credentials migrated (count = failed only), re-check hygiene
    const afterCredCount = failed;
    const afterCredsBySeverity: Record<string, number> = {};
    for (const r of results) {
      if (r.error) {
        const sev = r.credential.severity;
        afterCredsBySeverity[sev] = (afterCredsBySeverity[sev] || 0) + 1;
      }
    }
    const checksAfter = runScoringChecks(targetDir, afterCredCount);
    scoreAfter = calculateSecurityScore(afterCredsBySeverity, checksAfter).score;
  } catch {
    // Score calculation is best-effort
  }

  // Verification re-scan
  let verificationPassed = true;
  if (!options.skipVerify && migrated > 0) {
    if (!isJson) {
      spinner.update('Verifying migration...');
      spinner.start();
    }

    const remainingMatches = scanForCredentials(targetDir)
      .filter(m => {
        // Exclude .env files from verification -- credentials are supposed to be there
        const basename = path.basename(m.filePath);
        return !basename.startsWith('.env');
      });
    verificationPassed = remainingMatches.length === 0;

    if (!isJson) {
      spinner.stop();
      if (verificationPassed) {
        process.stdout.write(green('Verification passed: no credentials remain in source.\n\n'));
      } else {
        process.stdout.write(yellow(
          `Verification: ${remainingMatches.length} credential(s) still detected.\n` +
          'Some credentials may require manual migration.\n\n'
        ));
      }
    }
  }

  // Report
  const durationMs = Date.now() - startTime;
  // Convert liveness results map to plain object for JSON serialization
  let livenessRecord: Record<string, LivenessResult> | undefined;
  if (livenessResults && livenessResults.size > 0) {
    livenessRecord = {};
    for (const [key, val] of livenessResults) {
      livenessRecord[key] = val;
    }
  }

  const hasAdditionalFixes = additionalFixes.gitignoreFixed ||
    (additionalFixes.gitExclusionsAdded && additionalFixes.gitExclusionsAdded.length > 0) ||
    (additionalFixes.configsSigned && additionalFixes.configsSigned > 0);

  const report: ProtectReport = {
    targetDir,
    totalFound: matches.length,
    migrated,
    failed,
    skipped,
    results,
    verificationPassed,
    durationMs,
    livenessResults: livenessRecord,
    aiToolsUpdated,
    ...(hasAdditionalFixes ? { additionalFixes } : {}),
    ...(scoreBefore !== undefined ? { scoreBefore } : {}),
    ...(scoreAfter !== undefined ? { scoreAfter } : {}),
  };

  if (options.format === 'json') {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printReport(report);

    // Offer backend upgrade only if currently on local/keychain vault
    if (report.migrated > 0 && !options.ci) {
      try {
        // Read current backend -- skip upgrade offer if already on a team vault
        let currentBackend = 'local';
        try {
          const secretless = await (Function('return import("secretless-ai")')() as Promise<any>);
          const mod = 'default' in secretless ? secretless.default : secretless;
          currentBackend = mod.readBackendConfig?.() ?? mod.getBackend?.() ?? 'local';
        } catch {
          // secretless not available -- assume local
        }

        if (currentBackend === '1password' || currentBackend === 'vault' || currentBackend === 'gcp-sm') {
          // Already on a team vault -- skip the upgrade offer silently
        } else {
          const { select } = await import('@inquirer/prompts');
          process.stdout.write('\n' + bold('Where should credentials be stored?') + '\n');
          process.stdout.write(dim('Credentials are currently in the local Secretless vault (~/.secretless-ai/).') + '\n');
          process.stdout.write(dim('A vault backend keeps secrets encrypted and out of AI tool context.') + '\n\n');
          const backendChoice = await select({
            message: 'Choose a vault backend:',
            choices: [
              {
                name: 'OS Keychain            Encrypted by macOS/Windows, no extra tools needed',
                value: 'keychain',
                description: 'Best for solo developers. Uses macOS Keychain or Windows Credential Manager.',
              },
              {
                name: '1Password              Team sharing, Touch ID unlock, audit trails',
                value: '1password',
                description: 'Best for teams. Requires 1Password CLI (op). Setup: brew install 1password-cli',
              },
              {
                name: 'HashiCorp Vault         Self-hosted, fine-grained policies, dynamic secrets',
                value: 'vault',
                description: 'Best for enterprises. Requires a running Vault server. Setup: brew install vault',
              },
              {
                name: 'GCP Secret Manager      Cloud-native, IAM-integrated, auto-versioned',
                value: 'gcp-sm',
                description: 'Best for GCP users. Requires gcloud CLI or service account key.',
              },
              {
                name: 'Keep local vault        File-based, works offline, no setup required',
                value: 'local',
              },
            ],
          }).catch(() => 'local');

          if (backendChoice === 'keychain') {
            try {
              const secretless = await (Function('return import("secretless-ai")')() as Promise<any>);
              const mod = 'default' in secretless ? secretless.default : secretless;
              if (typeof mod.setBackend === 'function') {
                mod.setBackend('keychain');
                process.stdout.write(green('Vault backend set to OS Keychain.\n'));
                process.stdout.write(dim('Credentials will be encrypted by your OS. No extra setup needed.\n'));
              }
            } catch {
              process.stdout.write(yellow('To set up keychain backend: npx secretless-ai backend set keychain\n'));
            }
          }

          if (backendChoice === '1password') {
            const { offer1PasswordMigration } = await import('./onepassword-migration.js');
            await offer1PasswordMigration({ credentialCount: report.migrated, ci: options.ci });
          } else if (backendChoice === 'vault') {
            const { offerVaultMigration } = await import('./vault-migration.js');
            await offerVaultMigration({ credentialCount: report.migrated, ci: options.ci });
          } else if (backendChoice === 'gcp-sm') {
            const { offerGCPSMMigration } = await import('./gcp-sm-migration.js');
            await offerGCPSMMigration({ credentialCount: report.migrated, ci: options.ci });
          }
        }
      } catch {
        // Backend upgrade is optional -- skip silently on any error
      }
    }
  }

  // Generate interactive HTML report if --report path provided
  if (options.report) {
    await writeHtmlReport(options.report, targetDir, matches, isJson);
  }

  return failed > 0 ? 1 : 0;
}

// --- Scanning ---

function scanForCredentials(targetDir: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  const seen = new Set<string>(); // dedup by value+file

  walkFiles(targetDir, (filePath) => {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      return; // skip unreadable files
    }

    const lines = content.split('\n');

    for (const pattern of CREDENTIAL_PATTERNS) {
      // Reset regex lastIndex for global patterns
      pattern.pattern.lastIndex = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        let match: RegExpExecArray | null;

        // Clone regex to avoid shared state issues
        const re = new RegExp(pattern.pattern.source, pattern.pattern.flags);
        while ((match = re.exec(line)) !== null) {
          // For capture group patterns, use group 1; otherwise full match
          const value = match[1] ?? match[0];
          const dedupKey = `${value}:${filePath}`;

          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          // Skip if it looks like an env var reference already
          if (isEnvVarReference(line, match.index)) continue;

          const envVar = deriveEnvVarName(pattern, filePath, matches);

          matches.push({
            value,
            filePath,
            line: i + 1,
            findingId: pattern.id,
            envVar,
            severity: pattern.severity,
            title: pattern.title,
            explanation: pattern.explanation,
            businessImpact: pattern.businessImpact,
          });
        }
      }
    }
  });

  return matches;
}

function isEnvVarReference(line: string, matchIndex: number): boolean {
  // Check if the match is inside process.env.X, ${X}, $X, os.environ, etc.
  const before = line.slice(0, matchIndex);
  return /process\.env\.\w*$/.test(before) ||
    /\$\{?\w*$/.test(before) ||
    /os\.environ\[['"]?\w*$/.test(before) ||
    /getenv\(['"]?\w*$/.test(before);
}

function deriveEnvVarName(
  pattern: CredentialPattern,
  _filePath: string,
  existingMatches: CredentialMatch[]
): string {
  const base = pattern.envVarPrefix;
  const existing = existingMatches.filter(m => m.envVar.startsWith(base));

  if (existing.length === 0) return base;
  // If the same prefix already exists, append a number
  return `${base}_${existing.length + 1}`;
}

// --- Migration ---

async function migrateCredentials(
  matches: CredentialMatch[],
  targetDir: string,
  options: ProtectOptions
): Promise<MigrationResult[]> {
  const results: MigrationResult[] = [];

  for (const credential of matches) {
    try {
      // Step 1: Store in Secretless vault
      const vaultResult = await storeInVault(credential);

      // Step 2: Replace in source file (only if stored somewhere)
      const replaced = vaultResult.stored ? replaceInSource(credential) : false;

      // Step 3: Create broker policy
      const policyCreated = vaultResult.stored ? createBrokerPolicy(credential, targetDir) : false;

      results.push({
        credential,
        stored: vaultResult.stored,
        storageLocation: vaultResult.location,
        replaced,
        policyCreated,
      });

      if (options.verbose) {
        const status = vaultResult.stored && replaced ? green('[OK]') : yellow('[PARTIAL]');
        process.stdout.write(`${status} ${credential.envVar} <- ${path.relative(targetDir, credential.filePath)}:${credential.line}\n`);
      }
    } catch (err) {
      results.push({
        credential,
        stored: false,
        replaced: false,
        policyCreated: false,
        error: err instanceof Error ? err.message : String(err),
      });

      if (options.verbose) {
        process.stderr.write(red(`[FAIL] ${credential.envVar}: ${err instanceof Error ? err.message : String(err)}\n`));
      }
    }
  }

  return results;
}

/**
 * Store a credential value in the Secretless SecretStore.
 * Uses dynamic import to avoid hard dependency on secretless-ai.
 *
 * IMPORTANT: Never silently fall back to .env files. AI coding tools
 * can read .env files, so storing credentials there defeats the purpose.
 * If SecretStore is unavailable, store in shell profile (export statements)
 * which are loaded at shell startup but not read by AI tools.
 */
async function storeInVault(credential: CredentialMatch): Promise<{ stored: boolean; location: 'vault' | 'shell-profile' | 'none' }> {
  try {
    // Dynamic import -- secretless-ai may not be installed
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    const secretless = await (Function('return import("secretless-ai")')() as Promise<any>);
    const mod = 'default' in secretless ? secretless.default : secretless;

    // Pre-flight check: if backend is 1password, verify `op` CLI is installed
    const backend = mod.readBackendConfig?.() ?? 'local';
    if (backend === '1password') {
      try {
        const { execFileSync } = await import('node:child_process');
        execFileSync('op', ['--version'], { stdio: 'pipe' });
      } catch {
        process.stderr.write(yellow(
          `\nVault backend is set to 1Password, but the 1Password CLI (op) is not installed.\n` +
          `Credentials cannot be stored until this is resolved.\n\n` +
          `To install the 1Password CLI:\n` +
          `  brew install 1password-cli\n\n` +
          `Or switch to a backend that works now:\n` +
          `  npx secretless-ai backend set keychain    Uses macOS Keychain (no extra tools)\n` +
          `  npx secretless-ai backend set local        File-based vault (~/.secretless-ai/)\n\n`
        ));
        return { stored: false, location: 'none' };
      }
    }

    const { SecretStore } = mod;
    const store = new SecretStore();
    await store.setSecret(credential.envVar, credential.value);
    return { stored: true, location: 'vault' };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);

    // Surface the actual error so users know WHY it failed
    if (message.includes('ENOENT')) {
      // Missing CLI binary (op, vault, etc.)
      process.stderr.write(yellow(
        `\nFailed to store ${credential.envVar}: vault CLI tool not found.\n` +
        `Check your vault backend: npx secretless-ai backend\n` +
        `Switch to keychain:       npx secretless-ai backend set keychain\n\n`
      ));
    } else if (message.includes('Cannot find module') || message.includes('ERR_MODULE_NOT_FOUND')) {
      process.stderr.write(yellow(
        `\nSecretless AI is not installed. Credentials will be stored in shell profile.\n` +
        `For vault storage: npm install -g secretless-ai && npx secretless-ai init\n\n`
      ));
    } else {
      process.stderr.write(yellow(
        `\nFailed to store ${credential.envVar} in vault: ${message}\n` +
        `Check backend status: npx secretless-ai backend\n\n`
      ));
    }

    // Secretless not available -- store in shell profile as env export.
    // .env files are NOT safe because AI coding tools read them.
    const shellResult = storeInShellProfile(credential);
    return { stored: shellResult, location: shellResult ? 'shell-profile' : 'none' };
  }
}

/**
 * Fallback: add credential as an export in the user's shell profile.
 * Shell profile (~/.zshrc, ~/.bashrc) is loaded at shell startup and
 * makes the variable available via process.env, but AI coding tools
 * do not read shell profiles (unlike .env files which they actively scan).
 */
function storeInShellProfile(credential: CredentialMatch): boolean {
  const home = process.env.HOME ?? process.env.USERPROFILE;
  if (!home) return false;

  // Detect shell profile
  const shell = process.env.SHELL ?? '';
  let profilePath: string;
  if (shell.includes('zsh')) {
    profilePath = path.join(home, '.zshrc');
  } else {
    profilePath = path.join(home, '.bashrc');
  }

  try {
    let content = '';
    if (fs.existsSync(profilePath)) {
      content = fs.readFileSync(profilePath, 'utf-8');
      // Don't add if already present
      if (content.includes(`export ${credential.envVar}=`)) return true;
      if (!content.endsWith('\n')) content += '\n';
    }

    content += `\n# Added by opena2a protect (migrate to a vault for better security: npx secretless-ai backend set keychain)\n`;
    content += `export ${credential.envVar}="${credential.value}"\n`;

    fs.writeFileSync(profilePath, content, { encoding: 'utf-8', mode: 0o600 });

    process.stderr.write(yellow(
      `Secretless vault not available. Stored ${credential.envVar} in ${path.basename(profilePath)} instead.\n` +
      `For better security, install a vault backend:\n` +
      `  npx secretless-ai backend set keychain    OS keychain (recommended for solo devs)\n` +
      `  npx secretless-ai backend set 1password    1Password (recommended for teams)\n\n`
    ));
    return true;
  } catch {
    return false;
  }
}

/**
 * Replace the hardcoded credential in the source file with an environment variable reference.
 *
 * For programming languages (JS, Python, Go, etc.), the credential is typically
 * inside quotes: `apiKey: "sk-ant-..."`. We must strip those quotes so the result
 * is `apiKey: process.env.ANTHROPIC_API_KEY` (code expression) rather than
 * `apiKey: "process.env.ANTHROPIC_API_KEY"` (string literal, broken at runtime).
 */
function replaceInSource(credential: CredentialMatch): boolean {
  const content = fs.readFileSync(credential.filePath, 'utf-8');
  const ext = path.extname(credential.filePath).toLowerCase();

  // Build the replacement string based on file type
  const replacement = getEnvVarReplacement(credential.envVar, ext, content, credential.value);

  if (!replacement) return false;

  let newContent: string;

  if (shouldStripQuotes(ext)) {
    // For programming languages, replace the entire quoted expression
    // (including surrounding quotes) with the bare env var reference.
    // Use regex to find the enclosing quoted string so we handle cases
    // where the matched credential is a substring of the quoted content
    // (e.g., regex matches 20-char AWS key but string has trailing chars).
    const escVal = credential.value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const dblQuoteRegex = new RegExp(`"[^"]*${escVal}[^"]*"`);
    const sglQuoteRegex = new RegExp(`'[^']*${escVal}[^']*'`);

    const dblMatch = content.match(dblQuoteRegex);
    const sglMatch = content.match(sglQuoteRegex);

    if (dblMatch) {
      newContent = content.replace(dblMatch[0], replacement);
    } else if (sglMatch) {
      newContent = content.replace(sglMatch[0], replacement);
    } else {
      // No enclosing quotes found (e.g., template literal or unquoted)
      newContent = content.replace(credential.value, replacement);
    }
  } else {
    // For config files (YAML, JSON, .env, etc.), replace value inside quotes
    newContent = content.replace(credential.value, replacement);
  }

  if (newContent === content) return false; // nothing changed

  fs.writeFileSync(credential.filePath, newContent, 'utf-8');
  return true;
}

/**
 * Programming languages where env var references must NOT be inside string quotes.
 */
function shouldStripQuotes(ext: string): boolean {
  return ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.py', '.go', '.rb', '.java', '.kt', '.rs'].includes(ext);
}

/**
 * Generate the appropriate env var reference for the file type.
 */
function getEnvVarReplacement(envVar: string, ext: string, content: string, _original: string): string | null {
  // Detect language/framework from file extension and content
  switch (ext) {
    case '.ts':
    case '.tsx':
    case '.js':
    case '.jsx':
    case '.mjs':
    case '.cjs':
      return `process.env.${envVar}`;

    case '.py':
      return `os.environ.get('${envVar}')`;

    case '.go':
      return `os.Getenv("${envVar}")`;

    case '.rb':
      return `ENV['${envVar}']`;

    case '.java':
    case '.kt':
      return `System.getenv("${envVar}")`;

    case '.rs':
      return `std::env::var("${envVar}").unwrap_or_default()`;

    case '.yaml':
    case '.yml':
      return `\${${envVar}}`;

    case '.toml':
    case '.ini':
    case '.cfg':
    case '.conf':
      return `\${${envVar}}`;

    case '.env':
    case '.sh':
    case '.bash':
    case '.zsh':
      return `$${envVar}`;

    case '.json':
      // JSON doesn't support env var references natively.
      // Replace with a placeholder that frameworks commonly understand.
      return `\${${envVar}}`;

    case '.dockerfile':
      return `$${envVar}`;

    default:
      // For Dockerfiles without extension
      if (content.includes('FROM ') || content.includes('RUN ')) {
        return `$${envVar}`;
      }
      // Default to shell-style
      return `\${${envVar}}`;
  }
}

/**
 * Create a deny-all broker policy for this credential.
 * The user must explicitly add allow rules.
 */
function createBrokerPolicy(credential: CredentialMatch, targetDir: string): boolean {
  const policyDir = path.join(
    process.env.HOME ?? process.env.USERPROFILE ?? '.',
    '.secretless-ai'
  );

  try {
    if (!fs.existsSync(policyDir)) {
      fs.mkdirSync(policyDir, { recursive: true, mode: 0o700 });
    }

    const policyFile = path.join(policyDir, 'broker-policies.json');
    let policies: any[] = [];

    if (fs.existsSync(policyFile)) {
      try {
        const raw = fs.readFileSync(policyFile, 'utf-8');
        const parsed = JSON.parse(raw);
        policies = Array.isArray(parsed) ? parsed : parsed.rules ?? [];
      } catch {
        // Corrupted file, start fresh
        policies = [];
      }
    }

    // Check if policy for this credential already exists
    const existingPolicy = policies.find(
      (p: any) => p.credentialSelector === credential.envVar
    );
    if (existingPolicy) return true;

    // Add deny-all policy for this credential
    const projectName = path.basename(targetDir);
    policies.push({
      id: `protect-${credential.envVar.toLowerCase()}-${Date.now()}`,
      agentSelector: '*',
      credentialSelector: credential.envVar,
      constraints: {},
      effect: 'deny' as const,
      comment: `Auto-generated by opena2a protect from ${projectName}. Add allow rules for authorized agents.`,
    });

    fs.writeFileSync(policyFile, JSON.stringify({ rules: policies }, null, 2) + '\n', { encoding: 'utf-8', mode: 0o600 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Update .env.example with the migrated variable names.
 */
function updateEnvExample(
  targetDir: string,
  migratedResults: MigrationResult[],
  quiet = false
): void {
  if (migratedResults.length === 0) return;

  const envExamplePath = path.join(targetDir, '.env.example');
  let content = '';

  if (fs.existsSync(envExamplePath)) {
    content = fs.readFileSync(envExamplePath, 'utf-8');
    if (!content.endsWith('\n')) content += '\n';
  }

  let added = 0;
  for (const result of migratedResults) {
    const envVar = result.credential.envVar;
    if (!content.includes(`${envVar}=`)) {
      content += `${envVar}=\n`;
      added++;
    }
  }

  if (added > 0) {
    fs.writeFileSync(envExamplePath, content, 'utf-8');
    if (!quiet) {
      process.stdout.write(green(`Updated .env.example with ${added} variable(s).\n`));
    }
  }
}

// --- Git hygiene fixes ---

/**
 * Ensure .gitignore contains .env exclusion.
 * Creates .gitignore if missing, appends if .env not already excluded.
 * Returns true if a change was made.
 */
function fixGitignore(targetDir: string, dryRun?: boolean): boolean {
  const gitignorePath = path.join(targetDir, '.gitignore');

  if (fs.existsSync(gitignorePath)) {
    const content = fs.readFileSync(gitignorePath, 'utf-8');
    if (content.includes('.env')) return false; // already present

    if (!dryRun) {
      const suffix = content.endsWith('\n') ? '' : '\n';
      fs.appendFileSync(gitignorePath, `${suffix}.env\n.env.*\n`);
    }
    return true;
  }

  // No .gitignore -- create one
  if (!dryRun) {
    fs.writeFileSync(gitignorePath, '.env\n.env.*\n', 'utf-8');
  }
  return true;
}

/**
 * Add unexcluded AI config files to .git/info/exclude.
 * Returns list of files added.
 */
function fixAiConfigExclusion(targetDir: string, dryRun?: boolean): string[] {
  const gitDir = path.join(targetDir, '.git');
  if (!fs.existsSync(gitDir)) return [];

  const finding = scanAiConfigFiles(targetDir);
  if (!finding || !finding.items || finding.items.length === 0) return [];

  if (dryRun) return finding.items;

  const excludeDir = path.join(gitDir, 'info');
  const excludePath = path.join(excludeDir, 'exclude');

  // Read existing content
  let content = '';
  if (fs.existsSync(excludePath)) {
    content = fs.readFileSync(excludePath, 'utf-8');
    if (!content.endsWith('\n')) content += '\n';
  } else {
    fs.mkdirSync(excludeDir, { recursive: true });
  }

  // Append missing entries
  const added: string[] = [];
  for (const file of finding.items) {
    if (!content.includes(file)) {
      content += `${file}\n`;
      added.push(file);
    }
  }

  if (added.length > 0) {
    fs.writeFileSync(excludePath, content, 'utf-8');
  }

  return added;
}

// --- Reporting ---

function printReport(report: ProtectReport): void {
  process.stdout.write('\n' + bold('Migration Report') + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');

  const rows: string[][] = [];

  for (const result of report.results) {
    let status: string;
    if (result.error) {
      status = red('FAILED');
    } else if (result.stored && result.replaced && result.storageLocation === 'vault') {
      status = green('VAULT');
    } else if (result.stored && result.replaced && result.storageLocation === 'shell-profile') {
      status = yellow('SHELL PROFILE');
    } else if (result.stored && result.replaced) {
      status = green('MIGRATED');
    } else {
      status = yellow('PARTIAL');
    }

    rows.push([
      status,
      result.credential.findingId,
      result.credential.envVar,
      path.relative(report.targetDir, result.credential.filePath) + ':' + result.credential.line,
    ]);

    if (result.error) {
      process.stdout.write(dim(`  Error: ${result.error}\n`));
    }
  }

  process.stdout.write(table(rows, ['Stored In', 'Finding', 'Env Var', 'Source']) + '\n\n');

  // Warn if any credentials ended up in shell profile instead of vault
  const shellProfileResults = report.results.filter(r => r.storageLocation === 'shell-profile');
  if (shellProfileResults.length > 0) {
    process.stdout.write(yellow(
      `${shellProfileResults.length} credential(s) stored in shell profile (fallback).\n` +
      `For better security, set up a vault backend and re-run protect:\n` +
      `  npx secretless-ai backend set keychain\n` +
      `  npx opena2a-cli protect\n\n`
    ));
  }

  // Summary
  process.stdout.write(bold('Summary: '));
  const parts: string[] = [];
  if (report.migrated > 0) parts.push(green(`${report.migrated} migrated`));
  if (report.skipped > 0) parts.push(yellow(`${report.skipped} skipped`));
  if (report.failed > 0) parts.push(red(`${report.failed} failed`));
  process.stdout.write(parts.join(', ') + '\n');

  process.stdout.write(dim(`Completed in ${formatDuration(report.durationMs)}\n`));

  // Additional fixes
  const af = report.additionalFixes;
  if (af && (af.gitignoreFixed || af.gitExclusionsAdded?.length || af.configsSigned)) {
    process.stdout.write('\n' + bold('Additional fixes applied:') + '\n');
    if (af.gitignoreFixed) {
      process.stdout.write(`  ${dim('.gitignore')}       ${green('Added .env exclusion')}\n`);
    }
    if (af.gitExclusionsAdded && af.gitExclusionsAdded.length > 0) {
      process.stdout.write(`  ${dim('Git exclusions')}   ${green(`Added ${af.gitExclusionsAdded.join(', ')} to .git/info/exclude`)}\n`);
    }
    if (report.aiToolsUpdated && report.aiToolsUpdated.length > 0) {
      process.stdout.write(`  ${dim('AI tool configs')}  ${green(`Updated ${report.aiToolsUpdated.join(', ')}`)}\n`);
    }
    if (af.configsSigned && af.configsSigned > 0) {
      const fileList = af.configsSignedFiles?.join(', ') ?? `${af.configsSigned} file${af.configsSigned === 1 ? '' : 's'}`;
      process.stdout.write(`  ${dim('Config signing')}   ${green(`Signed: ${fileList}`)}\n`);
      process.stdout.write(`  ${dim('                 After editing: ')}opena2a guard resign\n`);
      process.stdout.write(`  ${dim('                 To undo:       ')}rm .opena2a/guard/signatures.json\n`);
    }
  }

  // Before/after score
  if (report.scoreBefore !== undefined && report.scoreAfter !== undefined && report.scoreAfter !== report.scoreBefore) {
    const delta = report.scoreAfter - report.scoreBefore;
    const scoreColor = report.scoreAfter >= 80 ? green
      : report.scoreAfter >= 60 ? yellow
      : red;
    process.stdout.write('\n' + bold('Security Score: ') + `${report.scoreBefore} ${dim('->')} ${scoreColor(String(report.scoreAfter))}  ${green(`(+${delta})`)}\n`);
  } else if (report.scoreAfter !== undefined) {
    const scoreColor = report.scoreAfter >= 80 ? green
      : report.scoreAfter >= 60 ? yellow
      : red;
    process.stdout.write('\n' + bold('Security Score: ') + scoreColor(String(report.scoreAfter)) + dim(' / 100') + '\n');
  }

  if (report.migrated > 0 || (af && (af.gitignoreFixed || af.gitExclusionsAdded?.length || af.configsSigned))) {
    process.stdout.write('\n' + cyan('Next steps:') + '\n');
    process.stdout.write('  1. Review changes: ' + dim('git diff') + '\n');
    process.stdout.write('  2. Configure broker allow rules: ' + dim('~/.secretless-ai/broker-policies.json') + '\n');
    process.stdout.write('  3. Re-assess posture: ' + dim('opena2a init') + '\n');
    process.stdout.write('\n' + dim('Rollback:') + '\n');
    if (report.migrated > 0) {
      process.stdout.write(dim('  git checkout -- <files>    Restore original files (credentials re-appear in source)') + '\n');
    }
    if (af?.configsSigned) {
      process.stdout.write(dim('  rm .opena2a/guard/signatures.json   Remove config signatures') + '\n');
    }
    if (af?.gitignoreFixed) {
      process.stdout.write(dim('  git checkout -- .gitignore          Restore original .gitignore') + '\n');
    }
    process.stdout.write('\n' + dim('Continue hardening:') + '\n');
    process.stdout.write(dim('  opena2a runtime start     Enable runtime monitoring') + '\n');
  }
}

// --- Utilities ---

async function writeHtmlReport(
  reportPath: string,
  targetDir: string,
  matches: CredentialMatch[],
  quiet: boolean
): Promise<void> {
  try {
    const { generateInteractiveHtml } = await import('../report/interactive-html.js');
    const reportData = {
      metadata: {
        generatedAt: new Date().toISOString(),
        toolVersion: '0.1.0',
        targetName: path.basename(targetDir),
        scanType: 'protect',
      },
      summary: {
        totalFindings: matches.length,
        bySeverity: countBySeverity(matches),
        score: calculateScore(matches),
      },
      findings: matches.map(m => ({
        id: m.findingId,
        severity: m.severity as 'critical' | 'high' | 'medium' | 'low' | 'info',
        title: m.title,
        description: `Hardcoded ${m.title} found in source code.`,
        explanation: m.explanation,
        businessImpact: m.businessImpact,
        category: m.findingId.startsWith('DRIFT') ? 'Scope Drift' : 'Credential Exposure',
        file: path.relative(targetDir, m.filePath),
        line: m.line,
        fix: `Replace with environment variable: ${m.envVar}`,
        passed: false,
      })),
    };
    const html = generateInteractiveHtml(reportData);
    fs.writeFileSync(reportPath, html, 'utf-8');
    if (!quiet) {
      process.stdout.write(green(`\nHTML report written to ${reportPath}\n`));
    }
  } catch (err) {
    process.stderr.write(red(`Failed to generate HTML report: ${err instanceof Error ? err.message : String(err)}\n`));
  }
}

function countBySeverity(matches: CredentialMatch[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const m of matches) {
    counts[m.severity] = (counts[m.severity] || 0) + 1;
  }
  return counts;
}

function calculateScore(matches: CredentialMatch[]): number {
  if (matches.length === 0) return 100;
  const weights: Record<string, number> = { critical: 25, high: 15, medium: 8, low: 3, info: 1 };
  let penalty = 0;
  for (const m of matches) {
    penalty += weights[m.severity] || 5;
  }
  return Math.max(0, 100 - penalty);
}

function findProjectRoot(startPath: string): string | null {
  let dir = path.dirname(startPath);
  const root = path.parse(dir).root;

  while (dir !== root) {
    if (
      fs.existsSync(path.join(dir, 'package.json')) ||
      fs.existsSync(path.join(dir, 'go.mod')) ||
      fs.existsSync(path.join(dir, 'Cargo.toml')) ||
      fs.existsSync(path.join(dir, 'pyproject.toml')) ||
      fs.existsSync(path.join(dir, 'setup.py')) ||
      fs.existsSync(path.join(dir, '.git'))
    ) {
      return dir;
    }
    dir = path.dirname(dir);
  }

  return null;
}

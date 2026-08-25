/**
 * opena2a guard -- ConfigGuard: config file integrity signing and verification.
 *
 * Subcommands:
 * - sign:    Hash all detected config files, store in signatures.json
 * - verify:  Check all signed files for tampering (hash mismatch)
 * - status:  Summary of signed, unsigned, and tampered files
 * - watch:   Monitor signed files for changes in real-time
 * - diff:     Show detailed changes between current files and signed baseline
 * - policy:   Manage guard policy (signing requirements, heartbeat disable)
 * - hook:     Install/uninstall git pre-commit hook for automatic verification
 * - resign:   Re-sign modified files after confirming changes are intentional
 * - snapshot: Create, list, or restore timestamped signature snapshots
 */

import * as fs from 'node:fs';
import { execFileSync } from 'node:child_process';
import { signedByLabel } from '../util/signed-by.js';
import * as os from 'node:os';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { bold, green, yellow, red, dim, gray, cyan } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';

// --- Types ---

export interface GuardOptions {
  subcommand: 'sign' | 'verify' | 'status' | 'watch' | 'diff' | 'policy' | 'hook' | 'resign' | 'snapshot' | 'harden';
  files?: string[];
  targetDir?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
  enforce?: boolean;
  skills?: boolean;
  heartbeats?: boolean;
  fix?: boolean;
  dryRun?: boolean;
  args?: string[];
}

interface ConfigSignature {
  filePath: string;
  hash: string;
  signedAt: string;
  signedBy: string;
  fileSize: number;
}

interface SignatureStore {
  version: 1;
  signatures: ConfigSignature[];
  updatedAt: string;
}

export interface GuardResult {
  filePath: string;
  status: 'pass' | 'tampered' | 'unsigned' | 'missing';
  currentHash?: string;
  expectedHash?: string;
  diff?: FileDiff;
}

interface FileDiff {
  type: 'json' | 'text';
  sizeChange: number;
  added?: string[];
  removed?: string[];
  modified?: string[];
}

export interface GuardReport {
  subcommand: string;
  directory: string;
  results: GuardResult[];
  passed: number;
  tampered: number;
  unsigned: number;
  missing: number;
  totalSigned: number;
}

export interface ConfigIntegritySummary {
  filesMonitored: number;
  tamperedFiles: string[];
  signatureStatus: 'valid' | 'tampered' | 'unsigned';
}

// --- Default guarded files ---

const GUARD_FILES = [
  'mcp.json', '.mcp.json', '.mcp/config.json', '.claude/settings.json',
  'package.json', 'package-lock.json',
  'arp.yaml', 'arp.yml', 'arp.json',
  'openclaw.json', '.openclaw/config.json',
  '.opena2a.yaml', '.opena2a.json',
  'tsconfig.json', 'go.mod', 'go.sum',
  'pyproject.toml', 'requirements.txt',
  'Dockerfile', 'docker-compose.yml',
];

interface SkippedFile { filePath: string; reason: 'gitIgnored'; rule: string }

const STORE_DIR = '.opena2a/guard';
const STORE_FILE = 'signatures.json';
const EXIT_QUARANTINE = 3;

// --- Event emission ---

async function emitEvent(
  category: string, action: string, target: string,
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical',
  outcome: 'allowed' | 'blocked' | 'monitored',
  detail: Record<string, unknown>,
): Promise<void> {
  try {
    const { writeEvent } = await import('../shield/events.js');
    writeEvent({
      source: 'configguard', category, severity,
      agent: null, sessionId: null, action, target, outcome, detail,
      orgId: null, managed: false, agentId: null,
    });
  } catch {
    // Shield module not available
  }
}

// --- Core ---

export async function guard(options: GuardOptions): Promise<number> {
  const targetDir = path.resolve(options.targetDir ?? process.cwd());
  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Directory not found: ${targetDir}\n`));
    return 1;
  }

  switch (options.subcommand) {
    case 'sign': return guardSign(targetDir, options);
    case 'verify': return guardVerify(targetDir, options);
    case 'status': return guardStatus(targetDir, options);
    case 'watch': return guardWatch(targetDir, options);
    case 'diff': return guardDiff(targetDir, options);
    case 'policy': {
      const { guardPolicy } = await import('./guard-policy.js');
      const action = options.args?.[0] ?? 'show';
      return guardPolicy(targetDir, action, { format: options.format });
    }
    case 'hook': {
      const { guardHook } = await import('./guard-hooks.js');
      const action = options.args?.[0] ?? '';
      return guardHook(action, targetDir);
    }
    case 'resign': {
      const { guardResign: resign } = await import('./guard-snapshots.js');
      return resign(targetDir, options);
    }
    case 'snapshot': {
      const { guardSnapshot: snapshot } = await import('./guard-snapshots.js');
      return snapshot(targetDir, options);
    }
    case 'harden': {
      const { guardHarden } = await import('./guard-harden.js');
      return guardHarden(targetDir, {
        skills: options.skills,
        heartbeats: options.heartbeats,
        fix: options.fix,
        dryRun: options.dryRun,
        verbose: options.verbose,
        ci: options.ci,
        format: options.format,
      });
    }
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n\n`));
      process.stderr.write('Usage: opena2a guard <subcommand> [directory]\n\n');
      process.stderr.write('Subcommands:\n');
      process.stderr.write('  sign       Sign config files for integrity verification\n');
      process.stderr.write('  verify     Verify config file signatures\n');
      process.stderr.write('  status     Show current guard status\n');
      process.stderr.write('  watch      Watch for config file changes\n');
      process.stderr.write('  diff       Show changes since last signing\n');
      process.stderr.write('  policy     Manage guard policies\n');
      process.stderr.write('  hook       Install/manage git hooks\n');
      process.stderr.write('  resign     Re-sign after intentional changes\n');
      process.stderr.write('  snapshot   Take a config snapshot\n');
      process.stderr.write('  harden     Auto-fix config security issues\n');
      return 1;
  }
}

// --- Sign ---

async function guardSign(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const spinner = new Spinner('Signing config files...');
  if (!isJson) spinner.start();

  const usingCustomFiles = !!(options.files && options.files.length > 0);
  const defaultResolution = usingCustomFiles ? null : resolveDefaultFiles(targetDir);
  const filesToSign = usingCustomFiles ? resolveFiles(targetDir, options.files) : (defaultResolution?.files ?? []);
  const skipped: SkippedFile[] = defaultResolution?.skipped ?? [];
  // An explicit path is signed even when ignored, but the cost is stated.
  const explicitIgnored = usingCustomFiles ? gitIgnoredPaths(targetDir, filesToSign) : new Map<string, string>();
  const signatures: ConfigSignature[] = [];

  for (const relPath of filesToSign) {
    const fullPath = path.join(targetDir, relPath);
    if (!fs.existsSync(fullPath)) continue;
    const content = fs.readFileSync(fullPath);
    const hash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    const stat = fs.statSync(fullPath);
    signatures.push({ filePath: relPath, hash, signedAt: new Date().toISOString(), signedBy: signedByLabel(), fileSize: stat.size });
  }

  if (!isJson) spinner.stop();

  if (signatures.length === 0 && !options.skills && !options.heartbeats) {
    if (isJson) { process.stdout.write(JSON.stringify({ signed: 0, files: [], skipped }, null, 2) + '\n'); }
    else {
      process.stdout.write(yellow('No config files found to sign.\n'));
      process.stdout.write(dim('Guard signs: package.json, mcp.json, arp.yaml, tsconfig.json, Dockerfile, etc.\n'));
      printSkippedFiles(skipped);
    }
    return 0;
  }

  if (signatures.length > 0) {
    const store: SignatureStore = { version: 1, signatures, updatedAt: new Date().toISOString() };
    const storeDir = path.join(targetDir, STORE_DIR);
    fs.mkdirSync(storeDir, { recursive: true });
    fs.writeFileSync(path.join(storeDir, STORE_FILE), JSON.stringify(store, null, 2) + '\n', 'utf-8');

    await emitEvent('config.signed', 'guard.sign', targetDir, 'info', 'allowed', {
      fileCount: signatures.length, files: signatures.map(s => s.filePath),
    });
  }

  // Skill and heartbeat signing (delegated to guard-signing bridge)
  type SignResult = Awaited<ReturnType<typeof import('./guard-signing.js').signSkillFiles>>;
  let skillResults: SignResult = [];
  let heartbeatResults: SignResult = [];
  if (options.skills || options.heartbeats) {
    const { signSkillFiles, signHeartbeatFiles } = await import('./guard-signing.js');
    if (options.skills) skillResults = await signSkillFiles(targetDir);
    if (options.heartbeats) heartbeatResults = await signHeartbeatFiles(targetDir);
  }

  if (isJson) {
    const result: Record<string, unknown> = { signed: signatures.length, files: signatures.map(s => s.filePath), skipped };
    if (skillResults.length > 0) result.skills = skillResults.map(s => s.filePath);
    if (heartbeatResults.length > 0) result.heartbeats = heartbeatResults.map(s => s.filePath);
    process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  } else {
    if (signatures.length > 0) {
      process.stdout.write(green(`Signed ${signatures.length} config file${signatures.length === 1 ? '' : 's'}.\n`));
      for (const sig of signatures) { process.stdout.write(dim(`  ${sig.filePath}  ${sig.hash.slice(0, 23)}...\n`)); }
    }
    printSkippedFiles(skipped);
    for (const [ignoredPath, rule] of explicitIgnored) {
      process.stdout.write(yellow(`Note: ${ignoredPath} is git-ignored here (${rule}); a committed store that lists it reports missing in every other checkout.\n`));
    }
    if (signatures.length > 0) {
      process.stdout.write(dim(`Run \`opena2a guard resign\` again after editing signed files.\n`));
    }
    if (skillResults.length > 0) {
      process.stdout.write(green(`Signed ${skillResults.length} skill file${skillResults.length === 1 ? '' : 's'}.\n`));
      for (const sr of skillResults) { process.stdout.write(dim(`  ${sr.filePath}  ${sr.hash.slice(0, 23)}...\n`)); }
    }
    if (heartbeatResults.length > 0) {
      process.stdout.write(green(`Signed ${heartbeatResults.length} heartbeat file${heartbeatResults.length === 1 ? '' : 's'}.\n`));
      for (const hr of heartbeatResults) { process.stdout.write(dim(`  ${hr.filePath}  ${hr.hash.slice(0, 23)}...\n`)); }
    }
    if (signatures.length > 0) process.stdout.write(dim(`\nStore: ${STORE_DIR}/${STORE_FILE}\n`));

    // Recommend AIM for automatic signature management if no identity exists
    const aimIdentityPath = path.join(targetDir, '.opena2a', 'aim', 'identity.json');
    const globalAimPath = path.join(os.homedir(), '.opena2a', 'aim-core', 'identity.json');
    const hasIdentity = fs.existsSync(aimIdentityPath) || fs.existsSync(globalAimPath);
    if (!hasIdentity) {
      process.stdout.write('\n');
      process.stdout.write(cyan('Tip:') + ' Create an agent identity to manage signatures automatically.\n');
      process.stdout.write(dim('  opena2a identity create --name ' + path.basename(targetDir) + '\n'));
      process.stdout.write(dim('  Then run: hackmyagent fix-all --with-aim\n'));
      process.stdout.write(dim('  AIM signs files with Ed25519, logs changes, and tracks trust score.\n'));
      process.stdout.write(dim('  No need to manually re-sign after edits.\n'));
    }
  }
  return 0;
}

// --- Verify ---

async function guardVerify(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const enforce = options.enforce ?? false;
  const store = loadStore(targetDir);

  if (!store) {
    // A store file that exists but could not be loaded (unparseable, or written by a newer CLI
    // and refused) is not the same as no store: do not advise a sign that would overwrite it.
    if (fs.existsSync(path.join(targetDir, STORE_DIR, STORE_FILE))) {
      if (isJson) { process.stdout.write(JSON.stringify({ error: 'The signature store exists but could not be read; nothing was verified.' }, null, 2) + '\n'); }
      else { process.stdout.write(yellow('The signature store exists but could not be read; nothing was verified.\n')); }
    } else if (isJson) { process.stdout.write(JSON.stringify({ error: 'No signature store found. Run: opena2a guard sign' }, null, 2) + '\n'); }
    else { process.stdout.write(yellow('No signature store found. Run: opena2a guard sign to detect tampering.\n')); }
    return 1;
  }

  const results: GuardResult[] = [];
  for (const sig of store.signatures) {
    const fullPath = path.join(targetDir, sig.filePath);
    if (!fs.existsSync(fullPath)) { results.push({ filePath: sig.filePath, status: 'missing', expectedHash: sig.hash }); continue; }
    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    if (currentHash === sig.hash) { results.push({ filePath: sig.filePath, status: 'pass', currentHash }); }
    else {
      const diff = computeFileDiff(fullPath, sig, content);
      results.push({ filePath: sig.filePath, status: 'tampered', currentHash, expectedHash: sig.hash, diff });
    }
  }

  const signedPaths = new Set(store.signatures.map(s => s.filePath));
  for (const relPath of resolveFiles(targetDir)) {
    if (!signedPaths.has(relPath)) { results.push({ filePath: relPath, status: 'unsigned' }); }
  }

  const report = buildReport('verify', targetDir, results, store.signatures.length);
  const tamperedFiles = results.filter(r => r.status === 'tampered' || r.status === 'missing');

  if (tamperedFiles.length > 0) {
    await emitEvent('config.tampered', 'guard.verify', targetDir, enforce ? 'high' : 'medium', enforce ? 'blocked' : 'monitored', {
      tamperedCount: report.tampered, missingCount: report.missing,
      files: tamperedFiles.map(f => ({ path: f.filePath, status: f.status, diff: f.diff ?? null })),
    });
  } else {
    await emitEvent('config.verified', 'guard.verify', targetDir, 'info', 'allowed', {
      passedCount: report.passed, unsignedCount: report.unsigned, totalSigned: report.totalSigned,
    });
  }

  // Policy-aware enforcement: heartbeat disable on tamper, blockOnUnsigned
  let policyViolations = 0;
  try {
    const { loadGuardPolicy, checkPolicyCompliance, disableHeartbeat } = await import('./guard-policy.js');
    const policy = loadGuardPolicy(targetDir);
    if (policy) {
      const compliance = checkPolicyCompliance(targetDir, policy);
      // Disable heartbeat on tamper if policy requires it
      if (policy.disableHeartbeatOnTamper && (compliance.requiredTampered.length > 0 || compliance.requiredMissing.length > 0)) {
        const reason = `Tamper detected: ${[...compliance.requiredTampered, ...compliance.requiredMissing].join(', ')}`;
        disableHeartbeat(targetDir, reason);
        await emitEvent('heartbeat.disabled', 'guard.verify', targetDir, 'high', 'blocked', { reason, tampered: compliance.requiredTampered, missing: compliance.requiredMissing });
      }
      // Block on unsigned required files
      if (policy.blockOnUnsigned && compliance.requiredUnsigned.length > 0) {
        policyViolations += compliance.requiredUnsigned.length;
        for (const f of compliance.requiredUnsigned) {
          // Add unsigned required files as failures if not already in results
          if (!results.find(r => r.filePath === f)) { results.push({ filePath: f, status: 'unsigned' }); }
        }
        await emitEvent('policy.violation', 'guard.verify', targetDir, 'medium', enforce ? 'blocked' : 'monitored', { unsignedRequired: compliance.requiredUnsigned });
      }
    }
  } catch {
    // guard-policy module not available
  }

  // Verify skill and heartbeat signatures
  type VResult = Awaited<ReturnType<typeof import('./guard-signing.js').verifySkillSignatures>>;
  let skillVerify: VResult = [];
  let heartbeatVerify: VResult = [];
  if (options.skills || options.heartbeats) {
    const { verifySkillSignatures, verifyHeartbeatSignatures } = await import('./guard-signing.js');
    if (options.skills) skillVerify = await verifySkillSignatures(targetDir);
    if (options.heartbeats) heartbeatVerify = await verifyHeartbeatSignatures(targetDir);
  }

  if (isJson) {
    const output: Record<string, unknown> = { ...report };
    if (skillVerify.length > 0) output.skills = skillVerify;
    if (heartbeatVerify.length > 0) output.heartbeats = heartbeatVerify;
    process.stdout.write(JSON.stringify(output, null, 2) + '\n');
  } else {
    printVerifyReport(report, enforce);
    if (skillVerify.length > 0) {
      process.stdout.write(bold('  Skill Signatures') + '\n');
      for (const sv of skillVerify) { process.stdout.write(`  ${sv.filePath.padEnd(28)} ${sv.status === 'pass' ? green('PASS') : sv.status === 'tampered' ? red('TAMPERED') : yellow(sv.status.toUpperCase())}\n`); }
      process.stdout.write('\n');
    }
    if (heartbeatVerify.length > 0) {
      process.stdout.write(bold('  Heartbeat Signatures') + '\n');
      for (const hv of heartbeatVerify) { process.stdout.write(`  ${hv.filePath.padEnd(28)} ${hv.status === 'pass' ? green('PASS') : hv.status === 'expired' ? yellow('EXPIRED') : hv.status === 'tampered' ? red('TAMPERED') : yellow(hv.status.toUpperCase())}\n`); }
      process.stdout.write('\n');
    }
  }

  const sigFailed = [...skillVerify, ...heartbeatVerify].some(v => v.status !== 'pass');
  return (report.tampered > 0 || report.missing > 0 || sigFailed || policyViolations > 0) ? (enforce ? EXIT_QUARANTINE : 1) : 0;
}

// --- Status ---

async function guardStatus(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const store = loadStore(targetDir);
  const signedCount = store?.signatures.length ?? 0;
  const allConfigFiles = resolveFiles(targetDir);
  const signedPaths = new Set(store?.signatures.map(s => s.filePath) ?? []);
  const unsignedCount = allConfigFiles.filter(f => !signedPaths.has(f)).length;

  let tamperedCount = 0;
  if (store) {
    for (const sig of store.signatures) {
      const fullPath = path.join(targetDir, sig.filePath);
      if (!fs.existsSync(fullPath)) { tamperedCount++; continue; }
      const content = fs.readFileSync(fullPath);
      const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
      if (currentHash !== sig.hash) tamperedCount++;
    }
  }

  // Skill and heartbeat counts for status
  let skillCount = 0;
  let heartbeatCount = 0;
  if (options.skills || options.heartbeats) {
    const { _internals: sigInternals } = await import('./guard-signing.js');
    if (options.skills) skillCount = sigInternals.findFiles(targetDir, sigInternals.SKILL_PATTERNS).length;
    if (options.heartbeats) heartbeatCount = sigInternals.findFiles(targetDir, sigInternals.HEARTBEAT_PATTERNS).length;
  }

  const statusReport: Record<string, unknown> = { signed: signedCount, unsigned: unsignedCount, tampered: tamperedCount, lastUpdated: store?.updatedAt ?? null };
  if (skillCount > 0) statusReport.skills = skillCount;
  if (heartbeatCount > 0) statusReport.heartbeats = heartbeatCount;

  if (isJson) { process.stdout.write(JSON.stringify(statusReport, null, 2) + '\n'); }
  else {
    process.stdout.write(bold('ConfigGuard Status') + '\n');
    process.stdout.write(gray('-'.repeat(40)) + '\n');
    process.stdout.write(`  Signed:      ${green(String(signedCount))}\n`);
    process.stdout.write(`  Unsigned:    ${unsignedCount > 0 ? yellow(String(unsignedCount)) : dim('0')}\n`);
    process.stdout.write(`  Tampered:    ${tamperedCount > 0 ? red(String(tamperedCount)) : dim('0')}\n`);
    if (skillCount > 0) process.stdout.write(`  Skills:      ${green(String(skillCount))}\n`);
    if (heartbeatCount > 0) process.stdout.write(`  Heartbeats:  ${green(String(heartbeatCount))}\n`);
    if (store?.updatedAt) { process.stdout.write(dim(`  Last signed: ${store.updatedAt}\n`)); }
    process.stdout.write(gray('-'.repeat(40)) + '\n');
  }
  return tamperedCount > 0 ? 1 : 0;
}

// --- Watch ---

async function guardWatch(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const enforce = options.enforce ?? false;
  const store = loadStore(targetDir);

  if (!store) {
    // A store file that exists but could not be loaded (unparseable, or written by a newer CLI
    // and refused) is not the same as no store: do not advise a sign that would overwrite it.
    if (fs.existsSync(path.join(targetDir, STORE_DIR, STORE_FILE))) {
      if (isJson) { process.stdout.write(JSON.stringify({ error: 'The signature store exists but could not be read; nothing was verified.' }, null, 2) + '\n'); }
      else { process.stdout.write(yellow('The signature store exists but could not be read; nothing was verified.\n')); }
    } else if (isJson) { process.stdout.write(JSON.stringify({ error: 'No signature store found. Run: opena2a guard sign' }, null, 2) + '\n'); }
    else { process.stdout.write(yellow('No signature store found. Run: opena2a guard sign to detect tampering.\n')); }
    return 1;
  }

  if (!isJson) {
    process.stdout.write(bold('ConfigGuard Watch') + '\n');
    process.stdout.write(dim(`Monitoring ${store.signatures.length} signed file(s)...\n`));
    process.stdout.write(dim('Press Ctrl+C to stop.\n\n'));
  }

  const watchers: fs.FSWatcher[] = [];
  const debounceTimers = new Map<string, NodeJS.Timeout>();

  for (const sig of store.signatures) {
    const fullPath = path.join(targetDir, sig.filePath);
    if (!fs.existsSync(fullPath)) continue;
    try {
      const watcher = fs.watch(fullPath, { persistent: true }, () => {
        const existing = debounceTimers.get(sig.filePath);
        if (existing) clearTimeout(existing);
        debounceTimers.set(sig.filePath, setTimeout(async () => {
          debounceTimers.delete(sig.filePath);
          await handleFileChange(targetDir, sig, isJson, enforce, options.verbose);
        }, 100));
      });
      watchers.push(watcher);
    } catch {
      if (!isJson) process.stderr.write(yellow(`  Cannot watch: ${sig.filePath}\n`));
    }
  }

  if (watchers.length === 0) {
    if (!isJson) process.stdout.write(yellow('No files to watch.\n'));
    return 1;
  }

  return new Promise<number>((resolve) => {
    const cleanup = () => {
      for (const w of watchers) { try { w.close(); } catch { /* noop */ } }
      for (const timer of debounceTimers.values()) clearTimeout(timer);
      if (!isJson) process.stdout.write(dim('\nWatch stopped.\n'));
      resolve(0);
    };
    process.once('SIGINT', cleanup);
    process.once('SIGTERM', cleanup);
  });
}

async function handleFileChange(targetDir: string, sig: ConfigSignature, isJson: boolean, enforce: boolean, verbose?: boolean): Promise<void> {
  const fullPath = path.join(targetDir, sig.filePath);
  const timestamp = new Date().toISOString();

  if (!fs.existsSync(fullPath)) {
    if (isJson) { process.stdout.write(JSON.stringify({ time: timestamp, file: sig.filePath, status: 'missing' }) + '\n'); }
    else { process.stdout.write(`${dim(timestamp.slice(11, 19))}  ${red('MISSING')}   ${sig.filePath}\n`); }
    // Emit absolute path so the Shield path-scoping filter (#109 sub-item 1)
    // can drop these events when an unrelated `opena2a review <dir>` runs.
    // Relative paths leak across targets — see #110.
    await emitEvent('config.tampered', 'guard.watch', fullPath, 'high', enforce ? 'blocked' : 'monitored', { reason: 'file_deleted' });
    return;
  }

  const content = fs.readFileSync(fullPath);
  const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');

  if (currentHash === sig.hash) {
    if (verbose) {
      if (isJson) { process.stdout.write(JSON.stringify({ time: timestamp, file: sig.filePath, status: 'unchanged' }) + '\n'); }
      else { process.stdout.write(`${dim(timestamp.slice(11, 19))}  ${dim('OK')}        ${dim(sig.filePath)}\n`); }
    }
    return;
  }

  const diff = computeFileDiff(fullPath, sig, content);
  if (isJson) { process.stdout.write(JSON.stringify({ time: timestamp, file: sig.filePath, status: 'tampered', diff }) + '\n'); }
  else {
    process.stdout.write(`${dim(timestamp.slice(11, 19))}  ${red('TAMPERED')}  ${sig.filePath}`);
    if (diff) {
      const changes: string[] = [];
      if (diff.added?.length) changes.push(`+${diff.added.length} keys`);
      if (diff.removed?.length) changes.push(`-${diff.removed.length} keys`);
      if (diff.modified?.length) changes.push(`~${diff.modified.length} keys`);
      if (diff.sizeChange !== 0) changes.push(`${diff.sizeChange > 0 ? '+' : ''}${diff.sizeChange}b`);
      if (changes.length > 0) process.stdout.write(dim(` (${changes.join(', ')})`));
    }
    process.stdout.write('\n');
  }
  await emitEvent('config.tampered', 'guard.watch', fullPath, enforce ? 'high' : 'medium', enforce ? 'blocked' : 'monitored', { currentHash, expectedHash: sig.hash, diff });
}

// --- Diff ---

async function guardDiff(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const store = loadStore(targetDir);

  if (!store) {
    // A store file that exists but could not be loaded (unparseable, or written by a newer CLI
    // and refused) is not the same as no store: do not advise a sign that would overwrite it.
    if (fs.existsSync(path.join(targetDir, STORE_DIR, STORE_FILE))) {
      if (isJson) { process.stdout.write(JSON.stringify({ error: 'The signature store exists but could not be read; nothing was verified.' }, null, 2) + '\n'); }
      else { process.stdout.write(yellow('The signature store exists but could not be read; nothing was verified.\n')); }
    } else if (isJson) { process.stdout.write(JSON.stringify({ error: 'No signature store found. Run: opena2a guard sign' }, null, 2) + '\n'); }
    else { process.stdout.write(yellow('No signature store found. Run: opena2a guard sign to detect tampering.\n')); }
    return 1;
  }

  const filesToCheck = options.files ? store.signatures.filter(s => options.files!.includes(s.filePath)) : store.signatures;
  const diffs: Array<{ filePath: string; status: string; diff: FileDiff | null }> = [];
  let hasChanges = false;

  for (const sig of filesToCheck) {
    const fullPath = path.join(targetDir, sig.filePath);
    if (!fs.existsSync(fullPath)) { diffs.push({ filePath: sig.filePath, status: 'missing', diff: null }); hasChanges = true; continue; }
    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    if (currentHash === sig.hash) { diffs.push({ filePath: sig.filePath, status: 'unchanged', diff: null }); continue; }
    hasChanges = true;
    diffs.push({ filePath: sig.filePath, status: 'changed', diff: computeFileDiff(fullPath, sig, content) });
  }

  if (isJson) { process.stdout.write(JSON.stringify({ files: diffs, hasChanges }, null, 2) + '\n'); return hasChanges ? 1 : 0; }

  process.stdout.write(bold('ConfigGuard Diff') + '\n');
  process.stdout.write(gray('-'.repeat(50)) + '\n');
  for (const entry of diffs) {
    if (entry.status === 'unchanged') { if (options.verbose) process.stdout.write(`  ${dim('--')} ${dim(entry.filePath)} ${dim('(unchanged)')}\n`); continue; }
    if (entry.status === 'missing') { process.stdout.write(`  ${red('MISSING')} ${entry.filePath}\n`); continue; }
    process.stdout.write(`  ${yellow('CHANGED')} ${entry.filePath}\n`);
    if (entry.diff) {
      if (entry.diff.sizeChange !== 0) { const sign = entry.diff.sizeChange > 0 ? '+' : ''; process.stdout.write(dim(`           Size: ${sign}${entry.diff.sizeChange} bytes\n`)); }
      if (entry.diff.added?.length) { for (const key of entry.diff.added) process.stdout.write(`           ${green('+ ' + key)}\n`); }
      if (entry.diff.removed?.length) { for (const key of entry.diff.removed) process.stdout.write(`           ${red('- ' + key)}\n`); }
      if (entry.diff.modified?.length) { for (const key of entry.diff.modified) process.stdout.write(`           ${cyan('~ ' + key)}\n`); }
    }
  }
  process.stdout.write(gray('-'.repeat(50)) + '\n');
  return hasChanges ? 1 : 0;
}

// --- Shield Integration ---

export function verifyConfigIntegrity(targetDir?: string): ConfigIntegritySummary {
  const dir = targetDir ?? process.cwd();
  const store = loadStore(dir);
  if (!store || store.signatures.length === 0) { return { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'unsigned' }; }

  const tampered: string[] = [];
  for (const sig of store.signatures) {
    const fullPath = path.join(dir, sig.filePath);
    if (!fs.existsSync(fullPath)) { tampered.push(sig.filePath); continue; }
    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    if (currentHash !== sig.hash) tampered.push(sig.filePath);
  }
  return { filesMonitored: store.signatures.length, tamperedFiles: tampered, signatureStatus: tampered.length > 0 ? 'tampered' : 'valid' };
}

// --- Diff computation ---

function computeFileDiff(fullPath: string, sig: ConfigSignature, currentContent: Buffer): FileDiff {
  const sizeChange = currentContent.length - sig.fileSize;
  if (fullPath.endsWith('.json') || fullPath.endsWith('.yaml') || fullPath.endsWith('.yml')) {
    try { JSON.parse(currentContent.toString('utf-8')); return { type: 'json', sizeChange }; } catch { /* not JSON */ }
  }
  return { type: 'text', sizeChange };
}

function diffJsonKeys(original: Record<string, unknown>, current: Record<string, unknown>): { added: string[]; removed: string[]; modified: string[] } {
  const origKeys = new Set(Object.keys(original));
  const currKeys = new Set(Object.keys(current));
  const added: string[] = []; const removed: string[] = []; const modified: string[] = [];
  for (const key of currKeys) { if (!origKeys.has(key)) added.push(key); else if (JSON.stringify(original[key]) !== JSON.stringify(current[key])) modified.push(key); }
  for (const key of origKeys) { if (!currKeys.has(key)) removed.push(key); }
  return { added, removed, modified };
}

function flattenKeys(obj: unknown, prefix = ''): string[] {
  if (obj === null || typeof obj !== 'object') return [prefix || '(root)'];
  const keys: string[] = [];
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    if (value && typeof value === 'object' && !Array.isArray(value)) { keys.push(...flattenKeys(value, fullKey)); }
    else { keys.push(fullKey); }
  }
  return keys;
}

// --- Helpers ---

function resolveFiles(targetDir: string, customFiles?: string[]): string[] {
  if (customFiles && customFiles.length > 0) return customFiles.filter(f => fs.existsSync(path.join(targetDir, f)));
  return resolveDefaultFiles(targetDir).files;
}

/**
 * The default signing set: files that exist AND that git does not report as ignored. The store
 * is committed with the repository, so an entry for a path the repository cannot contain has no
 * verifier anywhere; outside a git repository the predicate is inert and everything present is
 * listed. Explicit --files paths bypass this (an explicit choice beats the default).
 */
function resolveDefaultFiles(targetDir: string): { files: string[]; skipped: SkippedFile[] } {
  const present = GUARD_FILES.filter(f => fs.existsSync(path.join(targetDir, f)));
  const ignored = gitIgnoredPaths(targetDir, present);
  return {
    files: present.filter(f => !ignored.has(f)),
    skipped: present.filter(f => ignored.has(f)).map(f => ({ filePath: f, reason: 'gitIgnored' as const, rule: ignored.get(f) ?? '' })),
  };
}

/**
 * Which of the given paths does git consider ignored here? Index-aware (a tracked file is never
 * reported, whatever the patterns say), one batched spawn. Exit 1 means none; not a repository
 * means the question does not apply. A failure INSIDE a repository skips nothing and says so on
 * stderr: a degraded instrument must not emit a healthy-looking answer.
 */
function gitIgnoredPaths(targetDir: string, candidates: string[]): Map<string, string> {
  const none = new Map<string, string>();
  if (candidates.length === 0) return none;
  let out: string;
  try {
    out = execFileSync('git', ['-C', targetDir, '-c', 'core.fsmonitor=false', 'check-ignore', '-z', '-v', '--stdin'], {
      input: candidates.join('\0') + '\0',
      stdio: ['pipe', 'pipe', 'ignore'],
      encoding: 'utf-8',
    });
  } catch (err) {
    const e = err as { status?: number | null };
    if (e.status === 1) return none; // ran fine: nothing is ignored
    // Any other failure: skip nothing. Inside a repository that is a degraded instrument, and a
    // degraded instrument must say so rather than emit a healthy-looking store; outside one the
    // question does not apply and silence is correct.
    if (hasGitDirAncestor(targetDir)) {
      process.stderr.write('guard: git ignore rules could not be consulted; no files were skipped\n');
    }
    return none;
  }
  // -z -v output is <source> NUL <linenum> NUL <pattern> NUL <path> NUL, repeated.
  const parts = out.split('\0');
  const ignored = new Map<string, string>();
  for (let i = 0; i + 3 < parts.length; i += 4) {
    const source = parts[i];
    const line = parts[i + 1];
    const pattern = parts[i + 2];
    const matchedPath = parts[i + 3];
    // A negation match is check-ignore telling us the path is NOT ignored.
    if (!matchedPath || pattern.startsWith('!')) continue;
    ignored.set(matchedPath, source ? `${source}:${line}:${pattern}` : pattern);
  }
  return ignored;
}

function hasGitDirAncestor(dir: string): boolean {
  let current = path.resolve(dir);
  for (;;) {
    if (fs.existsSync(path.join(current, '.git'))) return true;
    const parent = path.dirname(current);
    if (parent === current) return false;
    current = parent;
  }
}

function loadStore(targetDir: string): SignatureStore | null {
  const storePath = path.join(targetDir, STORE_DIR, STORE_FILE);
  if (!fs.existsSync(storePath)) return null;
  try {
    const store = JSON.parse(fs.readFileSync(storePath, 'utf-8')) as SignatureStore;
    const version = (store as { version?: unknown }).version ?? 1;
    if (typeof version === 'number' && version > 1) {
      // No reader consulted version before this check existed; refusing here is what lets a
      // future shape change be a version bump instead of a silent misread.
      process.stderr.write(`guard: ${STORE_FILE} was written by a newer opena2a-cli (store version ${version}); upgrade to read it\n`);
      return null;
    }
    return store;
  } catch { return null; }
}

function buildReport(subcommand: string, targetDir: string, results: GuardResult[], totalSigned: number): GuardReport {
  return { subcommand, directory: targetDir, results,
    passed: results.filter(r => r.status === 'pass').length, tampered: results.filter(r => r.status === 'tampered').length,
    unsigned: results.filter(r => r.status === 'unsigned').length, missing: results.filter(r => r.status === 'missing').length, totalSigned };
}

function printSkippedFiles(skipped: SkippedFile[]): void {
  if (skipped.length === 0) return;
  process.stdout.write(`Skipped ${skipped.length} git-ignored file${skipped.length === 1 ? '' : 's'}. The store is committed with the repository, so it lists only files the repository carries.\n`);
  for (const skip of skipped) { process.stdout.write(dim(`  ${skip.filePath}  ${skip.rule}\n`)); }
}

function printVerifyReport(report: GuardReport, enforce?: boolean): void {
  process.stdout.write('\n' + bold('  ConfigGuard Verification') + '\n\n');
  process.stdout.write(`  ${dim('File'.padEnd(28))} ${dim('Status'.padEnd(12))} ${dim('Hash')}\n`);
  process.stdout.write(gray('  ' + '-'.repeat(60)) + '\n');

  for (const result of report.results) {
    const statusLabel = result.status === 'pass' ? green('PASS') : result.status === 'tampered' ? red('TAMPERED') : result.status === 'unsigned' ? yellow('UNSIGNED') : red('MISSING');
    const hashDisplay = result.currentHash ? dim(result.currentHash.slice(0, 23) + '...') : dim('--');
    process.stdout.write(`  ${result.filePath.padEnd(28)} ${statusLabel.padEnd(20)} ${hashDisplay}\n`);
    if (result.status === 'missing') {
      process.stdout.write(`  ${' '.repeat(28)} ${dim('fix: restore the file, or run `opena2a guard sign` to rebuild the store from the files present')}\n`);
    }
    if (result.status === 'tampered' && result.expectedHash) { process.stdout.write(`  ${' '.repeat(28)} ${dim('expected: ' + result.expectedHash.slice(0, 23) + '...')}\n`); }
    if (result.status === 'tampered' && result.diff) {
      const parts: string[] = [];
      if (result.diff.sizeChange !== 0) parts.push(`${result.diff.sizeChange > 0 ? '+' : ''}${result.diff.sizeChange}b`);
      if (result.diff.added?.length) parts.push(`+${result.diff.added.length} keys`);
      if (result.diff.removed?.length) parts.push(`-${result.diff.removed.length} keys`);
      if (result.diff.modified?.length) parts.push(`~${result.diff.modified.length} keys`);
      if (parts.length > 0) process.stdout.write(`  ${' '.repeat(28)} ${dim('diff: ' + parts.join(', '))}\n`);
    }
  }

  process.stdout.write(gray('  ' + '-'.repeat(60)) + '\n');
  process.stdout.write(`  ${dim('Result:')} ${green(String(report.passed))} passed, `);
  process.stdout.write(`${report.tampered > 0 ? red(String(report.tampered)) : '0'} tampered, `);
  process.stdout.write(`${report.missing > 0 ? red(String(report.missing)) : '0'} missing, `);
  process.stdout.write(`${report.unsigned > 0 ? yellow(String(report.unsigned)) : '0'} unsigned`);
  if (enforce && (report.tampered > 0 || report.missing > 0)) { process.stdout.write(`  ${red('[QUARANTINE]')}`); }
  process.stdout.write('\n\n');
}

// --- Silent signing (for protect command integration) ---

/**
 * Sign config files without any stdout output. Returns what was signed.
 * Used by `protect` to silently sign configs as part of the fix-all flow.
 */
export async function signConfigFilesSilent(targetDir: string): Promise<{ signed: number; files: string[] }> {
  const filesToSign = resolveFiles(targetDir);
  const signatures: ConfigSignature[] = [];

  for (const relPath of filesToSign) {
    const fullPath = path.join(targetDir, relPath);
    if (!fs.existsSync(fullPath)) continue;
    const content = fs.readFileSync(fullPath);
    const hash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    const stat = fs.statSync(fullPath);
    signatures.push({ filePath: relPath, hash, signedAt: new Date().toISOString(), signedBy: signedByLabel(), fileSize: stat.size });
  }

  if (signatures.length === 0) {
    return { signed: 0, files: [] };
  }

  const store: SignatureStore = { version: 1, signatures, updatedAt: new Date().toISOString() };
  const storeDir = path.join(targetDir, STORE_DIR);
  fs.mkdirSync(storeDir, { recursive: true });
  fs.writeFileSync(path.join(storeDir, STORE_FILE), JSON.stringify(store, null, 2) + '\n', 'utf-8');

  await emitEvent('config.signed', 'guard.sign', targetDir, 'info', 'allowed', {
    fileCount: signatures.length, files: signatures.map(s => s.filePath),
  });

  return { signed: signatures.length, files: signatures.map(s => s.filePath) };
}

// --- Testable internals ---

export const _internals = {
  resolveFiles, resolveDefaultFiles, gitIgnoredPaths, loadStore, computeFileDiff, diffJsonKeys, flattenKeys, emitEvent, verifyConfigIntegrity,
  GUARD_FILES, STORE_DIR, STORE_FILE, EXIT_QUARANTINE,
};

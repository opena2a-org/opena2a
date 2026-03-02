/**
 * opena2a guard -- ConfigGuard: config file integrity signing and verification.
 *
 * Subcommands:
 * - sign:   Hash all detected config files, store in signatures.json
 * - verify: Check all signed files for tampering (hash mismatch)
 * - status: Summary of signed, unsigned, and tampered files
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { bold, green, yellow, red, dim, gray, cyan } from '../util/colors.js';
import { Spinner } from '../util/spinner.js';

// --- Types ---

export interface GuardOptions {
  subcommand: 'sign' | 'verify' | 'status';
  files?: string[];
  targetDir?: string;
  ci?: boolean;
  format?: 'text' | 'json';
  verbose?: boolean;
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

interface GuardResult {
  filePath: string;
  status: 'pass' | 'tampered' | 'unsigned' | 'missing';
  currentHash?: string;
  expectedHash?: string;
}

interface GuardReport {
  subcommand: string;
  directory: string;
  results: GuardResult[];
  passed: number;
  tampered: number;
  unsigned: number;
  missing: number;
  totalSigned: number;
}

// --- Default guarded files ---

const GUARD_FILES = [
  'mcp.json', '.mcp.json', '.claude/settings.json',
  'package.json', 'package-lock.json',
  'arp.yaml', 'arp.yml', 'arp.json',
  'openclaw.json', '.openclaw/config.json',
  '.opena2a.yaml', '.opena2a.json',
  'tsconfig.json', 'go.mod', 'go.sum',
  'pyproject.toml', 'requirements.txt',
  'Dockerfile', 'docker-compose.yml',
];

const STORE_DIR = '.opena2a/guard';
const STORE_FILE = 'signatures.json';

// --- Core ---

export async function guard(options: GuardOptions): Promise<number> {
  const targetDir = path.resolve(options.targetDir ?? process.cwd());

  if (!fs.existsSync(targetDir)) {
    process.stderr.write(red(`Directory not found: ${targetDir}\n`));
    return 1;
  }

  switch (options.subcommand) {
    case 'sign':
      return guardSign(targetDir, options);
    case 'verify':
      return guardVerify(targetDir, options);
    case 'status':
      return guardStatus(targetDir, options);
    default:
      process.stderr.write(red(`Unknown subcommand: ${options.subcommand}\n`));
      process.stderr.write('Usage: opena2a guard <sign|verify|status>\n');
      return 1;
  }
}

// --- Sign ---

async function guardSign(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const spinner = new Spinner('Signing config files...');
  if (!isJson) spinner.start();

  const filesToSign = resolveFiles(targetDir, options.files);
  const signatures: ConfigSignature[] = [];

  for (const relPath of filesToSign) {
    const fullPath = path.join(targetDir, relPath);
    if (!fs.existsSync(fullPath)) continue;

    const content = fs.readFileSync(fullPath);
    const hash = 'sha256:' + createHash('sha256').update(content).digest('hex');
    const stat = fs.statSync(fullPath);

    signatures.push({
      filePath: relPath,
      hash,
      signedAt: new Date().toISOString(),
      signedBy: 'opena2a-cli',
      fileSize: stat.size,
    });
  }

  if (!isJson) spinner.stop();

  if (signatures.length === 0) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ signed: 0, files: [] }, null, 2) + '\n');
    } else {
      process.stdout.write(yellow('No config files found to sign.\n'));
    }
    return 0;
  }

  // Write signature store
  const store: SignatureStore = {
    version: 1,
    signatures,
    updatedAt: new Date().toISOString(),
  };

  const storeDir = path.join(targetDir, STORE_DIR);
  fs.mkdirSync(storeDir, { recursive: true });
  fs.writeFileSync(
    path.join(storeDir, STORE_FILE),
    JSON.stringify(store, null, 2) + '\n',
    'utf-8',
  );

  if (isJson) {
    process.stdout.write(JSON.stringify({ signed: signatures.length, files: signatures.map(s => s.filePath) }, null, 2) + '\n');
  } else {
    process.stdout.write(green(`Signed ${signatures.length} config file${signatures.length === 1 ? '' : 's'}.\n`));
    for (const sig of signatures) {
      process.stdout.write(dim(`  ${sig.filePath}  ${sig.hash.slice(0, 23)}...\n`));
    }
    process.stdout.write(dim(`\nStore: ${STORE_DIR}/${STORE_FILE}\n`));
  }

  return 0;
}

// --- Verify ---

async function guardVerify(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const store = loadStore(targetDir);

  if (!store) {
    if (isJson) {
      process.stdout.write(JSON.stringify({ error: 'No signature store found. Run: opena2a guard sign' }, null, 2) + '\n');
    } else {
      process.stdout.write(yellow('No signature store found. Run: opena2a guard sign\n'));
    }
    return 1;
  }

  const results: GuardResult[] = [];

  // Check signed files
  for (const sig of store.signatures) {
    const fullPath = path.join(targetDir, sig.filePath);
    if (!fs.existsSync(fullPath)) {
      results.push({
        filePath: sig.filePath,
        status: 'missing',
        expectedHash: sig.hash,
      });
      continue;
    }

    const content = fs.readFileSync(fullPath);
    const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');

    if (currentHash === sig.hash) {
      results.push({
        filePath: sig.filePath,
        status: 'pass',
        currentHash,
      });
    } else {
      results.push({
        filePath: sig.filePath,
        status: 'tampered',
        currentHash,
        expectedHash: sig.hash,
      });
    }
  }

  // Check for unsigned config files
  const signedPaths = new Set(store.signatures.map(s => s.filePath));
  const allConfigFiles = resolveFiles(targetDir);
  for (const relPath of allConfigFiles) {
    if (!signedPaths.has(relPath)) {
      results.push({
        filePath: relPath,
        status: 'unsigned',
      });
    }
  }

  const report = buildReport('verify', targetDir, results, store.signatures.length);

  if (isJson) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  } else {
    printVerifyReport(report);
  }

  return report.tampered > 0 ? 1 : 0;
}

// --- Status ---

async function guardStatus(targetDir: string, options: GuardOptions): Promise<number> {
  const isJson = options.format === 'json';
  const store = loadStore(targetDir);

  const signedCount = store?.signatures.length ?? 0;
  const allConfigFiles = resolveFiles(targetDir);
  const signedPaths = new Set(store?.signatures.map(s => s.filePath) ?? []);
  const unsignedCount = allConfigFiles.filter(f => !signedPaths.has(f)).length;

  // Quick tamper check
  let tamperedCount = 0;
  if (store) {
    for (const sig of store.signatures) {
      const fullPath = path.join(targetDir, sig.filePath);
      if (!fs.existsSync(fullPath)) {
        tamperedCount++;
        continue;
      }
      const content = fs.readFileSync(fullPath);
      const currentHash = 'sha256:' + createHash('sha256').update(content).digest('hex');
      if (currentHash !== sig.hash) tamperedCount++;
    }
  }

  const statusReport = {
    signed: signedCount,
    unsigned: unsignedCount,
    tampered: tamperedCount,
    lastUpdated: store?.updatedAt ?? null,
  };

  if (isJson) {
    process.stdout.write(JSON.stringify(statusReport, null, 2) + '\n');
  } else {
    process.stdout.write(bold('ConfigGuard Status') + '\n');
    process.stdout.write(gray('-'.repeat(40)) + '\n');
    process.stdout.write(`  Signed:    ${green(String(signedCount))}\n`);
    process.stdout.write(`  Unsigned:  ${unsignedCount > 0 ? yellow(String(unsignedCount)) : dim('0')}\n`);
    process.stdout.write(`  Tampered:  ${tamperedCount > 0 ? red(String(tamperedCount)) : dim('0')}\n`);
    if (store?.updatedAt) {
      process.stdout.write(dim(`  Last signed: ${store.updatedAt}\n`));
    }
    process.stdout.write(gray('-'.repeat(40)) + '\n');
  }

  return tamperedCount > 0 ? 1 : 0;
}

// --- Helpers ---

function resolveFiles(targetDir: string, customFiles?: string[]): string[] {
  if (customFiles && customFiles.length > 0) {
    return customFiles.filter(f => fs.existsSync(path.join(targetDir, f)));
  }
  return GUARD_FILES.filter(f => fs.existsSync(path.join(targetDir, f)));
}

function loadStore(targetDir: string): SignatureStore | null {
  const storePath = path.join(targetDir, STORE_DIR, STORE_FILE);
  if (!fs.existsSync(storePath)) return null;

  try {
    const raw = fs.readFileSync(storePath, 'utf-8');
    return JSON.parse(raw) as SignatureStore;
  } catch {
    return null;
  }
}

function buildReport(
  subcommand: string,
  targetDir: string,
  results: GuardResult[],
  totalSigned: number,
): GuardReport {
  return {
    subcommand,
    directory: targetDir,
    results,
    passed: results.filter(r => r.status === 'pass').length,
    tampered: results.filter(r => r.status === 'tampered').length,
    unsigned: results.filter(r => r.status === 'unsigned').length,
    missing: results.filter(r => r.status === 'missing').length,
    totalSigned,
  };
}

function printVerifyReport(report: GuardReport): void {
  process.stdout.write('\n' + bold('  ConfigGuard Verification') + '\n\n');

  process.stdout.write(`  ${dim('File'.padEnd(28))} ${dim('Status'.padEnd(12))} ${dim('Hash')}\n`);
  process.stdout.write(gray('  ' + '-'.repeat(60)) + '\n');

  for (const result of report.results) {
    const statusLabel = result.status === 'pass' ? green('PASS')
      : result.status === 'tampered' ? red('TAMPERED')
      : result.status === 'unsigned' ? yellow('UNSIGNED')
      : red('MISSING');

    const hashDisplay = result.currentHash
      ? dim(result.currentHash.slice(0, 23) + '...')
      : dim('--');

    process.stdout.write(`  ${result.filePath.padEnd(28)} ${statusLabel.padEnd(20)} ${hashDisplay}\n`);

    if (result.status === 'tampered' && result.expectedHash) {
      process.stdout.write(`  ${' '.repeat(28)} ${dim('expected: ' + result.expectedHash.slice(0, 23) + '...')}\n`);
    }
  }

  process.stdout.write(gray('  ' + '-'.repeat(60)) + '\n');
  process.stdout.write(`  ${dim('Result:')} ${green(String(report.passed))} passed, `);
  process.stdout.write(`${report.tampered > 0 ? red(String(report.tampered)) : '0'} tampered, `);
  process.stdout.write(`${report.unsigned > 0 ? yellow(String(report.unsigned)) : '0'} unsigned\n\n`);
}

// --- Testable internals ---

export const _internals = {
  resolveFiles,
  loadStore,
  GUARD_FILES,
};

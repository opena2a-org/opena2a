/**
 * Detect cryptographic key/cert files in the scanned tree, tracked by git or
 * not; the finding says which.
 *
 * `quickCredentialScan` matches text patterns inside files. Private keys
 * stored as `.key` / `.pem` / `.p12` / `.pfx` files are credentials by
 * file type, not by string content — and binary container formats are
 * unreadable as text. We treat the file extension as the finding signal.
 *
 * The malicious-fixture under `opena2a-corpus/repo/malicious/kitchen-sink`
 * carries `fake-private.key` and `fake-cert.pem` in the project root.
 * Without this scanner those surfaces are invisible to `opena2a init`,
 * so the assessment scores artificially high (#116).
 *
 * Severity table (per audit decision 2026-04-29):
 *   .key  / .pem  / .p12 / .pfx — CRITICAL (private-key-bearing)
 *   .crt  / .cer                 — MEDIUM   (cert; usually public, but
 *                                            committing certs leaks chain
 *                                            metadata and may indicate
 *                                            sloppy key handling)
 *
 * `.pem` files can be public certs, but in source-tree context the
 * convention is private-key material, so we keep CRITICAL with a clear
 * verify command so the user can downgrade by inspection.
 */

import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { probeEnv } from './child-env.js';
import type { CredentialMatch } from './credential-patterns.js';
import { SKIP_DIRS } from './credential-patterns.js';
import { pathFrom, shellPath, shellWord } from './shell-word.js';

const KEY_FILE_SEVERITY: Record<string, 'critical' | 'medium'> = {
  '.key': 'critical',
  '.pem': 'critical',
  '.p12': 'critical',
  '.pfx': 'critical',
  '.crt': 'medium',
  '.cer': 'medium',
};

const TITLE_BY_EXT: Record<string, string> = {
  '.key': 'Private key file',
  '.pem': 'PEM key/cert file',
  '.p12': 'PKCS#12 keystore',
  '.pfx': 'PKCS#12 keystore',
  '.crt': 'X.509 certificate file',
  '.cer': 'X.509 certificate file',
};

/**
 * The key file of the encrypted credential store that `hackmyagent fix-all`
 * writes (its credvault plugin): a hex AES-256-GCM key beside the
 * `secrets.enc` it decrypts. hackmyagent writes no ignore rule for it.
 */
const VAULT_STORE_KEY = '.opena2a/credvault/store.key';

function isVaultStoreKey(relativePath: string): boolean {
  const posix = relativePath.split(path.sep).join('/');
  return posix === VAULT_STORE_KEY || posix.endsWith(`/${VAULT_STORE_KEY}`);
}

/**
 * What the finding says, from what was measured: the file type, whether git
 * tracks the file, and whether it is the vault store key. Severity is by file
 * type only.
 */
function describeKeyFile(
  severity: 'critical' | 'medium',
  tracked: boolean,
  vault: boolean,
): { explanation: string; businessImpact: string } {
  const where = tracked ? 'tracked by git' : 'in the working tree, not tracked by git';
  if (vault) {
    return tracked
      ? {
        explanation: `Store key of the credential vault that hackmyagent fix-all writes to .opena2a/credvault/, ${where}. It decrypts secrets.enc beside it, so anyone with repository access and that file can read the stored credentials.`,
        businessImpact: 'Revoke or replace the credentials the vault holds, remove the key from history, and ignore .opena2a/credvault/store.key so it is not committed again.',
      }
      : {
        explanation: `Store key of the credential vault that hackmyagent fix-all writes to .opena2a/credvault/, ${where}. It decrypts secrets.enc beside it, and hackmyagent writes no ignore rule for it, so a commit that adds the directory includes it.`,
        businessImpact: 'Ignore .opena2a/credvault/store.key so the key is never committed beside the store it decrypts.',
      };
  }
  if (severity === 'critical') {
    return tracked
      ? {
        explanation: `Cryptographic key file ${where}. Anyone with repository access has the key material, in every clone and in the history.`,
        businessImpact: 'Rotate the key, remove the file from history, and store keys outside the repository (env var, vault, KMS).',
      }
      : {
        explanation: `Cryptographic key file ${where}. Anyone who can read this directory has the key material, and a commit that adds the directory includes it unless an ignore rule excludes it.`,
        businessImpact: 'Keep the key out of every commit with an ignore rule, or store it outside the repository (env var, vault, KMS). If it was ever committed or shared, revoke or replace it with the CA or service that issued it.',
      };
  }
  return {
    explanation: tracked
      ? `X.509 certificate ${where}. Certs are usually public, but committing them often signals lax handling of the matching private key.`
      : `X.509 certificate ${where}. Certs are usually public, but a cert beside the source often signals lax handling of the matching private key.`,
    businessImpact: 'Audit cert handling and verify the matching private key is not stored alongside.',
  };
}

export function scanCryptoKeyFiles(targetDir: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  walk(targetDir, (full) => {
    const ext = path.extname(full).toLowerCase();
    const severity = KEY_FILE_SEVERITY[ext];
    if (!severity) return;
    const relativePath = path.relative(targetDir, full);
    const vault = severity === 'critical' && isVaultStoreKey(relativePath);
    matches.push({
      value: path.basename(full),
      filePath: full,
      line: 1,
      findingId: severity === 'critical' ? 'CRED-KEYFILE' : 'CRED-CERTFILE',
      envVar: '',
      severity,
      title: vault ? 'Vault store key' : (TITLE_BY_EXT[ext] ?? 'Key/cert file in source'),
      ...describeKeyFile(severity, isTracked(targetDir, relativePath), vault),
    });
  });
  return matches;
}

function walk(dir: string, callback: (filePath: string) => void): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      // Skip on SKIP_DIRS membership only — descend into dot directories
      // like `.ssh/`, `.secrets/`, `.config/`, `.aws/` where private keys
      // conventionally live. A blanket dot-prefix skip would hide those
      // exact files this scanner exists to surface.
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, callback);
    } else if (entry.isFile()) {
      callback(full);
    }
  }
}

/**
 * The per-file remediation for a key or certificate file: one `git rm
 * --cached` command and the sentence printed with it. Revoking the key is a
 * step at the CA or service that issued it, which no command here can take,
 * so it is stated in the note and never chained into the command; neither is
 * the `.gitignore` step, which the note names.
 */
export function keyFileRemediation(
  findingId: string,
  relativePath: string,
): { remediation: string; remediationNote: string } {
  return {
    remediation: `git rm --cached ${shellWord(relativePath)}`,
    remediationNote: findingId === 'CRED-KEYFILE'
      ? 'Run after the key is revoked or replaced with the CA or service that issued it, which no opena2a command can do: it stops git tracking the file; add its extension to .gitignore so it is not committed again.'
      : 'This stops git tracking the file and leaves it on disk; add its extension to .gitignore so it is not committed again.',
  };
}

/**
 * Is `relativePath` in the git index of `dir`? Decided by `git ls-files
 * --error-unmatch`, started without a shell. Not a repository, or not
 * tracked, both answer false.
 */
function isTracked(dir: string, relativePath: string): boolean {
  try {
    execFileSync('git', ['-C', dir, '-c', 'core.fsmonitor=false', 'ls-files', '--error-unmatch', '--', relativePath], {
      stdio: 'ignore',
      env: probeEnv(['GIT_']),
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * The top level of the git work tree that holds `dir`, as a real path, or
 * null when `dir` is not in one.
 */
function repositoryRoot(dir: string): string | null {
  try {
    const top = execFileSync('git', ['-C', dir, '-c', 'core.fsmonitor=false', 'rev-parse', '--show-toplevel'], {
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env: probeEnv(['GIT_']),
    }).trim();
    return top ? fs.realpathSync(top) : null;
  } catch {
    return null;
  }
}

/**
 * One `git rm --cached` command over every given path that git tracks in
 * `dir` (each relative to `dir`), each a single-quoted shell word, in
 * ascending order of relative path. Never truncated: a command that reads
 * complete and leaves files tracked is worse than a long one. Null when none
 * of them is tracked.
 *
 * The command runs from `cwd`, the directory the user pastes it in. Run
 * from the repository root it is `git rm --cached` over paths relative to
 * that root; from anywhere else it is `git -C <root> rm --cached` over the
 * same paths, `<root>` named from `cwd`. `paths` stays relative to `dir`.
 */
export function untrackCommand(
  dir: string,
  relativePaths: string[],
  cwd: string = process.cwd(),
): { command: string; paths: string[] } | null {
  const paths = Array.from(new Set(relativePaths)).sort().filter(p => isTracked(dir, p));
  if (paths.length === 0) return null;
  const root = repositoryRoot(dir);
  if (!root) {
    return { command: `git -C ${shellPath(dir, cwd)} rm --cached ${paths.map(shellWord).join(' ')}`, paths };
  }
  const realDir = fs.realpathSync(dir);
  const fromRoot = paths.map(p => path.relative(root, path.join(realDir, p)));
  const git = pathFrom(root, cwd) === '.' ? 'git' : `git -C ${shellPath(root, cwd)}`;
  return { command: `${git} rm --cached ${fromRoot.map(shellWord).join(' ')}`, paths };
}

/**
 * The .gitignore rule that matches `relativePath` and nothing else: anchored
 * with a leading `/` to the directory of the .gitignore, with the pattern
 * characters `\ * ? [` and trailing spaces escaped so a file name is never a
 * glob.
 */
function ignoreRule(relativePath: string): string {
  const rule = relativePath.split(path.sep).join('/').replace(/[\\*?[]/g, '\\$&');
  return `/${rule.replace(/ +$/, spaces => '\\ '.repeat(spaces.length))}`;
}

/**
 * One command that appends an anchored rule to `dir`/.gitignore for every
 * given path git does not track in `dir`, each a single-quoted shell word, in
 * ascending order of relative path; the files stay on disk. The empty first
 * line keeps the rules on their own lines when .gitignore does not end with a
 * newline. Null when git tracks all of them; those take {@link untrackCommand}.
 *
 * The command runs from `cwd`, the directory the user pastes it in. Run from
 * `dir` it appends to `.gitignore`; from anywhere else it names
 * `dir`/.gitignore from `cwd`, because the rules are anchored to `dir`: in
 * another directory's .gitignore they name a path in that directory, not the
 * file. `paths` stays relative to `dir`.
 */
export function ignoreCommand(
  dir: string,
  relativePaths: string[],
  cwd: string = process.cwd(),
): { command: string; paths: string[] } | null {
  const paths = Array.from(new Set(relativePaths)).sort().filter(p => !isTracked(dir, p));
  if (paths.length === 0) return null;
  const gitignore = pathFrom(dir, cwd) === '.' ? '.gitignore' : shellPath(path.join(dir, '.gitignore'), cwd);
  return { command: `printf '%s\\n' '' ${paths.map(p => shellWord(ignoreRule(p))).join(' ')} >> ${gitignore}`, paths };
}

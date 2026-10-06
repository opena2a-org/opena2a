/**
 * Detect cryptographic key/cert files committed to source.
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
import { shellWord } from './shell-word.js';

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

export function scanCryptoKeyFiles(targetDir: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  walk(targetDir, (full) => {
    const ext = path.extname(full).toLowerCase();
    const severity = KEY_FILE_SEVERITY[ext];
    if (!severity) return;
    matches.push({
      value: path.basename(full),
      filePath: full,
      line: 1,
      findingId: severity === 'critical' ? 'CRED-KEYFILE' : 'CRED-CERTFILE',
      envVar: '',
      severity,
      title: TITLE_BY_EXT[ext] ?? 'Key/cert file in source',
      explanation: severity === 'critical'
        ? 'Cryptographic key file checked into source. Anyone with repository access has the key material.'
        : 'X.509 certificate checked into source. Certs are usually public, but committing them often signals lax handling of the matching private key.',
      businessImpact: severity === 'critical'
        ? 'Rotate the key, remove the file from history, and store keys outside the repository (env var, vault, KMS).'
        : 'Audit cert handling and verify the matching private key is not stored alongside.',
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
 * One `git rm --cached` command over every given path that git tracks in
 * `dir`, each a single-quoted shell word, in ascending order of relative
 * path. Never truncated: a command that reads complete and leaves files
 * tracked is worse than a long one. Null when none of them is tracked.
 */
export function untrackCommand(
  dir: string,
  relativePaths: string[],
): { command: string; paths: string[] } | null {
  const paths = Array.from(new Set(relativePaths)).sort().filter(p => isTracked(dir, p));
  if (paths.length === 0) return null;
  return { command: `git rm --cached ${paths.map(shellWord).join(' ')}`, paths };
}

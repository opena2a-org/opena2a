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

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { CredentialMatch } from './credential-patterns.js';
import { SKIP_DIRS } from './credential-patterns.js';

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
    if (entry.name.startsWith('.') && entry.name !== '.opena2a') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walk(full, callback);
    } else if (entry.isFile()) {
      callback(full);
    }
  }
}

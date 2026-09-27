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
 *
 * A PEM private key pasted INTO a source file (a string literal, a template,
 * a YAML value) is the same exposure under a different file type, and the
 * line-oriented text patterns cannot see it: the armor spans many lines and
 * the value is not a token. `scanEmbeddedPrivateKeys` reports those as
 * CRED-KEYEMBED (#270). Like key files, protect surfaces them and does not
 * migrate them: a multi-line key has no single value to swap for an env var.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import type { CredentialMatch } from './credential-patterns.js';
import { SKIP_DIRS, walkFiles } from './credential-patterns.js';

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
  matches.push(...scanEmbeddedPrivateKeys(targetDir));
  return matches;
}

// Armor labels that carry private key material: PKCS#8 (bare and encrypted),
// PKCS#1 RSA, SEC1 EC, DSA, OpenSSH, and PGP secret key blocks.
const PRIVATE_KEY_BEGIN =
  /-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----/g;
// Armor alone is not a key: docs, pattern tables and placeholder fixtures
// quote the header. Key material is base64 in lines of 64 (70 for OpenSSH),
// so a key has at least one unbroken run this long between BEGIN and END;
// prose, `...` and `<your key>` placeholders do not. Escaped newlines (`\n`
// inside a string literal) break runs at line boundaries, which still leaves
// full-length body lines.
const KEY_BODY_RUN = /[A-Za-z0-9+/]{40,}/;

/**
 * PEM private-key blocks embedded in text files (#270). Walks the same file
 * set as the text credential scan (`walkFiles`), minus key/cert files, which
 * the extension pass above already reports. The match `value` is the armor
 * label, never key material.
 */
export function scanEmbeddedPrivateKeys(targetDir: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  walkFiles(targetDir, (full) => {
    if (KEY_FILE_SEVERITY[path.extname(full).toLowerCase()]) return;
    let content: string;
    try {
      content = fs.readFileSync(full, 'utf-8');
    } catch {
      return;
    }
    if (!content.includes('PRIVATE KEY')) return;

    const re = new RegExp(PRIVATE_KEY_BEGIN.source, 'g');
    let m: RegExpExecArray | null;
    while ((m = re.exec(content)) !== null) {
      const label = m[1];
      const endMarker = `-----END ${label}-----`;
      const end = content.indexOf(endMarker, re.lastIndex);
      if (end === -1) continue;
      if (!KEY_BODY_RUN.test(content.slice(re.lastIndex, end))) continue;
      matches.push({
        value: label,
        filePath: full,
        line: content.slice(0, m.index).split('\n').length,
        findingId: 'CRED-KEYEMBED',
        envVar: '',
        severity: 'critical',
        title: 'Private key embedded in source',
        explanation: `A PEM ${label} block is written into this file. Anyone with repository access has the key material.`,
        businessImpact: 'Rotate the key, move it out of source (a key file outside the repository, or a vault/KMS), and load it at runtime.',
      });
      re.lastIndex = end + endMarker.length;
    }
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

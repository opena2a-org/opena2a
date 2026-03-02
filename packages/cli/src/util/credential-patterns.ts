/**
 * Shared credential detection patterns used by protect and init commands.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

// --- Types ---

export interface CredentialPattern {
  id: string;
  title: string;
  pattern: RegExp;
  envVarPrefix: string;
  severity: string;
  explanation: string;
  businessImpact: string;
}

export interface CredentialMatch {
  /** Original matched value (e.g., "sk-ant-api03-...") */
  value: string;
  /** File where the credential was found */
  filePath: string;
  /** Line number in the file */
  line: number;
  /** Finding ID (e.g., "CRED-001", "DRIFT-001") */
  findingId: string;
  /** Suggested environment variable name */
  envVar: string;
  /** Severity from the scanner */
  severity: string;
  /** Human-readable title */
  title: string;
  /** Plain-language explanation of the risk */
  explanation?: string;
  /** Business impact description */
  businessImpact?: string;
}

// --- Patterns ---

export const CREDENTIAL_PATTERNS: CredentialPattern[] = [
  {
    id: 'CRED-001',
    title: 'Anthropic API Key',
    pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{80,}/g,
    envVarPrefix: 'ANTHROPIC_API_KEY',
    severity: 'critical',
    explanation: 'Anthropic API key hardcoded in source. Anyone who reads this file can use your Anthropic account and access Claude models.',
    businessImpact: 'Thousands in unauthorized API charges within hours. Bots actively scan for exposed keys in public repos.',
  },
  {
    id: 'CRED-002',
    title: 'OpenAI API Key',
    pattern: /sk-(?:proj-|test-|svcacct-|live-)?[A-Za-z0-9_-]{20,}/g,
    envVarPrefix: 'OPENAI_API_KEY',
    severity: 'critical',
    explanation: 'OpenAI API key hardcoded in source. Grants full API access to anyone with the source code.',
    businessImpact: 'Unauthorized model usage, data extraction, and billing abuse. Exposed keys are exploited within minutes.',
  },
  {
    id: 'DRIFT-001',
    title: 'Google API Key (Gemini drift risk)',
    pattern: /AIza[0-9A-Za-z_-]{35,}/g,
    envVarPrefix: 'GOOGLE_API_KEY',
    severity: 'high',
    explanation: 'Google API key may have been provisioned for Maps but also grants Gemini AI access. Scope drift means the key can do more than intended.',
    businessImpact: 'Attacker could run AI workloads billed to your account. Cross-service scope drift means you pay for services you did not authorize.',
  },
  {
    id: 'DRIFT-002',
    title: 'AWS Access Key (Bedrock drift risk)',
    pattern: /AKIA[0-9A-Z]{16}/g,
    envVarPrefix: 'AWS_ACCESS_KEY_ID',
    severity: 'high',
    explanation: 'AWS access key may grant Bedrock LLM access beyond its intended S3/EC2 scope. IAM policies often over-provision.',
    businessImpact: 'Cross-service privilege escalation. AI model invocations billed to your account. Potential data exfiltration via Bedrock.',
  },
  {
    id: 'CRED-003',
    title: 'GitHub Token',
    pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    envVarPrefix: 'GITHUB_TOKEN',
    severity: 'high',
    explanation: 'GitHub token hardcoded in source. Grants repository access, potentially including private repos and org resources.',
    businessImpact: 'Code theft, supply chain injection via unauthorized commits, and access to private repositories.',
  },
  {
    id: 'CRED-004',
    title: 'Generic API Key in Assignment',
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_\-/.]{20,})['"]/gi,
    envVarPrefix: 'API_KEY',
    severity: 'medium',
    explanation: 'Generic API key found in a variable assignment. The pattern suggests a secret intended for environment variables, not source code.',
    businessImpact: 'Depends on the service -- could expose billing, data, or administrative access. Rotate immediately.',
  },
];

// Files/dirs to skip during scanning
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '.nuxt', '__pycache__', '.venv', 'venv',
  '.tox', '.mypy_cache', '.pytest_cache',
]);

export const SKIP_EXTENSIONS = new Set([
  '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp',
  '.woff', '.woff2', '.ttf', '.eot', '.otf',
  '.zip', '.tar', '.gz', '.bz2', '.7z',
  '.mp3', '.mp4', '.avi', '.mov', '.wav',
  '.pdf', '.doc', '.docx', '.xls', '.xlsx',
  '.exe', '.dll', '.so', '.dylib', '.o',
  '.lock', '.map',
]);

// --- File walker ---

export function walkFiles(dir: string, callback: (filePath: string) => void): void {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }

  // Dot-files to scan (credential sources)
  const SCAN_DOTFILES = new Set(['.env', '.env.example', '.env.local', '.env.development', '.env.production', '.env.staging', '.env.test']);

  for (const entry of entries) {
    if (entry.name.startsWith('.') && !SCAN_DOTFILES.has(entry.name)) continue;

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walkFiles(path.join(dir, entry.name), callback);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;
      // Skip large files (>1MB)
      try {
        const stat = fs.statSync(path.join(dir, entry.name));
        if (stat.size > 1_048_576) return;
      } catch {
        return;
      }
      callback(path.join(dir, entry.name));
    }
  }
}

// --- Quick scan (used by init) ---

export function quickCredentialScan(targetDir: string): CredentialMatch[] {
  const matches: CredentialMatch[] = [];
  const seen = new Set<string>();

  walkFiles(targetDir, (filePath) => {
    let content: string;
    try {
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      return;
    }

    const lines = content.split('\n');

    for (const pattern of CREDENTIAL_PATTERNS) {
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const re = new RegExp(pattern.pattern.source, pattern.pattern.flags);
        let match: RegExpExecArray | null;
        while ((match = re.exec(line)) !== null) {
          const value = match[1] ?? match[0];
          const dedupKey = `${value}:${filePath}`;

          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          // Skip if it looks like an env var reference already
          const before = line.slice(0, match.index);
          if (/process\.env\.\w*$/.test(before) ||
            /\$\{?\w*$/.test(before) ||
            /os\.environ\[['"]?\w*$/.test(before) ||
            /getenv\(['"]?\w*$/.test(before)) continue;

          const base = pattern.envVarPrefix;
          const existing = matches.filter(m => m.envVar.startsWith(base));
          const envVar = existing.length === 0 ? base : `${base}_${existing.length + 1}`;

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

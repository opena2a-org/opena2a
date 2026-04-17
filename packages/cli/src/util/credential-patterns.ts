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
  /**
   * Character class regex (anchored, character-class form e.g. `[A-Z0-9]`)
   * describing valid trailing chars for this token type. Used by
   * expandValueToFullToken to extend a fixed-length match into the source
   * token (a 21-char AWS key in a fixture, etc.) WITHOUT overshooting into
   * adjacent unrelated text (e.g. an AWS-style token immediately followed by
   * a `.hostname` suffix, where `.` is not part of the key).
   *
   * If undefined, no expansion is performed — the regex match is used as-is.
   */
  tailChars?: RegExp;
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
    businessImpact: 'Grants full Anthropic API access. Migrate to environment variables and rotate the key.',
  },
  {
    id: 'CRED-002',
    title: 'OpenAI API Key',
    pattern: /sk-(?!ant-)(?:proj-|test-|svcacct-|live-)?[A-Za-z0-9_-]{20,}/g,
    envVarPrefix: 'OPENAI_API_KEY',
    severity: 'critical',
    explanation: 'OpenAI API key hardcoded in source. Grants full API access to anyone with the source code.',
    businessImpact: 'Grants full OpenAI API access. Migrate to environment variables and rotate the key.',
  },
  {
    id: 'DRIFT-001',
    title: 'Google API Key (Gemini drift risk)',
    pattern: /AIza[0-9A-Za-z_-]{35,}/g,
    envVarPrefix: 'GOOGLE_API_KEY',
    severity: 'high',
    explanation: 'Google API key may have been provisioned for Maps but also grants Gemini AI access. Scope drift means the key can do more than intended.',
    businessImpact: 'Key may access more Google services than intended. Review IAM scoping and restrict to required APIs.',
  },
  {
    id: 'DRIFT-002',
    title: 'AWS Access Key (Bedrock drift risk)',
    pattern: /AKIA[0-9A-Z]{16}/g,
    envVarPrefix: 'AWS_ACCESS_KEY_ID',
    severity: 'high',
    explanation: 'AWS access key may grant Bedrock LLM access beyond its intended S3/EC2 scope. IAM policies often over-provision.',
    businessImpact: 'Key may access more AWS services than intended. Review IAM policies and restrict to required services.',
    // AWS keys are uppercase alnum only — stop at lowercase, dot, slash, etc.
    tailChars: /[0-9A-Z]/,
  },
  {
    id: 'CRED-005',
    title: 'AWS Secret Access Key',
    // ['"]{0,2} handles all three formats:
    //   .env:  AWS_SECRET_ACCESS_KEY=value          (no quotes around key or value)
    //   code:  secretAccessKey = "value"            (quote on value side only)
    //   JSON:  "AWS_SECRET_ACCESS_KEY": "value"     (closing key-quote + colon + opening value-quote)
    pattern: /(?:AWS_SECRET_ACCESS_KEY|aws[_-]?secret[_-]?access[_-]?key|secretAccessKey|SecretAccessKey)['"]{0,2}\s*[:=]\s*['"]{0,2}([A-Za-z0-9+\/]{40})/g,
    envVarPrefix: 'AWS_SECRET_ACCESS_KEY',
    severity: 'critical',
    explanation: 'AWS Secret Access Key hardcoded in source. Combined with an Access Key ID, this grants full programmatic AWS access to all authorized services.',
    businessImpact: 'Full AWS API access. Migrate to environment variables and rotate the key pair immediately.',
    // base64-ish; stop at quote, dot, equals (last two are delimiters in JSON/YAML).
    tailChars: /[A-Za-z0-9+/]/,
  },
  {
    id: 'CRED-003',
    title: 'GitHub Token',
    // gh[psur]: p=PAT, s=server-to-server, u=user-to-server OAuth, r=refresh token
    pattern: /gh[psur]_[A-Za-z0-9_]{36,}/g,
    envVarPrefix: 'GITHUB_TOKEN',
    severity: 'high',
    explanation: 'GitHub token hardcoded in source. Grants repository access, potentially including private repos and org resources.',
    businessImpact: 'Grants repository access. Migrate to environment variables and rotate the token.',
  },
  {
    id: 'CRED-006',
    title: 'Slack Token',
    pattern: /xox[bpra]-[0-9A-Za-z-]{30,}/g,
    envVarPrefix: 'SLACK_TOKEN',
    severity: 'high',
    explanation: 'Slack token hardcoded in source. Grants access to Slack workspaces, channels, and messages.',
    businessImpact: 'Grants Slack workspace access. Migrate to environment variables and rotate the token.',
  },
  {
    id: 'CRED-007',
    title: 'Stripe Secret Key',
    pattern: /sk_(?:live|test)_[A-Za-z0-9]{24,}/g,
    envVarPrefix: 'STRIPE_SECRET_KEY',
    severity: 'critical',
    explanation: 'Stripe secret key hardcoded in source. Grants full access to your Stripe account including charges, refunds, and customer data.',
    businessImpact: 'Full Stripe account access. Migrate to environment variables and rotate the key immediately.',
  },
  {
    id: 'CRED-004',
    title: 'Generic API Key in Assignment',
    // ['"]{0,2} around the separator handles JSON-quoted keys:
    //   .py / .js: api_key = "value"             (no quotes around key)
    //   JSON:      "WATSONX_API_KEY": "value"    (closing key-quote then colon then opening value-quote)
    // Vendor-prefixed env-var names like WATSONX_API_KEY contain "api_key"
    // case-insensitively, so `api_key` in the alternation still matches the
    // tail of the longer name.
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)['"]{0,2}\s*[:=]\s*['"]{0,2}([A-Za-z0-9_\-/.]{20,})['"]?/gi,
    envVarPrefix: 'API_KEY',
    severity: 'medium',
    explanation: 'Generic API key found in a variable assignment. The pattern suggests a secret intended for environment variables, not source code.',
    businessImpact: 'Access level depends on the service. Migrate to environment variables and rotate.',
  },
];

// Files/dirs to skip during scanning
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '.nuxt', '__pycache__', '.venv', 'venv',
  '.tox', '.mypy_cache', '.pytest_cache',
  '__tests__', 'test', 'tests', 'spec', 'specs',
  'fixtures', '__fixtures__', 'test-fixtures', 'testdata', 'test-data',
  'e2e',
]);

/**
 * Absolute path of the opena2a-cli package root, resolved at module load.
 * Used to skip the CLI's own source tree during scanning so that regex
 * pattern examples and replacement templates don't trigger self-scan findings.
 *
 * Resolved by walking up from this file's __dirname looking for a package.json
 * whose name is "opena2a-cli". Returns null if the walk fails, in which case
 * no self-exemption is applied (false positives on dev scans are preferable
 * to a silent substring-match bypass that skips user code sharing the path).
 */
const CLI_SELF_ROOT: string | null = (() => {
  try {
    let dir = __dirname;
    const root = path.parse(dir).root;
    while (dir && dir !== root) {
      const pkgPath = path.join(dir, 'package.json');
      if (fs.existsSync(pkgPath)) {
        try {
          const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
          if (pkg && pkg.name === 'opena2a-cli') return dir;
        } catch {
          // unreadable package.json — keep walking
        }
      }
      dir = path.dirname(dir);
    }
  } catch {
    // __dirname unavailable or fs error — fall through
  }
  return null;
})();

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

  // Skip the CLI's own source/dist tree to prevent false positives from
  // regex pattern examples and replacement templates. The exemption matches
  // only when `dir` is physically inside the opena2a-cli install directory
  // (anchored absolute-path prefix), not via substring — a substring check
  // would silently skip any user project whose path contains "packages/cli/src".
  if (CLI_SELF_ROOT) {
    const abs = path.resolve(dir);
    if (abs === CLI_SELF_ROOT || abs.startsWith(CLI_SELF_ROOT + path.sep)) return;
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
        if (stat.size > 1_048_576) continue;
      } catch {
        continue;
      }
      callback(path.join(dir, entry.name));
    }
  }
}

/**
 * Expand a regex-captured credential value to the full token in source.
 *
 * Patterns capture expected-format prefixes (e.g. AWS access key is AKIA+16
 * chars = exactly 20). When a real token in the file is longer (test fixture
 * with one extra char, custom prefix), the captured value is a truncated
 * prefix. Returning the truncated value lets dedup, vault-store, and
 * source-replace paths drift apart.
 *
 * `tailChars` constrains expansion to the same character class the pattern's
 * trailing repeater allowed. Without it, expansion would consume `.` `/` `=`
 * etc. and overshoot into hostnames or URL paths (e.g. an AWS-style token
 * immediately followed by `.amazonaws.com` would yield the whole hostname).
 * When `tailChars` is undefined, no expansion is performed.
 */
export function expandValueToFullToken(
  line: string,
  matchIndex: number,
  capturedValue: string,
  tailChars?: RegExp
): string {
  if (!tailChars) return capturedValue;
  const valueStart = line.indexOf(capturedValue, matchIndex);
  if (valueStart === -1) return capturedValue;
  const afterValue = line.slice(valueStart + capturedValue.length);
  let extra = '';
  for (const ch of afterValue) {
    if (tailChars.test(ch)) extra += ch;
    else break;
  }
  return capturedValue + extra;
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
          // Expand to full token so dedup against other scanners (e.g.
          // scanMcpCredentials, which uses the full env value) is consistent.
          const value = expandValueToFullToken(line, match.index, match[1] ?? match[0], pattern.tailChars);
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

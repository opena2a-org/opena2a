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
   * Name-gated patterns match a prefix-less value (e.g. a 40-char AWS secret
   * access key) only by the credential NAME, so the captured value must pass a
   * placeholder / low-entropy check — otherwise the AWS docs example
   * (`wJalr…EXAMPLEKEY`) and sentinels (`xxxx…`) would be flagged as real.
   */
  nameGated?: boolean;
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
    // The `sk-ant-api\d{2}-` prefix is highly specific to Anthropic, so a 20+ char
    // body is enough signal — matching the OpenAI floor (CRED-002 below) instead of
    // requiring the full ~95-char production length. A shorter floor catches the
    // realistic fake/short keys that 80+ silently skipped while OpenAI's sibling key
    // was flagged on the same line (issue #184: asymmetric coverage). No legitimate
    // non-credential string carries this prefix, so the lower floor adds no FPs.
    pattern: /sk-ant-api\d{2}-[A-Za-z0-9_-]{20,}/g,
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
  },
  {
    id: 'CRED-005',
    title: 'AWS Secret Access Key',
    // Name-gated (the value has no prefix). Two anchors ending in `key`:
    // `aws … secret|private … key` and the AWS-specific full phrase
    // `secret[_ ]access[_ ]key` (covers JS-SDK `secretAccessKey` and Terraform
    // `secret_access_key` with no nearby `aws`). The `key` token rejects
    // `aws secretsmanager arn:` / etag FPs; value captured in group 1. The
    // placeholder/low-entropy suppression (nameGated) drops the AWS docs
    // example + sentinel values. Mirrors HMA's canonical scanner.
    pattern: /(?:aws.{0,16}(?:secret|private).{0,16}key|secret[_\s.-]?access[_\s.-]?key)["'\s]*[:=]+>?\s*['"]?([A-Za-z0-9+/]{40})(?![A-Za-z0-9+/])/gi,
    envVarPrefix: 'AWS_SECRET_ACCESS_KEY',
    severity: 'critical',
    nameGated: true,
    explanation: 'AWS Secret Access Key hardcoded in source. Combined with an Access Key ID, this grants full programmatic AWS access to all authorized services.',
    businessImpact: 'Full AWS API access. Migrate to environment variables and rotate the key pair immediately.',
  },
  {
    id: 'CRED-003',
    title: 'GitHub Token',
    pattern: /gh[ps]_[A-Za-z0-9_]{36,}/g,
    envVarPrefix: 'GITHUB_TOKEN',
    severity: 'high',
    explanation: 'GitHub token hardcoded in source. Grants repository access, potentially including private repos and org resources.',
    businessImpact: 'Grants repository access. Migrate to environment variables and rotate the token.',
  },
  {
    id: 'CRED-004',
    title: 'Generic API Key in Assignment',
    pattern: /(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['"]([A-Za-z0-9_\-/.]{20,})['"]/gi,
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
  'fixtures', 'testdata', 'test-data',
  'e2e',
  // VHS recording assets — convention is to embed placeholder credentials
  // for terminal-recording demos. Matches `docs/vhs/`, `vhs/` etc.
  'vhs',
]);

/**
 * Filename patterns that indicate test or demo files where credential-shaped
 * strings are intentional placeholders, not real exposures. Matches files
 * that live alongside source (e.g. `src/dlp/dlp.test.ts`) and aren't caught
 * by the SKIP_DIRS directory walk.
 *
 * Tradeoff: a real credential committed into a `*.test.ts` or `demo-*.sh`
 * file will not be flagged by this scanner. Real-credential exposure in
 * those paths is the wrong layer to fix — use git pre-commit hooks or
 * `git secrets`. The scanner's job here is composite-score correctness.
 */
export const SKIP_FILENAME_PATTERNS: RegExp[] = [
  /\.(test|spec)\.(?:tsx?|jsx?|mjs|cjs|py)$/i,
  /_test\.(?:go|py)$/i,
  /^demo[-_].*\.(?:sh|ts|js|py)$/i,
];

/**
 * Canonical list of template env files. They hold PLACEHOLDER values by
 * convention (e.g. `OPENAI_API_KEY=sk-your-key-here`), are meant to be
 * committed and edited, and per the project Secretless policy are explicitly
 * NOT credential surfaces — scanning them produces noisy CRITICAL false
 * positives (a `sk-…` placeholder is not a real exposure).
 *
 * Enforcement: these names are simply omitted from `SCAN_DOTFILES` in
 * `walkFiles`, so the existing "dot-name not in the allowlist is skipped" rule
 * excludes them — no separate skip branch (which would also have skipped a
 * directory of the same name). Real env files (`.env`, `.env.local`,
 * `.env.production`, …) stay in the allowlist and still scan. Detecting a real
 * secret accidentally pasted into a template is the wrong layer (use
 * git-secrets / a pre-commit hook), not the migration scanner. Exported so
 * callers/tests share one source of truth for "what is a template env file".
 */
export const TEMPLATE_ENV_FILES = new Set([
  '.env.example', '.env.sample', '.env.template', '.env.dist',
]);

/**
 * True when a name-gated credential value is a placeholder/sentinel rather than
 * a real secret. Used for prefix-less patterns (e.g. AWS secret access key)
 * where the value alone can't be trusted: catches the AWS docs example
 * (`wJalr…EXAMPLEKEY`), `YOUR_…`/`REPLACE_ME` templates, and low-entropy fillers
 * (`xxxx…`, `0000…`). A real 40-char base64 key has ~30+ distinct chars, far
 * above the entropy floor, so this never suppresses a genuine key.
 */
export function isPlaceholderSecretValue(value: string): boolean {
  if (/FAKE|EXAMPLE|PLACEHOLDER|DUMMY|YOUR[_-]?(?:KEY|SECRET|TOKEN)|REPLACE[_-]?ME|INSERT[_-]?HERE|SAMPLE|CHANGE[_-]?ME|TEST[_-]?(?:KEY|SECRET)/i.test(value)) {
    return true;
  }
  // Low-entropy fillers (40 `x`s, 40 `0`s, repeated short runs).
  if (new Set(value).size <= 6) return true;
  return false;
}

/**
 * Local finding IDs whose label is a generic/catch-all bucket and so should be
 * refined against the canonical `@opena2a/credential-patterns` catalog:
 *
 *   - CRED-002 ("OpenAI API Key") matches `sk-(?!ant-)…` — a broad rule that
 *     labels EVERY non-Anthropic `sk-` token "OpenAI API Key", which is wrong for
 *     OpenRouter (`sk-or-v1-`) and any future `sk-`-prefixed provider.
 *   - CRED-004 ("Generic API Key in Assignment") captures whatever sits inside
 *     `api_key = "…"`, so the value may be a Stripe (`sk_live_…`), Slack, etc.
 *
 * The other local patterns are intentionally specific (Anthropic, GitHub) or
 * carry deliberate framing the catalog lacks — DRIFT-001/002 say "(Gemini drift
 * risk)" / "(Bedrock drift risk)" — so they are NOT refined.
 */
const REFINABLE_FINDING_IDS = new Set(['CRED-002', 'CRED-004']);

/**
 * Minimal shape of a `@opena2a/credential-patterns` catalog entry. Declared
 * locally so this CommonJS module needs no static (type) import from that
 * ESM-only package — the catalog is pulled in at runtime via a dynamic
 * `import()` (see {@link loadCanonicalPatterns}).
 */
export interface CanonicalCredentialPattern {
  id: string;
  name: string;
  regex: RegExp;
  envPrefix: string;
  category?: string;
}

/**
 * Lazily import the canonical catalog from the ESM-only
 * `@opena2a/credential-patterns` package. This CLI is CommonJS, so a static
 * `import` would emit a `require()` that fails on an ESM target — the dynamic
 * `import()` is the supported bridge. The resolved array is memoised, so the
 * package is loaded at most once per process. On any import failure (e.g. the
 * dependency is absent in a degraded install) it resolves to `[]`, and every
 * caller falls back to its local label rather than crashing.
 */
let _canonicalPatterns: Promise<CanonicalCredentialPattern[]> | null = null;
export function loadCanonicalPatterns(): Promise<CanonicalCredentialPattern[]> {
  if (!_canonicalPatterns) {
    _canonicalPatterns = import('@opena2a/credential-patterns')
      .then(m => m.CREDENTIAL_PATTERNS as CanonicalCredentialPattern[])
      .catch(() => []);
  }
  return _canonicalPatterns;
}

/**
 * Map a raw credential value onto the canonical catalog to recover the precise
 * provider label and env-var prefix. The catalog orders specific prefixes before
 * catch-alls (`sk-ant-` / `sk-proj-` / `sk-or-v1-` before `sk-[48,]`; Stripe
 * `sk_live_`/`sk_test_` are their own entries), so the FIRST entry whose regex
 * matches the value is the correct provider.
 *
 * Returns null when nothing in the catalog matches — callers keep their local
 * label. Detection is unchanged: this only relabels values the local scanner
 * already flagged, never widens or narrows what gets flagged.
 */
export function classifyCredentialValue(
  value: string,
  catalog: CanonicalCredentialPattern[],
): { title: string; envVarPrefix: string } | null {
  for (const p of catalog) {
    // The catalog regexes are non-global, but clone defensively so a stray `g`
    // flag can't leak `lastIndex` state across calls.
    const re = new RegExp(p.regex.source, p.regex.flags.replace('g', ''));
    if (re.test(value)) {
      return { title: p.name, envVarPrefix: p.envPrefix };
    }
  }
  return null;
}

/**
 * A (possibly refined) credential label. `explanation`/`businessImpact` are only
 * populated when a refinement actually changed the title, in which case they
 * carry provider-neutral prose; otherwise they are absent and the caller keeps
 * the local pattern's richer provider-specific copy.
 */
export interface RefinedCredentialLabel {
  title: string;
  envVarPrefix: string;
  explanation?: string;
  businessImpact?: string;
}

/**
 * Apply {@link classifyCredentialValue} to a local match, but only for the
 * generic/catch-all buckets in {@link REFINABLE_FINDING_IDS}.
 *
 * When the catalog recovers a DIFFERENT provider than the local pattern's title
 * (e.g. "OpenRouter API Key" in place of CRED-002's "OpenAI API Key", or "Stripe
 * Live Key" in place of CRED-004's "Generic API Key in Assignment"), the local
 * pattern's `explanation`/`businessImpact` prose now names the wrong provider or
 * is generic. To avoid shipping a label that contradicts its own rationale
 * ("OpenRouter API Key … grants full OpenAI API access"), this also returns
 * provider-neutral prose keyed off the refined title. The catalog carries no
 * prose of its own, so neutral-but-correct is the safe choice over inventing
 * provider-specific copy.
 *
 * When the catalog agrees with the local title (no real change) or nothing
 * matches, the fallback is returned unchanged and the caller keeps its local
 * prose.
 */
export function refineCredentialLabel(
  findingId: string,
  value: string,
  fallback: { title: string; envVarPrefix: string },
  catalog: CanonicalCredentialPattern[],
): RefinedCredentialLabel {
  if (!REFINABLE_FINDING_IDS.has(findingId)) return fallback;
  const classified = classifyCredentialValue(value, catalog);
  if (!classified || classified.title === fallback.title) return fallback;
  return {
    title: classified.title,
    envVarPrefix: classified.envVarPrefix,
    explanation: `${classified.title} hardcoded in source. Anyone who can read this file can use it to access the associated account.`,
    businessImpact: 'Grants access to the associated service. Migrate to an environment variable and rotate the credential.',
  };
}

const CASE_INSENSITIVE_FS = process.platform === 'darwin' || process.platform === 'win32';

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
  // On case-insensitive filesystems (APFS/HFS+ on darwin, NTFS on win32) the
  // comparison is also case-insensitive so that a user-typed lowercase path
  // still matches the real install location.
  if (CLI_SELF_ROOT) {
    const abs = path.resolve(dir);
    const a = CASE_INSENSITIVE_FS ? abs.toLowerCase() : abs;
    const r = CASE_INSENSITIVE_FS ? CLI_SELF_ROOT.toLowerCase() : CLI_SELF_ROOT;
    if (a === r || a.startsWith(r + path.sep)) return;
  }

  // Dot-files to scan (credential sources). This is an explicit allowlist:
  // any dot-name NOT listed here is skipped by the rule below (files AND
  // directories alike — hidden dirs like .git/.vscode/.config are never
  // recursed). Template env files (TEMPLATE_ENV_FILES: .env.example/.sample/
  // .template/.dist) are deliberately OMITTED — they hold placeholders, not
  // live secrets, so a `sk-…` value in them is not a real exposure. Do NOT
  // add a template name here: it would re-introduce the .env.example CRITICAL
  // false positive (opena2a-cli 0.10.8 fresh-user finding).
  const SCAN_DOTFILES = new Set(['.env', '.env.local', '.env.development', '.env.production', '.env.staging', '.env.test']);

  for (const entry of entries) {
    if (entry.name.startsWith('.') && !SCAN_DOTFILES.has(entry.name)) continue;

    if (entry.isDirectory()) {
      if (SKIP_DIRS.has(entry.name)) continue;
      walkFiles(path.join(dir, entry.name), callback);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SKIP_EXTENSIONS.has(ext)) continue;
      if (SKIP_FILENAME_PATTERNS.some(re => re.test(entry.name))) continue;
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

// --- Quick scan (used by init) ---

export async function quickCredentialScan(targetDir: string): Promise<CredentialMatch[]> {
  const matches: CredentialMatch[] = [];
  const seen = new Set<string>();
  // Loaded once before the walk so per-value label refinement stays synchronous.
  const catalog = await loadCanonicalPatterns();

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
          // Name-gated patterns match a prefix-less value purely by name, so a
          // placeholder / low-entropy value (AWS docs `wJalr…EXAMPLEKEY`,
          // `xxxx…`, `0000…`) must be dropped — it's not a real exposure.
          if (pattern.nameGated && isPlaceholderSecretValue(value)) continue;
          const dedupKey = `${value}:${filePath}`;

          if (seen.has(dedupKey)) continue;
          seen.add(dedupKey);

          // Skip if it looks like an env var reference already
          const before = line.slice(0, match.index);
          if (/process\.env\.\w*$/.test(before) ||
            /\$\{?\w*$/.test(before) ||
            /os\.environ\[['"]?\w*$/.test(before) ||
            /getenv\(['"]?\w*$/.test(before)) continue;

          // Refine the catch-all label (CRED-002/CRED-004) against the canonical
          // catalog so a `sk-or-v1-…` / Stripe `sk_live_…` value isn't surfaced
          // as "OpenAI API Key". Specific patterns keep their local label.
          const refined = refineCredentialLabel(pattern.id, value, {
            title: pattern.title,
            envVarPrefix: pattern.envVarPrefix,
          }, catalog);
          const base = refined.envVarPrefix;
          const existing = matches.filter(m => m.envVar.startsWith(base));
          const envVar = existing.length === 0 ? base : `${base}_${existing.length + 1}`;

          matches.push({
            value,
            filePath,
            line: i + 1,
            findingId: pattern.id,
            envVar,
            severity: pattern.severity,
            title: refined.title,
            // Refined prose is present only when the title changed; otherwise
            // keep the local pattern's richer provider-specific copy.
            explanation: refined.explanation ?? pattern.explanation,
            businessImpact: refined.businessImpact ?? pattern.businessImpact,
          });
        }
      }
    }
  });

  return matches;
}

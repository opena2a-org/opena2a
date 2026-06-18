/**
 * opena2a comply -- inline compliance classifier for AI agent I/O.
 *
 * Detects PII, credentials, and regulated data in content before an agent
 * forwards it to a hosted LLM. Detection + verdict are delegated to the
 * @opena2a/aicomply library's public `comply()` API -- the single shared
 * source of truth for the regex (and, when a local nanomind-daemon is
 * reachable, semantic Guard) classification. This command only collects
 * sources and renders the result in opena2a house-style.
 *
 * Output never prints a raw detected value: every finding is masked, and the
 * mask is fail-safe for SHORT values (a short secret is fully masked rather
 * than revealing most of it through a fixed-length head). Untrusted strings
 * (file labels, finding types) are passed through cli-ui's terminal sanitizer
 * before rendering so a crafted value cannot inject control bytes.
 *
 * Exit codes make it usable as a CI gate:
 *   0  CLEAN          no findings, safe to forward
 *   1  VIOLATION/DENY findings present
 *   2  usage error    (bad/oversize path, no input on a terminal, IO error,
 *                      or an internal classification failure -- fail closed)
 */

import { readFileSync, statSync } from 'node:fs';
import { comply } from '@opena2a/aicomply';
import type { ComplyResult, Verdict, Violation } from '@opena2a/aicomply';
import { bold, dim, green, yellow, red, gray, cyan } from '../util/colors.js';

export interface ComplyCommandOptions {
  /** Positional file arguments. `-` means stdin. Empty = read stdin. */
  files: string[];
  ci?: boolean;
  format?: string;
  quiet?: boolean;
  verbose?: boolean;
}

interface Source {
  label: string;
  content: string;
}

/**
 * Upper bound on a single input (file or stdin). `comply` is an inline gate
 * for a message / transcript, not a bulk file scanner, so anything larger is
 * almost certainly a mistake -- and reading it unbounded would OOM-crash the
 * gate (a trivial DoS). Over-limit input fails closed with a usage error
 * rather than being silently truncated to a misleading CLEAN verdict.
 */
export const MAX_INPUT_BYTES = 5 * 1024 * 1024; // 5 MiB

/** A recoverable usage problem -> exit code 2. */
class UsageError extends Error {}

/**
 * Mask a detected value so the CLI never prints a meaningful slice of a
 * secret. Values of 8 chars or fewer are masked entirely -- a fixed-length
 * head would otherwise reveal most of a short password / token / SSN segment.
 * Longer values reveal a 3-char head and 2-char tail only (at most 5 chars,
 * a small fraction), enough to recognize a finding without disclosing it.
 */
export function maskValue(value: string): string {
  const v = value ?? '';
  const n = v.length;
  if (n === 0) return '•';
  if (n <= 8) return '•'.repeat(n);
  const head = v.slice(0, 3);
  const tail = v.slice(-2);
  return `${head}${'•'.repeat(n - 5)}${tail}`;
}

/** Strip terminal control bytes as a fallback if the cli-ui sanitizer can't load. */
function fallbackSanitize(s: string): string {
  // Strip C0/C1 control bytes (incl. ESC 0x1b) and DEL so a crafted value
  // can't inject ANSI escape sequences into the terminal.
  // eslint-disable-next-line no-control-regex
  return s.replace(/[\x00-\x1f\x7f-\x9f]/g, '');
}

/** Resolve cli-ui's terminal sanitizer, falling back to a local stripper. */
async function loadSanitizer(): Promise<(s: string) => string> {
  try {
    const cliUi = await import('@opena2a/cli-ui');
    if (typeof cliUi.sanitizeForTerminal === 'function') return cliUi.sanitizeForTerminal;
  } catch {
    // cli-ui (ESM) unavailable in this runtime -- use the local fallback.
  }
  return fallbackSanitize;
}

function readStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = '';
    let bytes = 0;
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk: string) => {
      bytes += Buffer.byteLength(chunk);
      if (bytes > MAX_INPUT_BYTES) {
        // Stop reading and fail closed rather than buffer an unbounded stream.
        process.stdin.pause();
        reject(
          new UsageError(
            `stdin exceeds the ${MAX_INPUT_BYTES / (1024 * 1024)} MiB limit. Pipe a smaller excerpt.`,
          ),
        );
        return;
      }
      data += chunk;
    });
    process.stdin.on('end', () => resolve(data));
    // Fail closed on a read error -- never resolve partial content into a
    // misleading CLEAN verdict.
    process.stdin.on('error', () => reject(new UsageError('could not read stdin (IO error).')));
  });
}

async function collectSources(files: string[]): Promise<Source[]> {
  const stdinRequested = files.length === 0 || files.includes('-');
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
    let size: number;
    try {
      size = statSync(file).size;
    } catch {
      throw new UsageError(
        `cannot read '${file}' (check the path). Try 'opena2a comply --help'.`,
      );
    }
    if (size > MAX_INPUT_BYTES) {
      throw new UsageError(
        `'${file}' is ${(size / (1024 * 1024)).toFixed(1)} MiB, over the ` +
          `${MAX_INPUT_BYTES / (1024 * 1024)} MiB limit. Scan a smaller excerpt.`,
      );
    }
    try {
      sources.push({ label: file, content: readFileSync(file, 'utf8') });
    } catch {
      throw new UsageError(
        `cannot read '${file}' (check the path). Try 'opena2a comply --help'.`,
      );
    }
  }

  if (stdinRequested) {
    if (process.stdin.isTTY) {
      // No piped input and no files -- guide the user rather than hang.
      throw new UsageError(
        'no input. Pass a file or pipe content:\n' +
          '  opena2a comply ./file.txt\n' +
          '  echo "My SSN is 123-45-6789" | opena2a comply',
      );
    }
    sources.push({ label: '(stdin)', content: await readStdin() });
  }

  return sources;
}

function guardActive(result: ComplyResult): boolean {
  return result.classifierResults.guard !== undefined;
}

function worstVerdict(results: ComplyResult[]): Verdict {
  if (results.some((r) => r.verdict === 'DENY')) return 'DENY';
  if (results.some((r) => r.verdict === 'VIOLATION')) return 'VIOLATION';
  return 'CLEAN';
}

function verdictColor(verdict: Verdict): (s: string) => string {
  if (verdict === 'CLEAN') return green;
  if (verdict === 'DENY') return red;
  return yellow;
}

/**
 * Machine-readable output. Mirrors the standalone aicomply `--json` field
 * shape so downstream tooling sees the same schema from either surface (the
 * masked-value string differs: comply masks short values more aggressively).
 * Masked values only -- `originalContent` is never serialized. JSON.stringify
 * escapes any control bytes, so the JSON path needs no extra sanitization.
 */
function renderJson(sources: Source[], results: ComplyResult[]): void {
  const payload = sources.map((src, i) => ({
    source: src.label,
    verdict: results[i].verdict,
    guardActive: guardActive(results[i]),
    findings: results[i].violations.map((v: Violation) => ({
      type: v.type,
      maskedValue: maskValue(v.value),
      confidence: v.confidence,
      classifier: v.classifier,
      view: v.view ?? 'normalized',
    })),
  }));
  process.stdout.write(JSON.stringify(payload, null, 2) + '\n');
}

function renderHuman(
  sources: Source[],
  results: ComplyResult[],
  ci: boolean,
  sanitize: (s: string) => string,
): void {
  const out = process.stdout;
  let anyGuard = false;
  let totalFindings = 0;

  if (!ci) out.write('\n');
  for (let i = 0; i < sources.length; i++) {
    const label = sanitize(sources[i].label);
    const res = results[i];
    if (guardActive(res)) anyGuard = true;
    totalFindings += res.violations.length;

    const color = verdictColor(res.verdict);
    out.write(`  ${color(bold(res.verdict.padEnd(9)))} ${label}\n`);

    if (res.verdict === 'CLEAN') {
      out.write(`    ${dim('no PII, credentials, or regulated data detected')}\n`);
      continue;
    }

    out.write(
      `    ${res.violations.length} finding${res.violations.length === 1 ? '' : 's'}\n`,
    );
    for (const v of res.violations as Violation[]) {
      // Both the finding type and the masked value are untrusted (a Guard
      // result type or the head/tail of a detected value could contain
      // control bytes); sanitize before writing to the terminal.
      const type = sanitize(v.type);
      const masked = sanitize(maskValue(v.value));
      const view = v.view && v.view !== 'normalized' ? `  ${dim(`view ${sanitize(v.view)}`)}` : '';
      out.write(
        `      ${cyan(type.padEnd(12))} ${masked.padEnd(18)} ` +
          `${dim(`confidence ${v.confidence.toFixed(2)}`)}  ${dim(`layer ${v.classifier}`)}${view}\n`,
      );
    }
  }

  // Observation block (CISO Rule 11): always state which layers actually ran,
  // even on a CLEAN verdict, and give a recovery path -- never a dead end.
  out.write('\n');
  out.write(`  ${dim('Layers:')} ${green('regex')} (always-on)`);
  if (anyGuard) {
    out.write(`, ${green('semantic Guard')} (nanomind-daemon)\n`);
  } else {
    out.write(`, ${gray('semantic Guard inactive')}\n`);
    out.write(
      `  ${dim('Guard catches prompt-injection / exfiltration the regex layer cannot see. Enable it:')}\n` +
        `    ${cyan('npm i @nanomind/daemon && npx nanomind-daemon start')}\n`,
    );
  }

  out.write('\n');
  const worst = worstVerdict(results);
  if (worst === 'CLEAN') {
    out.write(`  ${green(bold('Verdict: CLEAN'))}  ${dim('safe to forward.')}\n`);
  } else {
    const color = verdictColor(worst);
    out.write(
      `  ${color(bold(`Verdict: ${worst}`))}  ` +
        `${dim(`${totalFindings} finding${totalFindings === 1 ? '' : 's'} across ${sources.length} input${sources.length === 1 ? '' : 's'}. Block, redact, or log before this content reaches an LLM.`)}\n`,
    );
  }
}

/**
 * Run the comply command. Pure with respect to process exit -- returns the
 * intended exit code; the caller sets `process.exitCode`.
 */
export async function runComply(options: ComplyCommandOptions): Promise<number> {
  let sources: Source[];
  try {
    sources = await collectSources(options.files);
  } catch (err) {
    if (err instanceof UsageError) {
      process.stderr.write(`opena2a comply: ${err.message}\n`);
      return 2;
    }
    throw err;
  }

  const results: ComplyResult[] = [];
  try {
    for (const src of sources) {
      results.push(await comply({ content: src.content }));
    }
  } catch (err) {
    // An unexpected failure in the classification engine must fail closed --
    // never report CLEAN, never crash with a raw stack trace. Exit 2 keeps a
    // CI gate red and is distinct from a real finding (exit 1).
    const message = err instanceof Error ? err.message : String(err);
    process.stderr.write(`opena2a comply: classification failed: ${message}\n`);
    return 2;
  }

  const json = options.format === 'json';
  if (json) {
    renderJson(sources, results);
  } else if (options.quiet) {
    process.stdout.write(`${worstVerdict(results)}\n`);
  } else {
    const sanitize = await loadSanitizer();
    renderHuman(sources, results, options.ci === true, sanitize);
  }

  // Exit 1 when anything is not CLEAN so the command works as a CI gate.
  return results.some((r) => r.verdict !== 'CLEAN') ? 1 : 0;
}

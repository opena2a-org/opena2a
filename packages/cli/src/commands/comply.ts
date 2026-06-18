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
 * Output never prints a raw detected value: every finding is masked
 * (head + bullets + short tail), matching the standalone `aicomply` CLI.
 *
 * Exit codes make it usable as a CI gate:
 *   0  CLEAN          no findings, safe to forward
 *   1  VIOLATION/DENY findings present
 *   2  usage error    (bad path, or no input on an interactive terminal)
 */

import { readFileSync } from 'node:fs';
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
 * Mask a detected value so the CLI never prints a full secret to a terminal
 * or log. Kept byte-for-byte identical to the standalone aicomply CLI so the
 * two surfaces render the same masked form.
 */
export function maskValue(value: string): string {
  const v = value ?? '';
  if (v.length <= 4) return '•'.repeat(v.length || 1);
  const head = v.slice(0, 4);
  const tail = v.length > 8 ? v.slice(-2) : '';
  return `${head}${'•'.repeat(Math.max(3, v.length - head.length - tail.length))}${tail}`;
}

function readStdin(): Promise<string> {
  return new Promise((resolve) => {
    let data = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => (data += chunk));
    process.stdin.on('end', () => resolve(data));
    process.stdin.on('error', () => resolve(data));
  });
}

/** A recoverable usage problem -> exit code 2. */
class UsageError extends Error {}

async function collectSources(files: string[]): Promise<Source[]> {
  const stdinRequested = files.length === 0 || files.includes('-');
  const realFiles = files.filter((f) => f !== '-');
  const sources: Source[] = [];

  for (const file of realFiles) {
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
 * Machine-readable output. Mirrors the standalone aicomply `--json` shape so
 * downstream tooling sees the same schema from either surface. Masked values
 * only -- `originalContent` is never serialized.
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

function renderHuman(sources: Source[], results: ComplyResult[], ci: boolean): void {
  const out = process.stdout;
  let anyGuard = false;
  let totalFindings = 0;

  if (!ci) out.write('\n');
  for (let i = 0; i < sources.length; i++) {
    const src = sources[i];
    const res = results[i];
    if (guardActive(res)) anyGuard = true;
    totalFindings += res.violations.length;

    const color = verdictColor(res.verdict);
    out.write(`  ${color(bold(res.verdict.padEnd(9)))} ${src.label}\n`);

    if (res.verdict === 'CLEAN') {
      out.write(`    ${dim('no PII, credentials, or regulated data detected')}\n`);
      continue;
    }

    out.write(
      `    ${res.violations.length} finding${res.violations.length === 1 ? '' : 's'}\n`,
    );
    for (const v of res.violations as Violation[]) {
      const masked = maskValue(v.value);
      const view = v.view && v.view !== 'normalized' ? `  ${dim(`view ${v.view}`)}` : '';
      out.write(
        `      ${cyan(v.type.padEnd(12))} ${masked.padEnd(18)} ` +
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
  for (const src of sources) {
    results.push(await comply({ content: src.content }));
  }

  const json = options.format === 'json';
  if (json) {
    renderJson(sources, results);
  } else if (options.quiet) {
    process.stdout.write(`${worstVerdict(results)}\n`);
  } else {
    renderHuman(sources, results, options.ci === true);
  }

  // Exit 1 when anything is not CLEAN so the command works as a CI gate.
  return results.some((r) => r.verdict !== 'CLEAN') ? 1 : 0;
}

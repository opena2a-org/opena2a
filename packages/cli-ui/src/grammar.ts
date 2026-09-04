/**
 * Terminal grammar primitives — the six front-door renderers plus the
 * `envelope` builder from the CDO design-function ruling (COUNCIL_LEDGER
 * 56558, second ruling, decision 2).
 *
 * Every OpenA2A CLI front door speaks one grammar:
 *   - the verdict line comes first: one line, no leading blank;
 *   - the score only ever shows the path up (`72/100 -> 100 by <cmd>`) —
 *     never a delta (`-5`), never a letter grade (`B+`);
 *   - a finding always carries, in order: severity, title, `file:line`,
 *     one sentence of why, a `Verify:` command, a `Fix:` command, and at
 *     most one URL;
 *   - next steps are one to three runnable commands;
 *   - progress goes to a caller-supplied stderr sink, never stdout, and
 *     never leaks the home directory;
 *   - an error says what happened, what was not changed, and the one
 *     command to run next.
 *
 * Color discipline: a non-empty NO_COLOR, or a sink that reports non-TTY,
 * always wins — output is then the plain form with zero `\x1b` bytes. The
 * paired runner (`frontDoorConformance` in conformance.ts) re-checks the
 * same rules against a built binary.
 *
 * This module's runtime exports are exactly the seven names pinned by
 * OPA-03.AC1; everything else here is a type or module-private.
 */

import os from "node:os";
import { Chalk, type ChalkInstance } from "chalk";
import { normalizeVerdict } from "./verdict.js";
import { sanitizeForTerminal } from "./terminal-safe.js";

export type GrammarSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface GrammarRenderOptions {
  /**
   * Force color on or off. A non-empty NO_COLOR environment variable and
   * `isTTY: false` both override `color: true` — the rule is a floor, not
   * a preference.
   */
  color?: boolean;
  /** TTY-ness of the destination stream; `false` disables color. */
  isTTY?: boolean;
}

export interface VerdictLineInput {
  /** Verdict word or its registry variants ("passed", "failed", ...). */
  verdict: string;
  /** Optional short clause rendered after an em dash. */
  summary?: string;
}

export interface ScoreLineInput {
  /** Score on the 0-100 scale; clamped and rounded. */
  score: number;
  /**
   * The action that takes the score to 100, rendered as
   * ` -> 100 by <pathTo100>`. The grammar never renders what was lost —
   * only the path up.
   */
  pathTo100?: string;
}

export interface GrammarFinding {
  severity: GrammarSeverity;
  title: string;
  /** Repo-relative file path of the evidence. */
  file: string;
  line: number;
  /** One sentence: why this matters. */
  why: string;
  /** Runnable command that re-observes the finding. */
  verify: string;
  /** Runnable command that remediates the finding. */
  fix: string;
  /** At most one URL per finding; only this field renders as a link. */
  url?: string;
}

export interface ProgressSink {
  write(chunk: string): unknown;
  isTTY?: boolean;
}

export interface ProgressInput {
  label: string;
  current?: number;
  total?: number;
}

export interface GrammarErrorInput {
  /** What happened. */
  what: string;
  /** What was not changed — the safety statement. */
  unchanged: string;
  /** The one command to run next. */
  next: string;
}

export interface Envelope {
  schemaVersion: string;
  tool: string;
  version: string;
  verdict: string;
  score: number;
  findings: GrammarFinding[];
  nextSteps: string[];
  exitCode: number;
}

export interface EnvelopeInput {
  /** Defaults to "1". */
  schemaVersion?: string;
  tool: string;
  version: string;
  verdict: string;
  score: number;
  findings?: GrammarFinding[];
  nextSteps: string[];
  exitCode: number;
}

const METER_WIDTH = 20;

const colorChalk = new Chalk({ level: 3 });
const plainChalk = new Chalk({ level: 0 });

function resolveChalk(opts?: GrammarRenderOptions): ChalkInstance {
  const noColor = process.env.NO_COLOR;
  if (noColor !== undefined && noColor !== "") return plainChalk;
  if (opts?.isTTY === false) return plainChalk;
  if (opts?.color !== undefined) return opts.color ? colorChalk : plainChalk;
  return process.stdout.isTTY === true ? colorChalk : plainChalk;
}

/** Sanitize a caller string and collapse it onto one line. */
function oneLine(s: string | undefined | null): string {
  return sanitizeForTerminal(s).replace(/\s*\n\s*/g, " ").trim();
}

/**
 * Replace the home directory (os.homedir() and $HOME) with `~` so paths in
 * progress text never disclose the account name.
 */
function scrubHome(text: string): string {
  const homes = new Set<string>();
  const detected = os.homedir();
  if (detected && detected.length > 1) homes.add(detected);
  const fromEnv = process.env.HOME;
  if (fromEnv && fromEnv.length > 1) homes.add(fromEnv);
  let out = text;
  for (const home of homes) out = out.split(home).join("~");
  return out;
}

function severityColor(c: ChalkInstance, severity: GrammarSeverity) {
  switch (severity) {
    case "critical":
      return c.red.bold;
    case "high":
      return c.red;
    case "medium":
      return c.yellow;
    case "low":
      return c.blue;
    case "info":
      return c.dim;
  }
}

/**
 * The verdict line — always the first thing a front door prints. Exactly
 * one line, no leading blank line.
 */
export function renderVerdict(input: VerdictLineInput, opts?: GrammarRenderOptions): string {
  const c = resolveChalk(opts);
  const normalized = normalizeVerdict(oneLine(input.verdict));
  let symbol: string;
  let paint: (text: string) => string;
  switch (normalized) {
    case "safe":
      symbol = "✔";
      paint = c.green;
      break;
    case "warning":
      symbol = "⚠";
      paint = c.yellow;
      break;
    case "blocked":
      symbol = "✖";
      paint = c.red;
      break;
    case "listed":
      symbol = "◆";
      paint = c.cyan;
      break;
    default:
      symbol = "•";
      paint = c.gray;
      break;
  }
  const summary = oneLine(input.summary);
  const head = paint(`${symbol} ${normalized.toUpperCase()}`);
  return summary === "" ? head : `${head} — ${summary}`;
}

/**
 * The score line plus its meter. First line is always plain text matching
 * `^\d{1,3}/100( -> 100 by .+)?$` — no delta, no letter grade, no ANSI.
 */
export function renderScore(input: ScoreLineInput, opts?: GrammarRenderOptions): string {
  const c = resolveChalk(opts);
  const score = Math.min(100, Math.max(0, Math.round(input.score)));
  const path = oneLine(input.pathTo100);
  const head = path === "" ? `${score}/100` : `${score}/100 -> 100 by ${path}`;
  const filledCount = Math.round((score / 100) * METER_WIDTH);
  const paint = score >= 70 ? c.green : score >= 40 ? c.yellow : c.red;
  const meter =
    paint("━".repeat(filledCount)) + c.dim("─".repeat(METER_WIDTH - filledCount));
  return `${head}\n${meter}`;
}

/**
 * One finding block: severity, title, `file:line`, one sentence of why,
 * `Verify:` command, `Fix:` command, then the (at most one) URL.
 */
export function renderFinding(finding: GrammarFinding, opts?: GrammarRenderOptions): string {
  const c = resolveChalk(opts);
  const paint = severityColor(c, finding.severity);
  const locator = `${oneLine(finding.file)}:${Math.max(0, Math.round(finding.line))}`;
  const lines = [
    `${paint(finding.severity.toUpperCase())}  ${c.bold(oneLine(finding.title))}  ${c.dim(locator)}`,
    `  ${oneLine(finding.why)}`,
    `  Verify: ${c.cyan(oneLine(finding.verify))}`,
    `  Fix: ${c.cyan(oneLine(finding.fix))}`,
  ];
  const url = oneLine(finding.url);
  if (url !== "") lines.push(`  ${c.dim(url)}`);
  return lines.join("\n");
}

/**
 * The Next block: one to three runnable commands, first one primary.
 * Throws RangeError outside 1-3 — the grammar forbids both an empty
 * next-steps block and a wall of options.
 */
export function renderNextSteps(commands: string[], opts?: GrammarRenderOptions): string {
  if (!Array.isArray(commands) || commands.length < 1 || commands.length > 3) {
    throw new RangeError(
      `renderNextSteps requires one to three commands, got ${Array.isArray(commands) ? commands.length : typeof commands}`,
    );
  }
  const c = resolveChalk(opts);
  const lines = commands.map((command, i) => {
    const cmd = oneLine(command);
    return i === 0 ? `  → ${c.green(cmd)}` : `  • ${cmd}`;
  });
  return [c.bold("Next:"), ...lines].join("\n");
}

/**
 * Progress writes only to the sink handed in (a stderr stream in real
 * CLIs) so stdout stays parseable, and never discloses the home
 * directory in its text.
 */
export function renderProgress(
  input: ProgressInput,
  sink: ProgressSink,
  opts?: GrammarRenderOptions,
): void {
  const c = resolveChalk({ isTTY: sink.isTTY, ...opts });
  const label = scrubHome(oneLine(input.label));
  const counter =
    input.current !== undefined && input.total !== undefined
      ? `[${Math.round(input.current)}/${Math.round(input.total)}] `
      : "";
  sink.write(c.dim(`${counter}${label}`) + "\n");
}

/**
 * The error block: what happened, what was not changed, and the one
 * command to run next.
 */
export function renderError(input: GrammarErrorInput, opts?: GrammarRenderOptions): string {
  const c = resolveChalk(opts);
  return [
    c.red(`✖ ${oneLine(input.what)}`),
    `  Not changed: ${oneLine(input.unchanged)}`,
    `  Next: ${c.cyan(oneLine(input.next))}`,
  ].join("\n");
}

/**
 * Build the one envelope every `--json` front door prints. Exactly these
 * top-level keys, camelCase, in this order: schemaVersion, tool, version,
 * verdict, score, findings, nextSteps, exitCode.
 */
export function envelope(input: EnvelopeInput): Envelope {
  const { nextSteps, findings = [] } = input;
  if (!Array.isArray(nextSteps) || nextSteps.length < 1 || nextSteps.length > 3) {
    throw new RangeError(
      `envelope requires one to three nextSteps commands, got ${Array.isArray(nextSteps) ? nextSteps.length : typeof nextSteps}`,
    );
  }
  if (nextSteps.some((cmd) => typeof cmd !== "string" || cmd.trim() === "")) {
    throw new TypeError("envelope nextSteps entries must be non-empty command strings");
  }
  if (!Array.isArray(findings)) {
    throw new TypeError("envelope findings must be an array");
  }
  if (!Number.isInteger(input.score) || input.score < 0 || input.score > 100) {
    throw new RangeError(`envelope score must be an integer in 0-100, got ${input.score}`);
  }
  if (!Number.isInteger(input.exitCode) || input.exitCode < 0 || input.exitCode > 255) {
    throw new RangeError(`envelope exitCode must be an integer in 0-255, got ${input.exitCode}`);
  }
  return {
    schemaVersion: input.schemaVersion ?? "1",
    tool: input.tool,
    version: input.version,
    verdict: input.verdict,
    score: input.score,
    findings: [...findings],
    nextSteps: [...nextSteps],
    exitCode: input.exitCode,
  };
}

/**
 * Front-door conformance runner — `frontDoorConformance` spawns a built
 * CLI binary and checks the five grammar properties from the CDO
 * design-function ruling (COUNCIL_LEDGER 56558, decision 2) against what
 * the binary actually prints:
 *
 *   1. verdict-first-line — the first non-blank stdout line is the
 *      verdict line (it names the envelope's verdict);
 *   2. json-envelope-parity — the `--json` run of the same command yields
 *      an envelope whose verdict, score, findings and nextSteps equal
 *      what the human view rendered;
 *   3. exit-code-parity — the process exit code equals the envelope's
 *      `exitCode`;
 *   4. no-ansi-when-disabled — under NO_COLOR=1 and non-TTY (piped)
 *      stdout, output carries zero `\x1b` bytes;
 *   5. commands-parse-against-help — every command cited in `nextSteps`
 *      and in each finding's `verify`/`fix` parses against the binary's
 *      own `--help` (`<cmd> --help` exits 0).
 *
 * Every spawn gets a fresh temporary HOME (and USERPROFILE), NO_COLOR=1,
 * and closed stdin, so a front door that reads state from the user's real
 * home or blocks on input fails here instead of in a user's terminal.
 * CLIs adopt this as their `cli-grammar-conformance.test.ts` against the
 * built front door.
 */

import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

export interface FrontDoorTarget {
  /** Path to the built CLI binary (or any executable front door). */
  bin: string;
  /** Arguments of the command under test. */
  args?: string[];
  cwd?: string;
  /** Extra environment; HOME/USERPROFILE/NO_COLOR are always overridden. */
  env?: Record<string, string>;
  /**
   * Flag(s) that switch the same command to the envelope view. Defaults
   * to `["--json"]`, with an automatic `["--format", "json"]` fallback
   * when the default output does not parse as JSON.
   */
  jsonArgs?: string[];
  /** Per-spawn timeout in milliseconds (default 30000). */
  timeoutMs?: number;
}

export type ConformanceProperty =
  | "verdict-first-line"
  | "json-envelope-parity"
  | "exit-code-parity"
  | "no-ansi-when-disabled"
  | "commands-parse-against-help";

export interface ConformancePropertyResult {
  property: ConformanceProperty;
  pass: boolean;
  /** What was actually observed, pass or fail. */
  observed: string;
}

export interface FrontDoorConformanceResult {
  pass: boolean;
  properties: ConformancePropertyResult[];
}

interface SpawnOutcome {
  code: number | null;
  stdout: string;
  stderr: string;
  error?: string;
}

const ANSI_PATTERN = /\x1b\[[0-9;?]*[\x40-\x7e]|\x1b./g;

function stripAnsi(s: string): string {
  return s.replace(ANSI_PATTERN, "");
}

function runProcess(
  bin: string,
  args: string[],
  env: Record<string, string>,
  cwd: string | undefined,
  timeoutMs: number,
): Promise<SpawnOutcome> {
  return new Promise((resolve) => {
    const child = spawn(bin, args, {
      cwd,
      env,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let settled = false;
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      settle({ code: null, stdout, stderr, error: `timed out after ${timeoutMs}ms` });
    }, timeoutMs);
    const settle = (outcome: SpawnOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
    };
    child.stdout.on("data", (chunk: Buffer) => (stdout += chunk.toString("utf8")));
    child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
    child.on("error", (err) => settle({ code: null, stdout, stderr, error: err.message }));
    child.on("close", (code) => settle({ code, stdout, stderr }));
  });
}

function parseEnvelope(stdout: string): Record<string, unknown> | null {
  const trimmed = stdout.trim();
  const start = trimmed.indexOf("{");
  const end = trimmed.lastIndexOf("}");
  if (start === -1 || end <= start) return null;
  try {
    const parsed: unknown = JSON.parse(trimmed.slice(start, end + 1));
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function firstNonBlankLine(text: string): string {
  return text.split("\n").find((line) => line.trim() !== "") ?? "";
}

/** Commands cited by the envelope: nextSteps plus each finding's verify/fix. */
function citedCommands(env: Record<string, unknown>): string[] {
  const commands: string[] = [];
  const nextSteps = env.nextSteps;
  if (Array.isArray(nextSteps)) {
    for (const step of nextSteps) if (typeof step === "string") commands.push(step);
  }
  const findings = env.findings;
  if (Array.isArray(findings)) {
    for (const finding of findings) {
      if (typeof finding !== "object" || finding === null) continue;
      const f = finding as Record<string, unknown>;
      if (typeof f.verify === "string") commands.push(f.verify);
      if (typeof f.fix === "string") commands.push(f.fix);
    }
  }
  return [...new Set(commands.map((c) => c.trim()).filter((c) => c !== ""))];
}

export async function frontDoorConformance(
  target: FrontDoorTarget,
): Promise<FrontDoorConformanceResult> {
  const args = target.args ?? [];
  const timeoutMs = target.timeoutMs ?? 30_000;
  const freshHome = mkdtempSync(path.join(tmpdir(), "front-door-home-"));
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? "",
    ...target.env,
    HOME: freshHome,
    USERPROFILE: freshHome,
    NO_COLOR: "1",
  };

  try {
    const human = await runProcess(target.bin, args, env, target.cwd, timeoutMs);

    let json = await runProcess(
      target.bin,
      [...args, ...(target.jsonArgs ?? ["--json"])],
      env,
      target.cwd,
      timeoutMs,
    );
    let envelope = parseEnvelope(json.stdout);
    if (envelope === null && target.jsonArgs === undefined) {
      const fallback = await runProcess(
        target.bin,
        [...args, "--format", "json"],
        env,
        target.cwd,
        timeoutMs,
      );
      const fallbackEnvelope = parseEnvelope(fallback.stdout);
      if (fallbackEnvelope !== null) {
        json = fallback;
        envelope = fallbackEnvelope;
      }
    }

    const humanText = stripAnsi(human.stdout);
    const verdictLine = firstNonBlankLine(humanText);
    const noEnvelope = `no JSON envelope on stdout (exit ${json.code ?? json.error}): ${
      json.stdout.trim().slice(0, 120) || "<empty>"
    }`;

    const properties: ConformancePropertyResult[] = [];

    // 1. verdict-first-line
    if (envelope === null) {
      properties.push({ property: "verdict-first-line", pass: false, observed: noEnvelope });
    } else {
      const verdict = String(envelope.verdict ?? "");
      const pass =
        verdict !== "" && verdictLine.toLowerCase().includes(verdict.toLowerCase());
      properties.push({
        property: "verdict-first-line",
        pass,
        observed: `first non-blank stdout line: "${verdictLine}" (envelope verdict: "${verdict}")`,
      });
    }

    // 2. json-envelope-parity
    if (envelope === null) {
      properties.push({ property: "json-envelope-parity", pass: false, observed: noEnvelope });
    } else {
      const problems: string[] = [];
      const verdict = String(envelope.verdict ?? "");
      if (verdict === "" || !verdictLine.toLowerCase().includes(verdict.toLowerCase())) {
        problems.push(`verdict "${verdict}" not on the human verdict line`);
      }
      if (!humanText.includes(`${String(envelope.score)}/100`)) {
        problems.push(`score ${String(envelope.score)}/100 not in the human view`);
      }
      if (!Array.isArray(envelope.findings)) {
        problems.push("findings is not an array");
      } else {
        const fixLines = (humanText.match(/^\s*Fix:/gm) ?? []).length;
        if (fixLines !== envelope.findings.length) {
          problems.push(
            `human view renders ${fixLines} Fix: line(s), envelope has ${envelope.findings.length} finding(s)`,
          );
        }
        for (const finding of envelope.findings) {
          const title =
            typeof finding === "object" && finding !== null
              ? (finding as Record<string, unknown>).title
              : undefined;
          if (typeof title === "string" && title !== "" && !humanText.includes(title)) {
            problems.push(`finding title "${title}" not in the human view`);
          }
        }
      }
      if (!Array.isArray(envelope.nextSteps)) {
        problems.push("nextSteps is not an array");
      } else {
        for (const step of envelope.nextSteps) {
          if (typeof step === "string" && !humanText.includes(step)) {
            problems.push(`next step "${step}" not in the human view`);
          }
        }
      }
      properties.push({
        property: "json-envelope-parity",
        pass: problems.length === 0,
        observed:
          problems.length === 0
            ? "verdict, score, findings and nextSteps match the human view"
            : problems.join("; "),
      });
    }

    // 3. exit-code-parity
    if (envelope === null) {
      properties.push({ property: "exit-code-parity", pass: false, observed: noEnvelope });
    } else {
      const expected = envelope.exitCode;
      const pass = typeof expected === "number" && json.code === expected;
      properties.push({
        property: "exit-code-parity",
        pass,
        observed: `process exited ${json.code ?? json.error}, envelope.exitCode is ${String(expected)}`,
      });
    }

    // 4. no-ansi-when-disabled
    {
      const escapes =
        (human.stdout.match(/\x1b/g) ?? []).length + (json.stdout.match(/\x1b/g) ?? []).length;
      properties.push({
        property: "no-ansi-when-disabled",
        pass: escapes === 0,
        observed: `${escapes} \\x1b byte(s) on stdout under NO_COLOR=1 and non-TTY`,
      });
    }

    // 5. commands-parse-against-help
    if (envelope === null) {
      properties.push({
        property: "commands-parse-against-help",
        pass: false,
        observed: noEnvelope,
      });
    } else {
      const commands = citedCommands(envelope);
      const failures: string[] = [];
      for (const command of commands) {
        const tokens = command.split(/\s+/);
        const head = tokens[0];
        const bin =
          head === target.bin || head === path.basename(target.bin) ? target.bin : head;
        const help = await runProcess(
          bin,
          [...tokens.slice(1), "--help"],
          env,
          target.cwd,
          timeoutMs,
        );
        if (help.code !== 0) {
          failures.push(`"${command}" --help exited ${help.code ?? help.error}`);
        }
      }
      properties.push({
        property: "commands-parse-against-help",
        pass: failures.length === 0,
        observed:
          failures.length === 0
            ? `all ${commands.length} cited command(s) parse against --help`
            : failures.join("; "),
      });
    }

    return { pass: properties.every((p) => p.pass), properties };
  } finally {
    rmSync(freshHome, { recursive: true, force: true });
  }
}

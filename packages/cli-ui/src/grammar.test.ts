/**
 * OPA-03.AC1 — the seven grammar exports, pinned by golden snapshots.
 * Every `it` in this file carries OPA-03.AC1 as its first token; the
 * negative/rule pins live in grammar-rules.test.ts (OPA-03.AC2/AC4).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import {
  renderVerdict,
  renderScore,
  renderFinding,
  renderNextSteps,
  renderProgress,
  renderError,
  envelope,
  type GrammarFinding,
} from "./grammar.js";

const ANSI = /\x1b\[[0-9;?]*[\x40-\x7e]/g;
const stripAnsi = (s: string) => s.replace(ANSI, "");

const FINDING: GrammarFinding = {
  severity: "high",
  title: "Hardcoded API key",
  file: "src/config.ts",
  line: 42,
  why: "A committed credential lets anyone with repo read access impersonate the service.",
  verify: 'grep -n "sk-" src/config.ts',
  fix: "hackmyagent secure --rotate src/config.ts",
  url: "https://docs.opena2a.org/findings/hardcoded-secret",
};

function progressText(input: Parameters<typeof renderProgress>[0]): string {
  const writes: string[] = [];
  renderProgress(input, { write: (s: string) => writes.push(s), isTTY: false });
  return writes.join("");
}

describe("grammar exports (OPA-03.AC1)", () => {
  it("OPA-03.AC1 grammar module exports exactly the seven grammar names", async () => {
    const grammar = await import("./grammar.js");
    expect(Object.keys(grammar).sort()).toEqual([
      "envelope",
      "renderError",
      "renderFinding",
      "renderNextSteps",
      "renderProgress",
      "renderScore",
      "renderVerdict",
    ]);
  });

  it("OPA-03.AC1 the barrel re-exports all seven grammar names", async () => {
    const barrel = await import("./index.js");
    const keys = Object.keys(barrel);
    for (const name of [
      "renderVerdict",
      "renderScore",
      "renderFinding",
      "renderNextSteps",
      "renderProgress",
      "renderError",
      "envelope",
    ]) {
      expect(keys).toContain(name);
    }
  });

  it("OPA-03.AC1 envelope builds exactly the eight camelCase top-level keys in order", () => {
    const built = envelope({
      tool: "hackmyagent",
      version: "1.2.3",
      verdict: "warning",
      score: 72,
      findings: [FINDING],
      nextSteps: ["hackmyagent secure ."],
      exitCode: 1,
    });
    expect(Object.keys(built)).toEqual([
      "schemaVersion",
      "tool",
      "version",
      "verdict",
      "score",
      "findings",
      "nextSteps",
      "exitCode",
    ]);
    expect(JSON.stringify(built, null, 2)).toMatchSnapshot();
  });
});

describe("golden snapshots, plain form (OPA-03.AC1)", () => {
  it("OPA-03.AC1 renderVerdict golden", () => {
    expect(renderVerdict({ verdict: "warning", summary: "2 findings" }, { color: false })).toMatchSnapshot();
    expect(renderVerdict({ verdict: "safe" }, { color: false })).toMatchSnapshot();
    expect(renderVerdict({ verdict: "blocked", summary: "1 critical finding" }, { color: false })).toMatchSnapshot();
  });

  it("OPA-03.AC1 renderScore golden", () => {
    expect(renderScore({ score: 72, pathTo100: "hackmyagent secure ." }, { color: false })).toMatchSnapshot();
    expect(renderScore({ score: 100 }, { color: false })).toMatchSnapshot();
    expect(renderScore({ score: 0 }, { color: false })).toMatchSnapshot();
  });

  it("OPA-03.AC1 renderFinding golden", () => {
    expect(renderFinding(FINDING, { color: false })).toMatchSnapshot();
  });

  it("OPA-03.AC1 renderNextSteps golden", () => {
    expect(
      renderNextSteps(["hackmyagent secure .", "hackmyagent report"], { color: false }),
    ).toMatchSnapshot();
  });

  it("OPA-03.AC1 renderProgress golden", () => {
    expect(progressText({ label: "scanning src/config.ts", current: 2, total: 5 })).toMatchSnapshot();
  });

  it("OPA-03.AC1 renderError golden", () => {
    expect(
      renderError(
        {
          what: "Scan failed: registry unreachable (ETIMEDOUT)",
          unchanged: "no files were modified",
          next: "hackmyagent secure . --offline",
        },
        { color: false },
      ),
    ).toMatchSnapshot();
  });
});

describe("colored form strips back to the plain golden (OPA-03.AC1)", () => {
  beforeEach(() => {
    vi.stubEnv("NO_COLOR", "");
  });
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("OPA-03.AC1 each colored renderer output equals its plain form after ANSI strip", () => {
    const on = { color: true } as const;
    const off = { color: false } as const;
    const pairs: Array<[string, string]> = [
      [renderVerdict({ verdict: "blocked", summary: "x" }, on), renderVerdict({ verdict: "blocked", summary: "x" }, off)],
      [renderScore({ score: 72, pathTo100: "cmd" }, on), renderScore({ score: 72, pathTo100: "cmd" }, off)],
      [renderFinding(FINDING, on), renderFinding(FINDING, off)],
      [renderNextSteps(["a", "b"], on), renderNextSteps(["a", "b"], off)],
      [
        renderError({ what: "w", unchanged: "u", next: "n" }, on),
        renderError({ what: "w", unchanged: "u", next: "n" }, off),
      ],
    ];
    for (const [colored, plain] of pairs) {
      expect(colored).toContain("\x1b[");
      expect(stripAnsi(colored)).toBe(plain);
    }
  });
});

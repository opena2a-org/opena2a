/**
 * OPA-03.AC2 — the ruled shape of the grammar, negatively pinned.
 * OPA-03.AC4 — the additive-only / versioning invariants.
 * The golden snapshots live in grammar.test.ts (OPA-03.AC1).
 */
import { describe, it, expect, afterEach, vi } from "vitest";
import { readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  renderVerdict,
  renderScore,
  renderFinding,
  renderNextSteps,
  renderProgress,
  renderError,
  envelope,
  type GrammarFinding,
  type GrammarRenderOptions,
  type ProgressSink,
} from "./grammar.js";

const PKG_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const FINDING: GrammarFinding = {
  severity: "medium",
  title: "Unpinned action",
  file: ".github/workflows/ci.yml",
  line: 12,
  why: "A mutable tag lets the upstream repo change what runs in this pipeline.",
  verify: "hackmyagent verify actions",
  fix: "hackmyagent secure --pin-actions",
  url: "https://docs.opena2a.org/findings/unpinned-action",
};

function allRendererOutput(opts: GrammarRenderOptions): string {
  const writes: string[] = [];
  const sink: ProgressSink = { write: (s: string) => writes.push(s), isTTY: opts.isTTY };
  renderProgress({ label: "scanning", current: 1, total: 2 }, sink, opts);
  return [
    renderVerdict({ verdict: "warning", summary: "1 finding" }, opts),
    renderScore({ score: 64, pathTo100: "hackmyagent secure ." }, opts),
    renderFinding(FINDING, opts),
    renderNextSteps(["hackmyagent secure ."], opts),
    renderError({ what: "boom", unchanged: "nothing was written", next: "hackmyagent doctor" }, opts),
    writes.join(""),
  ].join("\n");
}

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

describe("renderScore rules (OPA-03.AC2)", () => {
  const SCORE_FIXTURES = [
    { score: 0 },
    { score: 100 },
    { score: 87, pathTo100: "hackmyagent secure ." },
    // a score below the previous one — still renders as a state, never a delta
    { score: 42 },
    { score: -5 },
    { score: 250 },
  ];

  it("OPA-03.AC2 renderScore first line matches ^\\d{1,3}/100( -> 100 by .+)?$ for every fixture", () => {
    for (const fixture of SCORE_FIXTURES) {
      const first = renderScore(fixture, { color: false }).split("\n")[0];
      expect(first).toMatch(/^\d{1,3}\/100( -> 100 by .+)?$/);
    }
  });

  it("OPA-03.AC2 renderScore output never carries a minus-delta or a letter grade", () => {
    // grep -E ' -[0-9]|[A-F][+-]?$' over the concatenated outputs prints nothing
    const outputs = SCORE_FIXTURES.flatMap((f) => [
      renderScore(f, { color: false }),
      renderScore(f, { color: true, isTTY: true }),
    ]).join("\n");
    expect(outputs).not.toMatch(/ -[0-9]|[A-F][+-]?$/m);
  });
});

describe("renderVerdict rules (OPA-03.AC2)", () => {
  it("OPA-03.AC2 renderVerdict is a single line with no leading blank line", () => {
    const outputs = [
      renderVerdict({ verdict: "safe" }),
      renderVerdict({ verdict: "blocked", summary: "1 critical finding" }),
      // injected newlines collapse instead of breaking the one-line rule
      renderVerdict({ verdict: "\nwarning", summary: "line one\nline two" }),
    ];
    for (const out of outputs) {
      expect(out).not.toContain("\n");
      expect(out).not.toMatch(/^\s/);
      expect(out.length).toBeGreaterThan(0);
    }
  });
});

describe("renderFinding rules (OPA-03.AC2)", () => {
  it("OPA-03.AC2 renderFinding carries severity, title, file:line, why, Verify:, Fix: in order", () => {
    const out = renderFinding(FINDING, { color: false });
    const positions = [
      out.indexOf("MEDIUM"),
      out.indexOf(FINDING.title),
      out.indexOf(".github/workflows/ci.yml:12"),
      out.indexOf(FINDING.why),
      out.indexOf("Verify: hackmyagent verify actions"),
      out.indexOf("Fix: hackmyagent secure --pin-actions"),
    ];
    for (const pos of positions) expect(pos).toBeGreaterThanOrEqual(0);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });

  it("OPA-03.AC2 renderFinding renders at most one URL", () => {
    const withUrl = renderFinding(FINDING, { color: false });
    expect(withUrl.match(/https?:\/\//g)).toHaveLength(1);
    const withoutUrl = renderFinding({ ...FINDING, url: undefined }, { color: false });
    expect(withoutUrl.match(/https?:\/\//g)).toBeNull();
  });
});

describe("renderProgress rules (OPA-03.AC2)", () => {
  it("OPA-03.AC2 renderProgress writes only to the passed sink, never stdout or stderr", () => {
    const stdoutWrite = vi.spyOn(process.stdout, "write");
    const stderrWrite = vi.spyOn(process.stderr, "write");
    const writes: string[] = [];
    renderProgress(
      { label: "scanning src", current: 1, total: 3 },
      { write: (s: string) => writes.push(s), isTTY: false },
    );
    expect(writes.join("")).toContain("scanning src");
    expect(stdoutWrite).not.toHaveBeenCalled();
    expect(stderrWrite).not.toHaveBeenCalled();
  });

  it("OPA-03.AC2 renderProgress never includes the home directory in its text", () => {
    const home = os.homedir();
    const envHome = process.env.HOME;
    const writes: string[] = [];
    const sink: ProgressSink = { write: (s: string) => writes.push(s), isTTY: false };
    renderProgress({ label: `${home}/project/src`, current: 1, total: 2 }, sink);
    if (envHome) renderProgress({ label: `reading ${envHome}/.config` }, sink);
    const out = writes.join("");
    if (home.length > 1) expect(out).not.toContain(home);
    if (envHome && envHome.length > 1) expect(out).not.toContain(envHome);
    expect(out).toContain("~/project/src");
  });
});

describe("renderError rules (OPA-03.AC2)", () => {
  it("OPA-03.AC2 renderError carries what happened, what was not changed, and one next command", () => {
    const out = renderError(
      {
        what: "Scan failed: registry unreachable (ETIMEDOUT)",
        unchanged: "no files were modified",
        next: "hackmyagent secure . --offline",
      },
      { color: false },
    );
    expect(out).toContain("Scan failed: registry unreachable (ETIMEDOUT)");
    expect(out).toContain("Not changed: no files were modified");
    expect(out.match(/^\s*Next: /gm)).toHaveLength(1);
    expect(out).toContain("Next: hackmyagent secure . --offline");
  });
});

describe("color kill-switches (OPA-03.AC2)", () => {
  it("OPA-03.AC2 NO_COLOR=1 yields zero ESC bytes across every renderer", () => {
    vi.stubEnv("NO_COLOR", "1");
    // even with color and TTY forced on, NO_COLOR wins
    const out = allRendererOutput({ color: true, isTTY: true });
    expect(out.match(/\x1b/g)).toBeNull();
  });

  it("OPA-03.AC2 a non-TTY sink yields zero ESC bytes across every renderer", () => {
    vi.stubEnv("NO_COLOR", "");
    const out = allRendererOutput({ color: true, isTTY: false });
    expect(out.match(/\x1b/g)).toBeNull();
  });
});

describe("additive versioned surface (OPA-03.AC4)", () => {
  it("OPA-03.AC4 version reads 0.6.0 and chalk stays the only runtime dependency", () => {
    const pkg = JSON.parse(readFileSync(path.join(PKG_DIR, "package.json"), "utf8")) as {
      version: string;
      dependencies: Record<string, string>;
    };
    expect(pkg.version).toBe("0.6.0");
    expect(Object.keys(pkg.dependencies)).toEqual(["chalk"]);
  });

  it("OPA-03.AC4 every base export of the barrel is still present", async () => {
    const barrel = await import("./index.js");
    const keys = Object.keys(barrel);
    const baseExports = [
      "scoreMeter",
      "miniMeter",
      "divider",
      "normalizeVerdict",
      "verdictColor",
      "trustLevelLabel",
      "trustLevelColor",
      "trustLevelLegend",
      "scoreColor",
      "formatScanAge",
      "buildCategorySummaries",
      "buildVerdict",
      "classifyCategory",
      "renderObservationsBlock",
      "ALL_CATEGORY_LABELS",
      "isRenderableAnalystFinding",
      "formatAnalystDescription",
      "capAnalystThreatLevel",
      "formatAnalystConfidence",
      "LOW_CONFIDENCE_CAP",
      "renderCheckBlock",
      "renderNotFoundBlock",
      "renderNextSteps",
      "versionLine",
      "versionLineParts",
      "runTelemetryCommand",
      "renderCheckRichBlock",
      "renderHardcodedSecretsBlock",
      "renderSkillMisuseNarrative",
      "renderSkillNarrativeBlock",
      "renderMcpNarrativeBlock",
      "renderVerdictReasoningBlock",
      "renderActionGradientBlock",
      "MCP_THREAT_MODEL_QUESTIONS",
      "SKILL_THREAT_MODEL_QUESTIONS",
      "threatModelQuestionsFor",
      "sanitizeArray",
      "sanitizeForTerminal",
    ];
    for (const name of baseExports) expect(keys).toContain(name);
    // the base renderNextSteps (CTA objects) keeps the barrel binding;
    // the grammar variant stays reachable from ./grammar.js
    const { renderNextSteps: barrelNextSteps } = barrel as { renderNextSteps: Function };
    const rendered = barrelNextSteps({ ctas: [{ label: "go", command: "go do" }] });
    expect(rendered.lines[0].command).toBe("go do");
  });

  it("OPA-03.AC4 the 0.6.0 CHANGELOG entry names the seven exports and frontDoorConformance", () => {
    const changelog = readFileSync(path.join(PKG_DIR, "CHANGELOG.md"), "utf8");
    const entry = changelog.split(/^## 0\.6\.0$/m)[1]?.split(/^## /m)[0] ?? "";
    for (const name of [
      "renderVerdict",
      "renderScore",
      "renderFinding",
      "renderNextSteps",
      "renderProgress",
      "renderError",
      "envelope",
      "frontDoorConformance",
    ]) {
      expect(entry).toContain(name);
    }
  });
});

describe("envelope validation (OPA-03.AC2)", () => {
  it("OPA-03.AC2 envelope rejects an empty or oversized nextSteps list", () => {
    const base = {
      tool: "t",
      version: "1.0.0",
      verdict: "safe",
      score: 100,
      findings: [],
      exitCode: 0,
    };
    expect(() => envelope({ ...base, nextSteps: [] })).toThrow(RangeError);
    expect(() => envelope({ ...base, nextSteps: ["a", "b", "c", "d"] })).toThrow(RangeError);
    expect(() => envelope({ ...base, nextSteps: ["a"] })).not.toThrow();
    expect(() => renderNextSteps([])).toThrow(RangeError);
    expect(() => renderNextSteps(["a", "b", "c", "d"])).toThrow(RangeError);
  });
});

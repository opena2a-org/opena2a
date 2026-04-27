import { describe, it, expect } from "vitest";
import {
  scoreMeter,
  miniMeter,
  divider,
  normalizeVerdict,
  trustLevelLabel,
  trustLevelLegend,
  formatScanAge,
  renderCheckBlock,
  renderNotFoundBlock,
  renderNextSteps,
  renderCheckRichBlock,
  renderHardcodedSecretsBlock,
  renderSkillNarrativeBlock,
  renderMcpNarrativeBlock,
  renderVerdictReasoningBlock,
  renderActionGradientBlock,
  threatModelQuestionsFor,
  SKILL_THREAT_MODEL_QUESTIONS,
  MCP_THREAT_MODEL_QUESTIONS,
} from "./index.js";

describe("scoreMeter", () => {
  it("renders value and max", () => {
    const out = scoreMeter(87);
    expect(out).toContain("87");
    expect(out).toContain("/100");
  });

  it("supports custom max", () => {
    const out = scoreMeter(5, 10);
    expect(out).toContain("5");
    expect(out).toContain("/10");
  });
});

describe("miniMeter", () => {
  it("renders value without max suffix", () => {
    const out = miniMeter(50);
    expect(out).toContain("50");
    expect(out).not.toContain("/100");
  });
});

describe("divider", () => {
  it("renders plain rule without label", () => {
    const out = divider();
    expect(out).toMatch(/─+/);
  });

  it("includes label when provided", () => {
    const out = divider("Findings");
    expect(out).toContain("Findings");
  });
});

describe("normalizeVerdict", () => {
  it("collapses scan-status variants", () => {
    expect(normalizeVerdict("passed")).toBe("safe");
    expect(normalizeVerdict("safe")).toBe("safe");
    expect(normalizeVerdict("warnings")).toBe("warning");
    expect(normalizeVerdict("warning")).toBe("warning");
    expect(normalizeVerdict("failed")).toBe("blocked");
    expect(normalizeVerdict("blocked")).toBe("blocked");
    expect(normalizeVerdict("listed")).toBe("listed");
  });

  it("returns unknown verdicts unchanged", () => {
    expect(normalizeVerdict("mystery")).toBe("mystery");
  });
});

describe("trustLevelLabel", () => {
  it("maps 0-4 to names", () => {
    expect(trustLevelLabel(0)).toBe("Blocked");
    expect(trustLevelLabel(1)).toBe("Warning");
    expect(trustLevelLabel(2)).toBe("Listed");
    expect(trustLevelLabel(3)).toBe("Scanned");
    expect(trustLevelLabel(4)).toBe("Verified");
  });

  it("marks unknown levels", () => {
    expect(trustLevelLabel(99)).toContain("Unknown");
  });
});

describe("trustLevelLegend", () => {
  it("includes all five levels", () => {
    const out = trustLevelLegend(2);
    expect(out).toContain("Blocked");
    expect(out).toContain("Warning");
    expect(out).toContain("Listed");
    expect(out).toContain("Scanned");
    expect(out).toContain("Verified");
  });
});

describe("formatScanAge", () => {
  it("returns null when timestamp missing", () => {
    expect(formatScanAge()).toBeNull();
    expect(formatScanAge(undefined)).toBeNull();
  });

  it('returns "today" for recent scans', () => {
    const now = new Date().toISOString();
    expect(formatScanAge(now)).toBe("today");
  });

  it('flags stale scans (>90 days)', () => {
    const old = new Date(Date.now() - 120 * 86400 * 1000).toISOString();
    const out = formatScanAge(old);
    expect(out).toContain("120");
    expect(out).toContain("stale");
  });
});

describe("renderCheckBlock (barrel export)", () => {
  it("is exported from the package entry point", () => {
    const out = renderCheckBlock({
      name: "x",
      trustLevel: 3,
      trustScore: 0.82,
      verdict: "passed",
      scanStatus: "completed",
    });
    expect(out.header.name).toBe("x");
    expect(out.meterShown).toBe(true);
  });
});

describe("renderNotFoundBlock (barrel export)", () => {
  it("is exported from the package entry point", () => {
    const out = renderNotFoundBlock({ pkg: "x", ecosystem: "npm" });
    expect(out.header.text).toContain("Package not found");
  });
});

describe("renderNextSteps (barrel export)", () => {
  it("is exported from the package entry point", () => {
    const out = renderNextSteps({ ctas: [{ label: "go", command: "go do", primary: true }] });
    expect(out.lines[0].bullet).toBe("→");
  });
});

describe("rich-block barrel exports (0.5.0)", () => {
  it("renderHardcodedSecretsBlock — clean state", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [],
      scanCovered: true,
      latestVersion: "1.0.0",
    });
    expect(out.lines[0].text).toBe("None detected on the latest version (1.0.0)");
  });

  it("renderSkillNarrativeBlock — header is 'What is this skill?'", () => {
    const out = renderSkillNarrativeBlock({
      skillName: "x",
      activationPhrases: [],
      behaviorDescription: "",
      permissions: [],
      externalServices: [],
      persistence: "",
      toolCallsObserved: [],
      misuseNarrative: "",
    });
    expect(out.header).toBe("What is this skill?");
  });

  it("renderMcpNarrativeBlock — header is 'What is this MCP?'", () => {
    const out = renderMcpNarrativeBlock({
      mcpName: "x",
      tools: [],
      pathScope: "",
      network: "",
      persistence: "",
      auth: "",
      sideEffects: [],
    });
    expect(out.header).toBe("What is this MCP?");
  });

  it("renderVerdictReasoningBlock — VERIFIED tier", () => {
    const out = renderVerdictReasoningBlock({
      tier: "VERIFIED",
      statements: [{ kind: "positive", text: "ok" }],
    });
    expect(out.header).toBe("Why VERIFIED");
  });

  it("renderActionGradientBlock — empty steps", () => {
    const out = renderActionGradientBlock({ tier: "VERIFIED", steps: [] });
    expect(out.lines).toEqual([]);
  });

  it("threat-model questions are exported as frozen lists", () => {
    expect(SKILL_THREAT_MODEL_QUESTIONS).toHaveLength(3);
    expect(MCP_THREAT_MODEL_QUESTIONS).toHaveLength(3);
    expect(threatModelQuestionsFor("skill")).toBe(SKILL_THREAT_MODEL_QUESTIONS);
  });

  it("renderCheckRichBlock — emits header + sections for VERIFIED skill", () => {
    const out = renderCheckRichBlock({
      name: "opena2a/clean-skill",
      artifactType: "skill",
      header: { trustVerdict: "VERIFIED", trustScore: 94 },
      hardcodedSecrets: { detected: [], scanCovered: true },
      skill: {
        skillName: "clean-skill",
        activationPhrases: [],
        behaviorDescription: "",
        permissions: [],
        externalServices: [],
        persistence: "",
        toolCallsObserved: [],
        misuseNarrative: "",
      },
      findings: [],
      verdictReasoning: [{ kind: "positive", text: "ok" }],
      nextSteps: [{ weight: "primary", label: "Install", command: "i x" }],
    });
    expect(out.header.name).toBe("opena2a/clean-skill");
    expect(out.sections.find((s) => s.divider === "Hardcoded secrets")).toBeDefined();
    expect(out.sections.find((s) => s.divider === "Why VERIFIED")).toBeDefined();
    expect(out.sections.find((s) => s.divider === "Next")).toBeDefined();
  });
});

import { describe, it, expect } from "vitest";
import { buildCheckOutput, buildNotFoundOutput } from "./output.js";
import type { ScanResult, TrustData } from "./types.js";
import type { PackageNarrative } from "./narrative.js";

describe("buildCheckOutput", () => {
  const baseScan: ScanResult = {
    projectType: "mcp-server",
    score: 100,
    maxScore: 100,
    findings: [],
  };

  const baseRegistry: TrustData = {
    found: true,
    name: "@modelcontextprotocol/server-filesystem",
    trustScore: 0.82,
    trustLevel: 3,
    verdict: "warnings",
    scanStatus: "passed",
    packageType: "mcp_server",
    lastScannedAt: "2026-03-02T10:00:00.000Z",
    communityScans: 12,
    cveCount: 0,
  };

  it("emits scan-only output with source=local-scan", () => {
    const out = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: baseScan,
    });
    expect(out).toEqual({
      name: "express",
      type: "npm-package",
      source: "local-scan",
      projectType: "mcp-server",
      score: 100,
      maxScore: 100,
      findings: [],
    });
  });

  it("emits registry-only output with source=registry", () => {
    const out = buildCheckOutput({
      name: baseRegistry.name,
      type: "npm-package",
      registry: baseRegistry,
    });
    expect(out).toEqual({
      name: baseRegistry.name,
      type: "npm-package",
      source: "registry",
      trustLevel: 3,
      trustScore: 0.82,
      verdict: "warnings",
      scanStatus: "passed",
      packageType: "mcp_server",
      lastScannedAt: "2026-03-02T10:00:00.000Z",
      communityScans: 12,
      cveCount: 0,
    });
  });

  it("merges scan + registry with source=local-scan (HMA's scan-first path)", () => {
    const out = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: baseScan,
      registry: baseRegistry,
    });
    expect(out.source).toBe("local-scan");
    expect(out.score).toBe(100);
    expect(out.trustLevel).toBe(3);
  });

  it("key order matches hackmyagent@0.18.3 buildCheckJsonOutput (byte-equality contract)", () => {
    // The parity harness compares JSON output byte-for-byte. Key order must
    // match the legacy emitter exactly so `hackmyagent check --json` does
    // not drift after migration.
    const out = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: { ...baseScan, version: "4.18.2", analystFindings: [{ id: "x" }] },
      registry: baseRegistry,
    });
    const keys = Object.keys(out);
    expect(keys).toEqual([
      "name",
      "type",
      "source",
      "projectType",
      "score",
      "maxScore",
      "findings",
      "version",
      "trustLevel",
      "trustScore",
      "verdict",
      "scanStatus",
      "packageType",
      "lastScannedAt",
      "communityScans",
      "cveCount",
      "analystFindings",
    ]);
  });

  it("omits analystFindings when empty", () => {
    const out = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: { ...baseScan, analystFindings: [] },
    });
    expect(out.analystFindings).toBeUndefined();
  });

  it("does not merge registry when found=false", () => {
    const out = buildCheckOutput({
      name: "ghost",
      type: "npm-package",
      scan: baseScan,
      registry: { ...baseRegistry, found: false },
    });
    expect(out.trustLevel).toBeUndefined();
    expect(out.verdict).toBeUndefined();
    expect(out.source).toBe("local-scan");
  });

  it("omits optional scan fields when absent", () => {
    const minimalScan: ScanResult = { score: 95, maxScore: 100, findings: [] };
    const out = buildCheckOutput({
      name: "minimal",
      type: "npm-package",
      scan: minimalScan,
    });
    expect(out.projectType).toBeUndefined();
    expect(out.version).toBeUndefined();
  });

  it("omits optional registry fields when undefined", () => {
    const minimalReg: TrustData = {
      found: true,
      name: "bare",
      trustScore: 0.5,
      trustLevel: 2,
      verdict: "pass",
    };
    const out = buildCheckOutput({
      name: "bare",
      type: "npm-package",
      registry: minimalReg,
    });
    expect(out.scanStatus).toBeUndefined();
    expect(out.packageType).toBeUndefined();
    expect(out.lastScannedAt).toBeUndefined();
  });

  it("appends narrative as the last key when provided (preserves byte-equality when absent)", () => {
    const narrative: PackageNarrative = {
      schemaVersion: 1,
      generatedAt: "2026-04-27T07:30:00.000Z",
      generatedFrom: {
        artifactType: "skill",
        artifactVersion: "0.3.1",
        scanRunId: "00000000-0000-0000-0000-000000000000",
      },
      summary: "A code-review skill that reads files and streams to Claude.",
      hardcodedSecrets: { detected: [], scanCovered: true },
      skill: {
        skillName: "opena2a/code-review-skill",
        activationPhrases: ["review"],
        behaviorDescription: "Reads files via Read tool only.",
        permissions: [],
        externalServices: ["anthropic.com"],
        persistence: "none",
        toolCallsObserved: [],
        misuseNarrative: "",
        threatModelQuestions: [],
      },
      verdictReasoning: [],
      nextSteps: [],
    };
    const out = buildCheckOutput({
      name: "opena2a/code-review-skill",
      type: "npm-package",
      scan: { score: 78, maxScore: 100, findings: [] },
      narrative,
    });
    const keys = Object.keys(out);
    expect(keys[keys.length - 1]).toBe("narrative");
    expect(out.narrative).toBe(narrative);
  });

  it("does not include narrative when undefined (zero key drift on the legacy path)", () => {
    const out = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: { score: 100, maxScore: 100, findings: [] },
    });
    expect(out).not.toHaveProperty("narrative");
    expect(Object.keys(out)).not.toContain("narrative");
  });
});

describe("buildNotFoundOutput", () => {
  it("emits minimal not-found shape", () => {
    const out = buildNotFoundOutput({ name: "ghost" });
    expect(out).toEqual({ name: "ghost", found: false });
  });

  it("includes errorHint and suggestions when present", () => {
    const out = buildNotFoundOutput({
      name: "anthropic/code-review",
      errorHint: "did you mean scoped?",
      suggestions: ["@anthropic/code-review"],
    });
    expect(out.errorHint).toBe("did you mean scoped?");
    expect(out.suggestions).toEqual(["@anthropic/code-review"]);
  });

  it("omits empty suggestions array", () => {
    const out = buildNotFoundOutput({ name: "ghost", suggestions: [] });
    expect(out.suggestions).toBeUndefined();
  });

  it("includes ecosystem when provided", () => {
    const out = buildNotFoundOutput({ name: "ghost", ecosystem: "npm" });
    expect(out.ecosystem).toBe("npm");
  });
});

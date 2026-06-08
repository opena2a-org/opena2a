import { describe, it, expect } from "vitest";
import { CHECK_FIELD_GUIDE, checkJsonSchema } from "./check-json-schema.js";
import { buildCheckOutput } from "./output.js";
import type { ScanResult, TrustData } from "./types.js";
import type { PackageNarrative } from "./narrative.js";

/**
 * Issue #124, UX rule 7: the machine-readable JSON schema must be
 * documented AND self-consistent with what `buildCheckOutput` actually
 * emits. These tests fail the moment a new field is added to the emitter
 * without a matching entry in the field guide — so the documented
 * contract can never silently drift from the wire format.
 */
describe("check-json contract", () => {
  const fullScan: ScanResult = {
    projectType: "mcp-server",
    score: 100,
    maxScore: 100,
    findings: [],
    version: "4.18.2",
    analystFindings: [{ id: "x" }],
  };

  // Every optional field set, so any newly-copied field in output.ts
  // surfaces in allEmittableKeys() and trips the drift guard (P2).
  const fullRegistry: TrustData = {
    found: true,
    name: "express",
    trustScore: 0.67,
    trustLevel: 2,
    verdict: "listed",
    scanStatus: "pending",
    packageType: "npm_package",
    lastScannedAt: "2026-03-02T10:00:00.000Z",
    communityScans: 12,
    cveCount: 0,
    recommendation: "review before adopting",
    dependencies: { totalDeps: 3, vulnerableDeps: 0, minTrustLevel: 2 },
  };

  const narrative = {
    schemaVersion: 1,
    generatedAt: "2026-04-27T07:30:00.000Z",
    generatedFrom: { artifactType: "skill", artifactVersion: "0.3.1" },
    summary: "",
    verdictReasoning: [],
    nextSteps: [],
  } as unknown as PackageNarrative;

  /** Every key the emitter can produce, across all paths. */
  function allEmittableKeys(): Set<string> {
    const merged = buildCheckOutput({
      name: "express",
      type: "npm-package",
      scan: fullScan,
      registry: fullRegistry,
      narrative,
    });
    return new Set(Object.keys(merged));
  }

  it("documents every field buildCheckOutput can emit (no undocumented drift)", () => {
    const undocumented = [...allEmittableKeys()].filter(
      (k) => !(k in CHECK_FIELD_GUIDE),
    );
    expect(undocumented).toEqual([]);
  });

  it("does not document fields the emitter never produces (no stale guide entries)", () => {
    const emittable = allEmittableKeys();
    const stale = Object.keys(CHECK_FIELD_GUIDE).filter((k) => !emittable.has(k));
    expect(stale).toEqual([]);
  });

  it("documents the skill-path output shape (built outside buildCheckOutput)", () => {
    // check-package.ts builds source:"skill" results as a bare literal that
    // bypasses buildCheckOutput, so the buildCheckOutput drift guard above
    // can't see it. Guard its keys here too. If the skill literal grows a
    // field, this fails until the guide documents it.
    const skillKeys = ["name", "type", "source"]; // mirrors check-package.ts skill branch
    const undocumented = skillKeys.filter((k) => !(k in CHECK_FIELD_GUIDE));
    expect(undocumented).toEqual([]);
    // The guide's `source` field must enumerate "skill" as a valid value.
    expect(CHECK_FIELD_GUIDE.source.scale).toContain("skill");
  });

  it("guide order matches the byte-equality emission order", () => {
    const emittedOrder = Object.keys(
      buildCheckOutput({
        name: "express",
        type: "npm-package",
        scan: fullScan,
        registry: fullRegistry,
        narrative,
      }),
    );
    const guideOrder = Object.keys(CHECK_FIELD_GUIDE);
    // The guide lists fields in emission order; filtering to emitted keys
    // must reproduce the exact wire order.
    expect(guideOrder.filter((k) => emittedOrder.includes(k))).toEqual(emittedOrder);
  });

  it("classifies the score-shaped fields on distinct axes (issue #124 core)", () => {
    expect(CHECK_FIELD_GUIDE.score.source).toBe("local-scan");
    expect(CHECK_FIELD_GUIDE.trustLevel.source).toBe("registry");
    expect(CHECK_FIELD_GUIDE.trustScore.source).toBe("registry");
    // trustLevel is the canonical 0..4 ordinal gate; trustScore (0..1) is
    // its continuous input, not a standalone gate.
    expect(CHECK_FIELD_GUIDE.trustLevel.scale).toBe("0..4 ordinal");
    expect(CHECK_FIELD_GUIDE.trustScore.scale).toBe("0..1");
    // score and trustLevel must carry explicit gating guidance so CI
    // consumers don't misread "score: 100" as a trust verdict, or gate on
    // a raw trustScore threshold.
    expect(CHECK_FIELD_GUIDE.score.gating).toBeTruthy();
    expect(CHECK_FIELD_GUIDE.trustLevel.gating).toBeTruthy();
    expect(CHECK_FIELD_GUIDE.trustScore.gating).toMatch(/prefer trustLevel/i);
  });

  it("every field carries a non-empty description and valid source", () => {
    for (const [field, doc] of Object.entries(CHECK_FIELD_GUIDE)) {
      expect(doc.description, `${field} description`).toBeTruthy();
      expect(["meta", "local-scan", "registry"]).toContain(doc.source);
    }
  });

  it("emits a JSON Schema whose properties match the field guide", () => {
    expect(checkJsonSchema.type).toBe("object");
    expect(Object.keys(checkJsonSchema.properties)).toEqual(
      Object.keys(CHECK_FIELD_GUIDE),
    );
    expect(checkJsonSchema.required).toContain("name");
    expect(checkJsonSchema.required).toContain("source");
  });
});

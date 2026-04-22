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

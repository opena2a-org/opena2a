import { describe, expect, it } from "vitest";
import {
  renderVerdictReasoningBlock,
  type VerdictReasoningStatementLike,
} from "./verdict-reasoning-block.js";

const positive = (text: string): VerdictReasoningStatementLike => ({
  kind: "positive",
  text,
});
const gap = (text: string): VerdictReasoningStatementLike => ({
  kind: "gap",
  text,
});
const critical = (text: string): VerdictReasoningStatementLike => ({
  kind: "critical",
  text,
});

describe("verdict-reasoning — VERIFIED clean", () => {
  it("renders header 'Why VERIFIED' when only positives", () => {
    const out = renderVerdictReasoningBlock({
      tier: "VERIFIED",
      statements: [
        positive("Publisher is a verified organization"),
        positive("Declared permissions match observed tool usage exactly"),
        positive("SOUL.md governance file present"),
      ],
    });
    expect(out.header).toBe("Why VERIFIED");
    expect(out.lines).toHaveLength(3);
    expect(out.lines[0].text).toBe("[ok]  Publisher is a verified organization");
    expect(out.lines[0].tone).toBe("good");
  });
});

describe("verdict-reasoning — VERIFIED despite findings", () => {
  it("uses 'despite findings' header when gaps coexist with positives", () => {
    const out = renderVerdictReasoningBlock({
      tier: "VERIFIED",
      statements: [
        positive("Publisher is a verified organization"),
        gap("Hardcoded API key in examples/"),
      ],
    });
    expect(out.header).toBe("Why VERIFIED despite findings");
  });
});

describe("verdict-reasoning — LISTED with multiple gaps", () => {
  it("renders header 'Why LISTED, not VERIFIED' and numbers 2+ gaps", () => {
    const out = renderVerdictReasoningBlock({
      tier: "LISTED",
      statements: [
        gap("Bash permission declared but unused (overreach above)"),
        gap("No SOUL.md governance file in repo"),
        gap("Fewer than 5 community scans (5+ required for VERIFIED)"),
      ],
    });
    expect(out.header).toBe("Why LISTED, not VERIFIED");
    expect(out.lines).toHaveLength(3);
    expect(out.lines[0].text).toBe(
      "1.  Bash permission declared but unused (overreach above)",
    );
    expect(out.lines[1].text).toBe(
      "2.  No SOUL.md governance file in repo",
    );
    expect(out.lines[2].text).toBe(
      "3.  Fewer than 5 community scans (5+ required for VERIFIED)",
    );
  });

  it("uses bare bullet when only one gap exists", () => {
    const out = renderVerdictReasoningBlock({
      tier: "LISTED",
      statements: [gap("Single gap")],
    });
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].text).toBe("-  Single gap");
  });

  it("renders positives before gaps when both exist", () => {
    const out = renderVerdictReasoningBlock({
      tier: "LISTED",
      statements: [
        gap("gap-1"),
        positive("pos-1"),
        gap("gap-2"),
      ],
    });
    expect(out.lines[0].text).toMatch(/^\[ok\]  pos-1/);
    expect(out.lines[1].text).toBe("1.  gap-1");
    expect(out.lines[2].text).toBe("2.  gap-2");
  });
});

describe("verdict-reasoning — BLOCKED", () => {
  it("renders only critical entries with CRITICAL prefix", () => {
    const out = renderVerdictReasoningBlock({
      tier: "BLOCKED",
      statements: [
        positive("(ignored on BLOCKED)"),
        critical("14 findings, 8 critical."),
        critical("CRED-EXFIL at scripts/postinstall.js:1"),
        critical("NET-PASTEBIN at scripts/postinstall.js:14"),
      ],
    });
    expect(out.header).toBe("Why BLOCKED");
    expect(out.lines).toHaveLength(3);
    expect(out.lines[0].text).toBe("CRITICAL  14 findings, 8 critical.");
    expect(out.lines[0].tone).toBe("critical");
  });
});

describe("verdict-reasoning — LISTED (UNSCANNED)", () => {
  it("renders header 'Why no score' with the engine's gap text", () => {
    const out = renderVerdictReasoningBlock({
      tier: "LISTED_UNSCANNED",
      statements: [
        gap(
          "No scan has been run on this artifact. A score and findings require a scan; without one we can verify identity but not behavior.",
        ),
      ],
    });
    expect(out.header).toBe("Why no score");
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].text).toMatch(/^-  No scan has been run/);
    expect(out.lines[0].tone).toBe("warning");
  });
});

describe("verdict-reasoning — NOT_FOUND", () => {
  it("returns empty block (different render path used by orchestrator)", () => {
    const out = renderVerdictReasoningBlock({
      tier: "NOT_FOUND",
      statements: [],
    });
    expect(out.header).toBe("");
    expect(out.lines).toEqual([]);
  });
});

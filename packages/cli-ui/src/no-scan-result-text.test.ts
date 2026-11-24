import { describe, it, expect } from "vitest";
import {
  NO_SCAN_RESULT_TEXT,
  NO_SCAN_RESULT_SHORT_TEXT,
  renderCheckBlock,
  renderCheckRichBlock,
  type CheckBlockInput,
  type CheckRichBlockInput,
} from "./index.js";

/**
 * A version with no Registry scan result prints one set of words in every
 * CLI: the block form on the check block's Trust line, the short form where
 * a line has less room. Both come from the barrel, so a CLI that imports
 * them prints exactly the words these cells pin.
 */

const BLOCK_FORM = "not scanned, no score";
const SHORT_FORM = "not scanned";
const EM_DASH = "—";
const NEWLINE = "\n";
const ESC = "\u001b";

// The check block's own test fixture: a found package with a completed scan.
function base(over: Partial<CheckBlockInput> = {}): CheckBlockInput {
  return {
    name: "example",
    trustLevel: 3,
    trustScore: 0.82,
    verdict: "passed",
    scanStatus: "completed",
    ...over,
  };
}

function renderTrust(over: Partial<CheckBlockInput>) {
  const out = renderCheckBlock(base(over));
  const trust = out.lines.find((l) => l.label === "Trust");
  expect(trust).toBeDefined();
  return { out, trust: trust! };
}

describe("no-scan-result texts", () => {
  it("exports the block form and the short form", () => {
    expect(NO_SCAN_RESULT_TEXT).toBe(BLOCK_FORM);
    expect(NO_SCAN_RESULT_SHORT_TEXT).toBe(SHORT_FORM);
  });

  it("each form is one line with no digit, no em dash and no escape sequence", () => {
    for (const text of [NO_SCAN_RESULT_TEXT, NO_SCAN_RESULT_SHORT_TEXT]) {
      expect(typeof text).toBe("string");
      expect(text).not.toContain(NEWLINE);
      expect(text).not.toMatch(/\d/);
      expect(text).not.toContain(EM_DASH);
      expect(text).not.toContain(ESC);
    }
  });
});

describe("renderCheckBlock: Trust line for a version with no Registry scan result", () => {
  it("prints the block form when scanStatus is absent", () => {
    const { trust } = renderTrust({ scanStatus: undefined });
    expect(trust.value).toBe(BLOCK_FORM);
    expect(trust.value).toBe(NO_SCAN_RESULT_TEXT);
  });

  it("has no em dash", () => {
    const { trust } = renderTrust({ scanStatus: undefined });
    expect(trust.value).not.toContain(EM_DASH);
  });

  it("keeps the dim tone and draws no meter", () => {
    const { out, trust } = renderTrust({ scanStatus: undefined });
    expect(trust.tone).toBe("dim");
    expect(out.meterShown).toBe(false);
  });

  it("has no digit and no escape sequence", () => {
    const { trust } = renderTrust({ scanStatus: undefined });
    expect(trust.value).not.toMatch(/\d/);
    expect(trust.value).not.toContain(ESC);
  });

  it("states the words once, on the Trust line", () => {
    const { out } = renderTrust({ scanStatus: undefined });
    const texts = [
      out.header.name,
      ...out.header.meta,
      out.verdict.text,
      ...out.lines.map((l) => l.value),
    ];
    expect(texts.filter((t) => t.includes(SHORT_FORM))).toHaveLength(1);
    expect(out.lines.filter((l) => l.value.includes(SHORT_FORM)).map((l) => l.label)).toEqual([
      "Trust",
    ]);
  });

  it("prints the block form when scanStatus is null, as the Registry serves it", () => {
    const { trust } = renderTrust({ scanStatus: null as unknown as string });
    expect(trust.value).toBe(BLOCK_FORM);
    expect(trust.tone).toBe("dim");
  });

  it("prints the same words for pending, a stored status that null replaces", () => {
    const { trust } = renderTrust({ scanStatus: "pending" });
    expect(trust.value).toBe(BLOCK_FORM);
    expect(trust.tone).toBe("dim");
  });
});

function unscannedSkill(
  header: Partial<CheckRichBlockInput["header"]> = {},
): CheckRichBlockInput {
  return {
    name: "some-org/example-skill",
    artifactType: "skill",
    header: { trustVerdict: "LISTED_UNSCANNED", ...header },
    hardcodedSecrets: { detected: [], scanCovered: false },
    findings: [],
    verdictReasoning: [{ kind: "gap", text: "No scan has been run on this artifact." }],
    nextSteps: [
      {
        weight: "primary",
        label: "Local scan",
        command: "hackmyagent check some-org/example-skill",
      },
    ],
  };
}

function scoreLineParts(input: CheckRichBlockInput): string[] {
  const out = renderCheckRichBlock(input);
  const line = out.header.metaLines.find((l) => l.text.startsWith("Score:"));
  expect(line).toBeDefined();
  return line!.text.split("  ·  ");
}

describe("renderCheckRichBlock: LISTED (UNSCANNED) with no scan age", () => {
  it("prints the short form when lastScanAge is absent", () => {
    const parts = scoreLineParts(unscannedSkill());
    expect(parts).toContain(SHORT_FORM);
    expect(parts).toContain(NO_SCAN_RESULT_SHORT_TEXT);
    expect(parts.join("  ·  ")).not.toContain("Never scanned");
  });

  it("prints the short form when lastScanAge is empty", () => {
    const parts = scoreLineParts(unscannedSkill({ lastScanAge: "" }));
    expect(parts).toContain(SHORT_FORM);
    expect(parts.join("  ·  ")).not.toContain("Never scanned");
    expect(parts.join("  ·  ")).not.toContain(ESC);
  });

  it("keeps the tier label and the Why no score heading", () => {
    const out = renderCheckRichBlock(unscannedSkill());
    expect(out.header.metaLines[0].text).toContain("LISTED (UNSCANNED)");
    expect(out.sections.some((s) => s.divider === "Why no score")).toBe(true);
  });
});

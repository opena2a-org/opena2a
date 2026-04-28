import { describe, expect, it } from "vitest";
import {
  renderActionGradientBlock,
  type NextStepLike,
} from "./action-gradient-block.js";

const primary = (label: string, command?: string): NextStepLike => ({
  weight: "primary",
  label,
  command,
});
const secondary = (label: string, command?: string): NextStepLike => ({
  weight: "secondary",
  label,
  command,
});

describe("action-gradient — VERIFIED clean (mockup 3.2)", () => {
  it("renders aligned label columns and good tone on first primary", () => {
    const out = renderActionGradientBlock({
      tier: "VERIFIED",
      steps: [
        primary("Install confidently", "opena2a install opena2a/refactor-helper"),
        secondary("Pin to current", "opena2a install opena2a/refactor-helper@1.1.0"),
      ],
    });
    expect(out.lines).toHaveLength(2);
    expect(out.lines[0].text).toBe(
      "Install confidently:  opena2a install opena2a/refactor-helper",
    );
    expect(out.lines[0].tone).toBe("good");
    // Second line label is shorter, must align with first.
    expect(out.lines[1].text).toBe(
      "Pin to current:       opena2a install opena2a/refactor-helper@1.1.0",
    );
    expect(out.lines[1].tone).toBe("default");
  });
});

describe("action-gradient — LISTED skill (mockup 3.1)", () => {
  it("renders three rows aligned to the longest label", () => {
    const out = renderActionGradientBlock({
      tier: "LISTED",
      steps: [
        primary(
          "Review the skill",
          "cat $(opena2a path opena2a/code-review-skill)/SKILL.md",
        ),
        secondary("Install", "opena2a install opena2a/code-review-skill"),
        secondary("With pinning", "opena2a install opena2a/code-review-skill@0.3.0"),
      ],
    });
    expect(out.lines).toHaveLength(3);
    // Longest label "Review the skill" → 16 chars + ':' + 2 spaces = 19,
    // capped at 24, so padded labels are 19 chars wide.
    expect(out.lines[0].text.startsWith("Review the skill:  ")).toBe(true);
    expect(out.lines[1].text.startsWith("Install:           ")).toBe(true);
    expect(out.lines[2].text.startsWith("With pinning:      ")).toBe(true);
    expect(out.lines[0].tone).toBe("default");
  });
});

describe("action-gradient — BLOCKED (mockup 3.6)", () => {
  it("renders critical tone on first primary", () => {
    const out = renderActionGradientBlock({
      tier: "BLOCKED",
      steps: [
        primary("Stop", "Do NOT install"),
        secondary("Find alternative", "ai-trust suggest mcp <what-you-needed>"),
        secondary("Report", "hackmyagent report malicious-mcp-xyz"),
      ],
    });
    expect(out.lines[0].tone).toBe("critical");
    expect(out.lines[0].text).toBe("Stop:              Do NOT install");
    expect(out.lines[1].tone).toBe("default");
  });
});

describe("action-gradient — empty steps", () => {
  it("returns an empty line list when no steps", () => {
    const out = renderActionGradientBlock({
      tier: "VERIFIED",
      steps: [],
    });
    expect(out.lines).toEqual([]);
  });
});

describe("action-gradient — step without command or URL", () => {
  it("renders label-only when neither command nor url is set", () => {
    const out = renderActionGradientBlock({
      tier: "BLOCKED",
      steps: [primary("Do not install — recovery path is not available")],
    });
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].text).toBe(
      "Do not install — recovery path is not available",
    );
  });
});

describe("action-gradient — URL fallback", () => {
  it("uses URL when command is absent", () => {
    const out = renderActionGradientBlock({
      tier: "BLOCKED",
      steps: [
        primary("Stop", "Do NOT install"),
        secondary("More info", undefined),
        {
          weight: "secondary",
          label: "Rotate",
          url: "https://console.anthropic.com/settings/keys",
        },
      ],
    });
    const rotate = out.lines.find((l) => l.text.startsWith("Rotate:"));
    expect(rotate?.text).toContain("https://console.anthropic.com/settings/keys");
  });
});

describe("action-gradient — primary tone applies to first primary only", () => {
  it("only the first primary gets the headline tone", () => {
    const out = renderActionGradientBlock({
      tier: "VERIFIED",
      steps: [
        primary("First", "cmd-a"),
        primary("Second", "cmd-b"),
        secondary("Third", "cmd-c"),
      ],
    });
    expect(out.lines[0].tone).toBe("good");
    expect(out.lines[1].tone).toBe("default");
    expect(out.lines[2].tone).toBe("default");
  });
});

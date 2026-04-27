import { describe, expect, it } from "vitest";
import {
  renderCheckRichBlock,
  type CheckRichBlockInput,
} from "./check-rich-block.js";

function skillFixture(
  over: Partial<CheckRichBlockInput> = {},
): CheckRichBlockInput {
  return {
    name: "opena2a/code-review-skill",
    artifactType: "skill",
    header: {
      trustVerdict: "LISTED",
      trustScore: 78,
      lastScanAge: "14d ago",
      latestVersionLabel: "0.3.1 (5d ago)",
      publisher: { name: "opena2a-org", verified: true, kind: "verified org" },
      license: "MIT",
      downloads: { perWeek: 607, trend: "rising" },
      communityScans: 4,
      findingsCount: 1,
    },
    hardcodedSecrets: { detected: [], scanCovered: true },
    latestVersion: "0.3.1",
    skill: {
      skillName: "code-review-skill",
      activationPhrases: ["review", "code review"],
      behaviorDescription:
        "Reads files from the current working directory.",
      permissions: [
        { name: "Read", declared: true, used: true, status: "used" },
        {
          name: "Bash",
          declared: true,
          used: false,
          status: "unused",
          note: "declared but no Bash invocation",
        },
      ],
      externalServices: ["anthropic.com"],
      persistence: "none",
      toolCallsObserved: [{ tool: "Read", count: 12 }],
      misuseNarrative: "Low risk overall.",
    },
    findings: [
      {
        severity: "medium",
        ruleId: "SKILL-PERM-OVERREACH",
        locator: "SKILL.md:23",
        description: "Declares Bash permission but no Bash invocation.",
      },
    ],
    verdictReasoning: [
      {
        kind: "gap",
        text: "Bash permission declared but unused (overreach above)",
      },
      { kind: "gap", text: "No SOUL.md governance file in repo" },
      {
        kind: "gap",
        text: "Fewer than 5 community scans (5+ required for VERIFIED)",
      },
    ],
    nextSteps: [
      {
        weight: "primary",
        label: "Review the skill",
        command: "cat $(opena2a path opena2a/code-review-skill)/SKILL.md",
      },
      {
        weight: "secondary",
        label: "Install",
        command: "opena2a install opena2a/code-review-skill",
      },
    ],
    reportTool: "hackmyagent",
    ...over,
  };
}

describe("renderCheckRichBlock — skill (mockup 3.1)", () => {
  it("emits header with name + verdict + score lines", () => {
    const out = renderCheckRichBlock(skillFixture());
    expect(out.header.name).toBe("opena2a/code-review-skill");
    expect(out.header.metaLines[0].text).toBe("skill  ·  LISTED");
    expect(out.header.metaLines[1].text).toContain("Score: 78/100");
    expect(out.header.metaLines[1].text).toContain("Last scan: 14d ago");
    expect(out.header.metaLines[1].text).toContain("Latest: 0.3.1 (5d ago)");
    expect(out.header.metaLines[2].text).toBe(
      "Publisher: opena2a-org (verified org)",
    );
    expect(out.header.metaLines[3].text).toBe("License: MIT");
    expect(out.header.metaLines[4].text).toContain("607 downloads/wk (rising)");
    expect(out.header.metaLines[4].text).toContain("4 community scans");
    expect(out.header.metaLines[4].text).toContain("1 finding");
  });

  it("includes Hardcoded secrets section in clean state", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find((s) => s.divider === "Hardcoded secrets");
    expect(sec).toBeDefined();
    expect(sec?.lines[0].text).toBe(
      "None detected on the latest version (0.3.1)",
    );
  });

  it("includes 'What is this skill?' section", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find((s) => s.divider === "What is this skill?");
    expect(sec).toBeDefined();
    expect(sec?.lines.some((l) => l.text.includes("code-review-skill"))).toBe(
      true,
    );
  });

  it("includes 'What we observed' with the medium finding", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find((s) => s.divider === "What we observed");
    expect(sec).toBeDefined();
    expect(sec?.lines[0].text).toBe(
      "MEDIUM   SKILL-PERM-OVERREACH at SKILL.md:23",
    );
  });

  it("includes 'Why LISTED, not VERIFIED' with numbered gaps", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find(
      (s) => s.divider === "Why LISTED, not VERIFIED",
    );
    expect(sec).toBeDefined();
    expect(sec?.lines).toHaveLength(3);
    expect(sec?.lines[0].text.startsWith("1.  ")).toBe(true);
  });

  it("includes 'How this skill could be misused' when misuseNarrative present", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find(
      (s) => s.divider === "How this skill could be misused",
    );
    expect(sec).toBeDefined();
    expect(sec?.lines[0].text).toBe("Low risk overall.");
  });

  it("includes 'Threat-model questions to consider' with 3 numbered items", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find(
      (s) => s.divider === "Threat-model questions to consider",
    );
    expect(sec).toBeDefined();
    expect(sec?.lines).toHaveLength(3);
    expect(sec?.lines[0].text.startsWith("1. ")).toBe(true);
  });

  it("includes 'Next' with action-gradient lines", () => {
    const out = renderCheckRichBlock(skillFixture());
    const sec = out.sections.find((s) => s.divider === "Next");
    expect(sec).toBeDefined();
    expect(sec?.lines).toHaveLength(2);
    expect(sec?.lines[0].text).toMatch(/^Review the skill:/);
  });
});

describe("renderCheckRichBlock — VERIFIED clean skill (mockup 3.2)", () => {
  it("'No findings.' under What we observed when findings empty", () => {
    const out = renderCheckRichBlock(
      skillFixture({
        header: {
          trustVerdict: "VERIFIED",
          trustScore: 94,
          lastScanAge: "3d ago",
          latestVersionLabel: "1.1.0 (3d ago)",
        },
        findings: [],
        verdictReasoning: [
          { kind: "positive", text: "Publisher is a verified organization" },
          {
            kind: "positive",
            text: "Declared permissions match observed tool usage exactly",
          },
        ],
      }),
    );
    const sec = out.sections.find((s) => s.divider === "What we observed");
    expect(sec?.lines[0].text).toBe("No findings.");
    expect(sec?.dividerTone).toBe("good");
  });

  it("Why VERIFIED renders [ok] markers when only positives", () => {
    const out = renderCheckRichBlock(
      skillFixture({
        header: { trustVerdict: "VERIFIED", trustScore: 94 },
        findings: [],
        verdictReasoning: [
          { kind: "positive", text: "Publisher is a verified organization" },
        ],
      }),
    );
    const sec = out.sections.find((s) => s.divider === "Why VERIFIED");
    expect(sec).toBeDefined();
    expect(sec?.lines[0].text).toBe(
      "[ok]  Publisher is a verified organization",
    );
  });
});

describe("renderCheckRichBlock — LISTED (UNSCANNED) skill (mockup 3.3)", () => {
  it("renders Score: [—], no observed-findings section, 'Why no score'", () => {
    const out = renderCheckRichBlock(
      skillFixture({
        header: {
          trustVerdict: "LISTED_UNSCANNED",
          trustScore: undefined,
          lastScanAge: "",
          latestVersionLabel: undefined,
          publisher: { name: "some-org", verified: true, kind: "verified org" },
          license: "Apache-2.0",
          downloads: { perWeek: 180, trend: "steady" },
          communityScans: 0,
          findingsCount: undefined,
        },
        hardcodedSecrets: { detected: [], scanCovered: false },
        latestVersion: undefined,
        findings: [],
        verdictReasoning: [
          {
            kind: "gap",
            text: "No scan has been run on this artifact.",
          },
        ],
        nextSteps: [
          {
            weight: "primary",
            label: "Local scan",
            command: "hackmyagent secure --skill some-org/data-explorer-skill",
          },
        ],
      }),
    );
    expect(out.header.metaLines[1].text).toContain("Score: [—]");
    expect(out.header.metaLines[1].text).toContain("Never scanned");
    expect(
      out.sections.some((s) => s.divider === "What we observed"),
    ).toBe(false);
    const why = out.sections.find((s) => s.divider === "Why no score");
    expect(why).toBeDefined();
    const secrets = out.sections.find((s) => s.divider === "Hardcoded secrets");
    expect(secrets?.lines[0].text).toMatch(/Not yet analyzed/);
  });
});

describe("renderCheckRichBlock — BLOCKED MCP (mockup 3.6)", () => {
  it("renders Recovery path + alternatives + critical primary action", () => {
    const out = renderCheckRichBlock({
      name: "malicious-mcp-xyz",
      artifactType: "mcp",
      header: {
        trustVerdict: "BLOCKED",
        trustScore: 8,
        lastScanAge: "1d ago",
        latestVersionLabel: "0.0.7 (1d ago)",
        publisher: { name: "unknown", verified: false, kind: "no provenance" },
        license: "none declared",
        downloads: { perWeek: 50, trend: "declining" },
        communityScans: 3,
        findingsCount: 14,
      },
      hardcodedSecrets: { detected: [], scanCovered: true },
      latestVersion: "0.0.7",
      mcp: {
        mcpName: "malicious-mcp-xyz",
        tools: [
          {
            name: "exec",
            signature: "exec(cmd)",
            description: "run shell command",
            destructive: true,
          },
        ],
        pathScope: "any",
        network: "pastebin.com",
        persistence: "writes binary to /tmp",
        auth: "none",
        sideEffects: ["spawn child", "fs read ~/.ssh"],
      },
      findings: [
        {
          severity: "critical",
          ruleId: "CRED-EXFIL",
          locator: "scripts/postinstall.js:1",
          description: "Reads ~/.ssh, ~/.aws, .env on install",
        },
      ],
      verdictReasoning: [
        { kind: "critical", text: "14 findings, 8 critical." },
        {
          kind: "critical",
          text: "CRED-EXFIL at scripts/postinstall.js:1",
        },
      ],
      nextSteps: [
        { weight: "primary", label: "Stop", command: "Do NOT install" },
        {
          weight: "secondary",
          label: "Find alternative",
          command: "ai-trust suggest mcp <what-you-needed>",
        },
      ],
      alternatives: [
        { name: "@malicious/mcp-xyz", tier: "VERIFIED", score: 87 },
        { name: "malicious-mcp-utility", tier: "LISTED", score: 71 },
        { name: "malicious-mcp", tier: "LISTED", score: 64 },
      ],
      reportTool: "hackmyagent",
    });
    expect(
      out.sections.some((s) => s.divider === "Recovery path"),
    ).toBe(true);
    const alt = out.sections.find(
      (s) => s.divider === "If you intended a different mcp",
    );
    expect(alt).toBeDefined();
    expect(alt?.lines).toHaveLength(4); // "Did you mean:" + 3 alternatives
    const next = out.sections.find((s) => s.divider === "Next");
    expect(next?.lines[0].tone).toBe("critical");
  });
});

describe("renderCheckRichBlock — section ordering invariant", () => {
  it("LISTED skill section order: Hardcoded secrets, What is this skill?, What we observed, Why LISTED, How misused, Threat-model, Next", () => {
    const out = renderCheckRichBlock(skillFixture());
    const order = out.sections.map((s) => s.divider);
    expect(order).toEqual([
      "Hardcoded secrets",
      "What is this skill?",
      "What we observed",
      "Why LISTED, not VERIFIED",
      "How this skill could be misused",
      "Threat-model questions to consider",
      "Next",
    ]);
  });

  it("MCP section order omits 'How this skill could be misused'", () => {
    const out = renderCheckRichBlock({
      ...skillFixture(),
      artifactType: "mcp",
      skill: undefined,
      mcp: {
        mcpName: "foo",
        tools: [],
        pathScope: "x",
        network: "x",
        persistence: "x",
        auth: "x",
        sideEffects: [],
      },
    });
    const order = out.sections.map((s) => s.divider);
    expect(order).toEqual([
      "Hardcoded secrets",
      "What is this MCP?",
      "What we observed",
      "Why LISTED, not VERIFIED",
      "Threat-model questions to consider",
      "Next",
    ]);
  });
});

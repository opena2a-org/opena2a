import { describe, it, expect } from "vitest";
import { runRuleEngine, type RuleEngineInput } from "./rule-engine.js";
import type {
  HardcodedSecret,
  McpNarrative,
  PermissionStatus,
  SkillNarrative,
} from "./narrative.js";

const skillPerms = (
  overrides: Partial<Record<string, PermissionStatus["status"]>> = {},
): PermissionStatus[] => [
  {
    name: "Read",
    declared: true,
    used: true,
    status: overrides.Read ?? "used",
  },
  {
    name: "Edit",
    declared: true,
    used: true,
    status: overrides.Edit ?? "used",
  },
];

const baseSkill = (perms: PermissionStatus[]): SkillNarrative => ({
  skillName: "opena2a/refactor-helper",
  activationPhrases: ["refactor", "extract function"],
  behaviorDescription: "Reads and edits source files in CWD.",
  permissions: perms,
  externalServices: ["anthropic.com"],
  persistence: "none",
  toolCallsObserved: [{ tool: "Read", count: 47 }],
  misuseNarrative: "",
  threatModelQuestions: [],
});

const baseMcp = (destructive: boolean): McpNarrative => ({
  mcpName: "@modelcontextprotocol/server-filesystem",
  tools: [
    {
      name: "read_file",
      signature: "read_file(path)",
      description: "file content as text",
      destructive: false,
    },
    {
      name: "write_file",
      signature: "write_file(path, content)",
      description: "overwrites if exists",
      destructive,
    },
  ],
  pathScope: "any path agent passes",
  network: "none",
  persistence: "none beyond user filesystem",
  auth: "none",
  sideEffects: [],
  threatModelQuestions: [],
});

const baseInput = (overrides: Partial<RuleEngineInput> = {}): RuleEngineInput => ({
  packageName: "opena2a/refactor-helper",
  latestVersion: "1.1.0",
  lastCleanVersion: "1.0.0",
  artifactType: "skill",
  verdict: "VERIFIED",
  scanStatus: "completed",
  publisher: { verified: true, hasNpmProvenance: true, hasMaintainerHistory: true },
  attestations: { predicateType: "https://slsa.dev/provenance/v1" },
  communityScans: 12,
  cleanCommunityScans: 12,
  hasSoulFile: true,
  findings: [],
  hardcodedSecrets: [],
  scanCovered: true,
  skill: baseSkill(skillPerms()),
  mcp: undefined,
  mcpHasSafetyAffordances: false,
  notFoundSuggestions: [],
  ...overrides,
});

describe("runRuleEngine — VERIFIED skill (mockup 3.2)", () => {
  const out = runRuleEngine(baseInput());

  it("emits all five expected positive reasoning entries", () => {
    const positives = out.verdictReasoning.filter((r) => r.kind === "positive").map((r) => r.text);
    expect(positives).toEqual(
      expect.arrayContaining([
        "Publisher is a verified organization",
        "npm provenance attestation present (SLSA v1)",
        "Declared permissions match observed tool usage exactly",
        "SOUL.md governance file present",
        "12 community scans, all clean",
        "No hardcoded credentials, no external service surprises",
      ]),
    );
  });

  it("emits no gap reasoning entries on a clean VERIFIED skill", () => {
    const gaps = out.verdictReasoning.filter((r) => r.kind === "gap");
    expect(gaps).toEqual([]);
  });

  it("primary action is Install confidently with the install command", () => {
    const primary = out.nextSteps.find((s) => s.weight === "primary");
    expect(primary?.label).toBe("Install confidently");
    expect(primary?.command).toBe("opena2a install opena2a/refactor-helper");
  });

  it("includes a pin-to-current secondary action", () => {
    const pin = out.nextSteps.find((s) => s.label.startsWith("Pin to "));
    expect(pin?.command).toBe("opena2a install opena2a/refactor-helper@1.1.0");
  });

  it("populates hardcodedSecretsBlock with scanCovered=true and empty detected[]", () => {
    expect(out.hardcodedSecretsBlock.scanCovered).toBe(true);
    expect(out.hardcodedSecretsBlock.detected).toEqual([]);
  });
});

describe("runRuleEngine — LISTED skill with permission overreach (mockup 3.1)", () => {
  const input = baseInput({
    packageName: "opena2a/code-review-skill",
    latestVersion: "0.3.1",
    lastCleanVersion: "",
    verdict: "LISTED",
    communityScans: 4,
    cleanCommunityScans: 4,
    hasSoulFile: false,
    skill: baseSkill([
      { name: "Read", declared: true, used: true, status: "used" },
      { name: "Bash", declared: true, used: false, status: "unused" },
    ]),
  });
  const out = runRuleEngine(input);

  it("flags Bash overreach as a gap", () => {
    const texts = out.verdictReasoning.map((r) => r.text);
    expect(texts).toEqual(
      expect.arrayContaining([
        "Bash permission declared but unused (overreach above)",
        "No SOUL.md governance file in repo",
        "Fewer than 5 community scans (5+ required for VERIFIED)",
      ]),
    );
  });

  it("does NOT emit the 'permissions match exactly' positive on overreach", () => {
    const texts = out.verdictReasoning.filter((r) => r.kind === "positive").map((r) => r.text);
    expect(texts).not.toContain("Declared permissions match observed tool usage exactly");
  });

  it("primary action is Review findings with --details", () => {
    const primary = out.nextSteps.find((s) => s.weight === "primary");
    expect(primary?.label).toBe("Review findings");
    expect(primary?.command).toBe("hackmyagent secure opena2a/code-review-skill --details");
  });

  it("falls back to pin-to-current when lastCleanVersion is empty", () => {
    const pin = out.nextSteps.find((s) => s.label.startsWith("Pin to current"));
    expect(pin?.command).toBe("opena2a install opena2a/code-review-skill@0.3.1");
  });
});

describe("runRuleEngine — LISTED MCP with destructive tools (mockup 3.4)", () => {
  const input = baseInput({
    packageName: "@modelcontextprotocol/server-filesystem",
    latestVersion: "2.1.0",
    lastCleanVersion: "",
    artifactType: "mcp",
    verdict: "LISTED",
    skill: undefined,
    mcp: baseMcp(true),
    mcpHasSafetyAffordances: false,
    communityScans: 31,
    cleanCommunityScans: 19,
    attestations: { predicateType: undefined },
  });
  const out = runRuleEngine(input);

  it("flags destructive-without-safety as a gap", () => {
    const texts = out.verdictReasoning.map((r) => r.text);
    expect(texts).toContain("Exposes destructive tools without safety affordances");
  });

  it("flags missing provenance as a gap", () => {
    const texts = out.verdictReasoning.map((r) => r.text);
    expect(texts).toContain("No provenance attestation");
  });

  it("clears the destructive gap when safety affordances are present", () => {
    const safe = runRuleEngine({ ...input, mcpHasSafetyAffordances: true });
    const texts = safe.verdictReasoning.map((r) => r.text);
    expect(texts).not.toContain("Exposes destructive tools without safety affordances");
  });
});

describe("runRuleEngine — BLOCKED MCP (mockup 3.6)", () => {
  const secret: HardcodedSecret = {
    type: "openai_api_key",
    typeLabel: "",
    file: "src/index.js",
    line: 12,
    maskedValue: "sk-proj-****",
    shownChars: 16,
    totalChars: 56,
    shipsInArtifact: true,
    severity: "high",
  };
  const input = baseInput({
    packageName: "malicious-mcp-xyz",
    artifactType: "mcp",
    verdict: "BLOCKED",
    skill: undefined,
    mcp: baseMcp(true),
    publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
    attestations: { predicateType: undefined },
    communityScans: 3,
    cleanCommunityScans: 0,
    hardcodedSecrets: [secret],
    findings: [
      {
        ruleId: "CRED-EXFIL",
        severity: "critical",
        description: "Reads ~/.ssh, ~/.aws, .env on install",
        locator: "scripts/postinstall.js:1",
      },
      {
        ruleId: "NET-PASTEBIN",
        severity: "critical",
        description: "Downloads binary from pastebin.com/raw/...",
        locator: "scripts/postinstall.js:14",
      },
      {
        ruleId: "NEMO-009",
        severity: "critical",
        description: "Executes downloaded binary via Function constructor",
        locator: "scripts/postinstall.js:18",
      },
    ],
  });
  const out = runRuleEngine(input);

  it("emits a header [critical] entry summarizing the count", () => {
    expect(out.verdictReasoning[0]).toEqual({
      kind: "critical",
      text: "3 findings, 3 critical.",
    });
  });

  it("emits one [critical] entry per critical finding with locator + description", () => {
    const texts = out.verdictReasoning.map((r) => r.text);
    expect(texts).toContain(
      "CRED-EXFIL at scripts/postinstall.js:1 — Reads ~/.ssh, ~/.aws, .env on install",
    );
    expect(texts).toContain(
      "NET-PASTEBIN at scripts/postinstall.js:14 — Downloads binary from pastebin.com/raw/...",
    );
    expect(texts).toContain(
      "NEMO-009 at scripts/postinstall.js:18 — Executes downloaded binary via Function constructor",
    );
  });

  it("flags missing maintainer history + missing provenance as critical", () => {
    const texts = out.verdictReasoning.map((r) => r.text);
    expect(texts).toContain("No maintainer history (typo-squat / drive-by profile).");
    expect(texts).toContain("No provenance attestation.");
  });

  it("emits 'Do NOT install' as the primary action", () => {
    const primary = out.nextSteps.find((s) => s.weight === "primary" && s.label === "Do NOT install");
    expect(primary).toBeDefined();
  });

  it("emits a Rotate <type> primary action with rotationUrl from the table", () => {
    const rotate = out.nextSteps.find((s) => s.label === "Rotate OpenAI API key");
    expect(rotate?.url).toBe("https://platform.openai.com/api-keys");
  });

  it("includes Find alternative + Report secondaries", () => {
    const labels = out.nextSteps.map((s) => s.label);
    expect(labels).toContain("Find alternative");
    expect(labels).toContain("Report");
  });
});

describe("runRuleEngine — LISTED_UNSCANNED (mockup 3.3)", () => {
  const input = baseInput({
    packageName: "some-org/data-explorer-skill",
    verdict: "LISTED_UNSCANNED",
    scanStatus: "never",
    scanCovered: false,
    skill: undefined,
    communityScans: 0,
    cleanCommunityScans: 0,
    hasSoulFile: false,
  });
  const out = runRuleEngine(input);

  it("emits a single 'no scan' explanation", () => {
    expect(out.verdictReasoning).toHaveLength(1);
    expect(out.verdictReasoning[0].kind).toBe("gap");
    expect(out.verdictReasoning[0].text).toMatch(/No scan has been run/);
  });

  it("primary action is 'Scan locally' with --skill flag", () => {
    const primary = out.nextSteps.find((s) => s.weight === "primary");
    expect(primary?.label).toBe("Scan locally");
    expect(primary?.command).toBe("hackmyagent secure --skill some-org/data-explorer-skill");
  });

  it("secondary action queues a community scan", () => {
    const queue = out.nextSteps.find((s) => s.label === "Queue community scan");
    expect(queue?.command).toBe("ai-trust check some-org/data-explorer-skill --scan-if-missing");
  });

  it("hardcodedSecretsBlock has scanCovered=false (renders 'Not yet analyzed.')", () => {
    expect(out.hardcodedSecretsBlock.scanCovered).toBe(false);
    expect(out.hardcodedSecretsBlock.detected).toEqual([]);
  });
});

describe("runRuleEngine — NOT_FOUND (mockup 3.7)", () => {
  const input = baseInput({
    packageName: "nonexistent-thing-xyz",
    verdict: "NOT_FOUND",
    scanStatus: "never",
    scanCovered: false,
    skill: undefined,
    notFoundSuggestions: ["nonexistent-thing", "nonexistent-thing-xy"],
  });
  const out = runRuleEngine(input);

  it("emits no verdictReasoning (renderer takes a different branch)", () => {
    expect(out.verdictReasoning).toEqual([]);
  });

  it("primary action is 'Did you mean' with the top suggestion", () => {
    const primary = out.nextSteps.find((s) => s.weight === "primary");
    expect(primary?.label).toBe("Did you mean");
    expect(primary?.command).toBe("hackmyagent check nonexistent-thing");
  });

  it("includes try-as-skill, try-as-mcp, and search-by-capability secondaries", () => {
    const cmds = out.nextSteps.filter((s) => s.weight === "secondary").map((s) => s.command);
    expect(cmds).toContain("hackmyagent check skill:nonexistent-thing-xyz");
    expect(cmds).toContain("hackmyagent check mcp:nonexistent-thing-xyz");
    expect(cmds).toContain("ai-trust suggest nonexistent-thing-xyz");
  });
});

describe("runRuleEngine — determinism", () => {
  it("identical inputs produce deeply-equal outputs (reasoning + nextSteps)", () => {
    const a = runRuleEngine(baseInput());
    const b = runRuleEngine(baseInput());
    expect(a).toEqual(b);
  });

  it("running on a BLOCKED input twice is deeply equal", () => {
    const input = baseInput({
      verdict: "BLOCKED",
      findings: [
        {
          ruleId: "CRED-EXFIL",
          severity: "critical",
          description: "X",
          locator: "a:1",
        },
      ],
      publisher: { verified: false, hasNpmProvenance: false, hasMaintainerHistory: false },
    });
    expect(runRuleEngine(input)).toEqual(runRuleEngine(input));
  });
});

describe("runRuleEngine — secret enrichment side effect", () => {
  it("populates rotationUrl on enrichedSecrets even when verdict is VERIFIED (mockup 3.5)", () => {
    const input = baseInput({
      verdict: "VERIFIED",
      hardcodedSecrets: [
        {
          type: "anthropic_api_key",
          typeLabel: "",
          file: "examples/quickstart.js",
          line: 14,
          maskedValue: "sk-ant-****",
          shownChars: 32,
          totalChars: 108,
          shipsInArtifact: true,
          severity: "critical",
        },
      ],
    });
    const out = runRuleEngine(input);
    expect(out.enrichedSecrets[0].rotationUrl).toBe("https://console.anthropic.com/settings/keys");
    expect(out.enrichedSecrets[0].typeLabel).toBe("Anthropic API key");
  });
});

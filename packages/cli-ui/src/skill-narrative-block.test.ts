import { describe, expect, it } from "vitest";
import {
  renderSkillMisuseNarrative,
  renderSkillNarrativeBlock,
  type SkillNarrativeLike,
} from "./skill-narrative-block.js";

function fixture(over: Partial<SkillNarrativeLike> = {}): SkillNarrativeLike {
  return {
    skillName: "code-review-skill",
    activationPhrases: ["review", "code review"],
    behaviorDescription:
      "Reads files from the current working directory and streams content to Claude.",
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
    misuseNarrative:
      "Low risk overall. Worst-case if compromised: Read access could exfiltrate files to anthropic.com.",
    ...over,
  };
}

describe("renderSkillNarrativeBlock", () => {
  it("emits the 'What is this skill?' header", () => {
    const out = renderSkillNarrativeBlock(fixture());
    expect(out.header).toBe("What is this skill?");
  });

  it("emits Skill name / Activates on / What it does rows in order", () => {
    const out = renderSkillNarrativeBlock(fixture());
    expect(out.lines[0].label).toMatch(/^Skill name:/);
    expect(out.lines[0].value).toBe("code-review-skill");
    expect(out.lines[1].label).toMatch(/^Activates on:/);
    expect(out.lines[1].value).toBe('"review", "code review"');
    expect(out.lines[2].label).toMatch(/^What it does:/);
    expect(out.lines[2].value).toMatch(/Reads files/);
  });

  it("renders Permissions header + indented sub-rows with status markers", () => {
    const out = renderSkillNarrativeBlock(fixture());
    const permRow = out.lines.find((l) => l.label.startsWith("Permissions declared"));
    expect(permRow).toBeDefined();
    const subRows = out.lines.filter((l) => l.indent === 1);
    expect(subRows).toHaveLength(2);
    expect(subRows[0].value).toContain("Read");
    expect(subRows[0].value).toContain("[used]");
    expect(subRows[0].tone).toBe("good");
    expect(subRows[1].value).toContain("Bash");
    expect(subRows[1].value).toContain("[unused]");
    expect(subRows[1].value).toContain("declared but no Bash invocation");
    expect(subRows[1].tone).toBe("warning");
  });

  it("renders External services / Persistence / Tool calls observed", () => {
    const out = renderSkillNarrativeBlock(fixture());
    const ext = out.lines.find((l) => l.label.startsWith("External services"));
    const per = out.lines.find((l) => l.label.startsWith("Persistence"));
    const tc = out.lines.find((l) => l.label.startsWith("Tool calls observed"));
    expect(ext?.value).toBe("anthropic.com");
    expect(per?.value).toBe("none");
    expect(tc?.value).toBe("Read x12");
  });

  it("falls back to placeholder when behaviorDescription is empty", () => {
    const out = renderSkillNarrativeBlock(fixture({ behaviorDescription: "" }));
    const row = out.lines.find((l) => l.label.startsWith("What it does"));
    expect(row?.value).toBe("Comprehension data not yet available.");
    expect(row?.tone).toBe("dim");
  });

  it("falls back to '(unknown)' when skillName is empty", () => {
    const out = renderSkillNarrativeBlock(fixture({ skillName: "" }));
    expect(out.lines[0].value).toBe("(unknown)");
  });

  it("renders 'no activation phrases declared' for empty list", () => {
    const out = renderSkillNarrativeBlock(fixture({ activationPhrases: [] }));
    expect(out.lines[1].value).toBe("no activation phrases declared");
  });

  it("renders 'no tool calls observed' for empty list", () => {
    const out = renderSkillNarrativeBlock(fixture({ toolCallsObserved: [] }));
    const tc = out.lines.find((l) => l.label.startsWith("Tool calls observed"));
    expect(tc?.value).toBe("no tool calls observed");
  });

  it("renders 'none' for empty externalServices", () => {
    const out = renderSkillNarrativeBlock(fixture({ externalServices: [] }));
    const ext = out.lines.find((l) => l.label.startsWith("External services"));
    expect(ext?.value).toBe("none");
  });

  it("permissions block is omitted when permissions[] is empty", () => {
    const out = renderSkillNarrativeBlock(fixture({ permissions: [] }));
    expect(
      out.lines.some((l) => l.label.startsWith("Permissions declared")),
    ).toBe(false);
  });

  it("escalates tone to critical for undeclared+used permissions", () => {
    const out = renderSkillNarrativeBlock(
      fixture({
        permissions: [
          {
            name: "Network",
            declared: false,
            used: true,
            status: "undeclared",
            note: "fetch() called but Network not in required-permissions",
          },
        ],
      }),
    );
    const sub = out.lines.find((l) => l.indent === 1 && l.value.includes("Network"));
    expect(sub?.tone).toBe("critical");
    expect(sub?.value).toContain("[undeclared]");
  });
});

describe("renderSkillMisuseNarrative", () => {
  it("returns the section when misuseNarrative is non-empty", () => {
    const out = renderSkillMisuseNarrative(fixture());
    expect(out).not.toBeNull();
    expect(out?.header).toBe("How this skill could be misused");
    expect(out?.paragraph).toMatch(/Low risk overall/);
  });

  it("returns null when misuseNarrative is empty (NanoMind OOD path)", () => {
    expect(renderSkillMisuseNarrative(fixture({ misuseNarrative: "" }))).toBeNull();
    expect(renderSkillMisuseNarrative(fixture({ misuseNarrative: "   " }))).toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import {
  MCP_THREAT_MODEL_QUESTIONS,
  SKILL_THREAT_MODEL_QUESTIONS,
  threatModelQuestionsFor,
} from "./threat-model-questions.js";

describe("threat-model questions — static templates", () => {
  it("skill has 3 questions per brief §6.1", () => {
    expect(SKILL_THREAT_MODEL_QUESTIONS).toHaveLength(3);
  });

  it("mcp has 3 questions per brief §6.2", () => {
    expect(MCP_THREAT_MODEL_QUESTIONS).toHaveLength(3);
  });

  it("skill questions cover CWD / pinning / API key scope", () => {
    expect(SKILL_THREAT_MODEL_QUESTIONS[0]).toMatch(/CWD|directory/);
    expect(SKILL_THREAT_MODEL_QUESTIONS[1]).toMatch(/pin|auto-update/);
    expect(SKILL_THREAT_MODEL_QUESTIONS[2]).toMatch(/API key|tenant/);
  });

  it("mcp questions cover write scope / realpath / backup", () => {
    expect(MCP_THREAT_MODEL_QUESTIONS[0]).toMatch(/writing outside|prompt-injected/);
    expect(MCP_THREAT_MODEL_QUESTIONS[1]).toMatch(/realpath|string-prefix/);
    expect(MCP_THREAT_MODEL_QUESTIONS[2]).toMatch(/snapshot|backup/);
  });

  it("frozen lists cannot be mutated by accident", () => {
    expect(() => {
      (SKILL_THREAT_MODEL_QUESTIONS as string[]).push("malicious");
    }).toThrow();
  });
});

describe("threatModelQuestionsFor", () => {
  it("returns the skill template for 'skill'", () => {
    expect(threatModelQuestionsFor("skill")).toBe(SKILL_THREAT_MODEL_QUESTIONS);
  });

  it("returns the mcp template for 'mcp'", () => {
    expect(threatModelQuestionsFor("mcp")).toBe(MCP_THREAT_MODEL_QUESTIONS);
  });
});

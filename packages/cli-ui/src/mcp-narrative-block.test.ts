import { describe, expect, it } from "vitest";
import {
  renderMcpNarrativeBlock,
  type McpNarrativeLike,
} from "./mcp-narrative-block.js";

function fixture(over: Partial<McpNarrativeLike> = {}): McpNarrativeLike {
  return {
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
        destructive: true,
      },
    ],
    pathScope: "Any path the agent passes is accepted.",
    network: "none.",
    persistence: "none beyond user filesystem.",
    auth: "none (relies on MCP transport's auth).",
    sideEffects: [],
    ...over,
  };
}

describe("renderMcpNarrativeBlock", () => {
  it("emits 'What is this MCP?' header", () => {
    const out = renderMcpNarrativeBlock(fixture());
    expect(out.header).toBe("What is this MCP?");
  });

  it("composes the opener from tools count (plural)", () => {
    const out = renderMcpNarrativeBlock(fixture());
    expect(out.lines[0].value).toBe(
      "MCP server. Exposes 2 tools to a connected agent:",
    );
  });

  it("uses 'tool' (singular) when exactly 1 tool exposed", () => {
    const out = renderMcpNarrativeBlock(
      fixture({
        tools: [
          {
            name: "exec",
            signature: "exec(cmd)",
            description: "run shell command",
            destructive: true,
          },
        ],
      }),
    );
    expect(out.lines[0].value).toBe(
      "MCP server. Exposes 1 tool to a connected agent:",
    );
  });

  it("renders 'No tools exposed' when tool list is empty", () => {
    const out = renderMcpNarrativeBlock(fixture({ tools: [] }));
    expect(out.lines[0].value).toBe("MCP server. No tools exposed.");
  });

  it("renders tool entries column-aligned by signature, with description suffix", () => {
    const out = renderMcpNarrativeBlock(fixture());
    const tools = out.lines.filter((l) => l.indent === 1);
    expect(tools).toHaveLength(2);
    expect(tools[0].value.startsWith("- read_file(path)")).toBe(true);
    expect(tools[0].value).toContain("— file content as text");
    expect(tools[1].value.startsWith("- write_file(path, content)")).toBe(true);
    expect(tools[1].value).toContain("— overwrites if exists");
  });

  it("destructive tools render with warning tone", () => {
    const out = renderMcpNarrativeBlock(fixture());
    const tools = out.lines.filter((l) => l.indent === 1);
    expect(tools[0].tone).toBe("default"); // read_file
    expect(tools[1].tone).toBe("warning"); // write_file (destructive)
  });

  it("renders Path scope / Network / Persistence / Auth labelled rows in order", () => {
    const out = renderMcpNarrativeBlock(fixture());
    const path = out.lines.find((l) => l.label.startsWith("Path scope"));
    const net = out.lines.find((l) => l.label.startsWith("Network"));
    const per = out.lines.find((l) => l.label.startsWith("Persistence"));
    const auth = out.lines.find((l) => l.label.startsWith("Auth"));
    expect(path?.value).toMatch(/Any path the agent passes/);
    expect(net?.value).toBe("none.");
    expect(per?.value).toBe("none beyond user filesystem.");
    expect(auth?.value).toMatch(/^none/);
  });

  it("falls back to placeholder strings for empty scope fields", () => {
    const out = renderMcpNarrativeBlock(
      fixture({
        pathScope: "",
        network: "",
        persistence: "",
        auth: "",
      }),
    );
    expect(
      out.lines.find((l) => l.label.startsWith("Path scope"))?.value,
    ).toBe("not specified");
    expect(
      out.lines.find((l) => l.label.startsWith("Network"))?.value,
    ).toBe("none");
    expect(
      out.lines.find((l) => l.label.startsWith("Persistence"))?.value,
    ).toBe("none");
    expect(out.lines.find((l) => l.label.startsWith("Auth"))?.value).toBe(
      "none",
    );
  });

  it("emits Side effects row only when sideEffects[] is non-empty", () => {
    const without = renderMcpNarrativeBlock(fixture());
    const withFx = renderMcpNarrativeBlock(
      fixture({ sideEffects: ["spawn child", "fs writes"] }),
    );
    expect(without.lines.some((l) => l.label.startsWith("Side effects"))).toBe(
      false,
    );
    const fxRow = withFx.lines.find((l) => l.label.startsWith("Side effects"));
    expect(fxRow?.value).toBe("spawn child; fs writes");
    expect(fxRow?.tone).toBe("warning");
  });
});

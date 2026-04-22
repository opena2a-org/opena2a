import { describe, it, expect } from "vitest";
import { renderNotFoundBlock } from "./not-found-block.js";

describe("renderNotFoundBlock — header", () => {
  it("includes ecosystem in header when provided", () => {
    const out = renderNotFoundBlock({ pkg: "@anthropic/code-review", ecosystem: "npm" });
    expect(out.header.text).toBe("Package not found: @anthropic/code-review (npm)");
    expect(out.header.tone).toBe("critical");
  });

  it("omits ecosystem suffix when not provided", () => {
    const out = renderNotFoundBlock({ pkg: "@anthropic/code-review" });
    expect(out.header.text).toBe("Package not found: @anthropic/code-review");
  });
});

describe("renderNotFoundBlock — suggestions", () => {
  it("emits Did-you-mean header then one line per suggestion", () => {
    const out = renderNotFoundBlock({
      pkg: "code-review",
      suggestions: ["claude-code-review", "@wuyanbin/ai-code-review"],
    });
    const values = out.lines.map((l) => l.value);
    expect(values[0]).toBe("Did you mean?");
    expect(values[1]).toBe("claude-code-review");
    expect(values[2]).toBe("@wuyanbin/ai-code-review");
    expect(out.lines[1].tone).toBe("good");
  });

  it("omits the Did-you-mean block when suggestions is empty", () => {
    const out = renderNotFoundBlock({ pkg: "x", suggestions: [] });
    expect(out.lines.find((l) => l.value === "Did you mean?")).toBeUndefined();
  });

  it("omits the Did-you-mean block when suggestions is undefined", () => {
    const out = renderNotFoundBlock({ pkg: "x" });
    expect(out.lines).toEqual([]);
  });
});

describe("renderNotFoundBlock — skill fallback", () => {
  it("renders a Try line when skillFallback is available", () => {
    const out = renderNotFoundBlock({
      pkg: "@anthropic/code-review",
      skillFallback: { available: true, command: "hma check @anthropic/code-review" },
    });
    const tryLine = out.lines.find((l) => l.label === "Try")!;
    expect(tryLine.value).toBe("hma check @anthropic/code-review");
    expect(tryLine.tone).toBe("default");
  });

  it("skips the Try line when skillFallback is unavailable", () => {
    const out = renderNotFoundBlock({
      pkg: "@anthropic/code-review",
      skillFallback: { available: false, command: "never-shown" },
    });
    expect(out.lines.find((l) => l.label === "Try")).toBeUndefined();
  });
});

describe("renderNotFoundBlock — error hint", () => {
  it("emits the error hint ahead of suggestions and fallback (F3 translation)", () => {
    const out = renderNotFoundBlock({
      pkg: "anthropic/code-review",
      errorHint: "Looks like a git path — use @scope/name for npm packages.",
      suggestions: ["@anthropic/code-review"],
    });
    expect(out.lines[0].value).toContain("git path");
    expect(out.lines[0].tone).toBe("warning");
    expect(out.lines[1].value).toBe("Did you mean?");
  });

  it("omits the hint line when errorHint is undefined", () => {
    const out = renderNotFoundBlock({ pkg: "x" });
    expect(out.lines.find((l) => l.tone === "warning")).toBeUndefined();
  });
});

describe("renderNotFoundBlock — combined", () => {
  it("renders everything in order: hint, suggestions header + items, fallback", () => {
    const out = renderNotFoundBlock({
      pkg: "anthropic/code-review",
      ecosystem: "npm",
      errorHint: "git-style name; try @scope/name",
      suggestions: ["@anthropic/code-review"],
      skillFallback: { available: true, command: "hma check @anthropic/code-review" },
    });
    expect(out.lines.map((l) => l.value)).toEqual([
      "git-style name; try @scope/name",
      "Did you mean?",
      "@anthropic/code-review",
      "hma check @anthropic/code-review",
    ]);
  });
});

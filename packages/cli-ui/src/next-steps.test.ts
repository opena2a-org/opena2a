import { describe, it, expect } from "vitest";
import { renderNextSteps } from "./next-steps.js";

describe("renderNextSteps — bullet style", () => {
  it("marks the first primary CTA with → and tone good", () => {
    const out = renderNextSteps({
      ctas: [
        { label: "Full scan", command: "hma secure .", primary: true },
        { label: "Contribute", command: "hma contribute" },
      ],
    });
    expect(out.lines[0].bullet).toBe("→");
    expect(out.lines[0].tone).toBe("good");
    expect(out.lines[1].bullet).toBe("•");
    expect(out.lines[1].tone).toBe("default");
  });

  it("only one line gets the primary bullet when multiple are flagged", () => {
    const out = renderNextSteps({
      ctas: [
        { label: "A", command: "a", primary: true },
        { label: "B", command: "b", primary: true },
      ],
    });
    expect(out.lines[0].bullet).toBe("→");
    expect(out.lines[1].bullet).toBe("•");
  });

  it("renders all lines as default-bullet when no CTA is primary", () => {
    const out = renderNextSteps({
      ctas: [
        { label: "A", command: "a" },
        { label: "B", command: "b" },
      ],
    });
    expect(out.lines.every((l) => l.bullet === "•")).toBe(true);
    expect(out.lines.every((l) => l.tone === "default")).toBe(true);
  });
});

describe("renderNextSteps — contents pass-through", () => {
  it("preserves labels and commands verbatim", () => {
    const out = renderNextSteps({
      ctas: [
        { label: "Full scan", command: "opena2a review ." },
        { label: "Contribute findings", command: "opena2a contribute --enable" },
      ],
    });
    expect(out.lines[0].label).toBe("Full scan");
    expect(out.lines[0].command).toBe("opena2a review .");
    expect(out.lines[1].label).toBe("Contribute findings");
    expect(out.lines[1].command).toBe("opena2a contribute --enable");
  });

  it("handles an empty CTA list gracefully", () => {
    const out = renderNextSteps({ ctas: [] });
    expect(out.lines).toEqual([]);
  });

  it("supports a single primary CTA", () => {
    const out = renderNextSteps({
      ctas: [{ label: "Rescan", command: "hma check express --refresh", primary: true }],
    });
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].bullet).toBe("→");
    expect(out.lines[0].tone).toBe("good");
  });
});

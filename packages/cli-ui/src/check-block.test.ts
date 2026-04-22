import { describe, it, expect } from "vitest";
import { renderCheckBlock, type CheckBlockInput } from "./check-block.js";

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

describe("renderCheckBlock — header", () => {
  it("passes the name through and includes version + type when present", () => {
    const out = renderCheckBlock(base({ version: "1.2.3", packageType: "mcp_server" }));
    expect(out.header.name).toBe("example");
    expect(out.header.meta).toEqual(["v1.2.3", "mcp server"]);
  });

  it("omits version and type when absent", () => {
    const out = renderCheckBlock(base());
    expect(out.header.meta).toEqual([]);
  });
});

describe("renderCheckBlock — verdict", () => {
  it.each([
    ["passed", "good", "No known issues"],
    ["safe", "good", "No known issues"],
    ["warning", "warning", "Warning — review before installing"],
    ["warnings", "warning", "Warning — review before installing"],
    ["blocked", "critical", "Blocked by registry"],
    ["failed", "critical", "Blocked by registry"],
    ["listed", "default", "Listed — limited signal"],
  ])("verdict %s → tone %s", (verdict, expectedTone, expectedText) => {
    const out = renderCheckBlock(base({ verdict }));
    expect(out.verdict.tone).toBe(expectedTone);
    expect(out.verdict.text).toBe(expectedText);
  });

  it("renders an unknown verdict as dim", () => {
    const out = renderCheckBlock(base({ verdict: "gibberish" }));
    expect(out.verdict.tone).toBe("dim");
    expect(out.verdict.text).toBe("Unknown verdict");
  });
});

describe("renderCheckBlock — meter gating (F6)", () => {
  it("shows the Trust meter when scanStatus is completed", () => {
    const out = renderCheckBlock(base({ scanStatus: "completed" }));
    expect(out.meterShown).toBe(true);
    const trust = out.lines.find((l) => l.label === "Trust")!;
    expect(trust).toBeDefined();
    // Meter string includes the score digits somewhere in the chalk-wrapped payload.
    expect(trust.value).toMatch(/82/);
    expect(trust.tone).toBe("good");
  });

  it("shows the Trust meter when scanStatus is warnings", () => {
    const out = renderCheckBlock(base({ scanStatus: "warnings" }));
    expect(out.meterShown).toBe(true);
  });

  it("hides the Trust meter when scanStatus is pending", () => {
    const out = renderCheckBlock(base({ scanStatus: "pending" }));
    expect(out.meterShown).toBe(false);
    const trust = out.lines.find((l) => l.label === "Trust")!;
    expect(trust.value).toContain("not scanned");
    expect(trust.tone).toBe("dim");
  });

  it("hides the Trust meter when scanStatus is undefined", () => {
    const out = renderCheckBlock(base({ scanStatus: undefined }));
    expect(out.meterShown).toBe(false);
  });

  it("hides the Trust meter for any unrecognized scanStatus", () => {
    const out = renderCheckBlock(base({ scanStatus: "weird-new-state" }));
    expect(out.meterShown).toBe(false);
  });
});

describe("renderCheckBlock — score normalization", () => {
  it("accepts 0-1 scores (Registry canonical scale) and scales to 0-100", () => {
    const out = renderCheckBlock(base({ trustScore: 0.35 }));
    const trust = out.lines.find((l) => l.label === "Trust")!;
    expect(trust.value).toMatch(/35/);
    expect(trust.tone).toBe("critical");
  });

  it("accepts 0-100 scores as-is for callers that pre-scale", () => {
    const out = renderCheckBlock(base({ trustScore: 45 }));
    const trust = out.lines.find((l) => l.label === "Trust")!;
    expect(trust.value).toMatch(/45/);
    expect(trust.tone).toBe("warning");
  });
});

describe("renderCheckBlock — trust level", () => {
  it("always emits a Level line even when meter is hidden", () => {
    const out = renderCheckBlock(base({ scanStatus: undefined }));
    const level = out.lines.find((l) => l.label === "Level")!;
    expect(level).toBeDefined();
    expect(level.value).toContain("Scanned");
  });

  it.each([
    [0, "critical"],
    [1, "warning"],
    [2, "warning"],
    [3, "good"],
    [4, "good"],
  ])("trustLevel %d → tone %s", (lvl, expectedTone) => {
    const out = renderCheckBlock(base({ trustLevel: lvl }));
    const level = out.lines.find((l) => l.label === "Level")!;
    expect(level.tone).toBe(expectedTone);
  });
});

describe("renderCheckBlock — optional fields", () => {
  it("hides Publisher when not provided (F5 missing=hidden)", () => {
    const out = renderCheckBlock(base());
    expect(out.lines.find((l) => l.label === "Publisher")).toBeUndefined();
  });

  it("shows Publisher with verified marker", () => {
    const out = renderCheckBlock(base({ publisher: { name: "Anthropic", verified: true } }));
    const pub = out.lines.find((l) => l.label === "Publisher")!;
    expect(pub.value).toBe("Anthropic · verified");
    expect(pub.tone).toBe("good");
  });

  it("shows Publisher with unverified marker", () => {
    const out = renderCheckBlock(base({ publisher: { name: "Someone", verified: false } }));
    const pub = out.lines.find((l) => l.label === "Publisher")!;
    expect(pub.value).toBe("Someone · unverified");
    expect(pub.tone).toBe("warning");
  });

  it("shows Publisher with no verification suffix when verified is undefined", () => {
    const out = renderCheckBlock(base({ publisher: { name: "Someone" } }));
    const pub = out.lines.find((l) => l.label === "Publisher")!;
    expect(pub.value).toBe("Someone");
    expect(pub.tone).toBe("default");
  });

  it("hides Permissions when empty or undefined", () => {
    expect(renderCheckBlock(base()).lines.find((l) => l.label === "Permissions")).toBeUndefined();
    expect(
      renderCheckBlock(base({ permissions: [] })).lines.find((l) => l.label === "Permissions"),
    ).toBeUndefined();
  });

  it("shows Permissions joined with comma-space", () => {
    const out = renderCheckBlock(base({ permissions: ["fs-write", "net-egress"] }));
    const perms = out.lines.find((l) => l.label === "Permissions")!;
    expect(perms.value).toBe("fs-write, net-egress");
  });

  it("renders Revocation listed as critical", () => {
    const out = renderCheckBlock(base({ revocation: { listed: true } }));
    const rev = out.lines.find((l) => l.label === "Revocation")!;
    expect(rev.value).toBe("on blocklist — do not install");
    expect(rev.tone).toBe("critical");
  });

  it("renders Revocation not-listed as good", () => {
    const out = renderCheckBlock(base({ revocation: { listed: false } }));
    const rev = out.lines.find((l) => l.label === "Revocation")!;
    expect(rev.value).toBe("not on blocklist");
    expect(rev.tone).toBe("good");
  });

  it("hides Revocation when undefined", () => {
    const out = renderCheckBlock(base());
    expect(out.lines.find((l) => l.label === "Revocation")).toBeUndefined();
  });

  it("hides Scans when 0 or undefined", () => {
    expect(renderCheckBlock(base()).lines.find((l) => l.label === "Scans")).toBeUndefined();
    expect(
      renderCheckBlock(base({ communityScans: 0 })).lines.find((l) => l.label === "Scans"),
    ).toBeUndefined();
  });

  it("pluralizes community scans correctly", () => {
    expect(
      renderCheckBlock(base({ communityScans: 1 })).lines.find((l) => l.label === "Scans")!.value,
    ).toBe("1 community scan");
    expect(
      renderCheckBlock(base({ communityScans: 7 })).lines.find((l) => l.label === "Scans")!.value,
    ).toBe("7 community scans");
  });

  it("renders Last scan as warning when stale (>90 days)", () => {
    const ancient = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000).toISOString();
    const out = renderCheckBlock(base({ lastScannedAt: ancient }));
    const last = out.lines.find((l) => l.label === "Last scan")!;
    expect(last.value).toContain("stale");
    expect(last.tone).toBe("warning");
  });

  it("renders Last scan as default when recent", () => {
    const recent = new Date(Date.now() - 2 * 24 * 60 * 60 * 1000).toISOString();
    const out = renderCheckBlock(base({ lastScannedAt: recent }));
    const last = out.lines.find((l) => l.label === "Last scan")!;
    expect(last.value).toBe("2 days ago");
    expect(last.tone).toBe("default");
  });

  it("hides Last scan when lastScannedAt is missing", () => {
    const out = renderCheckBlock(base());
    expect(out.lines.find((l) => l.label === "Last scan")).toBeUndefined();
  });
});

describe("renderCheckBlock — line ordering (F5 canonical schema)", () => {
  it("emits Trust, then Level, then optional rows in a stable order", () => {
    const out = renderCheckBlock(
      base({
        publisher: { name: "Anthropic", verified: true },
        permissions: ["fs"],
        revocation: { listed: false },
        communityScans: 3,
        lastScannedAt: new Date().toISOString(),
      }),
    );
    const labels = out.lines.map((l) => l.label);
    expect(labels).toEqual([
      "Trust",
      "Level",
      "Publisher",
      "Permissions",
      "Revocation",
      "Scans",
      "Last scan",
    ]);
  });
});

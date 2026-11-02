import { describe, it, expect } from "vitest";
import { renderCheckBlock, type CheckBlockInput, type CheckRevocation } from "./check-block.js";

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

  it("a listed revocation lifts a passed verdict to critical", () => {
    const revocation: CheckRevocation = {
      state: "listed",
      source: "Example list",
      listedAt: "2026-10-01T12:00:00Z",
    };
    expect(renderCheckBlock(base({ verdict: "passed", revocation })).verdict).toEqual({
      text: "Revoked — do not install",
      tone: "critical",
    });
    expect(renderCheckBlock(base({ verdict: "blocked", revocation })).verdict).toEqual({
      text: "Blocked by registry",
      tone: "critical",
    });
  });
});

describe("renderCheckBlock — meter gating", () => {
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
  it("hides Publisher when not provided (missing = hidden)", () => {
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

  it("renders a listed revocation as one critical row naming its source and date", () => {
    const out = renderCheckBlock(
      base({
        revocation: { state: "listed", source: "Example list", listedAt: "2026-10-01T12:00:00Z" },
      }),
    );
    const rows = out.lines.filter((l) => l.label === "Revoked");
    expect(rows).toHaveLength(1);
    expect(rows[0].value).toBe("by Example list on 2026-10-01 — do not install");
    expect(rows[0].tone).toBe("critical");
  });

  it("draws no row for not-listed or not-checked", () => {
    const plain = renderCheckBlock(base());
    const states: CheckRevocation[] = [
      { state: "not-listed", source: "Example list" },
      { state: "not-checked", reason: "no revocation source" },
    ];
    for (const revocation of states) {
      const out = renderCheckBlock(base({ revocation }));
      expect(out.lines).toEqual(plain.lines);
      const labels = out.lines.map((l) => l.label);
      expect(labels).not.toContain("Revoked");
      expect(labels).not.toContain("Revocation");
      expect(out.lines.some((l) => l.value.includes("blocklist"))).toBe(false);
      expect(out.verdict).toEqual(plain.verdict);
    }
  });

  it("hides Revoked when revocation is undefined", () => {
    const out = renderCheckBlock(base());
    expect(out.lines.find((l) => l.label === "Revoked")).toBeUndefined();
  });

  it("a listed revocation with an unparseable date or an empty source still draws its row", () => {
    const out = renderCheckBlock(
      base({ revocation: { state: "listed", source: " \n ", listedAt: "not a date" } }),
    );
    const rev = out.lines.find((l) => l.label === "Revoked")!;
    expect(rev.value).toBe("by an unnamed source on an unrecorded date — do not install");
    expect(rev.tone).toBe("critical");
  });

  it("a source is printed on one line without terminal escapes", () => {
    const out = renderCheckBlock(
      base({
        revocation: {
          state: "listed",
          source: "Example\x1b[31m\nlist",
          listedAt: "2026-10-01T12:00:00Z",
        },
      }),
    );
    const rev = out.lines.find((l) => l.label === "Revoked")!;
    expect(rev.value).toContain("by Example list on");
    expect(rev.value).not.toContain("\x1b");
    expect(rev.value).not.toContain("\n");
  });

  it("the revocation label leaves two spaces in a 10-column field", () => {
    const plainLabels = new Set(renderCheckBlock(base()).lines.map((l) => l.label));
    const out = renderCheckBlock(
      base({
        revocation: { state: "listed", source: "Example list", listedAt: "2026-10-01T12:00:00Z" },
      }),
    );
    // The listed row is the one row the revocation adds to the block.
    const added = out.lines.filter((l) => !plainLabels.has(l.label));
    expect(added).toHaveLength(1);
    expect(added[0].label.length).toBeLessThanOrEqual(8);
  });

  it("hides Scans when 0 or undefined", () => {
    expect(renderCheckBlock(base()).lines.find((l) => l.label === "Scans")).toBeUndefined();
    expect(
      renderCheckBlock(base({ communityScans: 0 })).lines.find((l) => l.label === "Scans"),
    ).toBeUndefined();
  });

  it("labels the count of shared scans unverified and pluralizes it", () => {
    const scans = (n: number) =>
      renderCheckBlock(base({ communityScans: n })).lines.find((l) => l.label === "Scans")!.value;
    expect(scans(1)).toBe("1 shared scan (unverified)");
    expect(scans(2)).toBe("2 shared scans (unverified)");
    expect(scans(7)).toBe("7 shared scans (unverified)");
  });

  it("does not call the count community scans for 0, 1 or 2 scans", () => {
    for (const n of [0, 1, 2]) {
      expect(JSON.stringify(renderCheckBlock(base({ communityScans: n })))).not.toContain(
        "community scan",
      );
    }
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

describe("renderCheckBlock — line ordering (canonical schema)", () => {
  it("emits Trust, then Level, then optional rows in a stable order", () => {
    const out = renderCheckBlock(
      base({
        publisher: { name: "Anthropic", verified: true },
        permissions: ["fs"],
        revocation: { state: "listed", source: "Example list", listedAt: "2026-10-01T00:00:00Z" },
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
      "Revoked",
      "Scans",
      "Last scan",
    ]);
  });
});

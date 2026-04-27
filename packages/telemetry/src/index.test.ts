import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";

let tmpHome: string;
let fetchMock: ReturnType<typeof vi.fn>;

async function freshSdk() {
  vi.resetModules();
  return await import("./index.js");
}

beforeEach(() => {
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-sdk-"));
  process.env.XDG_CONFIG_HOME = tmpHome;
  process.env.OPENA2A_TELEMETRY_URL = "http://test.local/event";
  delete process.env.OPENA2A_TELEMETRY;
  delete process.env.OPENA2A_TELEMETRY_DEBUG;
  fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  rmSync(tmpHome, { recursive: true, force: true });
  vi.unstubAllGlobals();
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.OPENA2A_TELEMETRY_URL;
});

describe("init + start", () => {
  it("init() does not emit a banner to stderr", async () => {
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    const writes = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(writes).not.toMatch(/telemetry/i);
    expect(writes).not.toMatch(/anonymous/i);
    stderrSpy.mockRestore();
  });

  it("start() POSTs a start event with platform + node_major", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.start();
    await new Promise((r) => setTimeout(r, 10));
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toMatchObject({
      tool: "dvaa",
      version: "0.8.1",
      event: "start",
    });
    expect(body.install_id).toMatch(/^[0-9a-f]{8}-/);
    expect(body.platform).toBeTruthy();
    expect(typeof body.node_major).toBe("number");
  });
});

describe("track", () => {
  it("posts a command event with name + success + duration_ms", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "hma", version: "0.18.0" });
    await tele.track("scan", { success: true, durationMs: 312 });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toMatchObject({
      tool: "hma",
      version: "0.18.0",
      event: "command",
      name: "scan",
      success: true,
      duration_ms: 312,
    });
  });

  it("posts even with no fields", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "ai-trust", version: "0.3.0" });
    await tele.track("audit");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.event).toBe("command");
    expect(body.name).toBe("audit");
  });
});

describe("error", () => {
  it("encodes failure code as name suffix and sets success=false", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.error("scan", "HMA_TIMEOUT");
    await new Promise((r) => setTimeout(r, 10));
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toMatchObject({
      event: "error",
      name: "scan:HMA_TIMEOUT",
      success: false,
    });
  });

  it("truncates name+code to 64 chars (Registry name_len constraint)", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.error("a".repeat(40), "B".repeat(40));
    await new Promise((r) => setTimeout(r, 10));
    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body.name.length).toBe(64);
  });
});

describe("opt-out", () => {
  it("OPENA2A_TELEMETRY=off blocks all sends", async () => {
    process.env.OPENA2A_TELEMETRY = "off";
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.start();
    await tele.track("scan");
    tele.error("scan", "X");
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("setOptOut(false) blocks subsequent sends", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.setOptOut(false);
    tele.start();
    await tele.track("scan");
    await new Promise((r) => setTimeout(r, 50));
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("status", () => {
  it("returns enabled+policy URL+install id even before init", async () => {
    const tele = await freshSdk();
    const s = tele.status();
    expect(s.enabled).toBe(true);
    expect(s.policyURL).toBe("https://opena2a.org/telemetry");
    expect(s.installId).toBeTruthy();
    expect(s.configPath).toContain("telemetry.json");
  });

  it("reflects setOptOut state", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    expect(tele.status().enabled).toBe(true);
    tele.setOptOut(false);
    expect(tele.status().enabled).toBe(false);
  });
});

describe("debug print", () => {
  it("OPENA2A_TELEMETRY_DEBUG=print echoes payload to stderr", async () => {
    process.env.OPENA2A_TELEMETRY_DEBUG = "print";
    const stderrSpy = vi.spyOn(process.stderr, "write").mockReturnValue(true);
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.start();
    await new Promise((r) => setTimeout(r, 10));
    const writes = stderrSpy.mock.calls.map((c) => String(c[0])).join("");
    expect(writes).toContain("[opena2a:telemetry]");
    expect(writes).toContain("\"event\":\"start\"");
    stderrSpy.mockRestore();
  });
});

describe("network failure tolerance", () => {
  it("never throws when fetch rejects", async () => {
    fetchMock.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    await expect(tele.track("scan")).resolves.toBeUndefined();
  });
});

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scrubSuppressionEnv, restoreSuppressionEnv, type SavedEnv } from "./test-support.js";

let tmpHome: string;
let fetchMock: ReturnType<typeof vi.fn>;
let savedEnv: SavedEnv;

async function freshSdk() {
  vi.resetModules();
  return await import("./index.js");
}

beforeEach(() => {
  // These suites assert telemetry actually fires; CI suppression would
  // silence every event and fail them on a runner. See test-support.ts.
  savedEnv = scrubSuppressionEnv();
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-sdk-"));
  process.env.XDG_CONFIG_HOME = tmpHome;
  process.env.OPENA2A_TELEMETRY_URL = "http://test.local/event";
  delete process.env.OPENA2A_TELEMETRY;
  delete process.env.OPENA2A_TELEMETRY_DEBUG;
  fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetchMock);
});

afterEach(() => {
  restoreSuppressionEnv(savedEnv);
  rmSync(tmpHome, { recursive: true, force: true });
  vi.unstubAllGlobals();
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.OPENA2A_TELEMETRY_URL;
});

describe("CI suppression (end to end)", () => {
  // The bug this guards: CI runners are ephemeral, so each job derived a
  // fresh install_id and was counted as a new install / active user.
  // Adoption metrics tracked our own build frequency instead of usage.
  it("emits nothing at all when running in CI", async () => {
    process.env.CI = "true";
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.9.3" });
    tele.start();
    await tele.track("scan", { success: true, durationMs: 10 });
    tele.error("scan", "BOOM");
    await tele.flush();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("emits nothing when DO_NOT_TRACK is set", async () => {
    process.env.DO_NOT_TRACK = "1";
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.25.0" });
    tele.start();
    await tele.track("scan", { success: true });
    await tele.flush();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("still emits in CI when explicitly opted in", async () => {
    process.env.CI = "true";
    process.env.OPENA2A_TELEMETRY = "on";
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.9.3" });
    await tele.track("scan", { success: true });
    await tele.flush();
    expect(fetchMock).toHaveBeenCalled();
  });
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

describe("successFromExitCode", () => {
  it("exit 0 = success (no findings)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(0)).toBe(true);
  });
  it("exit 1 = success (findings detected — security-tool convention)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(1)).toBe(true);
  });
  it("exit 2 = failure (real crash / config error)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(2)).toBe(false);
  });
  it("exit 127 = failure", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(127)).toBe(false);
  });
  it("undefined treated as 0 (success)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(undefined)).toBe(true);
  });
  it("null treated as 0 (success)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(null)).toBe(true);
  });
  it("string '0' coerced to success (Node 22 widened exitCode type)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode("0")).toBe(true);
  });
  it("string '1' coerced to success", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode("1")).toBe(true);
  });
  it("string '2' coerced to failure", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode("2")).toBe(false);
  });
  it("unparseable string = failure", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode("oops")).toBe(false);
  });
  it("negative exit codes return false (out of POSIX 0-255 range)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(-1)).toBe(false);
  });
  it("exit codes > 255 return false (out of POSIX 0-255 range)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(256)).toBe(false);
    expect(tele.successFromExitCode(999)).toBe(false);
    expect(tele.successFromExitCode(Number.MAX_SAFE_INTEGER)).toBe(false);
  });
  it("Infinity / -Infinity return false", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(Number.POSITIVE_INFINITY)).toBe(false);
    expect(tele.successFromExitCode(Number.NEGATIVE_INFINITY)).toBe(false);
  });
});

describe("successFromExitCode — semanticSuccessCodes ([CHIEF-CSR-018] + [CHIEF-CPO-022])", () => {
  it("exit 2 with semanticSuccessCodes [2] = success (ai-trust not-found is a working outcome)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(2, [2])).toBe(true);
  });
  it("exit 3 with semanticSuccessCodes [2] = failure (only listed codes are semantic)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(3, [2])).toBe(false);
  });
  it("exit 1 with semanticSuccessCodes [2] = success (POSIX convention still applies)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(1, [2])).toBe(true);
  });
  it("exit 0 with semanticSuccessCodes [2] = success", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(0, [2])).toBe(true);
  });
  it("multiple semantic codes: [2, 3, 4] honored independently", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(2, [2, 3, 4])).toBe(true);
    expect(tele.successFromExitCode(3, [2, 3, 4])).toBe(true);
    expect(tele.successFromExitCode(4, [2, 3, 4])).toBe(true);
    expect(tele.successFromExitCode(5, [2, 3, 4])).toBe(false);
  });
  it("out-of-range value in semanticSuccessCodes is still rejected (validation wins)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(256, [256])).toBe(false);
    expect(tele.successFromExitCode(-1, [-1])).toBe(false);
  });
  it("non-finite value still rejected even if exit is otherwise listed (validation wins)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(Number.POSITIVE_INFINITY, [Number.POSITIVE_INFINITY as number])).toBe(false);
    expect(tele.successFromExitCode("oops", [2])).toBe(false);
  });
  it("empty semanticSuccessCodes [] = same as undefined (no override)", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(2, [])).toBe(false);
    expect(tele.successFromExitCode(0, [])).toBe(true);
    expect(tele.successFromExitCode(1, [])).toBe(true);
  });
  it("undefined exit code with semanticSuccessCodes still treats as 0 = success", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(undefined, [2])).toBe(true);
    expect(tele.successFromExitCode(null, [2])).toBe(true);
  });
  it("string exit code with semanticSuccessCodes parses then checks", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode("2", [2])).toBe(true);
    expect(tele.successFromExitCode("3", [2])).toBe(false);
  });
  it("backward compatibility: omitting the second arg is identical to passing undefined", async () => {
    const tele = await freshSdk();
    expect(tele.successFromExitCode(2)).toBe(tele.successFromExitCode(2, undefined));
    expect(tele.successFromExitCode(0)).toBe(tele.successFromExitCode(0, undefined));
    expect(tele.successFromExitCode(127)).toBe(tele.successFromExitCode(127, undefined));
  });
});

describe("install_id stability", () => {
  it("status() returns the same install_id across processes for the same machine", async () => {
    const a = await freshSdk();
    const idA = a.status().installId;
    const b = await freshSdk();
    const idB = b.status().installId;
    expect(idA).toBe(idB);
    // shape is a v4-ish UUID
    expect(idA).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
  });

  it("install_id is non-empty even when no config file existed yet", async () => {
    const tele = await freshSdk();
    const s = tele.status();
    expect(s.installId).toBeTruthy();
    expect(s.installId.length).toBeGreaterThan(0);
  });

  it("install_id does not leak plaintext hostname (hash is irreversible)", async () => {
    const tele = await freshSdk();
    const host = (await import("node:os")).hostname();
    const id = tele.status().installId;
    if (host && host !== "localhost" && host.length >= 4) {
      // hostname substring must not appear in the install_id
      expect(id.toLowerCase()).not.toContain(host.toLowerCase());
    }
    // Always: install_id is a v4-shaped UUID, not a raw identifier
    expect(id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/);
  });
});

describe("flush", () => {
  it("waits for in-flight fetches before resolving", async () => {
    // A 1.5s slow request — process.exit() would kill it without flush().
    let resolveFetch: (v: Response) => void = () => {};
    fetchMock.mockImplementationOnce(
      () =>
        new Promise<Response>((r) => {
          resolveFetch = r;
        }),
    );
    const tele = await freshSdk();
    await tele.init({ tool: "dvaa", version: "0.8.1" });
    tele.start(); // fire-and-forget; doesn't await internally
    let flushDone = false;
    const flushPromise = tele.flush().then(() => {
      flushDone = true;
    });
    expect(flushDone).toBe(false);
    resolveFetch(new Response(null, { status: 204 }));
    await flushPromise;
    expect(flushDone).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("is a no-op with no in-flight events", async () => {
    const tele = await freshSdk();
    await expect(tele.flush()).resolves.toBeUndefined();
  });
});

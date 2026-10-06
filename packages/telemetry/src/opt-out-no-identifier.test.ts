/**
 * Under every opt-out, no command may mint, write, keep or send an install
 * ID, or probe the machine for one.
 *
 * Each negative case attempts the forbidden acts through the public SDK
 * surface a CLI uses and asserts refusal. The positive controls at the
 * bottom run the same recorders with telemetry on and show that they DO
 * fire there — a negative test whose spy cannot fire proves nothing, and a
 * test of the opt-in path alone proves nothing either.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { mkdtempSync, rmSync, mkdirSync, writeFileSync, readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { scrubSuppressionEnv, restoreSuppressionEnv, type SavedEnv } from "./test-support.js";

const probe = vi.hoisted(() => ({
  platform: "darwin" as NodeJS.Platform,
  calls: [] as string[],
}));

const MACHINE_ID_FILES = ["/etc/machine-id", "/var/lib/dbus/machine-id"];

// Every probe fails, so a telemetry-on run walks the whole derivation chain:
// platform probe, then hostname hash, then a random UUID.
vi.mock("node:child_process", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:child_process")>();
  return {
    ...actual,
    execSync: (cmd: string) => {
      probe.calls.push(`exec ${cmd}`);
      throw new Error("probe stand-in");
    },
  };
});

vi.mock("node:os", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:os")>();
  return {
    ...actual,
    platform: () => probe.platform,
    hostname: () => {
      probe.calls.push("hostname");
      return "probe-stand-in-host";
    },
  };
});

vi.mock("node:fs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:fs")>();
  const isMachineId = (p: unknown) => MACHINE_ID_FILES.includes(String(p));
  return {
    ...actual,
    existsSync: (p: Parameters<typeof actual.existsSync>[0]) => {
      if (isMachineId(p)) {
        probe.calls.push(`read ${String(p)}`);
        return false;
      }
      return actual.existsSync(p);
    },
    readFileSync: ((p: Parameters<typeof actual.readFileSync>[0], ...rest: unknown[]) => {
      if (isMachineId(p)) {
        probe.calls.push(`read ${String(p)}`);
        throw new Error("probe stand-in");
      }
      return (actual.readFileSync as (...a: unknown[]) => unknown)(p, ...rest);
    }) as typeof actual.readFileSync,
  };
});

type Sdk = typeof import("./index.js");

const LEGACY_ID = "11111111-2222-4333-8444-555555555555";
const PLATFORMS: NodeJS.Platform[] = ["darwin", "linux", "win32"];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-8[0-9a-f]{3}-[0-9a-f]{12}$/;

/** Opt-outs that live in the environment, in the spellings people write. */
const ENV_OPT_OUTS: Array<[string, Record<string, string>]> = [
  ["OPENA2A_TELEMETRY=off", { OPENA2A_TELEMETRY: "off" }],
  ["OPENA2A_TELEMETRY=OFF", { OPENA2A_TELEMETRY: "OFF" }],
  ['OPENA2A_TELEMETRY=" Off\\n"', { OPENA2A_TELEMETRY: " Off\n" }],
  ["OPENA2A_TELEMETRY=0", { OPENA2A_TELEMETRY: "0" }],
  ['OPENA2A_TELEMETRY=" 0 "', { OPENA2A_TELEMETRY: " 0 " }],
  ["OPENA2A_TELEMETRY=false", { OPENA2A_TELEMETRY: "false" }],
  ['OPENA2A_TELEMETRY="FALSE\\t"', { OPENA2A_TELEMETRY: "FALSE\t" }],
  ["OPENA2A_TELEMETRY=no", { OPENA2A_TELEMETRY: "no" }],
  ['OPENA2A_TELEMETRY=" No "', { OPENA2A_TELEMETRY: " No " }],
  ["DO_NOT_TRACK=1", { DO_NOT_TRACK: "1" }],
  ["DO_NOT_TRACK=1 with OPENA2A_TELEMETRY=on", { DO_NOT_TRACK: "1", OPENA2A_TELEMETRY: "on" }],
  ["CI=true", { CI: "true" }],
  ["GITHUB_ACTIONS=true", { GITHUB_ACTIONS: "true" }],
];

/** What an earlier release may have left in telemetry.json. */
const PRIOR_FILES: Array<[string, Record<string, unknown> | null]> = [
  ["no config file", null],
  ["an ID written by an earlier release", { enabled: true, installId: LEGACY_ID }],
  ["telemetry off plus an ID written by an earlier release", { enabled: false, installId: LEGACY_ID }],
];

/** The SDK calls each CLI command makes. */
const COMMANDS: Record<string, (tele: Sdk) => Promise<void>> = {
  "secure (init, start, track, error, flush)": async (tele) => {
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    tele.start();
    await tele.track("secure", { success: true, durationMs: 5 });
    tele.error("secure", "E_TEST");
    await tele.flush();
  },
  "telemetry status": async (tele) => {
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    tele.status();
  },
  "status() before init (a --version line)": async (tele) => {
    tele.status();
  },
  "telemetry off": async (tele) => {
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    tele.setOptOut(false);
  },
  "telemetry on": async (tele) => {
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    tele.setOptOut(true);
  },
};

let tmpHome: string;
let savedEnv: SavedEnv;
let fetchMock: ReturnType<typeof vi.fn>;

function configFile(): string {
  return join(tmpHome, "opena2a", "telemetry.json");
}

function writePrior(contents: Record<string, unknown> | null): void {
  if (contents === null) return;
  mkdirSync(join(tmpHome, "opena2a"), { recursive: true });
  writeFileSync(configFile(), JSON.stringify(contents));
}

function readPersisted(): Record<string, unknown> | null {
  if (!existsSync(configFile())) return null;
  return JSON.parse(readFileSync(configFile(), "utf8")) as Record<string, unknown>;
}

async function freshSdk(): Promise<Sdk> {
  vi.resetModules();
  return await import("./index.js");
}

function sentInstallIds(): unknown[] {
  return fetchMock.mock.calls.map(([, req]) => JSON.parse((req as RequestInit).body as string).install_id);
}

beforeEach(() => {
  savedEnv = scrubSuppressionEnv();
  for (const key of ["OPENA2A_TELEMETRY", "OPENA2A_TELEMETRY_DEBUG"]) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
  tmpHome = mkdtempSync(join(tmpdir(), "opena2a-telem-optout-"));
  process.env.XDG_CONFIG_HOME = tmpHome;
  process.env.OPENA2A_TELEMETRY_URL = "http://test.local/event";
  fetchMock = vi.fn().mockResolvedValue(new Response(null, { status: 204 }));
  vi.stubGlobal("fetch", fetchMock);
  probe.calls.length = 0;
  probe.platform = "darwin";
});

afterEach(() => {
  restoreSuppressionEnv(savedEnv);
  rmSync(tmpHome, { recursive: true, force: true });
  vi.unstubAllGlobals();
  delete process.env.XDG_CONFIG_HOME;
  delete process.env.OPENA2A_TELEMETRY_URL;
});

describe.each(PLATFORMS)("on %s, an environment opt-out", (platform) => {
  describe.each(ENV_OPT_OUTS)("%s", (_label, env) => {
    describe.each(PRIOR_FILES)("with %s", (_prior, prior) => {
      it.each(Object.keys(COMMANDS))("%s: no ID, no probe, no send", async (command) => {
        probe.platform = platform;
        writePrior(prior);
        Object.assign(process.env, env);

        const tele = await freshSdk();
        await COMMANDS[command](tele);
        await tele.track("after", { success: true });
        await tele.flush();

        expect(probe.calls).toEqual([]);
        expect(fetchMock).not.toHaveBeenCalled();
        expect(tele.status().installId).toBeNull();

        const persisted = readPersisted();
        if (command === "telemetry off") {
          expect(persisted).toEqual({ enabled: false });
        } else if (command === "telemetry on") {
          // The user asked for it; the env still holds telemetry off, so
          // the preference is saved without an ID.
          expect(persisted).toEqual({ enabled: true });
        } else if (prior?.enabled === false) {
          expect(persisted).toEqual({ enabled: false });
        } else {
          // An earlier ID is deleted, and the default is not written back.
          expect(persisted).toBeNull();
        }
      });
    });
  });
});

describe.each(PLATFORMS)("on %s, a persisted opt-out", (platform) => {
  const priors: Array<[string, Record<string, unknown>]> = [
    ['{"enabled":false}', { enabled: false }],
    ['{"enabled":false} plus an ID written by an earlier release', { enabled: false, installId: LEGACY_ID }],
  ];
  describe.each(priors)("%s", (_label, prior) => {
    const commands = Object.keys(COMMANDS).filter((c) => c !== "telemetry on");
    it.each(commands)("%s: no ID, no probe, no send", async (command) => {
      probe.platform = platform;
      writePrior(prior);
      // An opt-in env var does not undo a persisted opt-out either.
      process.env.OPENA2A_TELEMETRY = "on";

      const tele = await freshSdk();
      await COMMANDS[command](tele);
      await tele.track("after", { success: true });
      await tele.flush();

      expect(probe.calls).toEqual([]);
      expect(fetchMock).not.toHaveBeenCalled();
      expect(tele.status().installId).toBeNull();
      expect(readPersisted()).toEqual({ enabled: false });
    });
  });
});

describe("telemetry off writes exactly {\"enabled\":false}", () => {
  it("drops the ID that a telemetry-on run persisted", async () => {
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    expect(readPersisted()?.installId).toMatch(UUID);

    const s = tele.setOptOut(false);
    expect(s.installId).toBeNull();
    expect(tele.status().installId).toBeNull();
    expect(readFileSync(configFile(), "utf8")).toBe('{\n  "enabled": false\n}\n');

    await tele.track("secure", { success: true });
    await tele.flush();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("positive controls: the same recorders fire when telemetry is on", () => {
  it.each(PLATFORMS)("on %s, a first run probes the machine, persists the ID and sends it", async (platform) => {
    probe.platform = platform;
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    await tele.track("secure", { success: true });
    await tele.flush();

    const platformProbe = {
      darwin: "exec ioreg -rd1 -c IOPlatformExpertDevice",
      linux: "read /etc/machine-id",
      win32: 'exec reg query "HKLM\\SOFTWARE\\Microsoft\\Cryptography" /v MachineGuid',
    }[platform as "darwin" | "linux" | "win32"];
    expect(probe.calls).toContain(platformProbe);
    expect(probe.calls).toContain("hostname");

    const id = tele.status().installId;
    expect(id).toMatch(UUID);
    expect(readPersisted()).toEqual({ enabled: true, installId: id });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(sentInstallIds()).toEqual([id]);
  });

  it("an ID already on disk is sent as-is, without probing", async () => {
    writePrior({ enabled: true, installId: LEGACY_ID });
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    await tele.track("secure", { success: true });
    await tele.flush();

    expect(probe.calls).toEqual([]);
    expect(sentInstallIds()).toEqual([LEGACY_ID]);
  });

  it("OPENA2A_TELEMETRY=on in CI is an opt-in, so the ID is minted and sent", async () => {
    process.env.CI = "true";
    process.env.OPENA2A_TELEMETRY = "on";
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    await tele.track("secure", { success: true });
    await tele.flush();

    const id = tele.status().installId;
    expect(id).toMatch(UUID);
    expect(probe.calls).toContain("hostname");
    expect(sentInstallIds()).toEqual([id]);
  });

  it("telemetry on after a persisted opt-out mints an ID and sends it", async () => {
    writePrior({ enabled: false });
    const tele = await freshSdk();
    await tele.init({ tool: "hackmyagent", version: "0.0.0-test" });
    const s = tele.setOptOut(true);
    await tele.track("secure", { success: true });
    await tele.flush();

    expect(s.installId).toMatch(UUID);
    expect(readPersisted()).toEqual({ enabled: true, installId: s.installId });
    expect(sentInstallIds()).toEqual([s.installId]);
  });
});

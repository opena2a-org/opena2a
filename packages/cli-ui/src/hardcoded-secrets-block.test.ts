import { describe, expect, it } from "vitest";
import {
  renderHardcodedSecretsBlock,
  type SecretLike,
} from "./hardcoded-secrets-block.js";

function secret(over: Partial<SecretLike> = {}): SecretLike {
  return {
    type: "anthropic_api_key",
    typeLabel: "Anthropic API key",
    file: "examples/quickstart.js",
    line: 14,
    maskedValue: "sk-ant-api03-••••••••••••••",
    shownChars: 32,
    totalChars: 108,
    shipsInArtifact: true,
    severity: "critical",
    rotationUrl: "https://console.anthropic.com/settings/keys",
    ...over,
  };
}

describe("hardcoded-secrets — unscanned state", () => {
  it("renders the not-yet-analyzed line when scanCovered is false", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [],
      scanCovered: false,
    });
    expect(out.headerTone).toBe("dim");
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].text).toMatch(/Not yet analyzed/);
    expect(out.lines[0].tone).toBe("dim");
  });
});

describe("hardcoded-secrets — clean state", () => {
  it("renders 'None detected' with version suffix when scan is clean", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [],
      scanCovered: true,
      latestVersion: "0.3.1",
    });
    expect(out.headerTone).toBe("good");
    expect(out.lines).toHaveLength(1);
    expect(out.lines[0].text).toBe("None detected on the latest version (0.3.1)");
    expect(out.lines[0].tone).toBe("good");
  });

  it("drops the version suffix when latestVersion is missing", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [],
      scanCovered: true,
    });
    expect(out.lines[0].text).toBe("None detected on the latest version");
  });
});

describe("hardcoded-secrets — detected state", () => {
  it("uses CRITICAL prefix when at least one secret is critical", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret()],
      scanCovered: true,
      latestVersion: "0.8.1",
      packageName: "@some-org/agent-runtime-mcp",
    });
    expect(out.headerTone).toBe("critical");
    expect(out.lines[0].text).toBe(
      "CRITICAL  1 credential detected on the latest version (0.8.1)",
    );
  });

  it("escalates header tone to max severity across detected list", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [
        secret({ severity: "low" }),
        secret({ severity: "high" }),
        secret({ severity: "medium" }),
      ],
      scanCovered: true,
    });
    expect(out.headerTone).toBe("critical"); // high → critical tone
    expect(out.lines[0].text).toMatch(/^HIGH/);
  });

  it("uses 'credentials' (plural) when more than one detected", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret(), secret({ file: "src/auth.js" })],
      scanCovered: true,
      latestVersion: "0.0.7",
    });
    expect(out.lines[0].text).toMatch(/2 credentials detected/);
  });

  it("indents type+locator (1) and masked value (2)", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret()],
      scanCovered: true,
    });
    const typeLine = out.lines.find((l) => l.text.startsWith("Anthropic API key"));
    const maskLine = out.lines.find((l) => l.text.startsWith("sk-ant-api03"));
    expect(typeLine?.indent).toBe(1);
    expect(maskLine?.indent).toBe(2);
    expect(maskLine?.text).toBe(
      "sk-ant-api03-•••••••••••••• (32 of 108 chars)",
    );
  });

  it("renders 'File ships in package tarball' only when shipsInArtifact is true", () => {
    const shipping = renderHardcodedSecretsBlock({
      detected: [secret({ shipsInArtifact: true })],
      scanCovered: true,
    });
    const local = renderHardcodedSecretsBlock({
      detected: [secret({ shipsInArtifact: false })],
      scanCovered: true,
    });
    expect(
      shipping.lines.some((l) => l.text === "File ships in package tarball."),
    ).toBe(true);
    expect(
      local.lines.some((l) => l.text === "File ships in package tarball."),
    ).toBe(false);
  });

  it("emits a public-rotation note when at least one secret ships", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret({ shipsInArtifact: true })],
      scanCovered: true,
    });
    expect(
      out.lines.some((l) => /must be rotated regardless/.test(l.text)),
    ).toBe(true);
  });

  it("omits the public-rotation note when no secret ships", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret({ shipsInArtifact: false })],
      scanCovered: true,
    });
    expect(
      out.lines.some((l) => /must be rotated regardless/.test(l.text)),
    ).toBe(false);
  });

  it("dedups rotation URLs by type", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [
        secret({ file: "src/a.js" }),
        secret({ file: "src/b.js" }), // same anthropic_api_key type + URL
        secret({
          file: "src/c.js",
          type: "openai_api_key",
          typeLabel: "OpenAI API key",
          rotationUrl: "https://platform.openai.com/api-keys",
          severity: "high",
        }),
      ],
      scanCovered: true,
    });
    const rotateLines = out.lines.filter((l) =>
      l.text.startsWith("Rotate ("),
    );
    expect(rotateLines).toHaveLength(2);
  });

  it("renders the report command with tool + package name", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret()],
      scanCovered: true,
      packageName: "@some-org/agent-runtime-mcp",
      reportTool: "hackmyagent",
    });
    const reportLine = out.lines.find((l) => l.text.startsWith("Report:"));
    expect(reportLine?.text).toBe(
      "Report:  hackmyagent report @some-org/agent-runtime-mcp --secret-leak",
    );
  });

  it("falls back to <pkg> when packageName is omitted", () => {
    const out = renderHardcodedSecretsBlock({
      detected: [secret()],
      scanCovered: true,
    });
    const reportLine = out.lines.find((l) => l.text.startsWith("Report:"));
    expect(reportLine?.text).toMatch(/<pkg> --secret-leak$/);
  });
});

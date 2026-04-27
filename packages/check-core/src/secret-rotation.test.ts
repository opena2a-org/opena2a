import { describe, it, expect } from "vitest";
import {
  SECRET_ROTATION_TABLE,
  enrichSecretRotation,
  lookupSecretRotation,
} from "./secret-rotation.js";
import type { HardcodedSecret } from "./narrative.js";

const baseSecret = (overrides: Partial<HardcodedSecret> = {}): HardcodedSecret => ({
  type: "anthropic_api_key",
  typeLabel: "",
  file: "examples/quickstart.js",
  line: 14,
  maskedValue: "sk-ant-api03-****",
  shownChars: 32,
  totalChars: 108,
  shipsInArtifact: true,
  severity: "critical",
  ...overrides,
});

describe("SECRET_ROTATION_TABLE", () => {
  it("includes the v1 brief baseline credential types", () => {
    const required = [
      "anthropic_api_key",
      "openai_api_key",
      "aws_access_key",
      "github_pat",
      "private_key",
      "database_url",
      "generic_bearer",
      "unknown",
    ];
    for (const type of required) {
      expect(SECRET_ROTATION_TABLE[type], `missing ${type}`).toBeDefined();
    }
  });

  it("every known type has a typeLabel", () => {
    for (const [, guide] of Object.entries(SECRET_ROTATION_TABLE)) {
      expect(guide.typeLabel.length).toBeGreaterThan(0);
    }
  });

  it("anthropic + openai + aws + github point at console URLs", () => {
    expect(SECRET_ROTATION_TABLE.anthropic_api_key.rotationUrl).toContain("anthropic.com");
    expect(SECRET_ROTATION_TABLE.openai_api_key.rotationUrl).toContain("openai.com");
    expect(SECRET_ROTATION_TABLE.aws_access_key.rotationUrl).toContain("aws.amazon.com");
    expect(SECRET_ROTATION_TABLE.github_pat.rotationUrl).toContain("github.com");
  });

  it("aws includes a rotation command (cli-only path)", () => {
    expect(SECRET_ROTATION_TABLE.aws_access_key.rotationCommand).toMatch(/aws iam/);
  });
});

describe("lookupSecretRotation", () => {
  it("returns the entry for a known type", () => {
    const guide = lookupSecretRotation("openai_api_key");
    expect(guide.typeLabel).toBe("OpenAI API key");
    expect(guide.rotationUrl).toContain("openai.com");
  });

  it("falls back to the unknown entry for an unknown type", () => {
    const guide = lookupSecretRotation("totally_made_up_provider");
    expect(guide).toBe(SECRET_ROTATION_TABLE.unknown);
  });

  it("falls back for empty string", () => {
    const guide = lookupSecretRotation("");
    expect(guide).toBe(SECRET_ROTATION_TABLE.unknown);
  });
});

describe("enrichSecretRotation", () => {
  it("populates rotationUrl from the table when input has none", () => {
    const enriched = enrichSecretRotation(baseSecret({ type: "anthropic_api_key" }));
    expect(enriched.rotationUrl).toBe("https://console.anthropic.com/settings/keys");
  });

  it("populates typeLabel from the table when input label is empty", () => {
    const enriched = enrichSecretRotation(baseSecret({ type: "aws_access_key" }));
    expect(enriched.typeLabel).toBe("AWS access key");
  });

  it("preserves a caller-set typeLabel", () => {
    const enriched = enrichSecretRotation(
      baseSecret({ type: "anthropic_api_key", typeLabel: "Custom label" }),
    );
    expect(enriched.typeLabel).toBe("Custom label");
  });

  it("preserves a caller-set rotationUrl", () => {
    const enriched = enrichSecretRotation(
      baseSecret({ type: "anthropic_api_key", rotationUrl: "https://example.com/rotate" }),
    );
    expect(enriched.rotationUrl).toBe("https://example.com/rotate");
  });

  it("preserves a caller-set rotationCommand", () => {
    const enriched = enrichSecretRotation(
      baseSecret({ type: "aws_access_key", rotationCommand: "make rotate" }),
    );
    expect(enriched.rotationCommand).toBe("make rotate");
  });

  it("keeps unknown-type rotationUrl absent (renderer falls back)", () => {
    const enriched = enrichSecretRotation(baseSecret({ type: "unknown" }));
    expect(enriched.rotationUrl).toBeUndefined();
    expect(enriched.rotationCommand).toBeUndefined();
  });

  it("does not mutate the input", () => {
    const input = baseSecret({ type: "github_pat" });
    enrichSecretRotation(input);
    expect(input.rotationUrl).toBeUndefined();
    expect(input.typeLabel).toBe("");
  });

  it("is deterministic — same input produces equal output", () => {
    const input = baseSecret({ type: "openai_api_key" });
    expect(enrichSecretRotation(input)).toEqual(enrichSecretRotation(input));
  });
});

import type { ParsedCheckInput, PackageEcosystem } from "./types.js";

const NPM_NAME_RE = /^[@A-Za-z0-9_][A-Za-z0-9_.\-/]*$/;
const GIT_SHORTHAND_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const URL_RE = /^https?:\/\//i;
const LOCAL_PATH_RE = /^(\.\.?\/|\/)/;

/**
 * Classify a raw `check <target>` string into its ecosystem and normalized
 * form. The classifier is intentionally permissive — it does not reject
 * malformed names; the registry / downloader layers surface the real error.
 */
export function parseCheckInput(raw: string): ParsedCheckInput {
  const trimmed = raw.trim();

  if (URL_RE.test(trimmed)) {
    return {
      raw,
      ecosystem: "url",
      normalizedName: trimmed,
      isGitShorthand: false,
      isScoped: false,
    };
  }

  if (LOCAL_PATH_RE.test(trimmed)) {
    return {
      raw,
      ecosystem: "local",
      normalizedName: trimmed,
      isGitShorthand: false,
      isScoped: false,
    };
  }

  if (trimmed.startsWith("pip:")) {
    return {
      raw,
      ecosystem: "pypi",
      normalizedName: trimmed.slice(4),
      isGitShorthand: false,
      isScoped: false,
    };
  }

  const isScoped = trimmed.startsWith("@");
  const isGitShorthand =
    !isScoped && GIT_SHORTHAND_RE.test(trimmed);

  // Git-shorthand like `user/repo` (no `@` scope) is ambiguous — it could be
  // a typo for `@user/repo` on npm or an intentional GitHub reference. The
  // downloader will try npm first; translateDownloadError handles the
  // "code 128" fallback case. We tag ecosystem as `github` so the caller
  // can short-circuit if desired, but `normalizedName` is left as the raw
  // form so the registry lookup happens against the same literal.
  if (isGitShorthand) {
    return {
      raw,
      ecosystem: "github",
      normalizedName: trimmed,
      isGitShorthand: true,
      isScoped: false,
    };
  }

  if (NPM_NAME_RE.test(trimmed)) {
    return {
      raw,
      ecosystem: "npm",
      normalizedName: trimmed,
      isGitShorthand: false,
      isScoped,
    };
  }

  return {
    raw,
    ecosystem: "unknown",
    normalizedName: trimmed,
    isGitShorthand: false,
    isScoped: false,
  };
}

/** Map an ecosystem to the corresponding `CheckOutput.type` value. */
export function ecosystemToTargetType(eco: PackageEcosystem): "npm-package" | "github-repo" | "pypi-package" | undefined {
  if (eco === "npm") return "npm-package";
  if (eco === "github") return "github-repo";
  if (eco === "pypi") return "pypi-package";
  return undefined;
}

/**
 * Allowlist of well-known general-purpose libraries that we can confidently
 * reject as unrelated to AI trust, even if the registry lacks a `package_type`
 * for them. This covers the long tail of utility packages that show up in
 * every Node/Python project.
 *
 * Kept intentionally small and conservative. When in doubt, return "unknown"
 * instead of adding to this list — false rejections (treating an AI package
 * as unrelated) are worse than a graceful "we can't classify this yet."
 *
 * For v0.4 this will be supplemented by an allowlist of AI-ADJACENT names
 * (Tier 2) in a separate file.
 */

const JS_UTILITIES = [
  "lodash",
  "underscore",
  "chalk",
  "colors",
  "ansi-colors",
  "kleur",
  "cli-color",
  "picocolors",
  "debug",
  "minimist",
  "commander",
  "yargs",
  "ora",
  "prompts",
  "inquirer",
  "execa",
  "glob",
  "rimraf",
  "mkdirp",
  "uuid",
  "nanoid",
  "semver",
  "ms",
  "pretty-ms",
  "dayjs",
  "date-fns",
  "moment",
  "cross-env",
  "dotenv-cli",
];

const JS_FRAMEWORKS = [
  "express",
  "fastify",
  "koa",
  "hapi",
  "nestjs",
  "@nestjs/core",
  "next",
  "nuxt",
  "gatsby",
  "svelte",
  "remix",
  "astro",
];

const JS_BUILD_TOOLING = [
  "typescript",
  "tsx",
  "ts-node",
  "esbuild",
  "tsup",
  "vite",
  "rollup",
  "webpack",
  "parcel",
  "swc",
  "@swc/core",
  "turbo",
  "nx",
  "lerna",
];

const JS_TEST_TOOLING = [
  "vitest",
  "jest",
  "mocha",
  "chai",
  "sinon",
  "playwright",
  "cypress",
  "@playwright/test",
];

const JS_LINT_TOOLING = [
  "eslint",
  "prettier",
  "husky",
  "lint-staged",
  "commitlint",
];

const PY_UTILITIES = [
  "requests",
  "urllib3",
  "click",
  "rich",
  "typer",
  "pydantic",
  "python-dateutil",
  "setuptools",
  "pip",
  "wheel",
  "pytest",
  "black",
  "ruff",
  "mypy",
  "flake8",
  "isort",
];

/**
 * Known general-purpose libraries across npm and PyPI. Matched by exact name.
 */
export const UNRELATED_PACKAGE_NAMES: ReadonlySet<string> = new Set([
  ...JS_UTILITIES,
  ...JS_FRAMEWORKS,
  ...JS_BUILD_TOOLING,
  ...JS_TEST_TOOLING,
  ...JS_LINT_TOOLING,
  ...PY_UTILITIES,
]);

/**
 * Prefixes for scoped packages that are always general-purpose.
 * e.g. @types/* are TypeScript type definitions — never AI-specific.
 */
export const UNRELATED_SCOPE_PREFIXES: readonly string[] = [
  "@types/",
  "@typescript-eslint/",
  "@babel/",
  "@rollup/",
  "@vitejs/",
  "@webpack/",
];

export function isKnownUnrelatedName(name: string): boolean {
  if (UNRELATED_PACKAGE_NAMES.has(name)) return true;
  for (const prefix of UNRELATED_SCOPE_PREFIXES) {
    if (name.startsWith(prefix)) return true;
  }
  return false;
}

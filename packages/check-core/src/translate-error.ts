import type { TranslatedError } from "./types.js";

const GIT_STYLE_RE = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;
const CODE_128_RE = /code\s*128/i;
const NPM_NOT_FOUND_RE = /not found on npm/i;
const PYPI_NOT_FOUND_RE = /not found on pypi/i;

/**
 * Translate a raw downloader error message into a renderNotFoundBlock hint.
 *
 * Two recognized cases (merged from hackmyagent + ai-trust):
 *
 * 1. Git-style name (`anthropic/code-review`, no `@` scope) failing with
 *    `code 128` — npm's downloader tried the git-clone fallback because
 *    the name didn't resolve on the registry. Suggest the scoped form.
 *
 * 2. Clean "not found" on npm / PyPI — returns an empty hint object so the
 *    caller renders the default not-found block (no extra suggestion line).
 *
 * Returns `undefined` when the error is not recognized — caller decides
 * whether to surface it raw or translate generically.
 */
export function translateDownloadError(
  name: string,
  message: string,
): TranslatedError | undefined {
  const looksGitStyle = GIT_STYLE_RE.test(name) && !name.startsWith("@");
  if (looksGitStyle && CODE_128_RE.test(message)) {
    const scoped = `@${name}`;
    return {
      errorHint: `Looks like a git-style name. npm packages use "@scope/name" — did you mean "${scoped}"?`,
      suggestions: [scoped],
    };
  }
  if (NPM_NOT_FOUND_RE.test(message) || PYPI_NOT_FOUND_RE.test(message)) {
    return {};
  }
  return undefined;
}

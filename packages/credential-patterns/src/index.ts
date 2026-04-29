/**
 * @opena2a/credential-patterns — canonical credential regex catalog and
 * match-with-allowlist helpers for OpenA2A security tools.
 *
 * One source of truth so secretless-ai, hackmyagent, and downstream consumers
 * share the same patterns and the same known-example allowlist. Add new
 * patterns here, not in tools — duplicate catalogs are how detection drifts.
 */

export {
  CREDENTIAL_PATTERNS,
  CREDENTIAL_PREFIX_QUICK_CHECK,
  KNOWN_EXAMPLE_KEYS,
  PLACEHOLDER_INDICATORS,
  SECRET_FILE_PATTERNS,
  CONFIG_FILES,
  SOURCE_FILE_EXTENSIONS,
  SOURCE_SKIP_DIRS,
  type CredentialPattern,
} from './patterns.js';

export { findRealMatch, isKnownExample } from './match.js';

/**
 * Static credential-type → rotation-guidance lookup.
 *
 * Drives the "Rotate at: ..." line in the hardcoded-secrets render block.
 * Rule engine calls `enrichSecretRotation` on each detected secret to
 * populate `rotationUrl` / `rotationCommand` deterministically.
 *
 * Adding a new credential type: append an entry to `SECRET_ROTATION_TABLE`.
 * Unknown types fall through to the `unknown` row, which yields a generic
 * report-leak command without a service-specific URL.
 */
import type { HardcodedSecret } from "./narrative.js";

/**
 * Per-credential rotation guidance. At least one of `rotationUrl` or
 * `rotationCommand` should be set so the renderer always has somewhere
 * to point the operator. `unknown` is the only row that may have neither
 * — the renderer falls back to the generic report-leak action there.
 */
export interface SecretRotationGuide {
  /**
   * Human-readable label for the credential type, used in the secrets
   * block header (e.g. "Anthropic API key", "AWS access key").
   */
  typeLabel: string;
  /** Service-specific web URL where the operator can rotate the key. */
  rotationUrl?: string;
  /**
   * CLI command that performs (or starts) the rotation. An operand the
   * reader supplies is a shell parameter that refuses when unset,
   * `"${NAME:?set NAME to ...}"`, never an angle-bracket placeholder:
   * pasted before NAME is set, the shell prints the message and runs
   * nothing. A command of several steps joined by `&&` checks every
   * operand in its first step, `: "${A:?...}" "${B:?...}" && ...`: the
   * shell runs the first step before it expands the second, so a check
   * placed in a later step would come after the earlier steps had run.
   */
  rotationCommand?: string;
}

/**
 * Static lookup table. Keys mirror the `type` strings used by HMA's
 * credential scanners (CRED-*, AST-CRED-*, WEBCRED-*, SEM-CRED-*,
 * AGENT-CRED-*, ENVLEAK, CLIPASS, DRIFT prefixes).
 *
 * Entries beyond the v1 baseline credential types (slack_bot_token,
 * gcp_service_account_key, stripe_secret_key) are included because they
 * appear in HMA's existing credential corpus — leaving them to the
 * `unknown` fallback would surface a worse rotation message than today.
 */
export const SECRET_ROTATION_TABLE: Record<string, SecretRotationGuide> = {
  anthropic_api_key: {
    typeLabel: "Anthropic API key",
    rotationUrl: "https://console.anthropic.com/settings/keys",
  },
  openai_api_key: {
    typeLabel: "OpenAI API key",
    rotationUrl: "https://platform.openai.com/api-keys",
  },
  aws_access_key: {
    typeLabel: "AWS access key",
    rotationUrl: "https://console.aws.amazon.com/iam/home#/security_credentials",
    rotationCommand: "aws iam create-access-key && aws iam delete-access-key",
  },
  github_pat: {
    typeLabel: "GitHub personal access token",
    rotationUrl: "https://github.com/settings/tokens",
  },
  slack_bot_token: {
    typeLabel: "Slack bot token",
    rotationUrl: "https://api.slack.com/apps",
  },
  gcp_service_account_key: {
    typeLabel: "GCP service-account key",
    rotationUrl: "https://console.cloud.google.com/iam-admin/serviceaccounts",
    rotationCommand:
      ': "${SERVICE_ACCOUNT:?set SERVICE_ACCOUNT to the email of the service account that owns the key}" "${OLD_KEY_ID:?set OLD_KEY_ID to the ID of the leaked key}" && gcloud iam service-accounts keys create new.json --iam-account="$SERVICE_ACCOUNT" && gcloud iam service-accounts keys delete "$OLD_KEY_ID" --iam-account="$SERVICE_ACCOUNT"',
  },
  stripe_secret_key: {
    typeLabel: "Stripe secret key",
    rotationUrl: "https://dashboard.stripe.com/apikeys",
  },
  private_key: {
    typeLabel: "Private key (PEM)",
    rotationCommand: "Regenerate the key pair and re-issue any certificates that signed against the old key",
  },
  database_url: {
    typeLabel: "Database connection string",
    rotationCommand: "Rotate the database credentials at the database provider; update the application secret store",
  },
  generic_bearer: {
    typeLabel: "Bearer token",
    rotationCommand: "Rotate the token at the issuing service; revoke the leaked value",
  },
  unknown: {
    typeLabel: "Credential",
  },
};

/**
 * Look up rotation guidance for a credential type. Falls back to the
 * `unknown` row when the type is not in the table.
 */
export function lookupSecretRotation(type: string): SecretRotationGuide {
  return SECRET_ROTATION_TABLE[type] ?? SECRET_ROTATION_TABLE.unknown;
}

/**
 * Return a copy of `secret` with `rotationUrl` and `rotationCommand`
 * populated from the static table. Existing values on the input are
 * preserved (the rule engine never overwrites caller-set rotation
 * fields — useful when a scanner already has more-specific info).
 *
 * `typeLabel` is also backfilled when the input has an empty label.
 */
export function enrichSecretRotation(secret: HardcodedSecret): HardcodedSecret {
  const guide = lookupSecretRotation(secret.type);
  return {
    ...secret,
    typeLabel: secret.typeLabel || guide.typeLabel,
    rotationUrl: secret.rotationUrl ?? guide.rotationUrl,
    rotationCommand: secret.rotationCommand ?? guide.rotationCommand,
  };
}

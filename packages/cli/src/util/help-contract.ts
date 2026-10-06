/**
 * The automation contract printed at the end of every subcommand's --help:
 * the exit codes the command returns, what --json does to it, and what --ci
 * does to it. A CI job author reads this block to know which status fails a
 * pipeline and whether the output can be parsed, without reading the source.
 *
 * Each entry states what the command does today, traced to its handler. A
 * command whose behaviour changes updates its entry in the same change; the
 * help-layout test fails for any registered command without one.
 */

import { wordWrap } from './format.js';
import { HELP_WIDTH } from './subcommand-help.js';

export interface HelpContract {
  /** Exit status (or `engine` for a passed-through status) and its condition. */
  exit: ReadonlyArray<readonly [code: string, meaning: string]>;
  /** What `--json` (or `--format json`) does to this command. */
  json: string;
  /** What `--ci` does to this command. */
  ci: string;
}

/**
 * A command that runs a bundled engine returns the engine's exit status, adds
 * 1 when the engine cannot be started, and does not pass --ci on: the only
 * --ci effect is that the share prompt after a run stays quiet.
 */
function engineContract(engine: string, unavailable: string, json: string): HelpContract {
  return {
    exit: [
      ['engine', `the exit status of ${engine}, passed through unchanged`],
      ['1', unavailable],
    ],
    json,
    ci: `not passed to ${engine}; only skips the prompt to share scan results`,
  };
}

export const HELP_CONTRACTS: Readonly<Record<string, HelpContract>> = {
  scan: engineContract(
    'hackmyagent secure',
    'hackmyagent is not installed or could not start',
    'passed to hackmyagent secure as --format json',
  ),
  rollback: engineContract(
    'hackmyagent rollback',
    'hackmyagent is not installed or could not start',
    'not supported; a note is printed and the output stays text',
  ),
  'fix-all': engineContract(
    'hackmyagent fix-all',
    'hackmyagent is not installed or could not start',
    'passed to hackmyagent fix-all as --json',
  ),
  secrets: engineContract(
    'secretless-ai',
    'secretless-ai is not installed or could not start',
    'passed to secretless-ai as --format json',
  ),
  registry: {
    exit: [
      ['engine', 'the exit status of ai-trust check, passed through unchanged'],
      ['0', 'no package name was given (usage is printed)'],
      ['1', 'ai-trust is not installed or could not start'],
    ],
    json: 'passed to ai-trust check as --json',
    ci: 'not passed to ai-trust check; only skips the prompt to share scan results',
  },
  train: engineContract(
    'the opena2a/dvaa container',
    'Docker is not running or the container could not start',
    'passed to the container as --format json',
  ),
  crypto: engineContract(
    'cryptoserve',
    'the cryptoserve Python module is not installed or could not start',
    'passed to cryptoserve as --format json',
  ),
  broker: engineContract(
    'secretless-ai broker',
    'secretless-ai is not installed or could not start',
    'passed to secretless-ai broker as --format json',
  ),
  telemetry: {
    exit: [['0', 'always, also for an unknown action (the message names the valid ones)']],
    json: 'not supported; output is text',
    ci: 'no effect',
  },
  protect: {
    exit: [
      ['0', 'credentials migrated, none found, a --dry-run, or you declined at the prompt'],
      ['1', 'a migration failed, key files were found that protect cannot migrate, or the directory does not exist'],
      ['2', 'cannot prompt (stdin is not a terminal and --ci was not given), the prompt was aborted, or the --atx file for --grant is missing or invalid'],
      ['3', 'the broker denied the --grant'],
      ['4', 'the broker is unreachable or its socket belongs to another user'],
      ['5', 'the --grant check failed unexpectedly'],
      ['6', 'the broker answered with another error status'],
    ],
    json: 'prints the result as JSON',
    ci: 'migrates without prompting (needed when stdin is not a terminal)',
  },
  comply: {
    exit: [
      ['0', 'CLEAN: no findings, safe to forward'],
      ['1', 'VIOLATION or DENY: findings present'],
      ['2', 'usage error: a bad or oversize path, no input on a terminal, a read error, or a classification failure (fails closed)'],
    ],
    json: 'prints the verdicts as JSON',
    ci: 'no effect on verdicts or exit codes (comply never prompts)',
  },
  check: {
    exit: [
      ['engine', 'the exit status of hackmyagent (check for a package or repository, secure for a directory), passed through unchanged'],
      ['1', 'the target is not a recognised form, or hackmyagent could not start'],
    ],
    json: 'passed to hackmyagent as --format json for a directory and as --json for a package or repository',
    ci: 'passed to hackmyagent check for a package or repository; for a directory it only skips the prompt to share scan results',
  },
  status: {
    exit: [
      ['0', 'the status was printed'],
      ['1', 'the directory cannot be accessed'],
    ],
    json: 'prints the status as JSON',
    ci: 'no effect',
  },
  publish: {
    exit: [
      ['engine', 'the exit status of ai-trust check, passed through unchanged'],
      ['1', 'ai-trust is not installed or could not start'],
    ],
    json: 'passed to ai-trust check as --json',
    ci: 'not passed to ai-trust check; only skips the prompt to share scan results',
  },
  init: {
    exit: [
      ['0', 'the assessment ran and found no critical next step'],
      ['1', 'a critical next step was found, or the directory does not exist'],
    ],
    json: 'prints the assessment as JSON',
    ci: 'no effect',
  },
  guard: {
    exit: [
      ['0', 'the files verify clean, or the subcommand succeeded'],
      ['1', 'tampered, missing or policy-violating files, changes found by diff, no signature store, a declined resign, an unknown subcommand, or an error'],
      ['3', 'verify --enforce found what exit 1 reports (quarantine mode)'],
    ],
    json: 'prints JSON for every subcommand except hook',
    ci: 'resign re-signs without asking for confirmation',
  },
  runtime: {
    exit: [
      ['0', 'the subcommand succeeded'],
      ['1', 'a missing or unknown subcommand, no ARP configuration, or monitoring failed to start'],
    ],
    json: 'prints JSON',
    ci: 'no effect',
  },
  login: {
    exit: [
      ['0', 'logged in, or already logged in to this server'],
      ['1', 'login failed, was denied or timed out, or --ci was given without a stored login'],
    ],
    json: 'prints the result as JSON',
    ci: 'does not start the browser login; exits 1 unless already logged in',
  },
  logout: {
    exit: [['0', 'always: stored credentials were removed, or there were none']],
    json: 'prints the result as JSON',
    ci: 'no effect',
  },
  whoami: {
    exit: [['0', 'always: the output says whether you are logged in']],
    json: 'prints the login state as JSON',
    ci: 'no effect',
  },
  identity: {
    exit: [
      ['0', 'the subcommand succeeded'],
      ['1', 'an error, not logged in, check denied the capability, verify found an invalid signature, revoke without --ci or --json, or an unknown subcommand'],
    ],
    json: 'prints JSON; check and verify then exit 0 and report the result in the allowed or valid field',
    ci: 'revoke proceeds without the confirmation step',
  },
  shield: {
    exit: [
      ['0', 'the subcommand succeeded'],
      ['1', 'init had a failing step, selfcheck found Shield compromised or in lockdown, evaluate blocked the action, no policy is loaded, recover --verify failed, suggest, explain or triage have no LLM backend, or an unknown subcommand'],
    ],
    json: 'prints JSON',
    ci: 'init prints JSON, rewrites an existing policy, and skips --shell-hook and --ai-tools; other subcommands are unchanged',
  },
  review: {
    exit: [
      ['0', 'the composite score is 50 or higher'],
      ['1', 'the score is below 50, or the directory does not exist'],
    ],
    json: 'prints the results as JSON instead of writing the HTML report',
    ci: 'does not open the report in a browser',
  },
  'scan-soul': {
    exit: [
      ['0', 'the governance score is 60 or higher (with --strict, also no critical control missing)'],
      ['1', 'the score is below 60, a critical control is missing under --strict, or the scan failed'],
    ],
    json: 'prints the scan result as JSON',
    ci: 'no effect',
  },
  'harden-soul': {
    exit: [
      ['0', 'the governance file was written, or previewed with --dry-run'],
      ['1', 'the scanner is unavailable, or generation failed'],
    ],
    json: 'prints the result as JSON',
    ci: 'no effect',
  },
  'harden-skill': {
    exit: [
      ['0', 'the skill file was hardened (findings are informational)'],
      ['1', 'the file does not exist, or no skill file is in the current directory'],
    ],
    json: 'prints the result as JSON',
    ci: 'does not list the skill files before hardening several',
  },
  benchmark: {
    exit: [
      ['0', 'the benchmark ran (the score does not change the exit status)'],
      ['1', 'hackmyagent is unavailable, the --level is invalid, or the run failed'],
    ],
    json: 'prints the results as JSON',
    ci: 'no effect',
  },
  'self-register': {
    exit: [
      ['0', 'every tool was registered, or a --dry-run'],
      ['1', 'no tool matched --only, or a registration failed'],
      ['2', 'not confirmed: declined at the prompt, or a non-interactive run without --yes'],
    ],
    json: 'prints the result as JSON; never prompts, so pass --yes to write',
    ci: 'never prompts; without --yes it exits 2 before writing anything',
  },
  verify: {
    exit: [
      ['0', 'no installed package failed its integrity check'],
      ['1', 'a package hash does not match the registry (tamper detected)'],
    ],
    json: 'prints the results as JSON',
    ci: 'prints no heading or progress lines',
  },
  trust: {
    exit: [
      ['0', 'the trust profile was found and shown'],
      ['1', 'an invalid --source, no package name given or found, the package is not in the registry, or the lookup failed'],
    ],
    json: 'prints the profile as JSON',
    ci: 'shows no spinner',
  },
  claim: {
    exit: [
      ['0', 'the claim was registered'],
      ['1', 'no package name, the package is not in the registry or is already claimed, ownership could not be verified, or the claim request failed'],
    ],
    json: 'prints the result as JSON',
    ci: 'prints no progress lines or spinner',
  },
  admin: {
    exit: [
      ['0', 'the operation succeeded, or usage was printed as text'],
      ['1', 'no admin key, an invalid --registry, a registry or network error, approve or reject declined or refused without --yes, or a usage error under --json'],
    ],
    json: 'prints the result as JSON; approve and reject then need --yes',
    ci: 'approve and reject refuse to run without --yes',
  },
  baselines: {
    exit: [
      ['0', 'observations were collected'],
      ['1', 'community contributions are not enabled, or the package was not found'],
    ],
    json: 'prints the result as JSON',
    ci: 'prints no heading or spinner',
  },
  detect: {
    exit: [
      ['0', 'discovery finished'],
      ['1', 'the directory cannot be read'],
    ],
    json: 'prints the result as JSON',
    ci: 'never asks before scanning unknown MCP packages, does not open the --report file, and does not share results',
  },
  setup: {
    exit: [
      ['0', 'the agent is set up'],
      ['1', 'no stored login under --json or --ci, login failed, or the identity could not be created'],
    ],
    json: 'prints the result as JSON',
    ci: 'exits 1 instead of starting a browser login when no stored login exists',
  },
  watch: {
    exit: [
      ['0', 'stopped with Ctrl+C'],
      ['1', 'not logged in, or no agent is registered'],
    ],
    json: 'prints one JSON object per event line (NDJSON)',
    ci: 'no effect',
  },
  demo: {
    exit: [
      ['0', 'the demo finished'],
      ['1', 'an unknown scenario, or the demo failed'],
    ],
    json: 'prints the demo result as JSON',
    ci: 'runs without pauses and ignores --interactive',
  },
  config: {
    exit: [
      ['0', 'the setting was changed or shown'],
      ['1', 'an unknown action'],
    ],
    json: 'not used; config show always prints JSON',
    ci: 'no effect',
  },
  skill: {
    exit: [
      ['0', 'the skill was created'],
      ['1', 'a missing or unknown subcommand, a non-empty target directory without --force, or a critical warning in the scaffold'],
    ],
    json: 'prints the result as JSON',
    ci: 'creates without prompts from the given name and --template, or the defaults (also when CI is set)',
  },
  mcp: {
    exit: [
      ['0', 'the audit finished, the server was signed, or verify passed'],
      ['1', 'verify failed, the server or its identity was not found, no server name was given, an unknown subcommand, or an error'],
    ],
    json: 'prints JSON',
    ci: 'no effect',
  },
};

/** Two-column rows with a hanging indent, so wrapped text stays in its column. */
function formatRows(rows: ReadonlyArray<readonly [string, string]>, width: number): string[] {
  const labelWidth = Math.max(...rows.map(([label]) => label.length));
  const column = 2 + labelWidth + 2;
  return rows.map(([label, text]) => {
    const wrapped = wordWrap(text, width, column);
    return `  ${label.padEnd(labelWidth + 2)}${wrapped.slice(column)}`;
  });
}

/** The `Exit codes:` and `Automation:` sections, wrapped to `width` columns. */
export function formatHelpContract(contract: HelpContract, width: number = HELP_WIDTH): string {
  return [
    'Exit codes:',
    ...formatRows(contract.exit, width),
    '',
    'Automation:',
    ...formatRows([['--json', contract.json], ['--ci', contract.ci]], width),
  ].join('\n');
}

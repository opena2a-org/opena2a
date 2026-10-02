/**
 * `opena2a config` — read and change the user settings in ~/.opena2a.
 *
 * Two spellings change a setting, and they do the same thing:
 *
 *   opena2a config contribute off
 *   opena2a config set contribute false
 *
 * The second is the form the ai-trust README and the website docs print
 * (#343); before it was accepted, it answered "Unknown config action: set".
 */

import { loadUserConfig, setContributeEnabled, setLlmEnabled } from '@opena2a/shared';

type Toggle = 'contribute' | 'llm';

const TOGGLES: Record<Toggle, { changed: string; status: string }> = {
  contribute: { changed: 'Community contributions', status: 'Contribute' },
  llm: { changed: 'LLM features', status: 'LLM features' },
};

const ON_WORDS = new Set(['on', 'true', 'enable', 'enabled', 'yes', '1']);
const OFF_WORDS = new Set(['off', 'false', 'disable', 'disabled', 'no', '0']);

/** true / false for a recognised on/off word, null for anything else. */
export function parseToggleValue(value: string | undefined): boolean | null {
  if (value === undefined) return null;
  const v = value.trim().toLowerCase();
  if (ON_WORDS.has(v)) return true;
  if (OFF_WORDS.has(v)) return false;
  return null;
}

function isToggle(key: string | undefined): key is Toggle {
  return key === 'contribute' || key === 'llm';
}

const USAGE = [
  'Usage: opena2a config contribute on|off|--enable|--disable',
  '       opena2a config llm on|off|--enable|--disable',
  '       opena2a config set contribute|llm on|off',
  '       opena2a config show',
].join('\n');

export interface ConfigOptions {
  enable?: boolean;
  disable?: boolean;
}

function applyToggle(key: Toggle, value: string | undefined): number {
  const labels = TOGGLES[key];

  if (value === undefined) {
    const config = loadUserConfig();
    process.stdout.write(`${labels.status}: ${config[key].enabled ? 'enabled' : 'disabled'}\n`);
    if (config[key].consentedAt) {
      process.stdout.write(`Consented: ${config[key].consentedAt}\n`);
    }
    return 0;
  }

  const enabled = parseToggleValue(value);
  if (enabled === null) {
    process.stderr.write(`Unknown value for ${key}: ${value} (expected on or off)\n`);
    process.stderr.write(`${USAGE}\n`);
    return 1;
  }
  if (key === 'contribute') setContributeEnabled(enabled);
  else setLlmEnabled(enabled);
  process.stdout.write(`${labels.changed} ${enabled ? 'enabled' : 'disabled'}.\n`);
  return 0;
}

/** Runs `opena2a config <action> [key] [value]`; returns the exit code. */
export async function runConfig(
  action: string,
  key: string | undefined,
  value: string | undefined,
  opts: ConfigOptions = {},
): Promise<number> {
  // --enable / --disable stand in for the value.
  const flag = opts.enable ? 'on' : opts.disable ? 'off' : undefined;

  if (isToggle(action)) {
    return applyToggle(action, flag ?? key);
  }

  if (action === 'set') {
    if (!isToggle(key)) {
      process.stderr.write(
        key === undefined
          ? 'config set needs a key: contribute or llm\n'
          : `Unknown config key: ${key} (expected contribute or llm)\n`,
      );
      process.stderr.write(`${USAGE}\n`);
      return 1;
    }
    const setValue = flag ?? value;
    if (setValue === undefined) {
      process.stderr.write(`config set ${key} needs a value: on or off\n`);
      process.stderr.write(`${USAGE}\n`);
      return 1;
    }
    return applyToggle(key, setValue);
  }

  if (action === 'show' || action === 'get') {
    const config = loadUserConfig();
    // Report the registry URL commands will ACTUALLY use, not the raw
    // stored value. `config show` used to print whatever the config file
    // (or the pinned shared package's default) held, which on a fresh
    // install was `https://registry.opena2a.org` — a host with no DNS, so
    // the one command a user runs to find out where the CLI points told
    // them somewhere it never talks to.
    const { getRegistryUrl } = await import('../util/report-submission.js');
    const effective = { ...config, registry: { ...config.registry, url: await getRegistryUrl() } };
    process.stdout.write(JSON.stringify(effective, null, 2) + '\n');
    return 0;
  }

  process.stderr.write(`Unknown config action: ${action}\n`);
  process.stderr.write(`${USAGE}\n`);
  return 1;
}

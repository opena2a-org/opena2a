import { describe, it, expect } from 'vitest';
import { matchIntent } from '../../src/natural/intent-map.js';
import { isKnownCommand } from '../../src/natural/known-commands.js';

/**
 * Regression guard for the `opena2a detect credentials` help collision
 * fixed in 0.10.6.
 *
 * The `--help` "Smart Features" block in src/index.ts advertises a set of
 * natural-language examples. Each MUST route through the NL matcher, not a
 * registered command. The dispatch fallback only treats a phrase as natural
 * language when its first token is NOT a known command; `detect` is a real
 * command, so `detect credentials` silently scanned a `credentials/`
 * directory instead of matching an intent.
 *
 * Keep this list in sync with the "Smart Features" examples whose label is
 * "Natural language command matching".
 */
const HELP_NL_EXAMPLES = ['find secrets', 'audit my project'] as const;

describe('help natural-language examples', () => {
  for (const phrase of HELP_NL_EXAMPLES) {
    const firstToken = phrase.split(' ')[0];

    it(`"${phrase}" first token "${firstToken}" is not a registered command (would shadow NL routing)`, () => {
      expect(isKnownCommand(firstToken)).toBe(false);
    });

    it(`"${phrase}" resolves to a natural-language intent`, () => {
      expect(matchIntent(phrase)).not.toBeNull();
    });
  }

  it('documents why the old example was broken: "detect" IS a registered command', () => {
    // `detect credentials` routed to the `detect` command, never the NL matcher.
    expect(isKnownCommand('detect')).toBe(true);
  });
});

/**
 * The counts-only chain check is described as it runs.
 *
 * `verifyEventLog(path, { countsOnly: true })` leaves both of its windows
 * empty, but it does hold events: it parses each line into an event and
 * holds it while its link is checked, and it keeps `firstUntrusted`, the
 * first event past the break. A text that says the check holds or keeps no
 * event, or keeps at most one event whatever the log's size, misstates
 * that.
 *
 * The list is explicit: these are the option's doc, its callers' comments
 * and the tests that exercise it.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');

const TEXTS = [
  'packages/cli/src/shield/events.ts',
  'packages/cli/src/commands/shield.ts',
  'packages/cli/src/shield/integrity.ts',
  'packages/cli/__tests__/shield/recover-archive-log.test.ts',
  'packages/cli/__tests__/shield/event-log-any-size.test.ts',
];

// Each claim, matched across comment line breaks and `*` / `//` prefixes.
const BARRED = [
  { name: 'keeps no event', pattern: /keep(?:s|ing)? no events?\b/i },
  { name: 'holds no event', pattern: /hold(?:s|ing)? no events?\b/i },
  { name: 'without holding events', pattern: /without holding (?:any )?events?\b/i },
  { name: 'one event kept, whatever the size', pattern: /is kept, whatever the size/i },
];

function flatten(text) {
  return text.replace(/\n\s*(?:\*(?!\/)|\/\/)?\s*/g, ' ');
}

for (const rel of TEXTS) {
  test(`${rel} does not say the counts-only chain check holds no event`, () => {
    const text = flatten(readFileSync(path.join(REPO_ROOT, rel), 'utf-8'));
    const found = BARRED.filter(({ pattern }) => pattern.test(text)).map(({ name }) => name);
    assert.deepEqual(found, [], `${rel} claims: ${found.join('; ')}`);
  });
}

test('the countsOnly option doc says each event is held while its link is checked', () => {
  const source = readFileSync(path.join(REPO_ROOT, 'packages/cli/src/shield/events.ts'), 'utf-8');
  const doc = source.match(/\/\*\*((?:(?!\*\/)[\s\S])*)\*\/\s*countsOnly\?: boolean;/);
  assert.ok(doc, 'events.ts declares countsOnly under a doc comment');
  const text = flatten(doc[1]);
  assert.match(text, /holds it while its link is checked/);
  assert.match(text, /`firstUntrusted`/);
});

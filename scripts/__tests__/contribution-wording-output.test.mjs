/**
 * Text opena2a prints on behalf of a bundled engine does not call contributed
 * results anonymized (issue #388). They are not: each contributed summary is
 * sent with a contributor token made on the machine.
 *
 * hackmyagent and ai-trust ship their own help and prompt text, which still
 * says "anonymized"; opena2a corrects it as the text passes through.
 *
 * Runs the built CLI (`packages/cli/dist`), so `npm run build` comes first.
 * HOME and OPENA2A_HOME point into a temporary directory, so no file of the
 * user running the test is read or written.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, '..', '..');
const CLI_DIST = path.join(REPO_ROOT, 'packages', 'cli', 'dist');
const CLI = path.join(CLI_DIST, 'index.js');

const ANONYMIZED = /anonymi[sz]ed/i;

const { createLineRebrander, rewordContributionClaims } = await import(
  pathToFileURL(path.join(CLI_DIST, 'util', 'rebrand.js')).href
);

test('opena2a scan --help shows the --contribute option without calling the findings anonymized', (t) => {
  const root = mkdtempSync(path.join(os.tmpdir(), 'contribution-wording-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, 'home');
  mkdirSync(home);
  const res = spawnSync(process.execPath, [CLI, 'scan', '--help'], {
    cwd: root,
    encoding: 'utf8',
    env: {
      ...process.env,
      HOME: home,
      OPENA2A_HOME: path.join(root, 'opena2a-home'),
      OPENA2A_TELEMETRY: 'off',
      NO_COLOR: '1',
    },
    timeout: 60_000,
  });
  const output = `${res.stdout}\n${res.stderr}`;
  // The engine's own help must actually have been printed, or the check
  // below would pass on an empty screen.
  const contributeLine = output.split('\n').find((l) => /^\s*--contribute\b/.test(l));
  assert.ok(contributeLine, `no --contribute option in the help output:\n${output}`);
  assert.match(contributeLine, /Share scan findings with OpenA2A Registry/);
  assert.doesNotMatch(output, ANONYMIZED);
});

test('the streaming rebrander corrects each contribution line the bundled engines print', () => {
  const lines = [
    '  --contribute            Share anonymized scan findings with OpenA2A Registry (overrides config)',
    '  Sharing adds anonymized results to the OpenA2A trust registry',
    '  Share anonymized results so other developers can make informed security decisions.',
  ];
  const r = createLineRebrander();
  // Split mid-word, so the correction must survive a chunk boundary.
  const text = `${lines.join('\n')}\n`;
  const cut = text.indexOf('anonym') + 3;
  const out = r.push(text.slice(0, cut)) + r.push(text.slice(cut)) + r.flush();
  assert.doesNotMatch(out, ANONYMIZED);
  assert.equal(
    out,
    [
      '  --contribute            Share scan findings with OpenA2A Registry (overrides config)',
      '  Sharing adds results to the OpenA2A trust registry',
      '  Share results so other developers can make informed security decisions.',
      '',
    ].join('\n'),
  );
});

test('rewordContributionClaims keeps articles, capitals and predicative uses grammatical', () => {
  assert.equal(
    rewordContributionClaims('  Sharing anonymized results helps other developers'),
    '  Sharing results helps other developers',
  );
  assert.equal(rewordContributionClaims('Converts the list into an anonymized summary'), 'Converts the list into a summary');
  assert.equal(rewordContributionClaims('queues an anonymised event'), 'queues an event');
  assert.equal(rewordContributionClaims('Anonymized results help everyone'), 'Results help everyone');
  assert.equal(rewordContributionClaims('Results are anonymized.'), 'Results are sent with a contributor token.');
  assert.equal(rewordContributionClaims('Nothing to change here.'), 'Nothing to change here.');
});

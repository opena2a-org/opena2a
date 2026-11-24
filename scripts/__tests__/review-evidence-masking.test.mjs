/**
 * The review report masks secrets in the evidence lines it copies from the
 * tree, and writes fix commands that act on exactly the file a finding names
 * (issue #408). Covered here: lines broken by CR, a value that follows an
 * authorization scheme, URL passwords of any length, a bounded window read
 * before masking, ignore rules for names gitignore would read as patterns,
 * `--` before a file name, and the scanner's evidence lists read only as far
 * as the three lines the report keeps.
 *
 * Loads the built CLI module (`packages/cli/dist`), so `npm run build` comes
 * first. No file is written and no process is started.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DIST = path.resolve(HERE, '..', '..', 'packages', 'cli', 'dist', 'commands');
const require = createRequire(import.meta.url);
const { maskEvidenceLine, buildReviewFindings } = require(path.join(DIST, 'review-findings.js'));
const { scoreReview, CRITICAL_BAND } = require(path.join(DIST, 'review.js'));

const MASK = '••••';
const SHORT = 'FAKEvalue42'; // a placeholder under 16 characters, so no long-token rule masks it
/** A URL with user information. The parts are joined at run time so no line of
 *  this file reads as a URL that carries a password; every password is FAKE. */
const url = (scheme, user, password, rest) => [scheme, '://', user, ':', password, '@', rest].join('');
/** The masked form: the password replaced, the text after the last @ kept. */
const masked = (scheme, user, rest) => [scheme, '://', user, ':', MASK, rest === null ? '…' : `@${rest}`].join('');
const LONG = n => 'p'.repeat(n); // a FAKE password of n characters

function build({ envFiles = [], hmaFindings = [], warn = [] }) {
  const hygieneChecks = ['.gitignore', '.env protection', 'Lock file', 'Security config']
    .map(label => ({ label, status: warn.includes(label) ? 'warn' : 'pass', detail: '' }));
  const guardData = { filesMonitored: 0, tamperedFiles: [], signatureStatus: 'valid', candidates: [] };
  const credentialData = { matches: [], totalFindings: 0, bySeverity: {} };
  const shieldData = { classifiedFindings: [], policyLoaded: true, eventCount: 0 };
  const detectData = { mcpServers: [], aiConfigs: [] };
  return buildReviewFindings({
    targetDir: '/tmp/x',
    initData: { projectType: 'Node.js', hygieneChecks, envFiles, advisories: [], matchedPackages: [] },
    credentialData, guardData, shieldData, detectData,
    findings: [],
    hmaData: { available: true, score: 90, allFailedFindings: hmaFindings },
    state: { hygieneChecks, credentials: credentialData, guard: guardData, shield: shieldData, hma: { available: true, score: 90 }, detect: detectData },
    score: scoreReview,
    floorBand: CRITICAL_BAND,
  });
}

const hma = (checkId, file, extra = {}) => ({
  checkId, name: checkId, description: '', category: 'misc', severity: 'low', passed: false, message: '', file,
  fixable: false, guidance: '', count: 1, sampleFiles: [], ...extra,
});

test('a line broken by CR or CRLF is masked part by part and printed on one line', () => {
  assert.equal(maskEvidenceLine(`A=1\rDB=${SHORT}\r\n`, true), `A=${MASK} DB=${MASK}`);
  assert.equal(maskEvidenceLine(`DB=${SHORT}\r`, true), `DB=${MASK}`);
  assert.equal(maskEvidenceLine(`password=${SHORT}\nnote`, false), `password=${MASK} note`);
});

test('a value after an authorization scheme is masked with the scheme', () => {
  assert.equal(maskEvidenceLine(`Authorization: Bearer ${SHORT}`, false), `Authorization: ${MASK}`);
  assert.equal(maskEvidenceLine(`curl --token Basic ${SHORT}`, false), `curl --token ${MASK}`);
});

test('a URL password of any length is masked', () => {
  assert.equal(maskEvidenceLine(url('postgres', 'app', LONG(300), 'db/app'), false), masked('postgres', 'app', 'db/app'));
  assert.equal(maskEvidenceLine(url('redis', '', SHORT, 'cache:6379'), false), masked('redis', '', 'cache:6379'));
});

test('a long line is read only up to a window, and a URL password the window cuts off is masked', () => {
  const cut = maskEvidenceLine(url('postgres', 'app', LONG(100_000), 'db/app'), false);
  assert.equal(cut, masked('postgres', 'app', null));
  // No @ follows: the window cuts the line inside the password.
  const open = maskEvidenceLine(`u=${url('postgres', 'app', LONG(100_000), '').slice(0, -1)}`, false);
  assert.equal(open, `u=${masked('postgres', 'app', null)}`);
  const long = maskEvidenceLine('a'.repeat(5_000_000), false);
  assert.ok(long.length <= 160, `masked line is ${long.length} characters`);
});

test('an ignore rule escapes what gitignore would read as negation, comment or pattern', () => {
  const ruleFor = name => build({
    warn: ['.env protection'],
    envFiles: [{ path: name, assignments: 0, gitIgnored: false, gitTracked: false, stagedByAddAll: true, mode: '-rw-------' }],
  }).reportFindings[0].fix.command;
  assert.equal(ruleFor('!keep'), "printf '\\n%s\\n' '\\!keep' >> .gitignore");
  assert.equal(ruleFor('#note'), "printf '\\n%s\\n' '\\#note' >> .gitignore");
  assert.equal(ruleFor('a[1]*?\\b'), "printf '\\n%s\\n' 'a\\[1]\\*\\?\\\\b' >> .gitignore");
  assert.equal(ruleFor('a b '), "printf '\\n%s\\n' 'a b\\ ' >> .gitignore");
  assert.equal(ruleFor('a\nb'), "printf '\\n%s\\n' 'a?b' >> .gitignore");
});

test('chmod and ls get -- before the file name, and a name with a line break stays on one line', () => {
  const r = build({
    hmaFindings: [hma('PERM-001', '-x.env')],
    envFiles: [{ path: '-x.env', assignments: 0, gitIgnored: true, gitTracked: false, stagedByAddAll: false, mode: '-rw-r--r--' }],
  });
  assert.equal(r.reportFindings[0].fix.command, "chmod 600 -- '-x.env'");
  assert.equal(r.reportFindings[0].verify.command, "ls -l -- '-x.env'");
  const tracked = build({
    warn: ['.env protection'],
    envFiles: [{ path: 'a\nb', assignments: 0, gitIgnored: false, gitTracked: true, stagedByAddAll: true, mode: '-rw-------' }],
  }).reportFindings[0];
  assert.equal(tracked.fix.command, "git rm --cached -- $'a\\x0ab'");
  assert.equal(tracked.verify.command, "git ls-files -- $'a\\x0ab'");
});

test('scanner evidence is read only as far as the three lines the report keeps', () => {
  let reads = 0;
  const lines = new Proxy(Array.from({ length: 10_000 }, (_, i) => ({ n: i + 1, content: `line ${i}` })), {
    get(target, key, receiver) {
      if (typeof key === 'string' && /^\d+$/.test(key)) reads++;
      return Reflect.get(target, key, receiver);
    },
  });
  const r = build({ hmaFindings: [hma('X-001', 'x.js', { evidence: { kind: 'positive', lines } })] });
  assert.deepEqual(r.reportFindings[0].evidence.map(e => e.line), [1, 2, 3]);
  assert.ok(reads <= 3, `read ${reads} evidence lines`);

  // A list that is not an array in the scanner's JSON gives no evidence lines.
  const odd = build({ hmaFindings: [hma('X-002', 'y.js', { evidence: { kind: 'positive', lines: 'abc' } })] });
  assert.deepEqual(odd.reportFindings[0].evidence, []);
});

import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { createHash } from 'crypto';
import * as fs from 'fs';
import * as path from 'path';

// What the CLI says it sends to the OpenA2A Registry, and what it says the
// Registry counts, is fixed wording: each text below is pinned byte for byte,
// present once in its file, with the text it replaced gone.
//
// No public sentence says that usage telemetry protects, warns, detects for or
// informs anyone else. CLAIM runs over the repository's public text files, and
// every match must be on ALLOWED with the reason it is not a claim.

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

type Source = readonly [file: string, text: string];

function read(file: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8');
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

function occurrences(haystack: string, needle: string): number {
  return haystack.split(needle).length - 1;
}

// --- the ruled texts ----------------------------------------------------------

/** The advisories module header. */
const ADVISORIES_HEADER = 'Called during `opena2a init` and `opena2a review` to show the advisories the Registry has published for packages in the project.';
/** The reason given for `opena2a config contribute on`. */
const CONTRIBUTE_REASON = 'Share scans with the OpenA2A Registry: summaries are counted in its public statistics, and `detect` also sends its findings';
/** The doc comment on the check block's count of shared scans. */
const SHARED_SCANS_DOC = 'Number of shared scans the Registry counts for the package in the last 90 days; absent when they carry fewer than three distinct contributor tokens. The Registry does not verify them.';
/** The README clause on what the contribution flow becomes. */
const CONTRIBUTION_FLOW = 'that flow is stored by the Registry';
/** The count clause of the README's exchange lead. */
const COUNT_CLAUSE = 'and the number of shared scans counted for it in the last 90 days, which the Registry does not verify';

/** Byte length and the first 8 hex digits of the SHA-256 of each text, as ruled. */
const RULED: ReadonlyArray<readonly [text: string, bytes: number, sha256Prefix: string]> = [
  [ADVISORIES_HEADER, 128, '7ca42a73'],
  [CONTRIBUTE_REASON, 123, '5b2005d7'],
  [SHARED_SCANS_DOC, 183, '299be7bd'],
  [CONTRIBUTION_FLOW, 35, 'ba174d05'],
  [COUNT_CLAUSE, 101, 'e2768677'],
];

/** The runtime channel's config comment. */
const RUNTIME_COMMENT = 'Opt-in: send ARP runtime anomaly events to the Registry (POST /v1/telemetry/runtime)';
/** The `--contribute` option's help. */
const CONTRIBUTE_HELP = "Share this scan's summary with the OpenA2A Registry";
/** The README's exchange lead, up to its count clause. */
const LEAD_HEAD = 'opena2a looks things up in the OpenA2A Registry on `init`, `review`, `verify` and `detect`: back come the trust level and score the Registry holds for a package, the advisories the Registry publishes, ';
/** The README's contribution sentence, up to the clause on what the flow becomes. */
const CONTRIBUTION_PREMISE = 'This is **separate** from the community-contribution data the Registry already collects via `--publish` flags; ';
/** The rest of the contribution sentence, and the usage telemetry sentence. */
const FLOW_REST = ", and its totals are on the Registry's public statistics. Usage telemetry answers one question: which commands are run, and how often.";

const README = 'packages/cli/README.md';
const README_LEAD = `${LEAD_HEAD}${COUNT_CLAUSE}.`;
const README_CONTRIBUTION = `${CONTRIBUTION_PREMISE}${CONTRIBUTION_FLOW}${FLOW_REST}`;

/** The texts these replaced, as they read before. */
const REPLACED = {
  advisoriesHeader: 'Called during `opena2a init` and `opena2a review` to surface intelligence from community scan reports.',
  contributeReason: 'Help the community -- share scan summaries',
  sharedScansDoc: 'Count of independent community scans backing the score.',
  runtimeComment: 'Opt-in: join Global Threat Intelligence Network for ARP runtime telemetry (POST /v1/telemetry/runtime)',
  contributeHelp: 'Share scan summaries with OpenA2A community',
  readmeContribution: 'that flow continues to populate the public community page (scan submissions, findings, contributors). Telemetry just answers "is anyone running these commands at all?"',
} as const;

/** The paragraphs of a `/** ... *\/` block, each one's lines joined by single spaces. */
function commentParagraphs(block: string): string[] {
  const paragraphs: string[][] = [[]];
  for (const raw of block.replace(/^\s*\/\*\*/, '').replace(/\*\/\s*$/, '').split('\n')) {
    const line = raw.replace(/^\s*\*\s?/, '').trim();
    if (line === '') paragraphs.push([]);
    else paragraphs[paragraphs.length - 1].push(line);
  }
  return paragraphs.filter((p) => p.length > 0).map((p) => p.join(' '));
}

describe('the texts on what the CLI sends to the Registry and what it counts', () => {
  it('each ruled text has its ruled bytes', () => {
    for (const [text, bytes, prefix] of RULED) {
      expect(Buffer.byteLength(text, 'utf8'), text).toBe(bytes);
      expect(sha256(text).slice(0, 8), text).toBe(prefix);
    }
  });

  it('the advisories header is the ruled prose, wrapped no wider than the line that opens it', () => {
    const source = read('packages/cli/src/util/advisories.ts');
    const block = source.slice(0, source.indexOf('*/') + 2);
    const paragraphs = commentParagraphs(block);

    expect(paragraphs.filter((p) => p === ADVISORIES_HEADER)).toHaveLength(1);
    expect(paragraphs).not.toContain(REPLACED.advisoriesHeader);

    const lines = block.split('\n');
    const width = lines[1].length;
    expect(lines.filter((l) => l.length > width)).toEqual([]);
  });

  it('the contribute suggestion gives the ruled reason', () => {
    const source = read('packages/cli/src/contextual/advisor.ts');
    expect(occurrences(source, `reason: '${CONTRIBUTE_REASON}',`)).toBe(1);
    expect(occurrences(source, REPLACED.contributeReason)).toBe(0);
  });

  it('the check block documents its count of shared scans with the ruled comment', () => {
    const source = read('packages/cli-ui/src/check-block.ts');
    expect(occurrences(source, `/** ${SHARED_SCANS_DOC} */`)).toBe(1);
    expect(occurrences(source, REPLACED.sharedScansDoc)).toBe(0);
  });

  it('the runtime channel config comment says what the channel sends', () => {
    const source = read('packages/cli/src/identity/manifest.ts');
    expect(occurrences(source, `/** ${RUNTIME_COMMENT} */`)).toBe(1);
    expect(occurrences(source, REPLACED.runtimeComment)).toBe(0);
  });

  it('the --contribute help is the ruled text', () => {
    const source = read('packages/cli/src/index.ts');
    expect(occurrences(source, `.option('--contribute', "${CONTRIBUTE_HELP}")`)).toBe(1);
    expect(occurrences(source, REPLACED.contributeHelp)).toBe(0);
  });

  it('the README Telemetry section opens with the exchange lead and says what the contribution flow becomes', () => {
    const lines = read(README).split('\n');
    const heading = lines.indexOf('## Telemetry');

    expect(heading).toBeGreaterThan(-1);
    expect(lines.slice(heading + 1, heading + 3)).toEqual(['', README_LEAD]);
    expect(lines.filter((l) => l === README_LEAD)).toHaveLength(1);
    expect(lines.filter((l) => l === README_CONTRIBUTION)).toHaveLength(1);
    expect(occurrences(lines.join('\n'), REPLACED.readmeContribution)).toBe(0);
  });

  it('detect labels its count of shared scans unverified', () => {
    const source = read('packages/cli/src/commands/detect.ts');
    expect(
      occurrences(
        source,
        "shared scan${server.registryData.communityScans !== 1 ? 's' : ''} (unverified)`",
      ),
    ).toBe(1);
    expect(occurrences(source, 'community scan${')).toBe(0);
  });
});

// --- the claim gate -----------------------------------------------------------

/**
 * The gate's PCRE, copied byte for byte from its specification (line 625).
 * JavaScript has no inline `(?i)`, so that prefix becomes the `i` flag; the
 * rest, lookbehinds included, reads the same in both.
 */
const CLAIM_PCRE = String.raw`(?i)(usage (telemetry|data|events?)|telemetry)[^.\n]{0,140}(?<!runtime-)(protect|immun|threat intel|intelligence|safer|keeps? (you|everyone|users) safe|helps? (everyone|other users|the community))|(?<!runtime-)(protect|immun|intelligence|safer)[^.\n]{0,140}(usage (telemetry|data|events?)|\btelemetry\b)`;
const CLAIM_PCRE_SHA256 = '807b542ac5abb446a074933e74eba2dfaf0c09a0c4a650c395d66a6808dcf8a7';
const CLAIM = new RegExp(CLAIM_PCRE.replace(/^\(\?i\)/, ''), 'gi');

/** The file types the gate reads, as a git pathspec. */
const PUBLIC_TEXT = ['*.md', '*.mdx', '*.tsx', '*.ts', '*.js', '*.html'];

/** Tests, fixtures and change logs are left out. */
const LEFT_OUT =
  /(^|\/)(__tests__|tests?|__fixtures__|fixtures?)\/|\.(test|spec)\.[cm]?[jt]sx?$|(^|\/)CHANGELOG[^/]*$/i;

/**
 * The matches reviewed as not being a claim, each with its reason. A new match
 * fails until it is reviewed, and an entry that no longer matches fails too.
 */
const ALLOWED: ReadonlyArray<{ readonly file: string; readonly match: string }> = [
  // Not a claim: a command named `protect`.
  { file: README, match: 'usage data to the OpenA2A Registry: tool name, version, command name (`check`, `scan`, `protect' },
];

interface Hit {
  readonly file: string;
  readonly line: number;
  readonly match: string;
}

function publicTextFiles(): string[] {
  const out = execFileSync('git', ['ls-files', '-z', '--', ...PUBLIC_TEXT], {
    cwd: REPO_ROOT,
    encoding: 'utf-8',
  });
  return out
    .split('\0')
    .filter((f) => f && !LEFT_OUT.test(f))
    .filter((f) => fs.existsSync(path.join(REPO_ROOT, f)));
}

/** Every match on every line, so a reviewed match cannot cover a second one on its line. */
function claimHits(sources: readonly Source[]): Hit[] {
  const hits: Hit[] = [];
  for (const [file, text] of sources) {
    text.split('\n').forEach((line, i) => {
      for (const m of line.matchAll(CLAIM)) hits.push({ file, line: i + 1, match: m[0] });
    });
  }
  return hits;
}

function unreviewed(hits: readonly Hit[]): string[] {
  return hits
    .filter((h) => !ALLOWED.some((a) => a.file === h.file && a.match === h.match))
    .map((h) => `${h.file}:${h.line}: ${h.match}`);
}

describe('no public sentence says that usage telemetry protects, warns, detects for or informs anyone else', () => {
  const files = publicTextFiles();
  const sources: Source[] = files.map((f) => [f, read(f)]);

  it('the pattern is the ruled one, byte for byte', () => {
    expect(sha256(CLAIM_PCRE)).toBe(CLAIM_PCRE_SHA256);
    expect(CLAIM_PCRE.startsWith('(?i)')).toBe(true);
  });

  it('the gate reads the READMEs and sources, and leaves out tests, fixtures and change logs', () => {
    for (const file of [
      'README.md',
      README,
      'packages/cli/src/identity/manifest.ts',
      'packages/cli/src/index.ts',
      'packages/cli-ui/src/check-block.ts',
    ]) {
      expect(files, file).toContain(file);
    }
    expect(files.filter((f) => f.includes('__tests__/') || /\.test\.ts$/.test(f))).toEqual([]);
    expect(files.filter((f) => /CHANGELOG/i.test(f))).toEqual([]);
  });

  it('every match is a reviewed non-claim', () => {
    expect(unreviewed(claimHits(sources))).toEqual([]);
  });

  it('every reviewed entry still matches, once', () => {
    const hits = claimHits(sources);
    for (const entry of ALLOWED) {
      expect(
        hits.filter((h) => h.file === entry.file && h.match === entry.match),
        entry.match,
      ).toHaveLength(1);
    }
  });

  it('a planted claim fails the gate, also on the line that carries a reviewed match', () => {
    const reviewedLine = read(README)
      .split('\n')
      .find((l) => l.includes(ALLOWED[0].match));
    expect(reviewedLine).toBeDefined();

    const planted: Source[] = [
      ['docs/planted.md', 'Usage telemetry protects every user.'],
      ['docs/planted.md', 'Telemetry feeds threat intelligence.'],
      ['packages/cli/src/planted.ts', '// Shared intelligence comes from telemetry.'],
      [README, `${reviewedLine} Usage data keeps users safe.`],
    ];
    for (const source of planted) {
      expect(unreviewed(claimHits([source])), source[1]).toHaveLength(1);
    }
  });

  it('a module name with the runtime- prefix is not a match', () => {
    expect(claimHits([['docs/planted.md', 'The runtime-protection telemetry module.']])).toEqual([]);
  });
});

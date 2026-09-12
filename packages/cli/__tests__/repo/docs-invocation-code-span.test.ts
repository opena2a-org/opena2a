import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * Every `npx opena2a-cli` invocation in the documented surface sits inside a
 * fenced block or inside a code span.
 *
 * The residual this closes is the prose form: a line like
 *
 *     Run npx opena2a-cli review from your project root.
 *
 * is a command a reader can copy, but it is not marked up as one — no fence, no
 * backticks. A tokenizer that checks the *operand* admits it, because the word
 * after the binary is `review` and the word after that is `from`; it has no way
 * to tell a documented subcommand from the next word of a sentence without
 * parsing English. That is why this lint checks PLACEMENT and nothing else:
 * where an invocation sits is decidable from the markup, and an invocation that
 * sits in a code span or a fence is already reviewable by every other check.
 *
 * So this file says nothing about operands, subcommands or explicit targets.
 * `Run ` + backtick + `npx opena2a-cli review` + backtick + ` from your project
 * root.` is ADMITTED here even though a target-checking lint refuses it — that
 * is a different class and a different instrument.
 *
 * The walked set is written out as a literal rather than imported. The
 * target-checking test that names the same three roots
 * (`__tests__/repo/docs-npx-explicit-target.test.ts`) is not in this tree, so
 * there is nothing to import; if it lands later the two may share a walker, but
 * the literal set stays, because the set is what this criterion pins.
 *
 * The corpus is clean today: 56 occurrences over 8 walked files, 54 in fences,
 * 2 in code spans, 0 in bare prose. This suite is what keeps it that way.
 */

/**
 * The repository root, resolved from this file's own location and never from
 * `process.cwd()`.
 *
 * The cwd this suite runs under is `packages/cli`, not the root: ci.yml:65 runs
 * `npm run test` -> root package.json:11 `turbo run test` -> this package's
 * package.json:12 `vitest run`, and turbo runs each package script in that
 * package's own directory. A cwd-relative `packages/cli/README.md` would
 * resolve to `packages/cli/packages/cli/README.md`, which does not exist, and
 * the walk would silently read a short file list and pass having measured
 * almost nothing. The ascent is fixed because this file's location is fixed:
 * packages/cli/__tests__/repo/ -> four levels up is the root.
 */
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

/** The two literal roots; `docs/**\/*.md` is walked. Together: 8 files today. */
const LITERAL_FILES = ['README.md', 'packages/cli/README.md'] as const;
const DOCS_DIR = 'docs';

/** Every occurrence this lint reasons about. AC1 names this regex. */
const INVOCATION = /npx (?:-y )?opena2a-cli/g;

/**
 * The same pattern without `g`, for the yes/no reads.
 *
 * `INVOCATION` is only ever handed to `matchAll`, which copies `lastIndex` from
 * the regex it is given. Sharing one global regex between `matchAll` and a
 * `.test()` somewhere else means the first `.test()` leaves `lastIndex` past
 * the start of the line and the next scan quietly skips the first occurrence on
 * every line it reads.
 */
const INVOCATION_ONCE = new RegExp(INVOCATION.source);

/**
 * A fence delimiter: optional leading whitespace, then three backticks or three
 * tildes. Tracking is a toggle, so a file with an odd number of these lines
 * would leave the walker "inside" a fence to EOF and swallow every later
 * violation. That the count is even in all 8 files is measured below rather
 * than assumed.
 */
const FENCE_LINE = /^\s*(?:`{3}|~{3})/;

const BACKTICK = '`';

/**
 * Files exempted from the lint. Empty, and asserted empty: an allowlist is the
 * one way a bare-prose invocation could pass this suite, so adding an entry
 * fails the suite that entry was added to silence.
 */
const EXEMPTIONS: readonly string[] = [];

interface Occurrence {
  /** Repo-relative, POSIX separators. */
  readonly file: string;
  /** 1-based. */
  readonly line: number;
  /** The full line, verbatim. */
  readonly text: string;
}

interface Census {
  readonly fenced: Occurrence[];
  readonly codeSpan: Occurrence[];
  readonly bare: Occurrence[];
  /** Fence delimiter lines per file, in walk order. */
  readonly fenceLines: ReadonlyMap<string, number>;
}

type Source = readonly [file: string, text: string];

/** The walked set: the two literal roots, then every `docs/**\/*.md`, sorted. */
function walkedFiles(): string[] {
  const docs: string[] = [];
  const visit = (relDir: string): void => {
    const entries = fs.readdirSync(path.join(REPO_ROOT, relDir), { withFileTypes: true });
    for (const entry of entries) {
      const rel = `${relDir}/${entry.name}`;
      if (entry.isDirectory()) visit(rel);
      else if (entry.name.endsWith('.md')) docs.push(rel);
    }
  };
  visit(DOCS_DIR);
  docs.sort();
  return [...LITERAL_FILES, ...docs];
}

function readWalkedSet(): Source[] {
  return walkedFiles().map((file): Source => [
    file,
    fs.readFileSync(path.join(REPO_ROOT, file), 'utf-8'),
  ]);
}

/** Backticks on the line strictly before the match. Odd => inside a code span. */
function backticksBefore(line: string, matchStart: number): number {
  let count = 0;
  for (let i = 0; i < matchStart; i++) {
    if (line[i] === BACKTICK) count++;
  }
  return count;
}

/**
 * Classify every occurrence as fenced, code-span, or bare.
 *
 * Fence lines are counted and skipped — a delimiter line is markup, never a
 * site. Outside a fence, an occurrence is admitted only when an odd number of
 * backticks precedes it on the same line, so an unrelated code span earlier in
 * the line (`Run ` + backtick + `npm ci` + backtick + ` then npx opena2a-cli
 * review.`) leaves an even count and does not launder the bare invocation
 * after it.
 */
function classify(sources: readonly Source[]): Census {
  const fenced: Occurrence[] = [];
  const codeSpan: Occurrence[] = [];
  const bare: Occurrence[] = [];
  const fenceLines = new Map<string, number>();

  for (const [file, text] of sources) {
    let inFence = false;
    let fences = 0;
    const lines = text.split(/\r?\n/);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (FENCE_LINE.test(line)) {
        inFence = !inFence;
        fences++;
        continue;
      }
      for (const match of line.matchAll(INVOCATION)) {
        const occurrence: Occurrence = { file, line: i + 1, text: line };
        if (inFence) fenced.push(occurrence);
        else if (backticksBefore(line, match.index ?? 0) % 2 === 1) codeSpan.push(occurrence);
        else bare.push(occurrence);
      }
    }
    fenceLines.set(file, fences);
  }

  return { fenced, codeSpan, bare, fenceLines };
}

/**
 * The failure message: one line per violation, all of them, never a head and a
 * count. A reader fixing these needs every `file:line` in one pass — a
 * truncated list turns one red run into five.
 */
function report(bare: readonly Occurrence[]): string {
  const head =
    `${bare.length} \`npx opena2a-cli\` invocation(s) outside a fenced block and outside a ` +
    'code span. Wrap each one in backticks or move it into a fenced block. This lint is ' +
    'placement only — it says nothing about the operand:';
  return [head, ...bare.map((o) => `${o.file}:${o.line}: ${o.text}`)].join('\n');
}

/** `file:line` keys of every line matching a predicate, across the walked set. */
function lineKeys(sources: readonly Source[], predicate: (line: string) => boolean): string[] {
  const keys: string[] = [];
  for (const [file, text] of sources) {
    text.split(/\r?\n/).forEach((line, i) => {
      if (predicate(line)) keys.push(`${file}:${i + 1}`);
    });
  }
  return keys;
}

// --- committed fixtures, all measured on this tree ------------------------

const WALKED_SET = [
  'README.md',
  'packages/cli/README.md',
  'docs/USE-CASES.md',
  'docs/testing/release-smoke.md',
  'docs/use-cases/ci-cd.md',
  'docs/use-cases/developer.md',
  'docs/use-cases/mcp-server-author.md',
  'docs/use-cases/security-team.md',
] as const;

/** Fence delimiter lines per walked file. Every count is even; total 174. */
const FENCE_LINES_PER_FILE: Readonly<Record<string, number>> = {
  'README.md': 22,
  'packages/cli/README.md': 8,
  'docs/USE-CASES.md': 0,
  'docs/testing/release-smoke.md': 18,
  'docs/use-cases/ci-cd.md': 34,
  'docs/use-cases/developer.md': 30,
  'docs/use-cases/mcp-server-author.md': 26,
  'docs/use-cases/security-team.md': 36,
};

/** Occurrences per walked file. 56 in total, on 55 lines, in 6 of the 8 files. */
const OCCURRENCES_PER_FILE: Readonly<Record<string, number>> = {
  'README.md': 4,
  'packages/cli/README.md': 1,
  'docs/USE-CASES.md': 0,
  'docs/testing/release-smoke.md': 0,
  'docs/use-cases/ci-cd.md': 28,
  'docs/use-cases/developer.md': 5,
  'docs/use-cases/mcp-server-author.md': 7,
  'docs/use-cases/security-team.md': 11,
};

/** The only two code-span occurrences: the npx-hangs troubleshooting row. */
const CODE_SPAN_ROW = {
  file: 'docs/use-cases/ci-cd.md',
  line: 510,
  text: '| `npx opena2a-cli` hangs | npm prompting for install confirmation | Use `npx -y opena2a-cli` |',
} as const;

/**
 * The two bare-prose lines the negative case plants. Appended to IN-MEMORY
 * copies — nothing here writes to the tree. Their landing line numbers are
 * fixed by the files' current lengths (README.md 264 lines, developer.md 307),
 * and pinning them is what proves the report addresses the right line and not
 * merely some line.
 */
const PLANTED: Readonly<Record<string, { readonly text: string; readonly line: number }>> = {
  'README.md': { text: 'Use npx -y opena2a-cli detect to list agents.', line: 266 },
  'docs/use-cases/developer.md': {
    text: 'Run npx opena2a-cli review from your project root.',
    line: 309,
  },
};

function plant(sources: readonly Source[]): Source[] {
  return sources.map(([file, text]): Source => {
    const planted = PLANTED[file];
    return planted ? [file, `${text}\n${planted.text}\n`] : [file, text];
  });
}

/**
 * The four cases that pin the admit rule, with the outcome expected for each
 * occurrence on the line.
 *
 * Case 2 is the one that separates this lint from a target-checking one: a
 * target lint refuses it (the invocation carries no explicit target), this lint
 * admits it (the invocation sits in a code span). Case 1 is the trap — a code
 * span EARLIER on the line must not launder a bare invocation after it.
 */
const DISCRIMINATION: ReadonlyArray<{
  readonly line: string;
  readonly admit: readonly boolean[];
  readonly why: string;
}> = [
  {
    line: 'Run `npm ci` then npx opena2a-cli review.',
    admit: [false],
    why: 'two backticks before the match: an unrelated code span does not launder a bare invocation',
  },
  {
    line: 'Run `npx opena2a-cli review` from your project root.',
    admit: [true],
    why: 'one backtick before the match: inside a code span, admitted regardless of its operand',
  },
  {
    line: 'Run npx opena2a-cli review from your project root.',
    admit: [false],
    why: 'no backtick before the match: the bare prose form this lint exists to refuse',
  },
  {
    line: CODE_SPAN_ROW.text,
    admit: [true, true],
    why: 'the tree\'s own troubleshooting row: both occurrences sit in code spans',
  },
];

/**
 * The 55 occurrence lines, hashed: `file:line:text\n` per line in walk order.
 *
 * This is the "moves nothing" pin. Rewording an invocation, moving one to
 * another line, or re-fencing one all change this digest, so a delivery that
 * made the placement check green by editing the docs cannot also keep this
 * green. Updating it is a deliberate act: recompute only alongside a docs
 * change that is itself the point of the commit.
 */
const OCCURRENCE_LINES_SHA256 =
  'deddea35340cd2c7bb51971e9182754b9c342b0055ce64a2ca62e75a4f6b3f12';

function occurrenceLinesDigest(sources: readonly Source[]): string {
  const rows: string[] = [];
  for (const [file, text] of sources) {
    text.split(/\r?\n/).forEach((line, i) => {
      if (INVOCATION_ONCE.test(line)) rows.push(`${file}:${i + 1}:${line}\n`);
    });
  }
  return createHash('sha256').update(rows.join(''), 'utf8').digest('hex');
}

/** The 57th invocation, in a file with no fence or code-span notion. */
const UNWALKED_TAPE = { file: 'docs/images/review-demo.tape', line: 21 } as const;

describe('every documented `npx opena2a-cli` invocation sits in a fence or a code span', () => {
  // --- AC1: the walked set, the root resolution, and the runner chain ------

  it('OPA-06.AC1 resolves the repository root from this file, not from process.cwd()', () => {
    expect(REPO_ROOT).toBe(path.resolve(__dirname, '..', '..', '..', '..'));
    expect(path.relative(REPO_ROOT, __dirname).split(path.sep).join('/')).toBe(
      'packages/cli/__tests__/repo',
    );

    // The ascent landed on the workspace root, not on some ancestor that merely
    // happens to have a package.json.
    const manifest = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'),
    ) as { name?: string; workspaces?: unknown };
    expect(manifest.name).toBe('opena2a');
    expect(Array.isArray(manifest.workspaces)).toBe(true);

    // Every read is absolute and under that root, so no path in this suite is
    // sensitive to where the runner was invoked from.
    for (const file of walkedFiles()) {
      const absolute = path.join(REPO_ROOT, file);
      expect(path.isAbsolute(absolute)).toBe(true);
      expect(fs.existsSync(absolute)).toBe(true);
    }
  });

  it('OPA-06.AC1 walks exactly README.md, packages/cli/README.md and every docs/**/*.md', () => {
    expect(walkedFiles()).toEqual([...WALKED_SET]);
    expect(walkedFiles()).toHaveLength(8);
  });

  it('OPA-06.AC1 is collected by the required check with no workflow edit', () => {
    const packageDir = path.join(REPO_ROOT, 'packages', 'cli');

    // This file sits where the include glob looks.
    expect(path.relative(packageDir, __dirname).split(path.sep).join('/')).toBe('__tests__/repo');
    expect(fs.readdirSync(__dirname)).toContain('docs-invocation-code-span.test.ts');

    // ci.yml:65 `npm run test` -> root `turbo run test` -> this package's
    // `vitest run` -> include `__tests__/**/*.test.ts`. Each hop, read.
    const vitestConfig = fs.readFileSync(path.join(packageDir, 'vitest.config.ts'), 'utf-8');
    expect(vitestConfig).toContain("include: ['__tests__/**/*.test.ts']");

    const cliPkg = JSON.parse(fs.readFileSync(path.join(packageDir, 'package.json'), 'utf-8')) as {
      scripts?: Record<string, string>;
    };
    expect(cliPkg.scripts?.test).toBe('vitest run');

    const rootPkg = JSON.parse(
      fs.readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf-8'),
    ) as { scripts?: Record<string, string> };
    expect(rootPkg.scripts?.test).toBe('turbo run test');

    const ci = fs.readFileSync(path.join(REPO_ROOT, '.github', 'workflows', 'ci.yml'), 'utf-8');
    expect(ci.split(/\r?\n/).map((l) => l.trim())).toContain('- run: npm run test');
  });

  it('OPA-06.AC1 no invocation sits outside a fenced block and outside a code span', () => {
    const { bare } = classify(readWalkedSet());
    expect(bare, report(bare)).toHaveLength(0);
  });

  it('OPA-06.AC1 passes with an empty exemption list', () => {
    expect(EXEMPTIONS).toHaveLength(0);
  });

  // --- AC2: the negative case ---------------------------------------------

  it('OPA-06.AC2 reports every bare-prose invocation as file:line, not only the first', () => {
    const { fenced, codeSpan, bare } = classify(plant(readWalkedSet()));

    expect(bare.map((o) => `${o.file}:${o.line}`)).toEqual([
      'README.md:266',
      'docs/use-cases/developer.md:309',
    ]);
    expect(bare).toHaveLength(2);

    // Planting bare prose moves neither of the other two classes: the lint
    // found new violations, it did not reclassify existing occurrences.
    expect(fenced).toHaveLength(54);
    expect(codeSpan).toHaveLength(2);
  });

  it('OPA-06.AC2 the failure message carries every violation verbatim and does not truncate', () => {
    const { bare } = classify(plant(readWalkedSet()));
    const message = report(bare);

    for (const [file, { text, line }] of Object.entries(PLANTED)) {
      expect(message).toContain(`${file}:${line}: ${text}`);
      // Verbatim: the line as written, not a normalised or elided rendering.
      expect(message).toContain(text);
    }

    // One head line plus one line per violation, and nothing that stands in
    // for the rest of a list.
    expect(message.split('\n')).toHaveLength(bare.length + 1);
    expect(message).not.toMatch(/\.\.\.|and \d+ more|truncat/i);
  });

  it('OPA-06.AC2 the unplanted tree is green, so the red above is the plant and nothing else', () => {
    expect(classify(readWalkedSet()).bare).toEqual([]);
  });

  // --- AC3: the census and the two mechanics ------------------------------

  it('OPA-06.AC3 the census: 56 occurrences, 54 fenced, 2 code-span, 0 bare', () => {
    const { fenced, codeSpan, bare } = classify(readWalkedSet());

    expect(fenced).toHaveLength(54);
    expect(codeSpan).toHaveLength(2);
    expect(bare).toHaveLength(0);
    expect(fenced.length + codeSpan.length + bare.length).toBe(56);

    const perFile: Record<string, number> = Object.fromEntries(
      WALKED_SET.map((f): [string, number] => [f, 0]),
    );
    for (const o of [...fenced, ...codeSpan, ...bare]) perFile[o.file] += 1;
    expect(perFile).toEqual(OCCURRENCES_PER_FILE);
  });

  it('OPA-06.AC3 both code-span occurrences are the ci-cd.md:510 npx-hangs row', () => {
    const { codeSpan } = classify(readWalkedSet());
    expect(codeSpan).toEqual([
      { file: CODE_SPAN_ROW.file, line: CODE_SPAN_ROW.line, text: CODE_SPAN_ROW.text },
      { file: CODE_SPAN_ROW.file, line: CODE_SPAN_ROW.line, text: CODE_SPAN_ROW.text },
    ]);
  });

  it('OPA-06.AC3 fence tracking closes in every walked file: an even count, 174 in total', () => {
    const { fenceLines } = classify(readWalkedSet());

    expect(Object.fromEntries(fenceLines)).toEqual(FENCE_LINES_PER_FILE);
    for (const [file, count] of fenceLines) {
      expect(count % 2, `${file} has an odd number of fence lines — the toggle never closes`).toBe(
        0,
      );
    }
    expect([...fenceLines.values()].reduce((a, b) => a + b, 0)).toBe(174);
  });

  it('OPA-06.AC3 no tilde fence and no indented fence line in the walked set', () => {
    const sources = readWalkedSet();
    expect(lineKeys(sources, (l) => /^\s*~{3}/.test(l))).toEqual([]);
    expect(lineKeys(sources, (l) => FENCE_LINE.test(l) && /^\s/.test(l))).toEqual([]);
  });

  it('OPA-06.AC3 the lines carrying a double backtick are exactly the fence lines', () => {
    const sources = readWalkedSet();
    const doubles = lineKeys(sources, (l) => l.includes(`${BACKTICK}${BACKTICK}`));
    const fences = lineKeys(sources, (l) => FENCE_LINE.test(l));

    expect(doubles).toEqual(fences);
    expect(doubles).toHaveLength(174);
  });

  it('OPA-06.AC3 the admit rule discriminates on backtick parity before the match', () => {
    for (const { line, admit, why } of DISCRIMINATION) {
      const { fenced, codeSpan, bare } = classify([['fixture.md', line]]);
      expect(fenced, why).toHaveLength(0);
      const verdicts = [
        ...codeSpan.map(() => true),
        ...bare.map(() => false),
      ];
      expect(verdicts.sort(), why).toEqual([...admit].sort());
      expect(codeSpan.length + bare.length, why).toBe(admit.length);
      expect(codeSpan, why).toHaveLength(admit.filter(Boolean).length);
    }
  });

  it('OPA-06.AC3 an invocation in backticks is admitted whatever its operand: placement only', () => {
    // A target-checking lint refuses this line — the invocation names no
    // explicit target and `from` is read as its operand. That is a different
    // criterion; here it is clean, because it sits in a code span.
    const line = 'Run `npx opena2a-cli review` from your project root.';
    const { codeSpan, bare } = classify([['fixture.md', line]]);
    expect(bare).toEqual([]);
    expect(codeSpan).toHaveLength(1);

    // Strip the backticks and the same line is a violation. The markup is the
    // whole difference.
    const stripped = classify([['fixture.md', line.split(BACKTICK).join('')]]);
    expect(stripped.bare).toHaveLength(1);
  });

  // --- AC4: the instrument moves nothing ----------------------------------

  it('OPA-06.AC4 the 55 occurrence lines are byte-identical to the base tree', () => {
    const sources = readWalkedSet();
    const rows = lineKeys(sources, (l) => INVOCATION_ONCE.test(l));

    expect(rows).toHaveLength(55);
    expect(
      occurrenceLinesDigest(sources),
      'an existing invocation was reworded, moved or re-fenced — this lint is an instrument, ' +
        'and a green it earned by editing the corpus is not the green it claims',
    ).toBe(OCCURRENCE_LINES_SHA256);
  });

  it('OPA-06.AC4 the walked set is not widened: markdown only, three roots, no src', () => {
    const walked = walkedFiles();

    for (const file of walked) {
      expect(file.endsWith('.md'), `${file} is not markdown`).toBe(true);
      expect(
        LITERAL_FILES.includes(file as (typeof LITERAL_FILES)[number]) ||
          file.startsWith(`${DOCS_DIR}/`),
        `${file} is outside README.md, packages/cli/README.md and docs/`,
      ).toBe(true);
    }
    expect(walked.filter((f) => f.startsWith('packages/cli/src/'))).toEqual([]);
    expect(walked.filter((f) => f.endsWith('.tape'))).toEqual([]);
  });

  it('OPA-06.AC4 docs/images/review-demo.tape carries a 57th invocation and is not walked', () => {
    expect(walkedFiles()).not.toContain(UNWALKED_TAPE.file);

    // It exists and it does carry one — the exclusion is a decision about a
    // file format with no fence or code-span notion, not an oversight.
    const tape = fs
      .readFileSync(path.join(REPO_ROOT, UNWALKED_TAPE.file), 'utf-8')
      .split(/\r?\n/);
    expect(tape[UNWALKED_TAPE.line - 1]).toMatch(INVOCATION_ONCE);
    expect(tape[UNWALKED_TAPE.line - 1]).toContain('npx opena2a-cli init');
  });
});

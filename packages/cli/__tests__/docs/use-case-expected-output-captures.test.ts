import { describe, it, expect } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { table } from '../../src/util/format.js';

/**
 * The "Expected output" blocks in docs/use-cases/ were not captures. They were
 * prose written to look like output: a four-line `Shadow AI Detection v0.7.2`
 * header `formatText` has no code path to print, a `Governance Score  n / 100`
 * line `buildGovernanceSummary` never emits, a CSV header whose ten column names
 * are all different from `generateAssetCsv`'s, and a `self-register` block built
 * out of six strings that occur zero times in the command's source.
 *
 * A stale version number was the visible symptom -- `v0.7.2` in ten places, four
 * minor releases behind packages/cli/package.json -- but re-capturing alone does
 * not stop the drift coming back. So this file pins the RELATION rather than the
 * text: the doc's header line is compared against the string literal the CLI
 * pushes, the CSV header against the literal `generateAssetCsv` writes, the
 * self-register column row against that call site's own header array rendered by
 * the same `table()` the command calls, and every version inside a capture
 * against packages/cli/package.json read at run time. Bumping the package
 * version without re-capturing turns this file red; nothing here hard-codes it.
 *
 * The blocks themselves were produced by running the CLI. What is verified here
 * is the committed text, which is the only half of that a test can see.
 */

const DEV = 'docs/use-cases/developer.md';
const SEC = 'docs/use-cases/security-team.md';
const MCP = 'docs/use-cases/mcp-server-author.md';
const TAPE = 'docs/images/review-demo.tape';
const DOCS = [DEV, SEC, MCP];
const WALKED = [...DOCS, TAPE];

/**
 * Strings that only exist because a block was written rather than captured.
 * Each was measured at zero occurrences in the code that would have to print
 * it: `Shadow AI Detection` and `Governance Score` against detect.ts,
 * `Users can now discover` and `Checking npm ownership` against
 * self-register.ts, `scanDirectory` against generateAssetCsv's header.
 */
const FABRICATIONS = [
  'Shadow AI Detection',
  'Governance Score',
  'scanDirectory',
  'Users can now discover',
  'Checking npm ownership',
];

/** The six literals the old self-register block showed, none of which the command holds. */
const SELF_REGISTER_FABRICATIONS = [
  'Trust Registry Self-Registration',
  'Verification Method',
  'Checking npm ownership',
  'Users can now discover',
  'Profile URL',
  'Trust Score',
];

/** `Captured from opena2a-cli v<version> on <YYYY-MM-DD>`, anywhere in the label line. */
const CAPTURE_LABEL = /Captured from opena2a-cli v(\d+\.\d+\.\d+) on (\d{4}-\d{2}-\d{2})/;

/** A semantic version as a doc would print one, `v` prefix and all. */
const VERSION_IN_TEXT = /v\d+\.\d+\.\d+/g;

/** Info strings that mark a fence as input the reader types, not output they see. */
const SHELL_INFOS = new Set(['bash', 'sh', 'shell', 'console', 'zsh']);
const NON_OUTPUT_INFOS = new Set([
  ...SHELL_INFOS,
  'yaml', 'yml', 'json', 'js', 'javascript', 'ts', 'typescript', 'tsx',
  'diff', 'toml', 'ini', 'python', 'md', 'markdown',
]);

/** Repo root: the nearest ancestor whose package.json declares workspaces. */
function repoRoot(): string {
  let dir = __dirname;
  while (dir !== path.parse(dir).root) {
    const manifest = path.join(dir, 'package.json');
    if (fs.existsSync(manifest)) {
      try {
        const parsed = JSON.parse(fs.readFileSync(manifest, 'utf-8'));
        if (Array.isArray(parsed.workspaces)) return dir;
      } catch {
        // Unparseable manifest on the way up: keep walking.
      }
    }
    dir = path.dirname(dir);
  }
  throw new Error('repository root not found (no package.json with "workspaces" above this test)');
}

function read(rel: string): string {
  return fs.readFileSync(path.join(repoRoot(), rel), 'utf-8');
}

/**
 * The version the CLI can print, read from the manifest at run time.
 *
 * getVersion() (src/util/version.ts:9-20) resolves package.json relative to its
 * own directory and returns `pkg.version`, so this file is the single source of
 * the number -- which is exactly why it is read here instead of written down.
 */
function pinnedVersion(): string {
  const manifest = path.join(repoRoot(), 'packages', 'cli', 'package.json');
  const pkg = JSON.parse(fs.readFileSync(manifest, 'utf-8'));
  if (typeof pkg.version !== 'string') throw new Error(`${manifest} declares no "version"`);
  return pkg.version;
}

interface Fence {
  file: string;
  info: string;
  /** 1-based line of the opening ``` */
  fenceLine: number;
  /** Block body, one entry per line, with its 1-based line number in the file. */
  body: { line: number; text: string }[];
  /** The non-empty line immediately above the opening fence, if any. */
  label: string | null;
  /** Lines of the nearest preceding shell fence -- the command this block answers. */
  invocation: string[];
}

/** Every fenced block in a markdown file, each tagged with the command above it. */
function fences(file: string): Fence[] {
  const lines = read(file).split('\n');
  const out: Fence[] = [];
  let open: { info: string; start: number } | null = null;
  let lastShell: string[] = [];

  for (let i = 0; i < lines.length; i++) {
    const m = /^```(.*)$/.exec(lines[i]);
    if (!m) continue;
    if (open === null) {
      open = { info: m[1].trim().toLowerCase(), start: i };
      continue;
    }
    const body = lines.slice(open.start + 1, i).map((text, k) => ({ line: open!.start + 2 + k, text }));
    const above = open.start > 0 ? lines[open.start - 1] : '';
    out.push({
      file,
      info: open.info,
      fenceLine: open.start + 1,
      body,
      label: above.trim() === '' ? null : above,
      invocation: lastShell,
    });
    if (SHELL_INFOS.has(open.info)) lastShell = body.map((b) => b.text);
    open = null;
  }
  if (open !== null) throw new Error(`${file}: unclosed fence opened at line ${open.start + 1}`);
  return out;
}

/** Fences that show what a command printed, rather than what the reader types. */
function outputBlocks(file: string): Fence[] {
  return fences(file).filter((f) => !NON_OUTPUT_INFOS.has(f.info));
}

/** Output blocks whose invocation is an `opena2a-cli` command line. */
function cliOutputBlocks(file: string): Fence[] {
  return outputBlocks(file).filter((f) => f.invocation.some((l) => /\bopena2a-cli\b/.test(l)));
}

/** Output blocks answering an invocation line that matches `pattern` exactly. */
function blocksFor(file: string, pattern: RegExp): Fence[] {
  return outputBlocks(file).filter((f) => f.invocation.some((l) => pattern.test(l.trim())));
}

/** The block's first non-empty line -- where a banner would be if one were printed. */
function bannerLine(block: Fence): { line: number; text: string } | undefined {
  return block.body.find((b) => b.text.trim() !== '');
}

function labelOf(block: Fence): { version: string; date: string } | null {
  const m = block.label ? CAPTURE_LABEL.exec(block.label) : null;
  return m ? { version: m[1], date: m[2] } : null;
}

/** True when `YYYY-MM-DD` is a date that exists (2026-02-30 is not). */
function isRealDate(iso: string): boolean {
  const [y, m, d] = iso.split('-').map(Number);
  const parsed = new Date(Date.UTC(y, m - 1, d));
  return parsed.getUTCFullYear() === y && parsed.getUTCMonth() === m - 1 && parsed.getUTCDate() === d;
}

/**
 * The five blocks this contract re-captured, located by the command above them
 * rather than by line number -- a line-addressed locator follows the wrong block
 * the first time a paragraph above it grows.
 */
function requiredCaptures(): { what: string; block: Fence | undefined }[] {
  const bareDetect = /^npx opena2a-cli detect$/;
  const dev = blocksFor(DEV, bareDetect);
  const sec = blocksFor(SEC, bareDetect);
  const csv = fences(SEC).filter((f) => f.info === 'csv');
  const reg = blocksFor(MCP, /^npx opena2a-cli self-register\b/);
  return [
    { what: `${DEV} first \`opena2a-cli detect\` audit`, block: dev[0] },
    { what: `${DEV} second \`opena2a-cli detect\` audit`, block: dev[1] },
    { what: `${SEC} \`opena2a-cli detect\` audit`, block: sec[0] },
    { what: `${SEC} asset-inventory CSV`, block: csv[0] },
    { what: `${MCP} \`opena2a-cli self-register\` summary`, block: reg[0] },
  ];
}

/** Split one CSV record into fields, honouring csvEscape's `""` quoting. */
function csvFields(line: string): string[] {
  const fields: string[] = [];
  let field = '';
  let quoted = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (quoted) {
      if (c === '"' && line[i + 1] === '"') { field += '"'; i++; }
      else if (c === '"') quoted = false;
      else field += c;
    } else if (c === '"') {
      quoted = true;
    } else if (c === ',') {
      fields.push(field);
      field = '';
    } else {
      field += c;
    }
  }
  fields.push(field);
  return fields;
}

// --- Source-side measurements ---------------------------------------------

const DETECT_SRC = 'packages/cli/src/commands/detect.ts';
const SELF_REGISTER_SRC = 'packages/cli/src/commands/self-register.ts';
const INDEX_SRC = 'packages/cli/src/index.ts';

/** The single header row `generateAssetCsv` pushes, read out of its source. */
function csvHeaderLiteral(): string {
  const src = read(DETECT_SRC);
  const body = /function generateAssetCsv\b[\s\S]*?\n}/.exec(src);
  if (!body) throw new Error(`${DETECT_SRC}: no generateAssetCsv function found`);
  const pushes = [...body[0].matchAll(/rows\.push\('([^']*)'\)/g)].map((m) => m[1]);
  if (pushes.length !== 1) {
    throw new Error(`${DETECT_SRC}: expected generateAssetCsv to push exactly one literal row, found ${pushes.length}`);
  }
  return pushes[0];
}

/** The column headers `printSummary` hands to `table()`, read out of its source. */
function selfRegisterTableHeaders(): string[] {
  const src = read(SELF_REGISTER_SRC);
  const m = /table\(\s*rows\s*,\s*\[([^\]]*)\]\s*\)/.exec(src);
  if (!m) throw new Error(`${SELF_REGISTER_SRC}: no table(rows, [...]) call found`);
  return [...m[1].matchAll(/'([^']*)'/g)].map((h) => h[1]);
}

describe('docs/use-cases -- the "Expected output" blocks are captures of the pinned build', () => {
  it('OPA-07.AC1 the three detect audits are captures of formatText, not of a header it cannot print', () => {
    const version = pinnedVersion();
    const detectSrc = read(DETECT_SRC);

    // Measured against the source first: a doc that agreed with a constant in
    // this file while both disagreed with the CLI is the failure being fixed.
    expect(detectSrc).toContain("lines.push(bold('Shadow AI Agent Audit'));");
    expect(detectSrc).not.toContain('Shadow AI Detection');
    expect(detectSrc).not.toContain('Governance Score');

    const audits = [...blocksFor(DEV, /^npx opena2a-cli detect$/), ...blocksFor(SEC, /^npx opena2a-cli detect$/)];
    expect(audits, 'expected two detect audits in developer.md and one in security-team.md').toHaveLength(3);

    for (const block of audits) {
      const at = `${block.file}:${block.fenceLine}`;
      const banner = bannerLine(block);
      expect(banner?.text, `${at}: first content line of a detect capture`).toBe('Shadow AI Agent Audit');

      for (const { line, text } of block.body) {
        const where = `${block.file}:${line}`;
        expect(text, `${where}: a header formatText has no code path to print`).not.toMatch(/Shadow AI Detection/);
        expect(text, `${where}: the fabricated four-line device header`).not.toMatch(/^ {2}Machine {4}/);
        expect(text, `${where}: the fabricated four-line device header`).not.toMatch(/^ {2}User {7}/);
        expect(text, `${where}: buildGovernanceSummary emits "Governance: n/100"`).not.toMatch(/Governance Score/);
      }

      const scoreLines = block.body.filter((b) => b.text.startsWith('Governance'));
      expect(scoreLines, `${at}: exactly one governance line`).toHaveLength(1);
      expect(scoreLines[0].text, `${block.file}:${scoreLines[0].line}`).toMatch(/^Governance: [0-9]{1,3}\/100/);

      const label = labelOf(block);
      expect(label, `${at}: no "Captured from opena2a-cli v<version> on <date>" label above the fence`).not.toBe(null);
      expect(label!.version, `${at}: capture label names a version the CLI cannot print`).toBe(version);
    }
  });

  it('OPA-07.AC2 the CSV block carries generateAssetCsv\'s header verbatim and rows with that many columns', () => {
    const header = csvHeaderLiteral();
    const columns = header.split(',').length;

    const csv = fences(SEC).filter((f) => f.info === 'csv');
    expect(csv, `${SEC}: expected exactly one csv fence`).toHaveLength(1);
    const block = csv[0];
    const rows = block.body.filter((b) => b.text.trim() !== '');

    expect(rows[0].text, `${SEC}:${rows[0].line}: not generateAssetCsv's header`).toBe(header);
    expect(rows.length, 'the CSV block carries no data rows').toBeGreaterThan(1);

    const assetTypes = new Set(['AI Agent', 'MCP Server', 'AI Config']);
    for (const type of assetTypes) expect(read(DETECT_SRC)).toContain(`'${type}',`);

    for (const { line, text } of rows.slice(1)) {
      const fields = csvFields(text);
      expect(fields.length, `${SEC}:${line}: ${fields.length} fields, header declares ${columns}`).toBe(columns);
      expect([...assetTypes], `${SEC}:${line}: Asset Type column`).toContain(fields[4]);
    }

    const label = labelOf(block);
    expect(label, `${SEC}:${block.fenceLine}: no capture label above the csv fence`).not.toBe(null);
    expect(label!.version).toBe(pinnedVersion());

    // The sentence under the block used to name four columns the export does
    // not have; it has to name the ones it does.
    const after = read(SEC).split('\n').slice(block.body[block.body.length - 1].line + 1);
    const prose = after.find((l) => l.trim() !== '') ?? '';
    for (const column of ['Hostname', 'Username', 'Scan Directory', 'Scan Timestamp']) {
      expect(prose, `${SEC}: the prose under the CSV block does not name the ${column} column`).toContain(column);
    }
  });

  it('OPA-07.AC3 the self-register block prints only strings the command can produce', () => {
    const selfRegisterSrc = read(SELF_REGISTER_SRC);
    const doc = read(MCP);

    for (const literal of SELF_REGISTER_FABRICATIONS) {
      // Measured, not assumed: each of these is absent from the command's source.
      expect(selfRegisterSrc, `${SELF_REGISTER_SRC} now contains ${literal}`).not.toContain(literal);
      expect(doc, `${MCP} still shows "${literal}", which self-register cannot print`).not.toContain(literal);
    }

    const blocks = blocksFor(MCP, /^npx opena2a-cli self-register\b/);
    expect(blocks, `${MCP}: expected one self-register output block`).toHaveLength(1);
    const block = blocks[0];

    const label = labelOf(block);
    expect(label, `${MCP}:${block.fenceLine}: no capture label above the fence`).not.toBe(null);
    expect(label!.version).toBe(pinnedVersion());

    // The column row has to be what `table()` renders for printSummary's own
    // header array -- including its padding, which is derived from the rows.
    const headers = selfRegisterTableHeaders();
    const text = block.body.map((b) => b.text.trimEnd());
    const headerIdx = text.findIndex((l) => l.trim() !== '' && arraysEqual(l.split(/\s{2,}/), headers));
    expect(headerIdx, `${MCP}:${block.fenceLine}: no line splits into ${headers.join(', ')}`).toBeGreaterThan(-1);

    let end = headerIdx + 2;
    while (end < text.length && text[end].trim() !== '') end++;
    const dataRows = text.slice(headerIdx + 2, end).map((l) => l.split(/\s{2,}/));
    expect(dataRows.length, `${MCP}:${block.fenceLine}: table has no rows`).toBeGreaterThan(0);

    const rendered = table(dataRows, headers).split('\n').map((l) => l.trimEnd());
    const actual = text.slice(headerIdx, end);
    for (let i = 0; i < rendered.length; i++) {
      const line = block.body[headerIdx + i].line;
      expect(actual[i], `${MCP}:${line}: not what table() renders for self-register.ts's header array`).toBe(rendered[i]);
    }

    // What the command is for, from the one place that declares it.
    expect(read(INDEX_SRC)).toContain("Register OpenA2A tools in the public registry with security scan results");
    expect(doc, `${MCP}: still claims self-register publishes the reader's own server`)
      .not.toContain("Publish your server's trust profile");
    expect(doc, `${MCP}: does not say whose tools self-register publishes`)
      .toContain("OpenA2A project's own tools");
  });

  it('OPA-07.AC4 review-demo.tape names an init target instead of cd-ing into one maintainer\'s directory', () => {
    const lines = read(TAPE).split('\n');

    expect(read(INDEX_SRC), 'init no longer takes a directory operand').toContain(".command('init [directory]')");

    const typed = lines
      .map((text, i) => ({ line: i + 1, text }))
      .filter((l) => /^Type\s+"/.test(l.text));

    const initLines = typed.filter((l) => /opena2a-cli\s+init\b/.test(l.text));
    expect(initLines, `${TAPE}: no "npx opena2a-cli init" line`).toHaveLength(1);

    const m = /opena2a-cli\s+init\s+(\S+)/.exec(initLines[0].text);
    expect(m, `${TAPE}:${initLines[0].line}: init is invoked with no target, so it scans whatever the cwd happens to be`)
      .not.toBe(null);
    const target = m![1];
    expect(target, `${TAPE}:${initLines[0].line}: "${target}" is a redirection, not a target`).toMatch(/^[./~]?[\w./-]+$/);

    for (const { line, text } of typed) {
      expect(text, `${TAPE}:${line}: cd into the very directory init is given as its target`)
        .not.toMatch(new RegExp(`cd\\s+${target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(\\s|"|$)`));
    }
    for (const { line, text } of lines.map((text, i) => ({ line: i + 1, text }))) {
      expect(text, `${TAPE}:${line}: a path that exists only on one maintainer's machine`)
        .not.toMatch(/\/Users\/[a-z]/i);
    }

    const header = lines.slice(0, lines.findIndex((l) => l.trim() !== '' && !l.startsWith('#')));
    expect(header.join('\n'), `${TAPE}: the header comment carries no recording date`).toMatch(/\d{4}-\d{2}-\d{2}/);
  });

  it('OPA-07.AC5 every capture is pinned to packages/cli/package.json, and no fabrication is back', () => {
    const version = pinnedVersion();
    const violations: string[] = [];

    // (1) A version inside a capture, or on the banner line of any opena2a-cli
    //     output block, has to be the one this repo's CLI would print. It is the
    //     banner line that carried `v0.7.2` in all ten places, and printBanner --
    //     the only site that prints a version at all -- is reachable only from
    //     the no-argument wizard, never from a subcommand.
    for (const file of DOCS) {
      for (const block of cliOutputBlocks(file)) {
        const labelled = labelOf(block) !== null;
        const banner = bannerLine(block);
        for (const { line, text } of block.body) {
          if (!labelled && line !== banner?.line) continue;
          for (const found of text.match(VERSION_IN_TEXT) ?? []) {
            if (found === `v${version}`) continue;
            violations.push(`${file}:${line} shows ${found}, but packages/cli/package.json reads ${version}`);
          }
        }
      }
    }

    // (2) Each re-captured block carries a label naming this version and a date
    //     that exists.
    for (const { what, block } of requiredCaptures()) {
      if (!block) {
        violations.push(`${what}: block not found`);
        continue;
      }
      const label = labelOf(block);
      if (!label) {
        violations.push(`${block.file}:${block.fenceLine} has no "Captured from opena2a-cli v${version} on <YYYY-MM-DD>" label (${what})`);
        continue;
      }
      if (label.version !== version) {
        violations.push(`${block.file}:${block.fenceLine} is labelled v${label.version}, but packages/cli/package.json reads ${version}`);
      }
      if (!isRealDate(label.date)) {
        violations.push(`${block.file}:${block.fenceLine} is labelled with ${label.date}, which is not a calendar date`);
      }
    }

    // (3) None of the strings that only ever existed in the fabricated blocks.
    for (const file of WALKED) {
      read(file).split('\n').forEach((text, i) => {
        for (const bad of FABRICATIONS) {
          if (text.includes(bad)) violations.push(`${file}:${i + 1} contains "${bad}"`);
        }
      });
    }

    expect(violations).toEqual([]);
  });

  it('OPA-07.AC5 the pinned version is derived, never written down here', () => {
    const self = fs.readFileSync(__filename, 'utf-8');
    expect(
      self,
      'this file hard-codes the current CLI version, so a version bump would no longer turn it red',
    ).not.toContain(pinnedVersion());
  });
});

function arraysEqual(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

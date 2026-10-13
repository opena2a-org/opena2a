import { describe, it, expect } from 'vitest';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';

/**
 * The repository README stays a short form.
 *
 * A reader meets the first command and what it prints inside the first
 * screen, a job list that links to one section per job, the install lines,
 * the telemetry disclosure and a list of the reference pages. Everything
 * else lives under docs/ or in CONTRIBUTING.md. This file pins that shape:
 * the word and section budgets, the absence of release numbers and dates
 * (they go stale on every release), the capture's tie to its sidecar, and
 * the presence of each moved passage at its new path.
 *
 * It reads files only. Nothing here starts a process or reaches the network.
 */

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..', '..');

const MAX_WORDS = 887;
const MAX_H2 = 7;
/** No paragraph is longer than this, and at most one is longer than the soft cap. */
const MAX_PARAGRAPH_WORDS = 69;
const SOFT_PARAGRAPH_WORDS = 60;
const FIRST_SCREEN_LINES = 30;
const MAX_JOB_LINES = 7;

const START_COMMAND = 'npx opena2a-cli init my-agent';
const CAPTURE_TXT = 'docs/captures/quick-start-init.txt';
const CAPTURE_JSON = 'docs/captures/quick-start-init.json';
const ELISION_LINE = '  ...';

/** A release number (`1.2.3`, `v1.2.3`) or an ISO date. */
const VERSION_OR_DATE = /v?[0-9]+\.[0-9]+\.[0-9]+|20[0-9]{2}-[0-9]{2}-[0-9]{2}/;

/** The sentence every description of the usage events carries, word for word. */
const INSTALL_ID_SENTENCE =
  'Each event carries an install ID that identifies the machine, so the data is personal data.';

/** Each passage that left the README, by the heading it carries at its new path. */
const MOVED: ReadonlyArray<readonly [heading: string, destination: string]> = [
  ['From source', 'CONTRIBUTING.md'],
  ['Verifying what was installed', 'docs/verifying-npm-packages.md'],
  ['Assess', 'docs/commands.md'],
  ['Protect', 'docs/commands.md'],
  ['Operate', 'docs/commands.md'],
  ['Post-incident review', 'docs/post-incident-review.md'],
  ['Self-host or AIM Cloud', 'docs/commands.md'],
  ['Use cases', 'docs/USE-CASES.md'],
  ['Contributing', 'CONTRIBUTING.md'],
];

const FENCE = /^\s*```/;

function read(rel: string): string {
  return fs.readFileSync(path.join(REPO_ROOT, rel), 'utf-8');
}

/** Whitespace-separated tokens, the count `wc -w` prints. */
export function countWords(text: string): number {
  return text.split(/\s+/).filter(Boolean).length;
}

export function h2Titles(markdown: string): string[] {
  const titles: string[] = [];
  let inFence = false;
  for (const line of markdown.split('\n')) {
    if (FENCE.test(line)) inFence = !inFence;
    else if (!inFence && line.startsWith('## ')) titles.push(line.slice(3).trim());
  }
  return titles;
}

/**
 * The README cut into blocks: a run of non-blank lines, or one whole fenced
 * block with its fence lines and any blank lines inside it. A list is one
 * block. This is the widest reading of "paragraph", so a README that passes
 * here passes any narrower one.
 */
export function blocks(markdown: string): string[] {
  const out: string[] = [];
  let current: string[] = [];
  let inFence = false;
  const flush = (): void => {
    if (current.length > 0) out.push(current.join('\n'));
    current = [];
  };
  for (const line of markdown.split('\n')) {
    if (FENCE.test(line)) {
      if (!inFence) flush();
      current.push(line);
      inFence = !inFence;
      if (!inFence) flush();
    } else if (inFence || line.trim() !== '') {
      current.push(line);
    } else {
      flush();
    }
  }
  flush();
  return out;
}

/** `line: text` for each line that carries a release number or a date. */
export function versionOrDateLines(markdown: string): string[] {
  const hits: string[] = [];
  markdown.split('\n').forEach((line, i) => {
    if (VERSION_OR_DATE.test(line)) hits.push(`${i + 1}: ${line}`);
  });
  return hits;
}

/**
 * Where the first command and its output start, 1-based: the first line
 * that carries the command, and the first line inside the next fenced block
 * that opens after it.
 */
export function firstScreen(markdown: string, command: string): { command: number; output: number } {
  let inFence = false;
  let commandLine = 0;
  let outputFence = 0;
  markdown.split('\n').forEach((line, i) => {
    if (FENCE.test(line)) {
      inFence = !inFence;
      if (inFence && commandLine > 0 && outputFence === 0) outputFence = i + 1;
      return;
    }
    if (commandLine === 0 && line.includes(command)) commandLine = i + 1;
  });
  return { command: commandLine, output: outputFence + 1 };
}

/** The anchor GitHub gives a heading. */
export function slug(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9 _-]/g, '')
    .replace(/ /g, '-');
}

interface Section {
  readonly heading: string;
  readonly firstCodeLine: string | undefined;
}

/** Every heading of a page with the first line of the first fenced block under it. */
function sections(markdown: string): Section[] {
  const found: { heading: string; firstCodeLine: string | undefined }[] = [];
  let inFence = false;
  let takeNext = false;
  for (const line of markdown.split('\n')) {
    if (FENCE.test(line)) {
      inFence = !inFence;
      const last = found[found.length - 1];
      takeNext = inFence && last !== undefined && last.firstCodeLine === undefined;
      continue;
    }
    if (inFence) {
      if (takeNext) {
        found[found.length - 1].firstCodeLine = line;
        takeNext = false;
      }
      continue;
    }
    const heading = /^#{1,6} +(.*)$/.exec(line);
    if (heading) found.push({ heading: heading[1], firstCodeLine: undefined });
  }
  return found;
}

/** The text of one `## ` section, heading line excluded. */
function h2Section(markdown: string, title: string): string {
  const lines = markdown.split('\n');
  const start = lines.findIndex((l) => l === `## ${title}`);
  if (start === -1) return '';
  const next = lines.findIndex((l, i) => i > start && l.startsWith('## '));
  return lines.slice(start + 1, next === -1 ? undefined : next).join('\n');
}

/** Relative link targets as `[path, anchor]`; web and mail links are left out. */
function relativeLinks(markdown: string): Array<readonly [string, string]> {
  const links: Array<readonly [string, string]> = [];
  for (const match of markdown.matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = match[1];
    if (/^(https?:|mailto:)/.test(target)) continue;
    const [file, anchor = ''] = target.split('#');
    links.push([file, anchor]);
  }
  return links;
}

describe('the repository README is a short form', () => {
  const readme = read('README.md');

  it('stays inside the word and section budgets', () => {
    expect(countWords(readme)).toBeLessThanOrEqual(MAX_WORDS);
    expect(h2Titles(readme).length).toBeLessThanOrEqual(MAX_H2);
  });

  it('orders its sections: start block, job list, usage, then Install, Telemetry, Documentation, License', () => {
    const titles = h2Titles(readme);
    expect(titles[0]).toBe('Quick start');
    expect(titles.slice(-4)).toEqual(['Install', 'Telemetry', 'Documentation', 'License']);
  });

  it('shows the first command and the start of its output inside the first screen', () => {
    const { command, output } = firstScreen(readme, START_COMMAND);
    expect(command).toBeGreaterThan(0);
    expect(command).toBeLessThanOrEqual(FIRST_SCREEN_LINES);
    expect(output).toBeGreaterThan(command);
    expect(output).toBeLessThanOrEqual(FIRST_SCREEN_LINES);
  });

  it('carries no release number and no date', () => {
    expect(versionOrDateLines(readme)).toEqual([]);
  });

  it('keeps every paragraph short', () => {
    const counts = blocks(readme).map(countWords);
    expect(Math.max(...counts)).toBeLessThanOrEqual(MAX_PARAGRAPH_WORDS);
    expect(counts.filter((n) => n > SOFT_PARAGRAPH_WORDS).length).toBeLessThanOrEqual(1);
  });

  it('quotes the search form, because zsh expands an unquoted ~word before the CLI sees it', () => {
    const unquoted = readme.split('\n').filter((line) => /(^|\s)~[A-Za-z]/.test(line));
    expect(unquoted).toEqual([]);
    expect(readme).toContain('opena2a "~');
  });
});

describe('the measures catch the long form they replace', () => {
  it('counts words the way wc -w does', () => {
    expect(countWords('one  two\nthree\t`four five`\n')).toBe(5);
  });

  it('reports a release number, a v-prefixed one and a date, and leaves two-part numbers alone', () => {
    const planted = [
      'captured from a release 0.10.13 run',
      '  Assessment  v0.10.13',
      'as of 2026-10-06',
      'Requires Node.js 18 or later, licensed Apache-2.0.',
    ].join('\n');
    expect(versionOrDateLines(planted).map((h) => h.split(':')[0])).toEqual(['1', '2', '3']);
  });

  it('treats a list and a fenced block as one block each, and counts a long paragraph', () => {
    const long = Array.from({ length: 70 }, (_, i) => `w${i}`).join(' ');
    const sample = ['# T', '', long, '', '- a b', '- c d', '', '```', 'x y', '', 'z', '```', ''].join('\n');
    expect(blocks(sample).map(countWords)).toEqual([2, 70, 6, 5]);
  });

  it('places a command that sits below the first screen', () => {
    const pad = Array.from({ length: 40 }, () => 'text').join('\n\n');
    const late = `${pad}\n\n\`\`\`bash\n${START_COMMAND}\n\`\`\`\n\n\`\`\`\nout\n\`\`\`\n`;
    expect(firstScreen(late, START_COMMAND).command).toBeGreaterThan(FIRST_SCREEN_LINES);
  });

  it('slugs a heading the way the job-list links are written', () => {
    expect(slug("Look up a package's trust profile")).toBe('look-up-a-packages-trust-profile');
    expect(slug('Check a package, MCP server, skill or repo')).toBe(
      'check-a-package-mcp-server-skill-or-repo',
    );
  });
});

describe('the quick-start capture is the recorded run, not composed text', () => {
  const readme = read('README.md');
  const label = `What \`${START_COMMAND}\` prints, trimmed ([full output](${CAPTURE_TXT})):`;

  it('labels the excerpt with the command and links the full output', () => {
    expect(readme.split('\n')).toContain(label);
  });

  it('shows only lines of the recorded output, in order, with elision marked', () => {
    const lines = readme.split('\n');
    const open = lines.findIndex((l, i) => i > lines.indexOf(label) && FENCE.test(l));
    const close = lines.findIndex((l, i) => i > open && FENCE.test(l));
    const excerpt = lines.slice(open + 1, close);
    const recorded = read(CAPTURE_TXT).split('\n');

    expect(excerpt.length).toBeGreaterThan(2);
    let cursor = 0;
    for (const line of excerpt) {
      if (line === ELISION_LINE) continue;
      const at = recorded.indexOf(line, cursor);
      expect(at, `not in the recorded output after line ${cursor}: ${line}`).toBeGreaterThanOrEqual(0);
      cursor = at + 1;
    }
    // An elision line stands for skipped output, so it never opens or closes the excerpt.
    expect(excerpt[0]).not.toBe(ELISION_LINE);
    expect(excerpt[excerpt.length - 1]).not.toBe(ELISION_LINE);
  });

  it('keeps the version, the date and the digest of the run in the sidecar', () => {
    const sidecar = JSON.parse(read(CAPTURE_JSON)) as Record<string, unknown>;
    expect(sidecar.capture).toBe(path.basename(CAPTURE_TXT));
    expect(sidecar.command).toBe(START_COMMAND);
    expect(String(sidecar.version)).toMatch(/^[0-9]+\.[0-9]+\.[0-9]+$/);
    expect(String(sidecar.capturedAt)).toMatch(/^20[0-9]{2}-[0-9]{2}-[0-9]{2}T/);
    expect(typeof sidecar.exitCode).toBe('number');
    expect(sidecar.outputSha256).toBe(
      createHash('sha256').update(read(CAPTURE_TXT), 'utf8').digest('hex'),
    );
  });
});

describe('the job list leads to one section per job', () => {
  const readme = read('README.md');
  const jobLines = h2Section(readme, h2Titles(readme)[1])
    .split('\n')
    .filter((line) => line.startsWith('- '));

  it('has at most seven lines, each a link and a command', () => {
    expect(jobLines.length).toBeGreaterThan(0);
    expect(jobLines.length).toBeLessThanOrEqual(MAX_JOB_LINES);
    for (const line of jobLines) {
      expect(line, line).toMatch(/^- \[[^\]]+\]\([^)#]+#[^)]+\): `[^`]+`$/);
    }
  });

  it('lands each link on a heading that names the job, with the command as its first code block', () => {
    for (const line of jobLines) {
      const parsed = /^- \[([^\]]+)\]\(([^)#]+)#([^)]+)\): `([^`]+)`$/.exec(line);
      expect(parsed, line).not.toBeNull();
      const [, job, file, anchor, command] = parsed as RegExpExecArray;
      const target = sections(read(file)).find((s) => slug(s.heading) === anchor);
      expect(target, `${file} has no heading for #${anchor}`).toBeDefined();
      expect(target?.heading).toBe(job);
      expect(target?.firstCodeLine).toBe(command);
    }
  });
});

describe('every relative link in the README resolves', () => {
  const readme = read('README.md');

  it('points at files in the tree and at headings that exist', () => {
    const broken: string[] = [];
    for (const [file, anchor] of relativeLinks(readme)) {
      if (!fs.existsSync(path.join(REPO_ROOT, file))) {
        broken.push(`${file}: no such file`);
      } else if (anchor && !sections(read(file)).some((s) => slug(s.heading) === anchor)) {
        broken.push(`${file}#${anchor}: no such heading`);
      }
    }
    expect(broken).toEqual([]);
  });
});

describe('the README discloses telemetry', () => {
  const telemetry = h2Section(read('README.md'), 'Telemetry');

  it('states what is sent, where, and that the install ID makes it personal data', () => {
    expect(telemetry).toContain(INSTALL_ID_SENTENCE);
    expect(telemetry).toContain('install ID');
    expect(telemetry).toContain('api.oa2a.org');
    expect(telemetry).toContain('https://opena2a.org/telemetry');
  });

  it('names opt-outs the CLI accepts', () => {
    expect(telemetry).toContain('`OPENA2A_TELEMETRY=off`');
    expect(telemetry).toContain('`opena2a telemetry off`');
    expect(read('packages/cli/src/index.ts')).toContain(".command('telemetry [action]')");
    expect(read('packages/cli-ui/src/telemetry-command.ts')).toContain('case "off":');
    expect(read('packages/telemetry/src/config.ts')).toContain('const ENV_OPT_OUT = "OPENA2A_TELEMETRY";');
  });
});

describe('each passage that left the README is at its new path', () => {
  for (const [heading, destination] of MOVED) {
    it(`${destination} carries "${heading}"`, () => {
      expect(read(destination)).toContain(heading);
    });
  }

  it('the README links every page a passage moved to', () => {
    const readme = read('README.md');
    for (const destination of new Set(MOVED.map(([, d]) => d))) {
      expect(readme, destination).toContain(`](${destination}`);
    }
  });
});

describe('a moved passage agrees with the CLI and the security policy', () => {
  it('the scan row offers only the targets `opena2a scan` accepts, and sends the rest to check', () => {
    // `opena2a scan` runs `hackmyagent secure [directory]`, which reads its
    // argument as a local path: `opena2a scan express` exits 1 with
    // "Directory '.../express' does not exist". Packages, repos, MCP servers
    // and skills are what `opena2a check <target>` resolves.
    expect(read('packages/cli/src/adapters/registry.ts')).toMatch(
      /\n {2}scan: \{\n(?: {4}.*\n)*? {4}subcommand: 'secure',\n/,
    );
    const rows = read('docs/commands.md')
      .split('\n')
      .filter((line) => line.startsWith('| `opena2a scan '));
    expect(rows).toHaveLength(1);
    const [command, description] = rows[0].split(' | ');
    expect(command).toBe('| `opena2a scan [directory]`');
    const sentences = description.split(/\.\s+/);
    const routed = sentences.filter((s) => s.includes('use `opena2a check <target>`'));
    expect(routed, 'the row sends packages and repos to check').toHaveLength(1);
    const ownTargets = sentences.filter((s) => !routed.includes(s)).join('. ');
    expect(ownTargets).not.toMatch(/npm|GitHub|MCP|skill/);
  });

  it('CONTRIBUTING states no response time of its own and points at SECURITY.md', () => {
    const hours = /acknowledge receipt within (\d+) hours/.exec(read('SECURITY.md'));
    expect(hours, 'SECURITY.md states the acknowledgement time').not.toBeNull();
    for (const file of ['README.md', 'CONTRIBUTING.md']) {
      for (const match of read(file).matchAll(/within (\d+) hours/g)) {
        expect(match[1], `${file}: "${match[0]}"`).toBe(hours![1]);
      }
    }
    const line = read('CONTRIBUTING.md')
      .split('\n')
      .find((l) => l.startsWith('Security issues:'));
    expect(line).toContain('`info@opena2a.org`');
    expect(line).toContain('](SECURITY.md)');
  });
});

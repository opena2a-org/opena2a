#!/usr/bin/env node
// Reads the Quick Start workflow out of docs/use-cases/ci-cd.md so that
// .github/workflows/recipe.yml runs the text the guide prints, not a copy of
// it. One edit is made: the published invocation `npx opena2a-cli` becomes
// `node packages/cli/dist/index.js`, the build of the pull request under test.
// The edit is checked by reversing it: the block with the substitution undone
// must be the guide's block byte for byte, and each step script handed to the
// workflow must map back onto its span of the guide byte for byte.
//
// The block is read by a narrow reader rather than a YAML library. It accepts
// only what it can reproduce exactly (single-line plain scalars and literal
// `|` block scripts, the step keys the workflow emulates) and refuses
// anything else with exit 1, so a change to the guide that the workflow
// cannot run faithfully stops the job instead of running something else.
// packages/cli/__tests__/recipe/extract-recipe.test.ts compares its reading
// with a YAML parser's.
//
// Usage: node scripts/ci/extract-recipe.mjs <guide.md> <out-dir>
// Writes <out-dir>/quick-start.yml (the edited block) and step-1.sh,
// step-2.sh, step-3.sh (the `run:` scripts, in order). Exit 0 written,
// 1 refused (nothing written), 2 usage or read error.

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';

export const DOCUMENTED_CLI = 'npx opena2a-cli';
export const OWN_BUILD_CLI = 'node packages/cli/dist/index.js';

const RUNNER_TEMP = '${{ runner.temp }}';
const STEP_KEYS = new Set(['name', 'uses', 'with', 'run', 'working-directory']);
const KEY_LINE = /^([A-Za-z][A-Za-z0-9_-]*):(?: (.*))?$/;

export class RecipeError extends Error {}

const indentOf = (line) => line.length - line.trimStart().length;

/** The text of the guide's Quick Start ```yaml block, by offset, byte for byte. */
function quickStartBlock(markdown) {
  const lines = markdown.split('\n');
  const heading = lines.findIndex((l) => /^## Quick Start\b/.test(l));
  if (heading === -1) throw new RecipeError('the guide has no "## Quick Start" heading');
  let open = -1;
  for (let i = heading + 1; i < lines.length; i++) {
    if (/^## /.test(lines[i])) break;
    if (lines[i] === '```yaml') {
      open = i;
      break;
    }
  }
  if (open === -1) throw new RecipeError('the Quick Start section holds no ```yaml block');
  const close = lines.findIndex((l, i) => i > open && l === '```');
  if (close === -1) throw new RecipeError('the Quick Start ```yaml block is not closed');
  const offset = (index) => lines.slice(0, index).reduce((sum, l) => sum + l.length + 1, 0);
  return markdown.slice(offset(open + 1), offset(close));
}

function plainScalar(raw, lineNo) {
  const value = raw.replace(/ +$/, '');
  if (value === '') throw new RecipeError(`line ${lineNo}: empty value`);
  if (/^[-?:,[\]{}#&*!|>'"%@`]/.test(value)) {
    throw new RecipeError(`line ${lineNo}: a quoted or indicator-led value is not read by this extractor: ${value}`);
  }
  if (value.includes(' #')) {
    throw new RecipeError(`line ${lineNo}: " #" starts a comment in a plain value, so YAML would cut the script there`);
  }
  if (value.includes(': ')) throw new RecipeError(`line ${lineNo}: ": " inside a plain value is not read by this extractor`);
  return value;
}

/** The index of the next line holding anything but spaces, or -1. */
function nextContent(lines, from) {
  for (let j = from; j < lines.length; j++) if (lines[j].trim() !== '') return j;
  return -1;
}

/**
 * Reads one `key: value` entry of a step whose key starts at column keyCol.
 * Returns the index of the first line after the entry.
 */
function readEntry(lines, i, keyCol, text, step) {
  const lineNo = i + 1;
  const m = KEY_LINE.exec(text);
  if (!m) throw new RecipeError(`line ${lineNo}: not a "key: value" line: ${text}`);
  const [, key, raw = ''] = m;
  if (Object.hasOwn(step.entries, key)) throw new RecipeError(`line ${lineNo}: "${key}" is given twice`);

  if (raw === '') {
    // A nested mapping of plain values (`with:`).
    const child = {};
    let j = i + 1;
    for (; j < lines.length; j++) {
      const t = lines[j].trim();
      if (t === '') continue;
      const ind = indentOf(lines[j]);
      if (ind <= keyCol) break;
      if (ind !== keyCol + 2 || t.startsWith('#')) throw new RecipeError(`line ${j + 1}: not read inside "${key}:"`);
      const cm = /^([A-Za-z][A-Za-z0-9_-]*): (.+)$/.exec(t);
      if (!cm) throw new RecipeError(`line ${j + 1}: not a "key: value" line inside "${key}:"`);
      child[cm[1]] = plainScalar(cm[2], j + 1);
    }
    step.entries[key] = child;
    return j;
  }

  if (raw === '|') {
    // A literal block scalar with clip chomping: the indentation of its first
    // line is removed from every line, and it ends in exactly one newline.
    const content = [];
    let indent = -1;
    let j = i + 1;
    for (; j < lines.length; j++) {
      const line = lines[j];
      if (line.trim() === '') {
        if (line !== '') throw new RecipeError(`line ${j + 1}: a script line holding only spaces is not read by this extractor`);
        content.push('');
        continue;
      }
      const ind = indentOf(line);
      if (indent === -1) {
        if (ind <= keyCol) break;
        indent = ind;
      }
      if (ind < indent) break;
      content.push(line.slice(indent));
    }
    while (content.length > 0 && content[content.length - 1] === '') content.pop();
    if (content.length === 0) throw new RecipeError(`line ${lineNo}: "${key}: |" holds no script`);
    step.entries[key] = content.join('\n') + '\n';
    step.literal[key] = indent;
    return j;
  }

  if (/^[|>]/.test(raw)) {
    throw new RecipeError(`line ${lineNo}: the block style "${key}: ${raw}" is not read by this extractor; use "${key}: |"`);
  }
  step.entries[key] = plainScalar(raw, lineNo);
  const next = nextContent(lines, i + 1);
  if (next !== -1 && indentOf(lines[next]) > keyCol && !lines[next].trim().startsWith('#')) {
    throw new RecipeError(`line ${lineNo}: a value continued on the next line is not read by this extractor`);
  }
  return i + 1;
}

/** The items of the block's `steps:` list, in order. */
function readSteps(block) {
  if (block.includes('\t')) throw new RecipeError('the block holds a tab character');
  const lines = block.split('\n');
  const at = lines.findIndex((l) => /^ +steps:$/.test(l));
  if (at === -1) throw new RecipeError('the block has no "steps:" list');
  const listCol = indentOf(lines[at]);
  const steps = [];
  let itemCol = -1;
  let i = at + 1;
  while (i < lines.length) {
    const line = lines[i];
    const t = line.trim();
    if (t === '' || t.startsWith('#')) {
      i++;
      continue;
    }
    const ind = indentOf(line);
    if (ind <= listCol) break;
    if (t.startsWith('- ')) {
      if (itemCol === -1) itemCol = ind;
      if (ind !== itemCol) throw new RecipeError(`line ${i + 1}: a step at an unexpected indentation`);
      const step = { entries: {}, literal: {} };
      steps.push(step);
      i = readEntry(lines, i, ind + 2, line.slice(ind + 2), step);
      continue;
    }
    if (steps.length === 0 || ind !== itemCol + 2) throw new RecipeError(`line ${i + 1}: not read as part of a step`);
    i = readEntry(lines, i, ind, t, steps[steps.length - 1]);
  }
  return steps;
}

const count = (text, needle) => text.split(needle).length - 1;
const reverse = (text) => text.split(OWN_BUILD_CLI).join(DOCUMENTED_CLI);

/**
 * The guide's Quick Start, edited to run this repository's build.
 * Throws RecipeError for a guide it cannot reproduce exactly.
 */
export function extractQuickStart(markdown) {
  const docBlock = quickStartBlock(markdown);
  if (docBlock.includes(OWN_BUILD_CLI)) {
    throw new RecipeError(`the documented block already contains "${OWN_BUILD_CLI}", so the edit could not be reversed`);
  }
  const substitutions = count(docBlock, DOCUMENTED_CLI);
  if (substitutions === 0) throw new RecipeError(`the documented block never runs "${DOCUMENTED_CLI}"`);
  const block = docBlock.split(DOCUMENTED_CLI).join(OWN_BUILD_CLI);
  if (reverse(block) !== docBlock) throw new RecipeError('with the edit reversed, the block is not the documented block');

  const read = readSteps(block);
  read.forEach((step, n) => {
    for (const key of Object.keys(step.entries)) {
      if (!STEP_KEYS.has(key)) {
        throw new RecipeError(`step ${n + 1}: "${key}" is not reproduced by the recipe workflow`);
      }
    }
    if (('run' in step.entries) === ('uses' in step.entries)) {
      throw new RecipeError(`step ${n + 1}: has neither or both of "run" and "uses"`);
    }
  });

  const steps = read
    .filter((s) => 'run' in s.entries)
    .map((s) => {
      const run = s.entries.run;
      if (typeof run !== 'string') throw new RecipeError('a "run:" value is not a script');
      if (run.includes('${{')) {
        throw new RecipeError(`a step script holds "\${{", which the runner expands before the shell reads it: ${run.trim()}`);
      }
      const indent = s.literal.run;
      const source =
        indent === undefined
          ? `run: ${run}\n`
          : `run: |\n${run.slice(0, -1).split('\n').map((l) => (l === '' ? '' : ' '.repeat(indent) + l)).join('\n')}\n`;
      if (!docBlock.includes(reverse(source))) {
        throw new RecipeError(`a step script does not map back onto the guide byte for byte: ${run.trim()}`);
      }
      return {
        name: typeof s.entries.name === 'string' ? s.entries.name : null,
        workingDirectory: typeof s.entries['working-directory'] === 'string' ? s.entries['working-directory'] : null,
        run,
      };
    });

  if (steps.length !== 3) throw new RecipeError(`the block has ${steps.length} step scripts; the recipe workflow runs three`);
  steps.forEach((s, n) => {
    const expected = n < 2 ? RUNNER_TEMP : null;
    if (s.workingDirectory !== expected) {
      throw new RecipeError(
        `step script ${n + 1} has working-directory ${s.workingDirectory ?? '(none)'}; the recipe workflow starts it from ${expected ?? 'the workspace'}`,
      );
    }
    const runs = count(s.run, OWN_BUILD_CLI);
    if (runs !== (n < 2 ? 1 : 0)) {
      throw new RecipeError(`step script ${n + 1} runs the CLI ${runs} times; scripts 1 and 2 run it exactly once and script 3 not at all`);
    }
  });

  const setup = read
    .filter((s) => 'uses' in s.entries)
    .map((s) => ({ uses: s.entries.uses, with: typeof s.entries.with === 'object' ? s.entries.with : {} }));

  return { docBlock, block, substitutions, steps, setup };
}

const sha256 = (text) => createHash('sha256').update(text).digest('hex');

export function main(argv) {
  if (argv.length !== 2) {
    process.stderr.write('Usage: node scripts/ci/extract-recipe.mjs <guide.md> <out-dir>\n');
    return 2;
  }
  const [guide, outDir] = argv;
  let markdown;
  try {
    markdown = readFileSync(guide, 'utf8');
  } catch (err) {
    process.stderr.write(`extract-recipe: cannot read ${guide}: ${err.message}\n`);
    return 2;
  }
  let recipe;
  try {
    recipe = extractQuickStart(markdown);
  } catch (err) {
    if (!(err instanceof RecipeError)) throw err;
    process.stderr.write(`extract-recipe: ${guide}: ${err.message}\n`);
    return 1;
  }

  mkdirSync(outDir, { recursive: true });
  const files = [['quick-start.yml', recipe.block], ...recipe.steps.map((s, n) => [`step-${n + 1}.sh`, s.run])];
  for (const [name, text] of files) {
    writeFileSync(join(outDir, name), text);
    if (readFileSync(join(outDir, name), 'utf8') !== text) {
      process.stderr.write(`extract-recipe: ${join(outDir, name)} does not read back as written\n`);
      return 2;
    }
  }

  const out = [
    `Quick Start block of ${guide}: ${Buffer.byteLength(recipe.docBlock)} bytes, sha256 ${sha256(recipe.docBlock)}`,
    `"${DOCUMENTED_CLI}" replaced by "${OWN_BUILD_CLI}" ${recipe.substitutions} times; with that reversed, the block is byte-equal to the guide.`,
    ...recipe.steps.map(
      (s, n) => `step-${n + 1}.sh: ${s.name ?? '(unnamed)'}, from ${s.workingDirectory ?? 'the workspace'}, sha256 ${sha256(s.run)}`,
    ),
    '',
    ...recipe.steps.flatMap((s, n) => [`--- step-${n + 1}.sh`, s.run.replace(/\n$/, '')]),
  ];
  process.stdout.write(out.join('\n') + '\n');
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = main(process.argv.slice(2));
}

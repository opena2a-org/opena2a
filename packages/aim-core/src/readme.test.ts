import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as util from 'util';
import * as ts from 'typescript';
import * as aimCore from './index';
import { AIMCore } from './index';

/**
 * The README is the first code a user runs, so its quick start is checked the way a user
 * meets it: it must type-check against this package, run without throwing, and log the
 * values its `// =>` comments show.
 */

const PKG_DIR = path.resolve(__dirname, '..');
const README = fs.readFileSync(path.join(PKG_DIR, 'README.md'), 'utf-8');

function section(heading: string): string {
  const start = README.indexOf(`\n## ${heading}\n`);
  if (start === -1) throw new Error(`README has no "## ${heading}" section`);
  const next = README.indexOf('\n## ', start + 1);
  return README.slice(start, next === -1 ? undefined : next);
}

function quickStartSnippet(): string {
  const match = section('Quick Start').match(/```typescript\n([\s\S]*?)```/);
  if (!match) throw new Error('README Quick Start has no ```typescript block');
  return match[1];
}

/**
 * The expected output of each console.log line, in source order: the text after `// =>`
 * on that line, or on the line below it, joined with continuation lines that start with
 * `//` and two or more spaces. null for a console.log with no `// =>` comment.
 */
function expectedOutputs(snippet: string): Array<string | null> {
  const lines = snippet.split('\n');
  const out: Array<string | null> = [];
  for (let i = 0; i < lines.length; i++) {
    if (!lines[i].includes('console.log(')) continue;
    const parts: string[] = [];
    let next = i + 1;
    const inline = lines[i].match(/\/\/ => (.*)$/);
    if (inline) {
      parts.push(inline[1]);
    } else if (/^\s*\/\/ => /.test(lines[next] ?? '')) {
      parts.push(lines[next].replace(/^\s*\/\/ => /, ''));
      next++;
    }
    if (parts.length > 0) {
      while (/^\s*\/\/\s{2,}\S/.test(lines[next] ?? '')) {
        parts.push(lines[next].replace(/^\s*\/\//, '').trim());
        next++;
      }
    }
    out.push(parts.length > 0 ? parts.join(' ') : null);
  }
  return out;
}

/** Type errors in the snippet, compiled with this package's tsconfig against src/index.ts */
function typeErrors(snippet: string): string[] {
  const snippetPath = path.join(PKG_DIR, 'src', 'readme-quickstart.virtual.ts');
  const { config } = ts.readConfigFile(path.join(PKG_DIR, 'tsconfig.json'), ts.sys.readFile);
  const { options } = ts.parseJsonConfigFileContent(config, ts.sys, PKG_DIR);
  options.noEmit = true;
  options.paths = { '@opena2a/aim-core': [path.join(PKG_DIR, 'src', 'index.ts')] };

  const host = ts.createCompilerHost(options);
  const isSnippet = (fileName: string) => path.resolve(fileName) === snippetPath;
  const getSourceFile = host.getSourceFile.bind(host);
  const fileExists = host.fileExists.bind(host);
  const readFile = host.readFile.bind(host);
  host.getSourceFile = (fileName, languageVersion, ...rest) =>
    isSnippet(fileName)
      ? ts.createSourceFile(fileName, snippet, languageVersion, true)
      : getSourceFile(fileName, languageVersion, ...rest);
  host.fileExists = (fileName) => isSnippet(fileName) || fileExists(fileName);
  host.readFile = (fileName) => (isSnippet(fileName) ? snippet : readFile(fileName));

  const program = ts.createProgram([snippetPath], options, host);
  const diagnostics = [
    ...program.getOptionsDiagnostics(),
    ...ts.getPreEmitDiagnostics(program, program.getSourceFile(snippetPath)),
  ];
  return diagnostics.map((d) => {
    const message = ts.flattenDiagnosticMessageText(d.messageText, '\n');
    if (!d.file || d.start === undefined) return message;
    const { line } = d.file.getLineAndCharacterOfPosition(d.start);
    return `snippet line ${line + 1}: ${message}`;
  });
}

/**
 * Run the snippet as CommonJS with `@opena2a/aim-core` bound to this package, inside an async
 * function so a top-level `await` runs as it would in an ES module; returns what it logged.
 */
async function run(snippet: string): Promise<unknown[]> {
  const js = ts.transpileModule(snippet, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const logged: unknown[] = [];
  const fakeRequire = (id: string) => {
    if (id === '@opena2a/aim-core') return aimCore;
    throw new Error(`README snippet requires ${id}, which this test does not provide`);
  };
  const fakeConsole = { log: (...args: unknown[]) => logged.push(args.length === 1 ? args[0] : args) };
  const AsyncFunction = Object.getPrototypeOf(async () => {}).constructor as FunctionConstructor;
  await new AsyncFunction('require', 'exports', 'console', js)(fakeRequire, {}, fakeConsole);
  return logged;
}

describe('README quick start', () => {
  const snippet = quickStartSnippet();
  let home: string;
  let savedHome: string | undefined;

  beforeAll(() => {
    // The snippet uses the default data directory, which is derived from HOME
    savedHome = process.env.HOME;
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'aim-core-readme-'));
    process.env.HOME = home;
  });

  afterAll(() => {
    if (savedHome === undefined) delete process.env.HOME;
    else process.env.HOME = savedHome;
    fs.rmSync(home, { recursive: true, force: true });
  });

  it('type-checks against the package', () => {
    expect(typeErrors(snippet)).toEqual([]);
  }, 30_000);

  it('runs and logs the values its // => comments show', async () => {
    const logged = await run(snippet);
    const expected = expectedOutputs(snippet);
    const normalize = (text: string) => text.replace(/\s+/g, ' ').trim();

    expect(logged).toHaveLength(expected.length);
    expect(expected.filter((e) => e !== null).length).toBeGreaterThan(0);
    expected.forEach((text, i) => {
      if (text === null) return;
      // util.inspect is how console.log renders a value, quotes on strings included
      const shown = normalize(util.inspect(logged[i], { breakLength: Infinity }));
      expect(shown, `console.log #${i + 1}`).toBe(normalize(text));
    });
  });

  it('writes its identity, audit log and policy to the default data directory', () => {
    const dataDir = path.join(home, '.opena2a', 'aim-core');
    for (const file of ['identity.json', 'audit.jsonl', 'policy.yaml']) {
      expect(fs.existsSync(path.join(dataDir, file)), file).toBe(true);
    }
  });
});

describe('README API table', () => {
  it('lists AIMCore methods with the parameters they take', () => {
    const rows = [...section('API').matchAll(/^\| `(\w+)\(([^)]*)\)` \|/gm)];
    expect(rows.length).toBeGreaterThan(0);
    for (const [, name, params] of rows) {
      const method = (AIMCore.prototype as unknown as Record<string, unknown>)[name];
      expect(typeof method, `AIMCore.prototype.${name}`).toBe('function');
      const declared = params.trim() === '' ? 0 : params.split(',').length;
      expect((method as (...args: unknown[]) => unknown).length, `${name}(${params})`).toBe(declared);
    }
  });
});

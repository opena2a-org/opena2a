/**
 * The programs a shell command line names.
 *
 * In hook mode `shield evaluate` is handed one command line: the zsh preexec
 * hook passes the line as typed, the bash DEBUG trap passes $BASH_COMMAND.
 * programsOnLine() lists the programs the line names in the places below, so
 * that each one can be evaluated against the policy:
 *
 *  - The line is split at unquoted `;`, `&&`, `||`, `|`, `&`, newlines and
 *    subshell parentheses, and a case statement into its items. Quotes and
 *    backslashes are removed from each word as the shell removes them. A
 *    redirection and its file are not words of the command; a here-document
 *    body, a case pattern and a glob group are data.
 *  - In each part, the reserved words that open or close a compound command
 *    (`!`, `{`, `if`, `then`, `do`, `fi`, ...) and leading NAME=value
 *    assignments are set aside, and the first word left is a program. When
 *    it is one of the wrappers env, command, exec, nohup, nice, time,
 *    timeout, sudo and xargs, the wrapper's options (and timeout's duration)
 *    and any assignments after them are set aside too, and the next word is
 *    a program as well, unless an option means the wrapper starts none
 *    (`command -v` looks the name up).
 *  - A program is listed by its basename and, when written as a path, by
 *    the path as written as well.
 *  - The commands inside `$(...)`, backticks, `<(...)` and `>(...)`, the
 *    string bash, sh, zsh or dash is given with -c, and the string env is
 *    given with -S are read the same way, wherever they sit on the line.
 *
 * Not every program a line can start is listed; those not seen include the
 * following. A program reached through an alias or a function: the line
 * names it only by another word. A program whose name the shell builds from
 * a variable, a glob or brace pattern, or a command substitution's output:
 * the word is listed after quote removal, not expanded (`$X`, `aw?`,
 * `{aws,}`, `$(echo aws)`). A program started by eval, by zsh's noglob,
 * nocorrect or `-` precommand modifiers, by a wrapper other than the nine
 * above (find -exec, watch, su -c), by a shell other than those four, by a
 * shell that reads its commands from standard input (a here-document, a
 * here-string, a pipe), or by bash's named coproc (`coproc NAME { ...; }`):
 * only the word in the program's place is listed (eval, noglob, find, ksh,
 * bash, NAME).
 */

import * as path from 'node:path';

/**
 * Nesting depth (command substitutions, -c strings) read word by word.
 * Deeper text is listed whole: every word in it is listed as a program.
 */
const MAX_DEPTH = 8;

/** A word of the line. */
interface Word {
  /** As written: quotes, backslashes and substitutions included. */
  raw: string;
  /** After quote removal. Substitutions are left as written. */
  text: string;
  /** The command lines this word runs: `$(...)`, backticks, `<(...)`, `>(...)`. */
  commands: string[];
  /** Text this word holds that is not a command but can hold one: `$((...))`, `name=(...)`. */
  expressions: string[];
  /**
   * A redirection's file, a here-document body, a case pattern or an
   * arithmetic command: never a program, an option or an operand.
   */
  inert: boolean;
}

/** Unquoted characters that end a word. */
const WORD_END = new Set([' ', '\t', '\n', ';', '&', '|', '<', '>', '(', ')']);

/** A redirection operator, bash's and zsh's forms. */
const REDIRECTION = /<<<|<<-|<<|<>|<&|<|&>>?[|!]?|>>?&?[|!]?/y;

/** The file descriptor written before a redirection operator: `2>`, `{fd}>`. */
const DESCRIPTOR = /(?:\d+|\{[A-Za-z_][A-Za-z0-9_]*\})(?=[<>])/y;

/** A word that assigns a variable: NAME=, NAME+=, NAME[index]=. */
const ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\+?=/;

/**
 * Reserved words at the start of a part. A command can follow the ones that
 * open a compound command; the ones that close it end the part. Neither kind
 * is a program.
 */
const RESERVED_WORDS = new Set([
  '!', '{', '}', 'if', 'then', 'elif', 'else', 'fi', 'while', 'until', 'do', 'done', 'esac', 'coproc',
]);

/** Words after which a `(` still opens a subshell: reserved words, and bash's `time -p`. */
const SUBSHELL_PREFIXES = new Set([...RESERVED_WORDS, 'time', '-p']);

/** Reserved words that open a part holding no command of its own. */
const NO_COMMAND_WORDS = new Set(['case', 'for', 'select', 'function', '[[']);

interface Wrapper {
  /** Short options that take an argument, attached or as the next word. */
  short: string;
  /** Short options that take an argument only when it is attached (`-i{}`). */
  attached?: string;
  /** Long options that take the next word as their argument when written without `=`. */
  long?: readonly string[];
  /** Long options with no argument whose name begins the name of one that takes one. */
  flags?: readonly string[];
  /** Words after the options that come before the program: timeout's duration. */
  operands?: number;
  /** The option whose argument holds the command itself: env -S, --split-string. */
  split?: { short: string; long: string };
  /** A lone `-` is an option (env reads it as -i). */
  dash?: boolean;
  /**
   * Options with which the wrapper starts no program: command -v and -V
   * look the name up, sudo -l lists it, sudo -e edits files.
   */
  withoutRunning?: { short: string; long?: readonly string[] };
}

/** The wrappers whose options are set aside to reach the program they start. */
const WRAPPERS = new Map<string, Wrapper>([
  ['command', { short: '', withoutRunning: { short: 'vV' } }],
  [
    'env',
    {
      short: 'CLPSUu',
      long: ['--chdir', '--split-string', '--unset'],
      split: { short: 'S', long: '--split-string' },
      dash: true,
    },
  ],
  ['exec', { short: 'a' }],
  ['nice', { short: 'n', long: ['--adjustment'] }],
  ['nohup', { short: '' }],
  [
    'sudo',
    {
      short: 'aCcDgpRrTtUu',
      attached: 'h',
      long: [
        '--auth-type', '--chdir', '--chroot', '--close-from', '--command-timeout', '--group',
        '--host', '--login-class', '--other-user', '--prompt', '--role', '--type', '--user',
      ],
      flags: ['--login'],
      withoutRunning: { short: 'el', long: ['--edit', '--list'] },
    },
  ],
  ['time', { short: 'fo', long: ['--format', '--output'] }],
  ['timeout', { short: 'ks', long: ['--kill-after', '--signal'], operands: 1 }],
  [
    'xargs',
    {
      short: 'adEIJLnPRSs',
      attached: 'eil',
      long: ['--arg-file', '--delimiter', '--max-args', '--max-chars', '--max-procs', '--process-slot-var'],
    },
  ],
]);

/** The shells whose -c string is read as a command line. */
const SHELLS = new Set(['bash', 'dash', 'sh', 'zsh']);

/** Shell options that take the next word as their argument. */
const SHELL_SHORT_WITH_ARGUMENT = 'oO';
const SHELL_LONG_WITH_ARGUMENT = ['--emulate', '--init-file', '--rcfile'];

/** Single-character escapes of a `$'...'` string. */
const ANSI_C_ESCAPES = new Map([
  ['a', '\x07'], ['b', '\b'], ['e', '\x1b'], ['E', '\x1b'], ['f', '\f'], ['n', '\n'],
  ['r', '\r'], ['t', '\t'], ['v', '\v'], ['\\', '\\'], ["'", "'"], ['"', '"'], ['?', '?'],
]);

/**
 * The programs `line` names in the places the comment at the top of this
 * file lists, in the order the line names them, each once. A program written
 * as a path is listed by its basename, then by the path.
 */
export function programsOnLine(line: string): string[] {
  const programs: string[] = [];
  const seen = new Set<string>();
  read(line, 0, true, (name) => {
    if (!seen.has(name)) {
      seen.add(name);
      programs.push(name);
    }
  });
  return programs;
}

/**
 * List the programs of `line`, a command line, or only those of the command
 * lines it holds when `withPrograms` is false (an arithmetic expression, an
 * array's elements).
 */
function read(line: string, depth: number, withPrograms: boolean, list: (name: string) => void): void {
  if (depth > MAX_DEPTH) {
    for (const token of line.split(/[\s;&|()<>`$"'\\{}]+/)) {
      if (token !== '') listProgram(token, list);
    }
    return;
  }
  for (const words of parse(line)) {
    const plan = withPrograms ? planOf(words.filter((word) => !word.inert)) : undefined;
    for (const word of words) {
      if (plan?.programs.has(word)) listProgram(word.text, list);
      const commandString = plan?.commandStrings.get(word);
      if (commandString !== undefined) read(commandString, depth + 1, true, list);
      // A command string holds this word's substitutions as written, so they
      // are read once, through it.
      if (plan?.covered.has(word)) continue;
      for (const command of word.commands) read(command, depth + 1, true, list);
      for (const expression of word.expressions) read(expression, depth + 1, false, list);
    }
  }
}

/** zsh replaces a word `=name` with the path of the program `name`. */
function programPath(text: string): string {
  return text.length > 1 && text.startsWith('=') ? text.slice(1) : text;
}

function listProgram(text: string, list: (name: string) => void): void {
  const program = programPath(text);
  const base = path.posix.basename(program);
  if (base !== '') list(base);
  if (program.includes('/') && program !== base) list(program);
}

// ---------------------------------------------------------------------------
// Which words of a part are programs
// ---------------------------------------------------------------------------

interface Plan {
  /** The words that name a program. */
  programs: Set<Word>;
  /** A word holding a command line of its own, and that line: a -c string, an env -S string. */
  commandStrings: Map<Word, string>;
  /** The words whose text is part of a command string. */
  covered: Set<Word>;
}

/** The programs of one part of the line, given its words that are not inert. */
function planOf(words: Word[]): Plan {
  const plan: Plan = { programs: new Set(), commandStrings: new Map(), covered: new Set() };
  let i = 0;
  while (i < words.length && RESERVED_WORDS.has(words[i].raw)) i += 1;
  if (i < words.length && NO_COMMAND_WORDS.has(words[i].raw)) return plan;

  while (i < words.length) {
    while (i < words.length && ASSIGNMENT.test(words[i].raw)) i += 1;
    if (i >= words.length) break;

    const word = words[i];
    plan.programs.add(word);
    const name = path.posix.basename(programPath(word.text));
    const wrapper = WRAPPERS.get(name);
    if (wrapper === undefined) {
      if (SHELLS.has(name)) {
        const commandWord = shellCommandWord(words, i + 1);
        if (commandWord !== undefined) {
          plan.commandStrings.set(commandWord, commandWord.text);
          plan.covered.add(commandWord);
        }
      }
      break;
    }

    const after = skipOptions(words, i + 1, wrapper);
    if (after.split !== undefined) {
      // env -S splits its argument into the words that follow env's options:
      // read it as the rest of an env command.
      const rest = words.slice(after.next);
      plan.commandStrings.set(
        after.split.word,
        ['env', after.split.text, ...rest.map((word) => word.raw)].join(' '),
      );
      plan.covered.add(after.split.word);
      for (const word of rest) plan.covered.add(word);
      break;
    }
    if (!after.runs) break;
    i = after.next;
  }
  return plan;
}

/**
 * The index of the first word after a wrapper's options (and its operands),
 * whether the wrapper runs that word as a program, or the word holding env's
 * -S string.
 */
function skipOptions(
  words: Word[],
  start: number,
  wrapper: Wrapper,
): { next: number; runs: boolean; split?: { word: Word; text: string } } {
  let runs = true;
  // The argument of env -S: attached to the option word, or the next word.
  const splitAt = (word: Word, attached: string | null, next: number) =>
    attached !== null
      ? { next, runs, split: { word, text: attached } }
      : next < words.length
        ? { next: next + 1, runs, split: { word: words[next], text: words[next].text } }
        : { next, runs };

  let i = start;
  while (i < words.length) {
    const word = words[i];
    const text = word.text;
    if (text === '--') {
      i += 1;
      break;
    }
    if (text === '-' && wrapper.dash) {
      i += 1;
      continue;
    }
    if (text.length < 2 || text[0] !== '-') break;
    i += 1;

    if (text.startsWith('--')) {
      const equals = text.indexOf('=');
      const name = equals === -1 ? text : text.slice(0, equals);
      if (wrapper.withoutRunning?.long?.includes(name)) runs = false;
      const option = longOptionWithArgument(name, wrapper);
      if (option !== undefined && option === wrapper.split?.long) {
        return splitAt(word, equals === -1 ? null : text.slice(equals + 1), i);
      }
      if (option !== undefined && equals === -1) i += 1;
      continue;
    }

    for (let k = 1; k < text.length; k += 1) {
      const option = text[k];
      const attached = k < text.length - 1 ? text.slice(k + 1) : null;
      if (wrapper.withoutRunning?.short.includes(option)) runs = false;
      if (option === wrapper.split?.short) return splitAt(word, attached, i);
      if (wrapper.short.includes(option)) {
        if (attached === null) i += 1;
        break;
      }
      if (wrapper.attached?.includes(option)) break;
    }
  }
  return { next: Math.min(i + (wrapper.operands ?? 0), words.length), runs };
}

/**
 * The argument-taking long option `name` names, written whole or as the
 * unambiguous abbreviation getopt_long accepts; undefined for any other.
 */
function longOptionWithArgument(name: string, wrapper: Wrapper): string | undefined {
  const long = wrapper.long ?? [];
  if (long.includes(name)) return name;
  if (name.length < 3 || wrapper.flags?.includes(name)) return undefined;
  return long.find((option) => option.startsWith(name));
}

/** The word a shell reads as its command line: the first operand after -c. */
function shellCommandWord(words: Word[], start: number): Word | undefined {
  let readsString = false;
  let i = start;
  while (i < words.length) {
    const text = words[i].text;
    if (text === '-' || text === '--') {
      i += 1;
      break;
    }
    if (text.startsWith('--')) {
      i += SHELL_LONG_WITH_ARGUMENT.includes(text) ? 2 : 1;
      continue;
    }
    if (text.length < 2 || (text[0] !== '-' && text[0] !== '+')) break;
    i += 1;
    for (let k = 1; k < text.length; k += 1) {
      if (text[k] === 'c') readsString = true;
      if (SHELL_SHORT_WITH_ARGUMENT.includes(text[k])) {
        if (k === text.length - 1) i += 1;
        break;
      }
    }
  }
  return readsString && i < words.length ? words[i] : undefined;
}

// ---------------------------------------------------------------------------
// Words and parts
// ---------------------------------------------------------------------------

interface HereDocument {
  delimiter: string;
  /** `<<-` removes leading tabs from each line, the delimiter's included. */
  stripTabs: boolean;
  /** An unquoted delimiter: substitutions in the body run. */
  expands: boolean;
}

function newWord(): Word {
  return { raw: '', text: '', commands: [], expressions: [], inert: false };
}

/** An open subshell, or a case statement and the part of it being read. */
type Frame = { kind: 'group' } | CaseFrame;
interface CaseFrame {
  kind: 'case';
  /** The word after `case`, the `in`, the patterns before `)`, or an item's commands. */
  at: 'subject' | 'in' | 'patterns' | 'body';
}

/** The parts of `src`, each the list of its words, in line order. */
function parse(src: string): Word[][] {
  const parts: Word[][] = [];
  let words: Word[] = [];
  let hereDocuments: HereDocument[] = [];
  const frames: Frame[] = [];
  // True while the part holds only reserved words: the next word is where a
  // command starts.
  let commandStart = true;
  const endPart = () => {
    if (words.length > 0) parts.push(words);
    words = [];
    commandStart = true;
  };
  const push = (word: Word) => {
    words.push(word);
    commandStart = commandStart && SUBSHELL_PREFIXES.has(word.raw);
  };
  const atCommandStart = () => commandStart;

  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const top = frames[frames.length - 1];
    const inCase = top?.kind === 'case' ? top : undefined;
    if (c === ' ' || c === '\t') {
      i += 1;
      continue;
    }
    if (c === '\\' && src[i + 1] === '\n') {
      i += 2;
      continue;
    }
    if (c === '\n') {
      if (inCase?.at !== 'patterns') endPart();
      i += 1;
      // Here-document bodies start on the line after their operators.
      for (const document of hereDocuments) {
        const body = readHereDocument(src, i, document);
        if (document.expands) {
          const holder = newWord();
          holder.inert = true;
          readExpanding(body.text, 0, holder, null);
          parts.push([holder]);
        }
        i = body.end;
      }
      hereDocuments = [];
      continue;
    }

    if (inCase?.at === 'patterns') {
      // A case item's patterns, up to its `)`: an optional `(` first, `|`
      // between alternatives. `esac` in their place ends the statement.
      if (c === ')') {
        for (const word of words) word.inert = true;
        endPart();
        inCase.at = 'body';
        i += 1;
        continue;
      }
      if (WORD_END.has(c)) {
        i += 1;
        continue;
      }
      const read = readWord(src, i, false);
      i = read.end;
      if (words.length === 0 && read.word.raw === 'esac') {
        frames.pop();
        parts.push([read.word]);
        continue;
      }
      push(read.word);
      continue;
    }

    if (c === ';') {
      // ;; ;& ;;& and zsh's ;| end a case item.
      const next = src[i + 1];
      if (inCase?.at === 'body' && (next === ';' || next === '&' || next === '|')) {
        endPart();
        inCase.at = 'patterns';
        i += next === ';' && src[i + 2] === '&' ? 3 : 2;
        continue;
      }
      endPart();
      i += 1;
      continue;
    }
    if (c === '|' || (c === '&' && src[i + 1] !== '>')) {
      endPart();
      i += 1;
      continue;
    }
    if (c === '(') {
      if (!atCommandStart()) {
        // Inside a command a parenthesis is part of a word: a zsh glob, a
        // bash extglob, the () of a function definition.
        const read = readWord(src, i, true);
        push(read.word);
        i = read.end;
        continue;
      }
      const inner = src[i + 1] === '(' ? closingParenthesis(src, i + 2) : -1;
      if (inner !== -1 && src[inner + 1] === ')') {
        // (( ... )): an arithmetic command.
        const holder = newWord();
        holder.inert = true;
        holder.expressions.push(src.slice(i + 2, inner));
        push(holder);
        i = inner + 2;
        continue;
      }
      frames.push({ kind: 'group' });
      endPart();
      i += 1;
      continue;
    }
    if (c === ')') {
      if (top?.kind === 'group') frames.pop();
      endPart();
      i += 1;
      continue;
    }
    if ((c === '<' || c === '>') && src[i + 1] === '(') {
      const read = readWord(src, i, false);
      push(read.word);
      i = read.end;
      continue;
    }

    DESCRIPTOR.lastIndex = i;
    if (DESCRIPTOR.test(src)) {
      i = DESCRIPTOR.lastIndex;
      continue;
    }

    REDIRECTION.lastIndex = i;
    if (REDIRECTION.test(src)) {
      const operator = src.slice(i, REDIRECTION.lastIndex);
      i = REDIRECTION.lastIndex;
      while (src[i] === ' ' || src[i] === '\t' || (src[i] === '\\' && src[i + 1] === '\n')) {
        i += src[i] === '\\' ? 2 : 1;
      }
      const processSubstitution = (src[i] === '<' || src[i] === '>') && src[i + 1] === '(';
      if (i < src.length && (!WORD_END.has(src[i]) || processSubstitution)) {
        const read = readWord(src, i, false);
        i = read.end;
        read.word.inert = true;
        push(read.word);
        if (operator === '<<' || operator === '<<-') {
          hereDocuments.push({
            delimiter: read.word.text,
            stripTabs: operator === '<<-',
            expands: !/['"\\]/.test(read.word.raw),
          });
        }
      }
      continue;
    }

    const read = readWord(src, i, false);
    i = read.end;
    const word = read.word;
    if (inCase?.at === 'subject') {
      inCase.at = 'in';
    } else if (inCase?.at === 'in') {
      push(word);
      if (word.raw === 'in') {
        endPart();
        inCase.at = 'patterns';
      } else {
        frames.pop();
      }
      continue;
    } else if (inCase?.at === 'body' && word.raw === 'esac' && atCommandStart()) {
      frames.pop();
    } else if (word.raw === 'case' && atCommandStart()) {
      frames.push({ kind: 'case', at: 'subject' });
    }
    push(word);
  }
  endPart();
  return parts;
}

/**
 * Read the word that starts at `start`. With `leadingParenthesis` the word
 * may start with a parenthesis that belongs to it (a glob group).
 */
function readWord(src: string, start: number, leadingParenthesis: boolean): { word: Word; end: number } {
  const word = newWord();
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if ((c === '<' || c === '>') && src[i + 1] === '(' && i === start) {
      // <(...) and >(...): a file name standing for a command's output or input.
      const close = closingParenthesis(src, i + 2);
      const end = close === -1 ? src.length : close + 1;
      word.commands.push(src.slice(i + 2, close === -1 ? src.length : close));
      word.text += src.slice(i, end);
      i = end;
      continue;
    }
    if (c === '(' && (i > start || leadingParenthesis)) {
      // zsh's =(...) runs a command, as <(...) does. Elsewhere a parenthesis
      // in a word holds an array's elements (NAME=(...)), a glob or extglob
      // group, or the () of a function definition: words, not a command.
      const close = closingParenthesis(src, i + 1);
      const end = close === -1 ? src.length : close + 1;
      const inside = src.slice(i + 1, close === -1 ? src.length : close);
      if (src.slice(start, i) === '=') word.commands.push(inside);
      else word.expressions.push(inside);
      word.text += src.slice(i, end);
      i = end;
      continue;
    }
    if (WORD_END.has(c)) break;

    if (c === '\\') {
      if (src[i + 1] !== '\n' && i + 1 < src.length) word.text += src[i + 1];
      i += 2;
      continue;
    }
    if (c === "'") {
      const close = src.indexOf("'", i + 1);
      word.text += src.slice(i + 1, close === -1 ? src.length : close);
      i = close === -1 ? src.length : close + 1;
      continue;
    }
    if (c === '"') {
      i = readExpanding(src, i + 1, word, '"');
      continue;
    }
    if (c === '$' && src[i + 1] === "'") {
      const ansi = readAnsiC(src, i + 2);
      word.text += ansi.text;
      i = ansi.end;
      continue;
    }
    if (c === '$' && src[i + 1] === '"') {
      // $"..." is read as "...".
      i += 1;
      continue;
    }
    if (c === '$' && src[i + 1] === '(') {
      i = readDollarParenthesis(src, i, word);
      continue;
    }
    if (c === '`') {
      i = readBackticks(src, i, word);
      continue;
    }
    word.text += c;
    i += 1;
  }
  word.raw = src.slice(start, i);
  return { word, end: i };
}

/**
 * Read the inside of a double-quoted string (`closing` is `"`) or a whole
 * here-document body (`closing` is null), where only substitutions and a
 * backslash before `$`, a backtick, `\` or the closing quote are special.
 * Returns the index after the closing quote.
 */
function readExpanding(src: string, start: number, word: Word, closing: '"' | null): number {
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === closing) return i + 1;
    if (c === '\\') {
      const next = src[i + 1];
      if (next === '\n') {
        i += 2;
        continue;
      }
      if (next === '$' || next === '`' || next === '\\' || (closing !== null && next === closing)) {
        word.text += next;
        i += 2;
        continue;
      }
      word.text += c;
      i += 1;
      continue;
    }
    if (c === '$' && src[i + 1] === '(') {
      i = readDollarParenthesis(src, i, word);
      continue;
    }
    if (c === '`') {
      i = readBackticks(src, i, word);
      continue;
    }
    word.text += c;
    i += 1;
  }
  return src.length;
}

/** Read `$(...)`, a command, or `$((...))`, arithmetic, starting at the `$`. */
function readDollarParenthesis(src: string, at: number, word: Word): number {
  const close = closingParenthesis(src, at + 2);
  const end = close === -1 ? src.length : close + 1;
  const body = src.slice(at + 2, close === -1 ? src.length : close);
  if (body.startsWith('(') && closingParenthesis(body, 1) === body.length - 1) {
    word.expressions.push(body.slice(1, -1));
  } else {
    word.commands.push(body);
  }
  word.text += src.slice(at, end);
  return end;
}

/** Read a backtick substitution starting at the opening backtick. */
function readBackticks(src: string, at: number, word: Word): number {
  let i = at + 1;
  let body = '';
  while (i < src.length && src[i] !== '`') {
    if (src[i] === '\\' && i + 1 < src.length) {
      // Inside backticks a backslash quotes only $, a backtick, \ and a newline.
      const next = src[i + 1];
      if (next === '$' || next === '`' || next === '\\') body += next;
      else if (next !== '\n') body += src[i] + next;
      i += 2;
      continue;
    }
    body += src[i];
    i += 1;
  }
  const end = i < src.length ? i + 1 : src.length;
  word.commands.push(body);
  word.text += src.slice(at, end);
  return end;
}

/**
 * The index of the `)` that closes the parenthesis opened just before
 * `start`, or -1. Quotes, backticks and nested parentheses are skipped.
 */
function closingParenthesis(src: string, start: number): number {
  const open: Array<'(' | '"' | '`'> = ['('];
  let i = start;
  while (i < src.length) {
    const c = src[i];
    const inside = open[open.length - 1];
    if (c === '\\') {
      i += 2;
      continue;
    }
    if (inside === '`') {
      if (c === '`') open.pop();
      i += 1;
      continue;
    }
    if (inside === '"') {
      if (c === '"') open.pop();
      else if (c === '`') open.push('`');
      else if (c === '$' && src[i + 1] === '(') {
        open.push('(');
        i += 1;
      }
      i += 1;
      continue;
    }
    if (c === "'") {
      const close = src.indexOf("'", i + 1);
      if (close === -1) return -1;
      i = close + 1;
      continue;
    }
    if (c === '$' && src[i + 1] === "'") {
      i = readAnsiC(src, i + 2).end;
      continue;
    }
    if (c === '"' || c === '`' || c === '(') {
      open.push(c);
    } else if (c === ')') {
      open.pop();
      if (open.length === 0) return i;
    }
    i += 1;
  }
  return -1;
}

/** Read the body of a `$'...'` string, which starts at `start`. */
function readAnsiC(src: string, start: number): { text: string; end: number } {
  let text = '';
  let i = start;
  while (i < src.length) {
    const c = src[i];
    if (c === "'") return { text, end: i + 1 };
    if (c !== '\\' || i + 1 >= src.length) {
      text += c;
      i += 1;
      continue;
    }
    const escape = src[i + 1];
    const simple = ANSI_C_ESCAPES.get(escape);
    if (simple !== undefined) {
      text += simple;
      i += 2;
      continue;
    }
    const octal = /^[0-7]{1,3}/.exec(src.slice(i + 1, i + 4));
    if (octal) {
      text += String.fromCharCode(parseInt(octal[0], 8) & 0xff);
      i += 1 + octal[0].length;
      continue;
    }
    const digits = escape === 'x' ? 2 : escape === 'u' ? 4 : escape === 'U' ? 8 : 0;
    const hex = digits > 0 ? new RegExp(`^[0-9A-Fa-f]{1,${digits}}`).exec(src.slice(i + 2, i + 2 + digits)) : null;
    if (hex) {
      const code = parseInt(hex[0], 16);
      if (code <= 0x10ffff) text += String.fromCodePoint(code);
      i += 2 + hex[0].length;
      continue;
    }
    if (escape === 'c' && i + 2 < src.length) {
      text += String.fromCharCode(src.charCodeAt(i + 2) & 0x1f);
      i += 3;
      continue;
    }
    text += c + escape;
    i += 2;
  }
  return { text, end: src.length };
}

/** Read a here-document body from `start` to its delimiter line; `end` is after that line. */
function readHereDocument(src: string, start: number, document: HereDocument): { text: string; end: number } {
  let i = start;
  while (i < src.length) {
    const newline = src.indexOf('\n', i);
    const lineEnd = newline === -1 ? src.length : newline;
    const next = newline === -1 ? src.length : newline + 1;
    const line = src.slice(i, lineEnd);
    if ((document.stripTabs ? line.replace(/^\t+/, '') : line) === document.delimiter) {
      return { text: src.slice(start, i), end: next };
    }
    i = next;
  }
  return { text: src.slice(start), end: src.length };
}

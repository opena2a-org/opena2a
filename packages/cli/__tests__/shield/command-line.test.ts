/**
 * programsOnLine() lists every program a shell command line names, in line
 * order, each once: the first word of each part of the line after leading
 * assignments, reserved words and redirections, the program each wrapper
 * (env, command, exec, nohup, nice, time, timeout, sudo, xargs) starts after
 * its options, and the programs of the command lines inside `$(...)`,
 * backticks, `<(...)`, `>(...)`, a shell's -c string and env's -S string. A
 * program written as a path is listed by its basename, then by the path.
 *
 * Words that are not programs (arguments, a redirection's file, a
 * here-document body, a quoted separator) are not listed. Every expected list
 * below is exact, order included.
 */
import { describe, it, expect } from 'vitest';
import { programsOnLine } from '../../src/shield/command-line.js';

type Case = [line: string, programs: string[]];

function expectCases(cases: Case[]): void {
  it.each(cases)('%j lists %j', (line, programs) => {
    expect(programsOnLine(line)).toEqual(programs);
  });
}

describe('a program and the path it is written as', () => {
  expectCases([
    ['aws s3 ls', ['aws']],
    ['/usr/bin/aws s3 ls', ['aws', '/usr/bin/aws']],
    ['./aws s3 ls', ['aws', './aws']],
    ['../bin/aws s3 ls', ['aws', '../bin/aws']],
    ['bin/aws s3 ls', ['aws', 'bin/aws']],
    ['~/bin/aws s3 ls', ['aws', '~/bin/aws']],
    ['"/usr/bin/aws" s3 ls', ['aws', '/usr/bin/aws']],
    // zsh replaces =name with the path of the program name.
    ['=aws s3 ls', ['aws']],
    ['/usr/bin/aws s3 ls; aws s3 ls; /usr/bin/aws ec2 x', ['aws', '/usr/bin/aws']],
  ]);
});

describe('the parts of a line', () => {
  expectCases([
    ['true; aws s3 ls', ['true', 'aws']],
    ['true && aws s3 ls', ['true', 'aws']],
    ['true || aws s3 ls', ['true', 'aws']],
    ['echo x | aws s3 ls', ['echo', 'aws']],
    ['echo x |& aws s3 ls', ['echo', 'aws']],
    ['sleep 1 & aws s3 ls', ['sleep', 'aws']],
    ['true\naws s3 ls', ['true', 'aws']],
    ['aws;gcloud&&az||kubectl|terraform&vercel', ['aws', 'gcloud', 'az', 'kubectl', 'terraform', 'vercel']],
    ['(aws s3 ls)', ['aws']],
    ['( cd /tmp && aws s3 ls )', ['cd', 'aws']],
    ['{ aws s3 ls; }', ['aws']],
    ['aws s3 ls; aws ec2 describe-instances', ['aws']],
  ]);
});

describe('quotes and backslashes', () => {
  expectCases([
    ["'aws' s3 ls", ['aws']],
    ['"aws" s3 ls', ['aws']],
    ['a\\ws s3 ls', ['aws']],
    ["$'\\x61ws' s3 ls", ['aws']],
    ["$'aw\\163' s3 ls", ['aws']],
    ['$"aws" s3 ls', ['aws']],
    ['aws \\\n s3 ls', ['aws']],
    ['a\\\nws s3 ls', ['aws']],
    // A quoted or escaped separator is part of a word.
    ["echo 'x; aws s3 ls'", ['echo']],
    ['echo "x && aws s3 ls"', ['echo']],
    ['echo x\\;aws s3 ls', ['echo']],
  ]);
});

describe('assignments', () => {
  expectCases([
    ['AWS_PROFILE=x aws s3 ls', ['aws']],
    ['A=1 B="2 3" aws s3 ls', ['aws']],
    ['FOO=bar', []],
    ['X=$(aws s3 ls)', ['aws']],
    // An array's elements are words, not commands.
    ['tools=(aws gcloud); ls', ['ls']],
    // A quoted name is not an assignment: the shell runs a program of that name.
    ['"FOO=1" aws', ['FOO=1']],
  ]);
});

describe('wrappers and their options', () => {
  expectCases([
    ['env AWS_PROFILE=x aws s3 ls', ['env', 'aws']],
    ['env -i PATH=/bin aws s3 ls', ['env', 'aws']],
    ['env -u HOME aws s3 ls', ['env', 'aws']],
    ['env - aws s3 ls', ['env', 'aws']],
    ["env -S 'aws s3 ls'", ['env', 'aws']],
    ['env -S"FOO=1 aws" s3 ls', ['env', 'aws']],
    ['env --split-string="FOO=1 aws s3 ls"', ['env', 'aws']],
    ['/usr/bin/env aws s3 ls', ['env', '/usr/bin/env', 'aws']],
    ['sudo aws s3 ls', ['sudo', 'aws']],
    ['sudo -u root -E aws s3 ls', ['sudo', 'aws']],
    ['sudo -Eu root aws s3 ls', ['sudo', 'aws']],
    ['sudo -uroot aws s3 ls', ['sudo', 'aws']],
    ['sudo --user root aws s3 ls', ['sudo', 'aws']],
    ['sudo --user=root aws s3 ls', ['sudo', 'aws']],
    ['sudo --us root aws s3 ls', ['sudo', 'aws']],
    // --login takes no argument, though --login-class does.
    ['sudo --login aws s3 ls', ['sudo', 'aws']],
    ['sudo -- aws s3 ls', ['sudo', 'aws']],
    ['command aws s3 ls', ['command', 'aws']],
    ['command -p aws s3 ls', ['command', 'aws']],
    ['exec aws s3 ls', ['exec', 'aws']],
    ['exec -a name aws s3 ls', ['exec', 'aws']],
    ['nohup aws s3 ls', ['nohup', 'aws']],
    ['nice -n 5 aws s3 ls', ['nice', 'aws']],
    ['nice -n5 aws s3 ls', ['nice', 'aws']],
    ['nice -5 aws s3 ls', ['nice', 'aws']],
    ['nice --adjustment=5 aws s3 ls', ['nice', 'aws']],
    ['nice --adjustment 5 aws s3 ls', ['nice', 'aws']],
    ['time aws s3 ls', ['time', 'aws']],
    ['time -p aws s3 ls', ['time', 'aws']],
    ['/usr/bin/time -o out.txt aws s3 ls', ['time', '/usr/bin/time', 'aws']],
    ['timeout 5 aws s3 ls', ['timeout', 'aws']],
    ['timeout -s KILL 5 aws s3 ls', ['timeout', 'aws']],
    ['timeout --signal=KILL 5 aws s3 ls', ['timeout', 'aws']],
    ['timeout -k 1 5 aws s3 ls', ['timeout', 'aws']],
    ['timeout --preserve-status 5 aws s3 ls', ['timeout', 'aws']],
    ['xargs aws', ['xargs', 'aws']],
    ['xargs -0 aws', ['xargs', 'aws']],
    ['xargs -n 1 aws', ['xargs', 'aws']],
    ['xargs -I {} aws {}', ['xargs', 'aws']],
    ['xargs -I{} aws {}', ['xargs', 'aws']],
    ['xargs -i aws', ['xargs', 'aws']],
    ['xargs --max-args 1 aws', ['xargs', 'aws']],
    ['sudo env FOO=1 nice -n 5 timeout 9 aws s3 ls', ['sudo', 'env', 'nice', 'timeout', 'aws']],
  ]);
});

describe('wrapper options that start no program', () => {
  expectCases([
    ['command -v aws', ['command']],
    ['command -V aws', ['command']],
    ['command -pv aws', ['command']],
    ['if command -v aws >/dev/null; then aws s3 ls; fi', ['command', 'aws']],
    ['sudo -l aws', ['sudo']],
    ['sudo --list aws', ['sudo']],
    ['sudo -e /etc/hosts', ['sudo']],
  ]);
});

describe('a shell given -c', () => {
  expectCases([
    ['bash -c "aws s3 ls"', ['bash', 'aws']],
    ["sh -c 'aws s3 ls'", ['sh', 'aws']],
    ['zsh -c aws', ['zsh', 'aws']],
    ['dash -c "true; aws s3 ls"', ['dash', 'true', 'aws']],
    ['bash -lc "aws s3 ls"', ['bash', 'aws']],
    ['bash -o pipefail -c "aws s3 ls"', ['bash', 'aws']],
    ['bash -euo pipefail -c "aws s3 ls"', ['bash', 'aws']],
    ['/bin/bash -c "aws s3 ls"', ['bash', '/bin/bash', 'aws']],
    ['bash -c "bash -c \\"aws s3 ls\\""', ['bash', 'aws']],
    ['sudo sh -c "aws s3 ls"', ['sudo', 'sh', 'aws']],
    // Without -c the operand is a script file, which the line does not show.
    ['bash script.sh', ['bash']],
  ]);
});

describe('substitutions', () => {
  expectCases([
    ['echo $(aws s3 ls)', ['echo', 'aws']],
    ['echo `aws s3 ls`', ['echo', 'aws']],
    ['echo "$(aws s3 ls)"', ['echo', 'aws']],
    ['echo "`aws s3 ls`"', ['echo', 'aws']],
    ['echo $(echo $(aws s3 ls))', ['echo', 'aws']],
    ['diff <(aws s3 ls) list.txt', ['diff', 'aws']],
    ['tee >(aws s3 cp - s3://bucket/key)', ['tee', 'aws']],
    ['ls > $(aws s3 ls)', ['ls', 'aws']],
    ['echo $(( $(aws s3 ls) + 1 ))', ['echo', 'aws']],
    ['echo $((aws); (gcloud))', ['echo', 'aws', 'gcloud']],
    // Single quotes hold no substitution, and arithmetic runs no command.
    ["echo '$(aws s3 ls)'", ['echo']],
    ['echo $((1 + 2))', ['echo']],
    ['echo $(( (1 + 2) * 3 ))', ['echo']],
  ]);
});

describe('redirections', () => {
  expectCases([
    ['> out.txt aws s3 ls', ['aws']],
    ['2>/dev/null aws s3 ls', ['aws']],
    ['aws s3 ls 2>&1 | grep x', ['aws', 'grep']],
    ['aws s3 ls &>/dev/null; gcloud auth list', ['aws', 'gcloud']],
    ['xargs aws < /dev/null', ['xargs', 'aws']],
    // A redirection's file is not a program.
    ['ls > aws', ['ls']],
    ['cat < aws', ['cat']],
    ['cat <<< aws', ['cat']],
  ]);
});

describe('here-documents', () => {
  expectCases([
    ['cat <<EOF\naws s3 ls\nEOF\ngcloud auth list', ['cat', 'gcloud']],
    ['cat <<-EOF\n\taws s3 ls\n\tEOF\ngcloud auth list', ['cat', 'gcloud']],
    ['cat <<EOF; aws s3 ls\nbody\nEOF', ['cat', 'aws']],
    // An unquoted delimiter: a substitution in the body runs.
    ['cat <<EOF\n$(aws s3 ls)\nEOF', ['cat', 'aws']],
    // A quoted delimiter: the body is text.
    ["cat <<'EOF'\n$(aws s3 ls)\nEOF", ['cat']],
  ]);
});

describe('reserved words', () => {
  expectCases([
    ['if aws s3 ls; then gcloud auth list; else az login; fi', ['aws', 'gcloud', 'az']],
    ['while true; do aws s3 ls; done', ['true', 'aws']],
    ['! aws s3 ls', ['aws']],
    ['! (aws s3 ls)', ['aws']],
    ['time (aws s3 ls)', ['time', 'aws']],
    ['coproc aws s3 ls', ['aws']],
    ['for x in a b; do aws s3 ls; done', ['aws']],
    ['[[ -x /usr/bin/aws ]] && aws s3 ls', ['aws']],
    ['(( x > 1 )) && aws s3 ls', ['aws']],
    // An arithmetic command names variables, not programs.
    ['(( aws = 1 ))', []],
  ]);
});

describe('case statements', () => {
  expectCases([
    ['case $x in a) aws s3 ls ;; esac', ['aws']],
    ['case $x in (a) aws s3 ls ;; esac', ['aws']],
    ['case $x in a|b) aws s3 ls ;; esac; gcloud auth list', ['aws', 'gcloud']],
    ['case $x in a) aws s3 ls ;& b) gcloud auth list ;;& c) az login ;; esac', ['aws', 'gcloud', 'az']],
    ['case $x in a) aws s3 ls ;| b) gcloud auth list ;; esac', ['aws', 'gcloud']],
    ['case $x in a) aws s3 ls\nesac\ngcloud auth list', ['aws', 'gcloud']],
    ['case $x in a) case $y in b) aws s3 ls ;; esac ;; esac; gcloud auth list', ['aws', 'gcloud']],
    ['case $(aws s3 ls) in a) ;; esac', ['aws']],
    // A pattern is not a program.
    ['case "$p" in\n  aws) region=us-east-1 ;;\n  gcp|azure) region=x ;;\nesac\nterraform plan', ['terraform']],
    ['case $p in (aws) echo cloud ;; esac', ['echo']],
  ]);
});

describe('parentheses inside a command', () => {
  expectCases([
    // A zsh glob or bash extglob group is a pattern, not a subshell.
    ['ls (aws|gcloud)*', ['ls']],
    ['ls *(.)', ['ls']],
    ['ls !(aws)', ['ls']],
    ['[[ $x =~ (aws|gcloud) ]] && echo y', ['echo']],
    // zsh's =(...) runs its command, as <(...) does.
    ['diff =(aws s3 ls) list.txt', ['diff', 'aws']],
  ]);

  it('a function definition does not run its body', () => {
    expect(programsOnLine('f() { aws s3 ls; }')).not.toContain('aws');
    expect(programsOnLine('function f { aws s3 ls; }')).not.toContain('aws');
  });
});

describe('words that are not programs', () => {
  expectCases([
    ['', []],
    ['   ', []],
    ['ls -la', ['ls']],
    ['echo aws', ['echo']],
    ['echo aws-docs', ['echo']],
    ['which aws', ['which']],
    // The user sudo runs as.
    ['sudo -u aws ls', ['sudo', 'ls']],
  ]);
});

describe('depth and size', () => {
  it('lists every word of text nested deeper than it reads word by word', () => {
    const line = 'echo ' + '$('.repeat(12) + 'aws s3 ls' + ')'.repeat(12);
    const programs = programsOnLine(line);
    expect(programs[0]).toBe('echo');
    expect(programs).toContain('aws');
  });

  it('reads 5,000 nested substitutions without exhausting the stack', () => {
    const line = 'echo ' + '$('.repeat(5000) + 'aws s3 ls' + ')'.repeat(5000);
    expect(programsOnLine(line)).toContain('aws');
  });

  it('reads a 220,000-character line', () => {
    expect(programsOnLine('aws s3 ls; '.repeat(20000))).toEqual(['aws']);
  });

  it('returns a list of names for any line', () => {
    // A fixed-seed generator over the characters the reader treats specially.
    const alphabet = ['a', 'w', 's', ' ', ';', '&', '|', '(', ')', '<', '>', "'", '"', '`', '$', '{', '}', '\\', '\n', '-', '=', '/'];
    let seed = 0x9e3779b9;
    const next = (): number => {
      seed = (Math.imul(seed, 1664525) + 1013904223) >>> 0;
      return seed;
    };
    for (let n = 0; n < 2000; n += 1) {
      let line = '';
      const length = next() % 80;
      for (let k = 0; k < length; k += 1) line += alphabet[next() % alphabet.length];
      const programs = programsOnLine(line);
      expect(Array.isArray(programs)).toBe(true);
      for (const program of programs) expect(typeof program).toBe('string');
      expect(new Set(programs).size).toBe(programs.length);
    }
  });
});

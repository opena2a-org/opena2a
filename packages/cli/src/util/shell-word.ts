/**
 * Render a scanned path as one POSIX shell word, for a command the CLI prints
 * for the user to paste (a Fix, a Verify, a recommendation).
 *
 * The path is a file name the scanned repository chose, so it is untrusted.
 * Inside single quotes sh, bash and zsh expand nothing: `$(...)`, backticks,
 * `;`, spaces and globs stay literal. An embedded `'` is written as `'\''`.
 * A path that begins with `-` gets `./` so the receiving command (`git`,
 * `head`, `sed`) cannot read it as an option. Every path takes this one form,
 * plain names included, so there is no classifier to get wrong.
 */
export function shellWord(p: string): string {
  const word = p.startsWith('-') ? `./${p}` : p;
  return `'${word.replace(/'/g, `'\\''`)}'`;
}

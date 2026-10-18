/**
 * The name the Registry knows an MCP server by: the npm package a package
 * runner (`npx`, `npm exec`, `pnpm dlx`, `bunx`) installs and starts. The key
 * of an `mcpServers` entry is a label the user chose, so looking it up answers
 * for a different package or for none.
 */

/** The parts of an MCP config entry that say how the server is started. */
export interface McpServerLaunch {
  transport?: string;
  command?: unknown;
  args?: unknown;
  url?: unknown;
}

// npm package names: an optional @scope/ prefix, then the name. Paths
// (./server, /opt/server), git and tarball specs (github:user/repo,
// git+https://..., file:...) and GitHub shorthand (user/repo) do not match.
const NPM_PACKAGE_NAME = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;

/** The longest name npm publishes, scope and separator included. */
const NPM_PACKAGE_NAME_MAX_LENGTH = 214;

/**
 * Whether `name` has the form of an npm package name: `name` or
 * `@scope/name`, at most 214 characters, each part starting with a letter or
 * digit and made of ASCII letters, digits, `.`, `_`, `~` and `-`. A string
 * of that form names one directory one or two levels below a node_modules
 * directory and nothing else: a path of either separator kind, a `.` or `..`
 * segment, a drive letter, a control character and a character outside
 * ASCII are not of that form.
 */
export function hasNpmPackageNameForm(name: string): boolean {
  return name.length <= NPM_PACKAGE_NAME_MAX_LENGTH && NPM_PACKAGE_NAME.test(name);
}

/**
 * The npm package of a stdio server started by a package runner, without a
 * version suffix and with its scope; null for a `node <file>` server, any
 * other binary, and a URL (SSE) server.
 */
export function registryNameFor(server: McpServerLaunch): string | null {
  if (server.transport === 'sse' || typeof server.url === 'string') return null;
  if (typeof server.command !== 'string') return null;
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const runnerArgs = packageRunnerArgs(server.command, args);
  if (!runnerArgs) return null;

  for (let i = 0; i < runnerArgs.length; i++) {
    const arg = runnerArgs[i];
    // --package names the package; the argument after it is a binary in it.
    if (arg.startsWith('--package=')) return packageName(arg.slice('--package='.length));
    if (arg === '--package' || arg === '-p') return packageName(runnerArgs[i + 1] ?? '');
    // -c / --call run a shell string, not a package.
    if (arg === '-c' || arg === '--call') return null;
    // -y, --yes, -- and every other runner flag.
    if (arg.startsWith('-')) continue;
    return packageName(arg);
  }
  return null;
}

/** The arguments after the runner's own command word, or null for a command that is not a package runner. */
function packageRunnerArgs(command: string, args: string[]): string[] | null {
  const bin = (command.split(/[\\/]/).pop() ?? '').replace(/\.(cmd|exe)$/i, '').toLowerCase();
  if (bin === 'npx' || bin === 'bunx' || bin === 'pnpx') return args;
  if (bin === 'npm' && (args[0] === 'exec' || args[0] === 'x')) return args.slice(1);
  if (bin === 'pnpm' && args[0] === 'dlx') return args.slice(1);
  return null;
}

/** `pkg@1.2.3` -> `pkg`, `@scope/pkg@latest` -> `@scope/pkg`; null when the rest is not a package name. */
function packageName(spec: string): string | null {
  const versionAt = spec.indexOf('@', spec.startsWith('@') ? 1 : 0);
  const name = versionAt === -1 ? spec : spec.slice(0, versionAt);
  return hasNpmPackageNameForm(name) ? name : null;
}

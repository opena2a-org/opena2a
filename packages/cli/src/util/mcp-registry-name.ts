/**
 * The name the Registry knows an MCP server by: the npm package a package
 * runner (`npx`, `npm exec`, `pnpm dlx`, `bunx`) installs and starts, or the
 * PyPI package `uvx` or `uv tool run` does. The key of an `mcpServers` entry
 * is a label the user chose, so looking it up answers for a different package
 * or for none.
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

/** A string hasNpmPackageNameForm has checked: it has the form of an npm package name. */
export type NpmPackageName = string & { readonly __brand: 'NpmPackageName' };

/**
 * Whether `name` has the form of an npm package name: `name` or
 * `@scope/name`, at most 214 characters, each part starting with a letter or
 * digit and made of ASCII letters, digits, `.`, `_`, `~` and `-`. A string
 * of that form names one directory one or two levels below a node_modules
 * directory and nothing else: a path of either separator kind, a `.` or `..`
 * segment, a drive letter, a control character and a character outside
 * ASCII are not of that form. Where it answers true, `name` is narrowed to
 * NpmPackageName.
 */
export function hasNpmPackageNameForm(name: string): name is NpmPackageName {
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

/** The package index a Registry package name belongs to. */
export type RegistryEcosystem = 'npm' | 'pypi';

/** A package a server's launch command runs, and the index it comes from. */
export interface RegistryPackage {
  name: string;
  ecosystem: RegistryEcosystem;
}

/**
 * The package a stdio server's launch command runs and the index it is
 * fetched from: an npm package for the runners registryNameFor reads, a PyPI
 * package for `uvx` and `uv tool run`. Null when the command names no package
 * either way can read with certainty: a `node <file>` or `python <file>`
 * server, any other binary, a URL (SSE) server, a path, URL or git source,
 * and a runner option this reader does not know, since it may take the next
 * argument as its value.
 */
export function registryPackageFor(server: McpServerLaunch): RegistryPackage | null {
  const npmName = registryNameFor(server);
  if (npmName) return { name: npmName, ecosystem: 'npm' };
  const pypiName = pypiNameFor(server);
  return pypiName ? { name: pypiName, ecosystem: 'pypi' } : null;
}

// uv options that take a value in the next argument (or after `=`). --from is
// read separately: its value is the package.
const UV_VALUE_OPTIONS = new Set([
  '--with', '-w', '--with-editable', '--with-requirements', '--python', '-p',
  '--index', '--default-index', '--index-url', '-i', '--extra-index-url',
  '--find-links', '-f', '--index-strategy', '--keyring-provider',
  '--resolution', '--prerelease', '--exclude-newer', '--link-mode',
  '--refresh-package', '--reinstall-package', '--upgrade-package', '-P',
  '--config-setting', '-C', '--no-build-package', '--no-binary-package',
  '--only-binary-package', '--python-platform', '--directory', '--project',
  '--config-file', '--cache-dir', '--color', '--allow-insecure-host',
  '--env-file', '--constraints', '-c', '--overrides', '--build-constraints', '-b',
  '--torch-backend',
]);

// uv options that take no value.
const UV_FLAG_OPTIONS = new Set([
  '-q', '--quiet', '-v', '--verbose', '-n', '--no-cache', '--isolated',
  '--offline', '--no-progress', '--native-tls', '--no-config',
  '--no-python-downloads', '--managed-python', '--no-managed-python',
  '--upgrade', '-U', '--refresh', '--reinstall', '--no-build', '--no-binary',
  '--no-sources', '--no-index', '--compile-bytecode', '--no-env-file',
  '--lfs', '--preview', '--no-preview',
]);

/**
 * PyPI project names: letters, digits, `.`, `_` and `-`, starting and ending
 * with a letter or digit (PEP 508). Paths, URLs and git sources do not match.
 */
const PYPI_NAME = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/i;

/** The PyPI package `uvx` or `uv tool run` runs, normalized as PyPI does (PEP 503); null otherwise. */
function pypiNameFor(server: McpServerLaunch): string | null {
  if (server.transport === 'sse' || typeof server.url === 'string') return null;
  if (typeof server.command !== 'string') return null;
  const args = Array.isArray(server.args) ? server.args.map(String) : [];
  const bin = (server.command.split(/[\\/]/).pop() ?? '').replace(/\.exe$/i, '').toLowerCase();
  let runnerArgs: string[];
  if (bin === 'uvx') runnerArgs = args;
  else if (bin === 'uv' && args[0] === 'tool' && args[1] === 'run') runnerArgs = args.slice(2);
  else return null;

  for (let i = 0; i < runnerArgs.length; i++) {
    const arg = runnerArgs[i];
    // --from names the package; the argument after it is a command in it.
    if (arg.startsWith('--from=')) return pypiName(arg.slice('--from='.length));
    if (arg === '--from') return pypiName(runnerArgs[i + 1] ?? '');
    if (arg === '--') return pypiName(runnerArgs[i + 1] ?? '');
    if (arg.startsWith('-')) {
      const option = arg.startsWith('--') ? arg.split('=')[0] : arg;
      if (UV_FLAG_OPTIONS.has(arg)) continue;
      if (UV_VALUE_OPTIONS.has(option)) {
        if (option === arg) i++;
        continue;
      }
      // An option this reader does not know may take the next argument.
      return null;
    }
    return pypiName(arg);
  }
  return null;
}

/**
 * `pkg`, `pkg@1.2`, `pkg@latest`, `pkg==1.2`, `pkg>=1`, `pkg[extra]` ->
 * `pkg`, lowercased with each run of `.`, `_` and `-` made one `-`; null
 * when the rest is not a PyPI name (a path, URL or git source).
 */
function pypiName(spec: string): string | null {
  const match = /^([^@=<>!~;\[\s]+)(?:\[[a-z0-9._,\s-]*\])?\s*(?:(?:@|==|>=|<=|!=|~=|===|>|<)\s*[^\s;]*)?$/i.exec(spec);
  if (!match || !PYPI_NAME.test(match[1])) return null;
  return match[1].toLowerCase().replace(/[-_.]+/g, '-');
}

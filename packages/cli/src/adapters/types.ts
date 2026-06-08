export type AdapterMethod = 'import' | 'spawn' | 'docker' | 'python';

export interface AdapterConfig {
  name: string;
  method: AdapterMethod;
  /** npm package name for import() adapters */
  packageName?: string;
  /** CLI command for spawn() adapters */
  command?: string;
  /** Docker image for docker() adapters */
  image?: string;
  /** Python module for python() adapters */
  pythonModule?: string;
  /** Subcommand to prepend to args (e.g. broker/dlp share secretless-ai but differ by subcommand) */
  subcommand?: string;
  /** Port mappings for docker() adapters (e.g. ['3001-3008:3001-3008']) */
  ports?: string[];
  /** Description shown in help text */
  description: string;
  /** Commander aliases for this command (e.g. scan exposes `secure` so HMA's prefix-substituted Next Steps text resolves). */
  aliases?: string[];
  /**
   * Whether the bundled tool accepts a `--format <fmt>` flag for structured
   * output. Default (undefined) = true. Set false for tools that reject it so
   * the router does not inject `--format json` and crash the delegated call.
   */
  acceptsFormatFlag?: boolean;
  /**
   * Flag the bundled tool uses to emit JSON when it does NOT take `--format`
   * (e.g. `ai-trust check` emits JSON via a bare `--json`, issue #191). When
   * set, the router injects this flag for `--json`/`format: 'json'` instead of
   * `--format json`, and surfaces a one-line note for unsupported formats
   * (e.g. sarif). Takes precedence over `acceptsFormatFlag` for json output.
   */
  jsonOutputFlag?: string;
}

export interface RunOptions {
  args: string[];
  verbose?: boolean;
  quiet?: boolean;
  ci?: boolean;
  format?: 'text' | 'json' | 'sarif';
  contribute?: boolean;
  noContribute?: boolean;
  cwd?: string;
  deep?: boolean;
  analm?: boolean;
  staticOnly?: boolean;
  /**
   * Rewrite bundled-tool command citations in the child's stdout to their
   * `opena2a`-prefixed form (issue #190). Applied line-buffered so streaming is
   * preserved. Callers must leave this off in --json mode.
   */
  rebrand?: boolean;
}

export interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface Adapter {
  readonly config: AdapterConfig;
  run(options: RunOptions): Promise<RunResult>;
  isAvailable(): Promise<boolean>;
}

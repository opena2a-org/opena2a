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
}

export interface RunOptions {
  args: string[];
  verbose?: boolean;
  quiet?: boolean;
  ci?: boolean;
  format?: 'text' | 'json' | 'sarif';
  contribute?: boolean;
  cwd?: string;
  deep?: boolean;
  staticOnly?: boolean;
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

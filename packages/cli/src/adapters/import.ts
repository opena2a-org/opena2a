import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';

/**
 * ImportAdapter handles workspace packages that are imported directly.
 * It delegates to the package's programmatic API or CLI entry point.
 */
export class ImportAdapter implements Adapter {
  readonly config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  async run(options: RunOptions): Promise<RunResult> {
    const pkgName = this.config.packageName;
    if (!pkgName) {
      return { exitCode: 1, stdout: '', stderr: `No package configured for ${this.config.name}` };
    }

    try {
      // Dynamic import of the workspace package
      const mod = await import(pkgName);

      // If the module has a CLI entry point, use it
      if (typeof mod.run === 'function') {
        const result = await mod.run(options.args, {
          verbose: options.verbose,
          quiet: options.quiet,
          ci: options.ci,
          format: options.format,
          cwd: options.cwd,
        });
        return {
          exitCode: result?.exitCode ?? 0,
          stdout: result?.stdout ?? '',
          stderr: result?.stderr ?? '',
        };
      }

      // If it has a main function
      if (typeof mod.main === 'function') {
        await mod.main(options.args);
        return { exitCode: 0, stdout: '', stderr: '' };
      }

      // Fallback: spawn the bin command from the package
      const { SpawnAdapter } = await import('./spawn.js');
      const fallback = new SpawnAdapter({
        ...this.config,
        method: 'spawn',
        command: pkgName,
      });
      return fallback.run(options);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      // Package not installed -- try npx fallback
      if (message.includes('Cannot find module') || message.includes('ERR_MODULE_NOT_FOUND')) {
        const { SpawnAdapter } = await import('./spawn.js');
        const fallback = new SpawnAdapter({
          ...this.config,
          method: 'spawn',
          command: `npx ${pkgName}`,
        });
        return fallback.run(options);
      }

      return { exitCode: 1, stdout: '', stderr: `Failed to load ${pkgName}: ${message}` };
    }
  }

  async isAvailable(): Promise<boolean> {
    try {
      await import(this.config.packageName!);
      return true;
    } catch {
      return false;
    }
  }
}

import { resolve, join, dirname } from 'node:path';
import { existsSync } from 'node:fs';
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

      // Fallback: spawn the workspace binary (not the global one)
      const { SpawnAdapter } = await import('./spawn.js');
      const workspaceBin = this.resolveWorkspaceBin(pkgName);
      const fallback = new SpawnAdapter({
        ...this.config,
        method: 'spawn',
        command: workspaceBin ?? pkgName,
      });
      return fallback.run(options);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);

      // Package not installed -- try npx fallback
      if (message.includes('Cannot find module') || message.includes('ERR_MODULE_NOT_FOUND')) {
        const { SpawnAdapter } = await import('./spawn.js');
        // Use npx as bin with package name as first arg (avoid shell injection)
        const fallback = new SpawnAdapter({
          ...this.config,
          method: 'spawn',
          command: 'npx',
        });
        return fallback.run({
          ...options,
          args: [pkgName!, ...options.args],
        });
      }

      return { exitCode: 1, stdout: '', stderr: `Failed to load ${pkgName}: ${message}` };
    }
  }

  /**
   * Resolve the workspace node_modules/.bin binary for a package.
   * This ensures we use the version installed in the workspace, not a stale global.
   */
  private resolveWorkspaceBin(pkgName: string): string | undefined {
    try {
      // Walk up from this file to find the nearest node_modules/.bin
      const thisDir = dirname(__filename);
      let dir = resolve(thisDir);
      for (let i = 0; i < 10; i++) {
        const binPath = join(dir, 'node_modules', '.bin', pkgName);
        if (existsSync(binPath)) return binPath;
        const parent = resolve(dir, '..');
        if (parent === dir) break;
        dir = parent;
      }
    } catch {
      // Fall through
    }
    return undefined;
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

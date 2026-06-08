import { resolve, join, dirname } from 'node:path';
import { existsSync } from 'node:fs';
import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';
import { createLineRebrander } from '../util/rebrand.js';

/**
 * Run `fn` with `process.stdout.write` intercepted so the bundled tool's direct
 * writes are rebranded to opena2a form (issue #191). Import-adapter tools that
 * expose a programmatic `run`/`main` write their Commander help straight to
 * process.stdout, bypassing the streaming rebrander a spawned child gets. We
 * line-buffer through `createLineRebrander` and restore the original writer in
 * `finally` (even on throw) so the patch can never leak past the delegated call.
 *
 * NOTE: the current bundled tools (hackmyagent, secretless-ai) expose no
 * `run`/`main`, so they fall through to the SpawnAdapter path which rebrands
 * natively. This wrapper is defense-in-depth so the fix does not silently
 * regress if a bundled tool later adds a programmatic entry point.
 *
 * CONSTRAINTS:
 *  - NON-REENTRANT: it patches a process-global. If a patch is already active
 *    (nested/overlapping call) we run `fn` WITHOUT re-patching, so the saved
 *    "original" can never be a still-patched writer (which would leak the patch
 *    permanently and double-rebrand all later output).
 *  - NOT for interactive entry points: output is line-buffered, so a no-newline
 *    prompt (`Continue? [y/N] `) is withheld until `fn` resolves. An in-process
 *    tool that prompts then blocks on stdin would deadlock. Only wrap
 *    non-interactive help/scan-style programmatic APIs.
 */
let stdoutPatchActive = false;

export async function withRebrandedStdout<T>(fn: () => Promise<T>): Promise<T> {
  if (stdoutPatchActive) {
    // A rebrand patch is already installed by an outer call; don't double-patch.
    return await fn();
  }
  const original = process.stdout.write.bind(process.stdout);
  const rebrander = createLineRebrander();
  stdoutPatchActive = true;
  // Patch only the string/Buffer signatures; preserve the original return
  // (backpressure boolean) and any encoding/callback arguments.
  process.stdout.write = ((chunk: unknown, ...rest: unknown[]): boolean => {
    if (typeof chunk === 'string') {
      return (original as (c: unknown, ...r: unknown[]) => boolean)(rebrander.push(chunk), ...rest);
    }
    if (Buffer.isBuffer(chunk)) {
      return (original as (c: unknown, ...r: unknown[]) => boolean)(rebrander.push(chunk.toString()), ...rest);
    }
    return (original as (c: unknown, ...r: unknown[]) => boolean)(chunk, ...rest);
  }) as typeof process.stdout.write;
  try {
    return await fn();
  } finally {
    const tail = rebrander.flush();
    if (tail) original(tail);
    process.stdout.write = original;
    stdoutPatchActive = false;
  }
}

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
        const call = () => mod.run(options.args, {
          verbose: options.verbose,
          quiet: options.quiet,
          ci: options.ci,
          format: options.format,
          cwd: options.cwd,
        });
        const result = options.rebrand && !options.quiet
          ? await withRebrandedStdout(call)
          : await call();
        return {
          exitCode: result?.exitCode ?? 0,
          stdout: result?.stdout ?? '',
          stderr: result?.stderr ?? '',
        };
      }

      // If it has a main function
      if (typeof mod.main === 'function') {
        const call = () => mod.main(options.args);
        if (options.rebrand && !options.quiet) {
          await withRebrandedStdout(call);
        } else {
          await call();
        }
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

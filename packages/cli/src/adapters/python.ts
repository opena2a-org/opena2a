import { spawn } from 'node:child_process';
import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';
import { createLineRebrander } from '../util/rebrand.js';

export class PythonAdapter implements Adapter {
  readonly config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  async run(options: RunOptions): Promise<RunResult> {
    const module = this.config.pythonModule;
    if (!module) {
      return { exitCode: 1, stdout: '', stderr: `No Python module configured for ${this.config.name}` };
    }

    // Try python3 -m module first, then pipx run
    const pythonBin = await this.findPython();
    const bin = pythonBin ?? 'pipx';
    const args = pythonBin
      ? ['-m', module, ...options.args]
      : ['run', module, ...options.args];

    return new Promise<RunResult>((resolve) => {
      const child = spawn(bin, args, {
        cwd: options.cwd ?? process.cwd(),
        stdio: ['inherit', 'pipe', 'pipe'],
        env: { ...process.env },
      });

      let stdout = '';
      let stderr = '';
      // Rebrand cryptoserve command citations (Usage lines, `cryptoserve <verb>`)
      // to opena2a form when asked (issue #191). Line-buffered so streaming is
      // preserved; never enabled in JSON mode (the router gates it off).
      const rebrander = options.rebrand ? createLineRebrander() : null;

      child.stdout?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stdout += chunk;
        if (!options.quiet) process.stdout.write(rebrander ? rebrander.push(chunk) : chunk);
      });

      child.stderr?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stderr += chunk;
        if (!options.quiet) process.stderr.write(chunk);
      });

      child.on('error', (err) => {
        if (rebrander && !options.quiet) process.stdout.write(rebrander.flush());
        resolve({ exitCode: 1, stdout, stderr: stderr + err.message });
      });

      child.on('close', (code) => {
        if (rebrander && !options.quiet) process.stdout.write(rebrander.flush());
        resolve({ exitCode: code ?? 1, stdout, stderr });
      });
    });
  }

  async isAvailable(): Promise<boolean> {
    const module = this.config.pythonModule;
    if (!module) return false;

    // Check if the actual Python module is importable, not just if Python exists
    const python = await this.findPython();
    if (!python) return false;

    return new Promise<boolean>((resolve) => {
      const child = spawn(python, ['-c', `import ${module}`], { stdio: 'ignore' });
      child.on('close', (code) => resolve(code === 0));
      child.on('error', () => resolve(false));
    });
  }

  private async findPython(): Promise<string | null> {
    for (const bin of ['python3', 'python']) {
      const exists = await new Promise<boolean>((resolve) => {
        const child = spawn(bin, ['--version'], { stdio: 'ignore' });
        child.on('close', (code) => resolve(code === 0));
        child.on('error', () => resolve(false));
      });
      if (exists) return bin;
    }
    return null;
  }
}

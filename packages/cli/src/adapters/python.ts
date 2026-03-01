import { spawn } from 'node:child_process';
import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';

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

      child.stdout?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stdout += chunk;
        if (!options.quiet) process.stdout.write(chunk);
      });

      child.stderr?.on('data', (data: Buffer) => {
        const chunk = data.toString();
        stderr += chunk;
        if (!options.quiet) process.stderr.write(chunk);
      });

      child.on('error', (err) => {
        resolve({ exitCode: 1, stdout, stderr: stderr + err.message });
      });

      child.on('close', (code) => {
        resolve({ exitCode: code ?? 1, stdout, stderr });
      });
    });
  }

  async isAvailable(): Promise<boolean> {
    const python = await this.findPython();
    if (python) return true;

    return new Promise((resolve) => {
      const child = spawn('pipx', ['--version'], { stdio: 'ignore' });
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

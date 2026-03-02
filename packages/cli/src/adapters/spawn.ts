import { spawn } from 'node:child_process';
import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';

export class SpawnAdapter implements Adapter {
  readonly config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  async run(options: RunOptions): Promise<RunResult> {
    const command = this.config.command;
    if (!command) {
      return { exitCode: 1, stdout: '', stderr: `No command configured for ${this.config.name}` };
    }

    // Try npx first, then direct command
    const args = [...options.args];
    const useNpx = !(await this.commandExists(command));
    const bin = useNpx ? 'npx' : command;
    const spawnArgs = useNpx ? [command, ...args] : args;

    return new Promise<RunResult>((resolve) => {
      const child = spawn(bin, spawnArgs, {
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
    const command = this.config.command;
    if (!command) return false;
    return this.commandExists(command) || this.commandExists('npx');
  }

  private async commandExists(cmd: string): Promise<boolean> {
    return new Promise((resolve) => {
      const child = spawn('which', [cmd], { stdio: 'ignore' });
      child.on('close', (code) => resolve(code === 0));
      child.on('error', () => resolve(false));
    });
  }
}

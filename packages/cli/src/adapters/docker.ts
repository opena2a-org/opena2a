import { spawn } from 'node:child_process';
import type { Adapter, AdapterConfig, RunOptions, RunResult } from './types.js';

export class DockerAdapter implements Adapter {
  readonly config: AdapterConfig;

  constructor(config: AdapterConfig) {
    this.config = config;
  }

  async run(options: RunOptions): Promise<RunResult> {
    const image = this.config.image;
    if (!image) {
      return { exitCode: 1, stdout: '', stderr: `No image configured for ${this.config.name}` };
    }

    const dockerArgs = ['run', '--rm'];

    if (options.args.includes('--interactive') || options.args.includes('-it')) {
      dockerArgs.push('-it');
    }

    // Map port ranges from adapter config, or fall back to a default
    const ports = this.config.ports ?? ['3000:3000'];
    for (const mapping of ports) {
      dockerArgs.push('-p', mapping);
    }
    dockerArgs.push(image);
    dockerArgs.push(...options.args.filter(a => a !== '--interactive' && a !== '-it'));

    return new Promise<RunResult>((resolve) => {
      const child = spawn('docker', dockerArgs, {
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
    return new Promise((resolve) => {
      const child = spawn('docker', ['info'], { stdio: 'ignore' });
      child.on('close', (code) => resolve(code === 0));
      child.on('error', () => resolve(false));
    });
  }
}

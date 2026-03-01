const FRAMES = ['|', '/', '-', '\\'];

export class Spinner {
  private intervalId: ReturnType<typeof setInterval> | null = null;
  private frameIndex = 0;
  private message: string;

  constructor(message: string) {
    this.message = message;
  }

  start(): void {
    if (!process.stderr.isTTY) return;
    this.intervalId = setInterval(() => {
      const frame = FRAMES[this.frameIndex % FRAMES.length];
      process.stderr.write(`\r${frame} ${this.message}`);
      this.frameIndex++;
    }, 100);
  }

  stop(finalMessage?: string): void {
    if (this.intervalId) {
      clearInterval(this.intervalId);
      this.intervalId = null;
    }
    if (process.stderr.isTTY) {
      process.stderr.write('\r' + ' '.repeat(this.message.length + 4) + '\r');
    }
    if (finalMessage) {
      process.stderr.write(finalMessage + '\n');
    }
  }

  update(message: string): void {
    this.message = message;
  }
}

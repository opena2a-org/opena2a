import { execFileSync } from 'node:child_process';

export const MIN_HMA_VERSION = '0.15.6';

let versionChecked = false;

/**
 * Check that the installed hackmyagent version meets the minimum required.
 * Warns once per process if the version is too old.
 */
export function checkMinHmaVersion(): void {
  if (versionChecked) return;
  versionChecked = true;

  try {
    const raw = execFileSync('hackmyagent', ['--version'], {
      timeout: 5000,
      encoding: 'utf8',
    }).trim();
    const match = raw.match(/(\d+\.\d+\.\d+)/);
    if (!match) return;
    const installed = match[1];
    const [iMaj, iMin, iPat] = installed.split('.').map(Number);
    const [rMaj, rMin, rPat] = MIN_HMA_VERSION.split('.').map(Number);
    if (iMaj < rMaj || (iMaj === rMaj && iMin < rMin) || (iMaj === rMaj && iMin === rMin && iPat < rPat)) {
      process.stderr.write(
        `\nWarning: hackmyagent ${installed} is installed, but opena2a-cli requires >=${MIN_HMA_VERSION}.\n` +
        `Some features (like GitHub repo scanning) may not work.\n` +
        `Upgrade: npm install -g hackmyagent@latest\n\n`,
      );
    }
  } catch {
    // hackmyagent not found — spawnHmaCheck will handle that error
  }
}

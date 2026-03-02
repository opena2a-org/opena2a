const LOGO = `
   ___                   _   ____    _
  / _ \\ _ __   ___ _ __ / \\ |___ \\  / \\
 | | | | '_ \\ / _ \\ '_ / _ \\  __) |/ _ \\
 | |_| | |_) |  __/ | / ___ \\/ __// ___ \\
  \\___/| .__/ \\___|_|/_/   \\_\\___|_/   \\_\\
       |_|
`;

const TAGLINE = 'Open-source security for AI agents';

export function printBanner(version: string): void {
  process.stdout.write(LOGO);
  process.stdout.write(`  ${TAGLINE}  v${version}\n\n`);
}

export function printCompact(version: string): void {
  process.stdout.write(`opena2a v${version}\n`);
}

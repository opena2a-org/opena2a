import { search } from './search.js';
import { bold, cyan, gray, dim } from '../util/colors.js';

export { search } from './search.js';

export function handleSearch(query: string): void {
  const results = search(query);

  if (results.length === 0) {
    process.stdout.write(`No commands found matching "${query}".\n`);
    process.stdout.write(`Try: opena2a --help\n`);
    return;
  }

  process.stdout.write(`\nCommands matching "${query}":\n\n`);

  for (let i = 0; i < results.length; i++) {
    const { entry, score } = results[i];
    const rank = `${i + 1}.`;
    process.stdout.write(`  ${bold(rank)} ${cyan(entry.path)}\n`);
    process.stdout.write(`     ${entry.description}\n`);
    if (entry.examples.length > 0) {
      process.stdout.write(`     ${dim('e.g.')} ${gray(entry.examples[0])}\n`);
    }
    process.stdout.write('\n');
  }
}

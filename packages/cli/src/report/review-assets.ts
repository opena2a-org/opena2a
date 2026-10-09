/**
 * Static assets of the review report, kept as plain files so they are edited
 * and diffed like any other source. The build copies src/report/review/assets/
 * to dist/report/review/assets/. Each file is read once and inlined, so the
 * report stays one self-contained HTML file.
 */

import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const REVIEW_ASSETS_DIR = join(__dirname, 'review', 'assets');

const cache = new Map<string, string>();

/** Text of `relPath` under `dir`. Throws, naming the path, if it is unreadable or would end the inlined element. */
export function readReviewAsset(relPath: string, dir: string = REVIEW_ASSETS_DIR): string {
  const file = join(dir, relPath);
  let text = cache.get(file);
  if (text !== undefined) return text;
  try {
    text = readFileSync(file, 'utf-8');
  } catch (err) {
    throw new Error(`Cannot read review report asset ${file}: ${(err as Error).message}`);
  }
  const closer = /<\/(script|style)/i.exec(text);
  if (closer) throw new Error(`Review report asset ${file} contains "${closer[0]}", which would end the inlined element`);
  cache.set(file, text);
  return text;
}

export const reviewReportCss = (): string => readReviewAsset('report.css');

/** The report's client script files, in load order. */
export const REVIEW_CLIENT_FILES: readonly string[] = [
  'client/00-core.js', // report data, tab switching, shared helpers
  'client/10-overview.js',
  'client/30-hygiene.js',
  'client/40-findings.js',
  'client/60-shadowai.js',
  'client/99-init.js', // renders the first tab; runs last
];

/** The client files concatenated in order inside one function scope, so their names stay off `window`. */
export function assembleReviewClientScript(
  files: readonly string[] = REVIEW_CLIENT_FILES,
  dir: string = REVIEW_ASSETS_DIR,
): string {
  return '(function(){\n' + files.map(f => readReviewAsset(f, dir)).join('\n') + '})();';
}

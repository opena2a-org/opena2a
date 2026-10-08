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

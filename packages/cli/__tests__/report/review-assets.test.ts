// The report's styles are a file under src/report/review/assets/, inlined at
// render time. Guards: no asset can end the element it is inlined into, a
// missing asset names its path, and the package ships every asset.

import { describe, it, expect, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { REVIEW_ASSETS_DIR, readReviewAsset, reviewReportCss } from '../../src/report/review-assets.js';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';

const listFiles = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap(e => (e.isDirectory() ? listFiles(join(dir, e.name)) : [join(dir, e.name)]));
const assets = listFiles(REVIEW_ASSETS_DIR).map(f => relative(REVIEW_ASSETS_DIR, f).split('\\').join('/'));
const scratch = mkdtempSync(join(tmpdir(), 'review-assets-'));
afterAll(() => rmSync(scratch, { recursive: true, force: true }));

describe('review report assets', () => {
  it('no asset contains </script or </style', () => {
    expect(assets).toContain('report.css'); // non-vacuity: the asset directory was found
    for (const name of assets) {
      expect(readFileSync(join(REVIEW_ASSETS_DIR, name), 'utf-8'), name).not.toMatch(/<\/(script|style)/i);
    }
  });

  it('the report inlines the stylesheet in its one <style> element', () => {
    const css = reviewReportCss();
    expect(css).toContain('.nav-tab {'); // non-vacuity: the real stylesheet
    const html = generateReviewHtml({ projectName: 'demo', directory: '/tmp/demo' } as unknown as ReviewReport);
    expect(html.match(/<style>/g)).toHaveLength(1);
    expect(html).toContain('<style>\n' + css);
  });

  it('a missing asset throws an error that names its path', () => {
    expect(() => readReviewAsset('missing.css', scratch)).toThrow(join(scratch, 'missing.css'));
  });

  it('an asset that would close its element is refused', () => {
    writeFileSync(join(scratch, 'bad.css'), 'a{color:red}</STYLE><script>alert(1)</script>');
    expect(() => readReviewAsset('bad.css', scratch)).toThrow(/bad\.css contains "<\/STYLE"/);
  });

  it('npm pack ships every asset under dist/report/review/assets/ (needs `npm run build`)', () => {
    const out = execFileSync('npm', ['pack', '--dry-run', '--json', '--ignore-scripts'], {
      cwd: join(__dirname, '..', '..'),
      encoding: 'utf-8',
      stdio: ['ignore', 'pipe', 'pipe'],
      timeout: 60_000,
    });
    const packed = (JSON.parse(out) as Array<{ files: Array<{ path: string }> }>)[0].files.map(f => f.path);
    for (const name of assets) expect(packed).toContain(`dist/report/review/assets/${name}`);
  });
});

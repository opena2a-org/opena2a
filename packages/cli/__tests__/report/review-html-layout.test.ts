// Regression: the review report fits a 375px screen and every control in it
// works from the keyboard.
//
// At 375px every tab of the report scrolled sideways to 518px (the six-tab bar
// did not wrap) and the Overview to 578px (a five-column findings table). The
// score banner squeezed "Composite Score" against "0/100" with no gap, and the
// "+N recoverable" badge spilled out of the banner. The Score Breakdown rows,
// "View details" and "+ N more files" were `div`/`span` elements with an
// onclick: a mouse could open them, Tab never reached them.
//
// The tabs are rendered in the browser from the embedded report JSON, so these
// tests pin the markup the renderer emits and the CSS that keeps it inside the
// screen. The layout itself was measured in a browser at 375px and 1280px.

import { describe, it, expect } from 'vitest';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';

// The page shell reads only these fields; everything else comes from the JSON.
const html = generateReviewHtml({
  projectName: 'demo',
  directory: '/tmp/demo',
  timestamp: '2026-10-06T00:00:00Z',
} as unknown as ReviewReport);
const css = html.slice(html.indexOf('<style>'), html.indexOf('</style>'));
const script = html.slice(html.lastIndexOf('<script>'), html.lastIndexOf('</script>'));

/** Declarations of the first rule in `block` whose selector is exactly `selector`. */
function declarations(block: string, selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const m = block.match(new RegExp('(?:^|[}\\n])\\s*' + escaped + '\\{([^}]*)\\}'));
  return m ? m[1] : '';
}

/** Body of `@media(<query>){...}`, braces matched. */
function mediaBlock(query: string): string {
  const at = css.indexOf('@media(' + query + '){');
  if (at < 0) return '';
  const open = css.indexOf('{', at);
  let depth = 0;
  for (let i = open; i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}' && --depth === 0) return css.slice(open + 1, i);
  }
  return '';
}

describe('review report: keyboard', () => {
  it('no div, span, td or tr is a click target; every click target is a native control', () => {
    const mouseOnly = html.match(/<(div|span|td|tr|li)\b[^>]*\sonclick=[^>]*>/g) ?? [];
    expect(mouseOnly).toEqual([]);
  });

  it('each Score Breakdown row is a button that opens its tab', () => {
    expect(script).toContain('<button type="button" class="breakdown-row" onclick="goToTab(');
    const start = script.indexOf('class="breakdown-row"');
    const row = script.slice(start, script.indexOf('</button>', start));
    expect(row.length).toBeGreaterThan(100); // non-vacuity: the row template was found
    // A button may hold only phrasing content.
    expect(row).not.toContain('<div');
  });

  it('opening a tab from inside the page moves focus to that tab', () => {
    const start = script.indexOf('window.goToTab=function');
    expect(start).toBeGreaterThan(-1);
    expect(script.slice(start, script.indexOf('};', start))).toContain('.focus()');
  });

  it('"View details" and the file-list toggles are buttons that report their state', () => {
    expect(script).toContain('<button type="button" class="action-link"');
    expect(script.match(/<button type="button" class="expand-toggle" aria-expanded="false"/g)).toHaveLength(2);
    const start = script.indexOf('window.toggleExpand=function');
    expect(script.slice(start, script.indexOf('};', start))).toContain("setAttribute('aria-expanded'");
  });

  it('focus is visible on every button', () => {
    expect(declarations(css, 'button:focus-visible,.table-scroll:focus-visible')).toContain('outline:2px solid');
  });
});

describe('review report: 375px', () => {
  it('the tab bar wraps instead of widening the page', () => {
    expect(declarations(css, '.nav')).toContain('flex-wrap:wrap');
  });

  it('a data table scrolls inside its own wrapper, never the page', () => {
    expect(declarations(css, '.table-scroll')).toContain('overflow-x:auto');
    // Every rendered tab passes through renderPage, which wraps its tables.
    expect(script).toMatch(/break;\}wrapTables\(el\);\}/);
    expect(script).toContain("w.className='table-scroll'");
  });

  it('the score banner stacks at phone widths so the label never meets the score', () => {
    const phone = mediaBlock('max-width:600px');
    expect(phone.length).toBeGreaterThan(0); // non-vacuity: the phone block exists
    expect(declarations(phone, '.score-banner')).toContain('flex-wrap:wrap');
    expect(declarations(phone, '.score-banner-bar')).toContain('flex-basis:100%');
    // Even when both label parts share one line, they keep a gap between them.
    expect(declarations(css, '.score-banner-label')).toMatch(/gap:0 \d+px/);
  });

  it('long file paths and commands break inside their card', () => {
    expect(declarations(css, '.cred-card')).toContain('overflow-wrap:anywhere');
    expect(declarations(css, '.cmd-text')).toContain('overflow-wrap:anywhere');
  });
});

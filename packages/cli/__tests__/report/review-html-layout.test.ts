// Regression: the review report fits a 375px screen and every control in it
// works from the keyboard.
//
// At 375px every tab of the report scrolled sideways to 518px (the six-tab bar
// did not wrap) and the Overview to 578px (a five-column findings table). The
// score banner squeezed "Composite Score" against "0/100" with no gap, and the
// "+N recoverable" badge spilled out of the banner. "+ N more files" was a
// `span` with an onclick: a mouse could open it, Tab never reached it.
//
// The tabs are rendered in the browser from the embedded report JSON, so these
// tests pin the markup the renderer emits and the CSS that keeps it inside the
// screen. The layout itself was measured in a browser at 375px and 1280px.

import { describe, it, expect } from 'vitest';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';
import { compactReportScript } from './compact-script.js';

// The page shell reads only these fields; everything else comes from the JSON.
const html = generateReviewHtml({
  projectName: 'demo',
  directory: '/tmp/demo',
  timestamp: '2026-10-06T00:00:00Z',
} as unknown as ReviewReport);
// The stylesheet is kept formatted (review/assets/report.css). Rules are
// matched with comments and formatting whitespace removed: `selector{a:b;}`.
const css = html
  .slice(html.indexOf('<style>'), html.indexOf('</style>'))
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/\s+/g, ' ')
  .replace(/\s*([{};:,>])\s*/g, '$1')
  .replace(/@media \(/g, '@media(');
const script = compactReportScript(html);

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

  it('each Fix-first Copy button is a labelled button, after the command it copies', () => {
    const start = script.indexOf('function commandRow(');
    const row = script.slice(start, script.indexOf('function textRow(', start));
    expect(row.length).toBeGreaterThan(100); // non-vacuity: the row template was found
    expect(row).toContain('<button type="button" class="copy-btn" aria-label="Copy ');
    // Reading order is tab order: the command, its tool, then its Copy button.
    expect(row.indexOf('class="cmd-text"')).toBeLessThan(row.indexOf('class="copy-btn"'));
  });

  it('a Fix-first card opens its locations and evidence with a native disclosure', () => {
    expect(script).toContain('<details class="ff-details"><summary>Where and evidence</summary>');
    expect(declarations(css, 'summary:focus-visible')).toContain('outline:2px solid');
  });

  it('opening a tab from inside the page moves focus to that tab', () => {
    const start = script.indexOf('window.goToTab=function');
    expect(start).toBeGreaterThan(-1);
    expect(script.slice(start, script.indexOf('};', start))).toContain('.focus()');
  });

  it('the link to Findings is a button, and each finding opens with a native disclosure', () => {
    expect(script).toContain('<button type="button" class="ff-tab-link" onclick="goToTab(&quot;findings&quot;)">');
    expect(script).toContain('<details class="fd" id="f-');
    expect(script).toContain('<summary>');
  });

  it('focus is visible on every button', () => {
    expect(declarations(css, 'button:focus-visible,.table-scroll:focus-visible')).toContain('outline:2px solid');
  });

  it('the controls that became buttons keep the line height of the text around them', () => {
    // A button does not inherit line-height, so as buttons the file-list
    // toggles went from 17.5px to 14px tall at 1280px.
    for (const selector of ['.expand-toggle', '.ff-tab-link']) {
      expect(declarations(css, selector), selector).toContain('line-height:inherit');
    }
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
    expect(declarations(css, '.fd')).toContain('overflow-wrap:anywhere');
    expect(declarations(css, '.cmd-text')).toContain('overflow-wrap:anywhere');
  });

  it('a Summary notice breaks a file path instead of widening the page', () => {
    // The provisional notice quotes the scanner's reason for having no result,
    // which can hold a file path with no space in it. Unbreakable, a path of
    // 92 characters set the Overview to 791px at a 375px viewport.
    expect(declarations(css, '.summary')).toContain('overflow-wrap:anywhere');
  });

  it('a Hygiene row breaks its value instead of widening the page', () => {
    // The "Security config" row prints the signature store path
    // (.opena2a/guard/signatures.json) as one flex item. Unbreakable, it set
    // the Hygiene tab to 382px at a 375px viewport on a project with a store.
    expect(declarations(css, '.hygiene-row')).toContain('overflow-wrap:anywhere');
  });
});

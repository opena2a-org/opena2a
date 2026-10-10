// Regression: collapsing an expanded file list gives the toggle back its own
// label.
//
// The Credentials and HMA tabs show the first few files of a group and a
// "+ N more files" / "+ N more" button for the rest. Opening the list relabelled
// the button "collapse"; closing it relabelled it "+ show all", so the count the
// reader had been given was gone after one round trip.
//
// The toggle runs in the browser, so these tests take window.toggleExpand from
// the generated page and drive it against a stand-in for the button.

import { runInNewContext } from 'node:vm';
import { describe, it, expect } from 'vitest';
import { generateReviewHtml } from '../../src/report/review-html.js';
import type { ReviewReport } from '../../src/commands/review.js';
import { compactReportScript } from './compact-script.js';

const html = generateReviewHtml({
  projectName: 'demo',
  directory: '/tmp/demo',
  timestamp: '2026-10-08T00:00:00Z',
} as unknown as ReviewReport);
const script = compactReportScript(html);

type Toggle = (el: unknown) => void;

function loadToggleExpand(): Toggle {
  const start = script.indexOf('window.toggleExpand=function');
  expect(start).toBeGreaterThan(-1);
  const source = script.slice(start, script.indexOf('};', start) + 2);
  const win: { toggleExpand?: Toggle } = {};
  runInNewContext(source, { window: win });
  expect(typeof win.toggleExpand).toBe('function');
  return win.toggleExpand as Toggle;
}

/** The button as the renderer emits it, followed by its hidden file list. */
function button(label: string) {
  const attrs = new Map<string, string>([['aria-expanded', 'false']]);
  const classes = new Set<string>();
  return {
    textContent: label,
    nextElementSibling: {
      classList: {
        toggle(name: string): boolean {
          if (classes.delete(name)) return false;
          classes.add(name);
          return true;
        },
      },
    },
    getAttribute: (name: string) => attrs.get(name) ?? null,
    setAttribute: (name: string, value: unknown) => void attrs.set(name, String(value)),
    hasAttribute: (name: string) => attrs.has(name),
  };
}

describe('review report: file-list toggle', () => {
  const toggleExpand = loadToggleExpand();

  for (const label of ['+ 7 more files', '+ 4 more']) {
    it(`"${label}" comes back when the list is collapsed`, () => {
      const el = button(label);

      toggleExpand(el);
      expect(el.textContent).toBe('collapse');
      expect(el.getAttribute('aria-expanded')).toBe('true');

      toggleExpand(el);
      expect(el.textContent).toBe(label);
      expect(el.getAttribute('aria-expanded')).toBe('false');

      toggleExpand(el);
      toggleExpand(el);
      expect(el.textContent).toBe(label);
      expect(el.getAttribute('aria-expanded')).toBe('false');
    });
  }

  it('each button keeps its own label', () => {
    const credentials = button('+ 7 more files');
    const hygiene = button('+ 4 more');
    toggleExpand(credentials);
    toggleExpand(hygiene);
    toggleExpand(credentials);
    toggleExpand(hygiene);
    expect(credentials.textContent).toBe('+ 7 more files');
    expect(hygiene.textContent).toBe('+ 4 more');
  });
});

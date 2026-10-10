// Regression: compactJs walked getChildren, which also returns the JSDoc
// comments attached to a node, so a `/** */` block survived compaction while
// every other comment was dropped.

import { describe, it, expect } from 'vitest';
import { compactJs } from './compact-script.js';

describe('compactJs', () => {
  it('drops a JSDoc block like every other comment', () => {
    expect(compactJs('/** secret */ function a(){}')).toBe('function a(){}');
    expect(compactJs('/** @type {number} */\nvar x = 1;')).toBe('var x=1;');
  });

  it('drops line and block comments and layout whitespace', () => {
    expect(compactJs('// x\nfunction a() {\n  /* y */ return 1;\n}')).toBe('function a(){return 1;}');
  });
});

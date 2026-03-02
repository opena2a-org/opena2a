import { describe, it, expect } from 'vitest';
import { search } from '../../src/semantic/search.js';

describe('semantic search', () => {
  it('finds scan command for "vulnerability" query', () => {
    const results = search('vulnerability');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].entry.id).toMatch(/scan/);
  });

  it('finds secrets command for "api key" query', () => {
    const results = search('api key');
    expect(results.length).toBeGreaterThan(0);
    const ids = results.map(r => r.entry.id);
    expect(ids.some(id => id.includes('secret') || id.includes('protect'))).toBe(true);
  });

  it('finds crypto command for "quantum" query', () => {
    const results = search('quantum');
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].entry.id).toBe('crypto');
  });

  it('finds training command for "practice" query', () => {
    const results = search('practice');
    expect(results.length).toBeGreaterThan(0);
    expect(results.some(r => r.entry.id === 'train')).toBe(true);
  });

  it('expands domain terms', () => {
    const results = search('openai');
    expect(results.length).toBeGreaterThan(0);
    // Should find credential-related commands via domain expansion
    expect(results.some(r =>
      r.entry.tags.includes('credentials') || r.entry.tags.includes('secrets')
    )).toBe(true);
  });

  it('returns empty for nonsense query', () => {
    const results = search('xyzzy12345');
    expect(results.length).toBe(0);
  });

  it('respects limit parameter', () => {
    const results = search('security', 2);
    expect(results.length).toBeLessThanOrEqual(2);
  });

  it('sorts results by score descending', () => {
    const results = search('security scan');
    for (let i = 1; i < results.length; i++) {
      expect(results[i].score).toBeLessThanOrEqual(results[i - 1].score);
    }
  });
});

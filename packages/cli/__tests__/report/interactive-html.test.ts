import { describe, it, expect } from 'vitest';
import { generateInteractiveHtml, type InteractiveReportData } from '../../src/report/interactive-html.js';

function sampleData(overrides?: Partial<InteractiveReportData>): InteractiveReportData {
  return {
    metadata: {
      generatedAt: '2026-03-01T00:00:00Z',
      toolVersion: '0.1.0',
      targetName: 'test-project',
      scanType: 'protect',
    },
    summary: {
      totalFindings: 3,
      bySeverity: { critical: 1, high: 1, medium: 1, low: 0, info: 0 },
      score: 52,
      grade: 'moderate',
    },
    findings: [
      {
        id: 'CRED-001',
        severity: 'critical',
        title: 'Anthropic API Key',
        description: 'Hardcoded Anthropic API key found.',
        explanation: 'Anyone can use your Anthropic account.',
        businessImpact: 'Thousands in unauthorized charges.',
        category: 'Credential Exposure',
        file: 'src/config.ts',
        line: 42,
        fix: 'Replace with process.env.ANTHROPIC_API_KEY',
        passed: false,
      },
      {
        id: 'DRIFT-001',
        severity: 'high',
        title: 'Google API Key (Gemini drift)',
        description: 'Google API key with scope drift risk.',
        explanation: 'Key may grant Gemini access beyond Maps.',
        businessImpact: 'Cross-service billing abuse.',
        category: 'Scope Drift',
        file: 'src/maps.ts',
        line: 10,
        fix: 'Replace with process.env.GOOGLE_API_KEY',
        passed: false,
      },
      {
        id: 'CRED-004',
        severity: 'medium',
        title: 'Generic API Key',
        description: 'Generic API key in assignment.',
        category: 'Credential Exposure',
        passed: false,
      },
    ],
    ...overrides,
  };
}

describe('generateInteractiveHtml', () => {
  it('generates valid HTML document', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
  });

  it('includes target name in title', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('test-project');
  });

  it('embeds report data as JSON', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('id="report-data"');
    expect(html).toContain('type="application/json"');
    // The JSON data should be embedded and parseable
    const match = html.match(/<script id="report-data" type="application\/json">(.*?)<\/script>/s);
    expect(match).toBeTruthy();
    // Unescape HTML entities for parsing
    const jsonStr = match![1]
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    const parsed = JSON.parse(jsonStr);
    expect(parsed.summary.totalFindings).toBe(3);
    expect(parsed.findings).toHaveLength(3);
  });

  it('includes dark theme CSS variables', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('#0a0a0a'); // background
    expect(html).toContain('#171717'); // card
    expect(html).toContain('#14b8a6'); // primary teal
    expect(html).toContain('#ef4444'); // critical red
    expect(html).toContain('#f97316'); // high orange
    expect(html).toContain('#eab308'); // medium yellow
    expect(html).toContain('#3b82f6'); // low blue
  });

  it('includes audience toggle (Executive/Engineering)', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('data-audience="engineering"');
    expect(html).toContain('data-audience="executive"');
    expect(html).toContain('audience-toggle');
  });

  it('includes severity filter buttons', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('data-severity="critical"');
    expect(html).toContain('data-severity="high"');
    expect(html).toContain('data-severity="medium"');
    expect(html).toContain('data-severity="low"');
    expect(html).toContain('data-severity="all"');
  });

  it('includes search input', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('id="search-input"');
    expect(html).toContain('Search findings');
  });

  it('includes hash-based navigation', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('#dashboard');
    expect(html).toContain('#findings');
    expect(html).toContain('hashchange');
  });

  it('includes executive-only and engineering-only sections', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('exec-only');
    expect(html).toContain('eng-only');
  });

  it('renders finding cards with severity borders', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('finding-card');
    expect(html).toContain('finding-header');
    expect(html).toContain('finding-body');
    expect(html).toContain('finding-chevron');
  });

  it('includes SVG donut chart code', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('donutChart');
    expect(html).toContain('stroke-dasharray');
  });

  it('renders score section for executive audience', () => {
    const html = generateInteractiveHtml(sampleData());
    // The JS handles rendering the score for executive view
    expect(html).toContain('score-section');
    expect(html).toContain('score-value');
  });

  it('handles empty findings', () => {
    const html = generateInteractiveHtml(sampleData({
      summary: { totalFindings: 0, bySeverity: {}, score: 100, grade: 'strong' },
      findings: [],
    }));
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('All checks passed');
  });

  it('escapes HTML in finding content', () => {
    const html = generateInteractiveHtml(sampleData({
      metadata: {
        generatedAt: '2026-03-01',
        toolVersion: '0.1.0',
        targetName: '<script>alert("xss")</script>',
        scanType: 'protect',
      },
    }));
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('includes monospace font family', () => {
    const html = generateInteractiveHtml(sampleData());
    expect(html).toContain('JetBrains Mono');
    expect(html).toContain('monospace');
  });

  it('is self-contained (no external dependencies)', () => {
    const html = generateInteractiveHtml(sampleData());
    // Should not contain any external CSS or JS references
    expect(html).not.toMatch(/<link[^>]+href="http/);
    expect(html).not.toMatch(/<script[^>]+src="http/);
  });
});

import { describe, it, expect } from 'vitest';
import { generateShieldHtmlReport } from '../../src/shield/report-html.js';
import type { WeeklyReport, ReportNarrative } from '../../src/shield/types.js';

function sampleReport(overrides?: Partial<WeeklyReport>): WeeklyReport {
  return {
    version: 1,
    generatedAt: '2026-03-01T12:00:00.000Z',
    periodStart: '2026-02-22T12:00:00.000Z',
    periodEnd: '2026-03-01T12:00:00.000Z',
    hostname: 'dev-workstation',

    agentActivity: {
      totalSessions: 5,
      totalActions: 42,
      byAgent: {
        'claude-code': {
          sessions: 3,
          actions: 30,
          firstSeen: '2026-02-22T14:00:00.000Z',
          lastSeen: '2026-03-01T10:00:00.000Z',
          topActions: [
            { action: 'file-write', count: 15 },
            { action: 'process-spawn', count: 10 },
            { action: 'network-request', count: 5 },
          ],
        },
        'cursor': {
          sessions: 2,
          actions: 12,
          firstSeen: '2026-02-25T09:00:00.000Z',
          lastSeen: '2026-02-28T16:00:00.000Z',
          topActions: [
            { action: 'file-read', count: 8 },
            { action: 'process-spawn', count: 4 },
          ],
        },
      },
    },

    policyEvaluation: {
      monitored: 35,
      wouldBlock: 0,
      blocked: 3,
      topViolations: [
        {
          action: 'process-spawn',
          target: '/usr/bin/curl',
          agent: 'claude-code',
          count: 2,
          severity: 'high',
          recommendation: 'Review and consider blocking',
        },
        {
          action: 'credential-access',
          target: 'OPENAI_API_KEY',
          agent: 'cursor',
          count: 1,
          severity: 'critical',
          recommendation: 'Already blocked by policy',
        },
      ],
    },

    credentialExposure: {
      accessAttempts: 5,
      uniqueCredentials: 3,
      byProvider: { secretless: 3, shield: 2 },
      recommendations: [],
    },

    supplyChain: {
      packagesInstalled: 12,
      advisoriesFound: 1,
      blockedInstalls: 0,
      lowTrustPackages: [],
    },

    configIntegrity: {
      filesMonitored: 8,
      tamperedFiles: [],
      signatureStatus: 'valid',
    },

    runtimeProtection: {
      arpActive: true,
      processesSpawned: 25,
      networkConnections: 18,
      anomalies: 2,
    },

    posture: {
      score: 77,
      grade: 'moderate',
      factors: [
        { name: 'severity', score: 77, weight: 0.4, detail: '0 critical, 1 high' },
        { name: 'enforcement', score: 80, weight: 0.3, detail: '3 blocked' },
        { name: 'coverage', score: 70, weight: 0.3, detail: '2 agents monitored' },
      ],
      trend: 'improving',
      comparative: null,
    },

    ...overrides,
  };
}

function sampleNarrative(): ReportNarrative {
  return {
    summary: 'Overall security posture is stable with minor concerns around credential access patterns.',
    highlights: [
      'ARP runtime protection is active and monitoring process spawns.',
      'Policy enforcement blocked 3 actions during the period.',
    ],
    concerns: [
      'Credential access by cursor agent should be reviewed.',
      '1 supply chain advisory requires attention.',
    ],
    recommendations: [
      'Consider tightening the process-spawn allow list for claude-code.',
      'Review and remediate the supply chain advisory.',
    ],
  };
}

function parseEmbeddedData(html: string): { report: WeeklyReport; narrative: ReportNarrative | null } {
  const match = html.match(/<script id="report-data" type="application\/json">(.*?)<\/script>/s);
  if (!match) throw new Error('No embedded report data found');
  const jsonStr = match[1]
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'");
  return JSON.parse(jsonStr);
}

describe('generateShieldHtmlReport', () => {
  it('generates valid HTML document', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
    expect(html).toContain('<html lang="en">');
  });

  it('includes hostname in title', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('dev-workstation');
  });

  it('contains Posture Score section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Posture Score');
  });

  it('contains Severity Breakdown section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Severity Breakdown');
  });

  it('contains Agent Activity section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Agent Activity');
  });

  it('contains Policy Violations section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Policy Violations');
  });

  it('contains Runtime Protection section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Runtime Protection');
  });

  it('contains Credential Exposure section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Credential Exposure');
  });

  it('contains Supply Chain section', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('Supply Chain');
  });

  it('contains the posture score value in embedded data', () => {
    const html = generateShieldHtmlReport(sampleReport());
    const parsed = parseEmbeddedData(html);
    expect(parsed.report.posture.score).toBe(77);
  });

  it('contains the posture grade in embedded data', () => {
    const html = generateShieldHtmlReport(sampleReport());
    const parsed = parseEmbeddedData(html);
    expect(parsed.report.posture.grade).toBe('moderate');
  });

  it('embeds report data as JSON', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('id="report-data"');
    expect(html).toContain('type="application/json"');

    // Extract and parse the embedded JSON
    const match = html.match(/<script id="report-data" type="application\/json">(.*?)<\/script>/s);
    expect(match).toBeTruthy();
    const jsonStr = match![1]
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    const parsed = JSON.parse(jsonStr);
    expect(parsed.report.posture.score).toBe(77);
    expect(parsed.report.hostname).toBe('dev-workstation');
  });

  it('contains no emoji characters', () => {
    const html = generateShieldHtmlReport(sampleReport(), sampleNarrative());
    // Check for common emoji ranges (U+1F600-U+1F64F, U+1F300-U+1F5FF, U+1F680-U+1F6FF, U+2600-U+26FF, U+2700-U+27BF)
    const emojiRegex = /[\u{1F600}-\u{1F64F}\u{1F300}-\u{1F5FF}\u{1F680}-\u{1F6FF}\u{2600}-\u{26FF}\u{2700}-\u{27BF}\u{1F900}-\u{1F9FF}\u{1FA00}-\u{1FA6F}\u{1FA70}-\u{1FAFF}]/u;
    expect(emojiRegex.test(html)).toBe(false);
  });

  it('includes dark theme CSS with slate colors', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('#0f172a'); // slate-900 background
    expect(html).toContain('#1e293b'); // slate-800 card
    expect(html).toContain('#06b6d4'); // teal primary
    expect(html).toContain('#ef4444'); // critical red
    expect(html).toContain('#f59e0b'); // amber warning
  });

  it('includes severity filter buttons', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('data-sev="critical"');
    expect(html).toContain('data-sev="high"');
    expect(html).toContain('data-sev="medium"');
    expect(html).toContain('data-sev="low"');
    expect(html).toContain('data-sev="info"');
    expect(html).toContain('data-sev="all"');
  });

  it('includes monospace font family', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('JetBrains Mono');
    expect(html).toContain('monospace');
  });

  it('is self-contained (no external dependencies)', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).not.toMatch(/<link[^>]+href="http/);
    expect(html).not.toMatch(/<script[^>]+src="http/);
  });

  it('handles empty report data gracefully', () => {
    const emptyReport = sampleReport({
      agentActivity: {
        totalSessions: 0,
        totalActions: 0,
        byAgent: {},
      },
      policyEvaluation: {
        monitored: 0,
        wouldBlock: 0,
        blocked: 0,
        topViolations: [],
      },
      credentialExposure: {
        accessAttempts: 0,
        uniqueCredentials: 0,
        byProvider: {},
        recommendations: [],
      },
      supplyChain: {
        packagesInstalled: 0,
        advisoriesFound: 0,
        blockedInstalls: 0,
        lowTrustPackages: [],
      },
      runtimeProtection: {
        arpActive: false,
        processesSpawned: 0,
        networkConnections: 0,
        anomalies: 0,
      },
      posture: {
        score: 100,
        grade: 'strong',
        factors: [],
        trend: null,
        comparative: null,
      },
    });

    const html = generateShieldHtmlReport(emptyReport);
    expect(html).toContain('<!DOCTYPE html>');
    expect(html).toContain('</html>');
    expect(html).toContain('Posture Score');
    expect(html).toContain('No agent activity recorded');
    expect(html).toContain('No policy violations recorded');
  });

  it('renders narrative when provided', () => {
    const html = generateShieldHtmlReport(sampleReport(), sampleNarrative());
    expect(html).toContain('Event Timeline');
    // The narrative data is embedded in the JSON
    expect(html).toContain('Overall security posture is stable');
  });

  it('omits narrative section when not provided', () => {
    const html = generateShieldHtmlReport(sampleReport());
    // The JS only renders narrative section if narrative is present in data
    // It should NOT contain the narrative-related content
    const match = html.match(/<script id="report-data" type="application\/json">(.*?)<\/script>/s);
    expect(match).toBeTruthy();
    const jsonStr = match![1]
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'");
    const parsed = JSON.parse(jsonStr);
    expect(parsed.narrative).toBeNull();
  });

  it('escapes HTML in hostname', () => {
    const html = generateShieldHtmlReport(sampleReport({
      hostname: '<script>alert("xss")</script>',
    }));
    expect(html).not.toContain('<script>alert("xss")</script>');
    expect(html).toContain('&lt;script&gt;');
  });

  it('includes agent names in the embedded data', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('claude-code');
    expect(html).toContain('cursor');
  });

  it('includes violation data in the embedded JSON', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('process-spawn');
    expect(html).toContain('credential-access');
    expect(html).toContain('OPENAI_API_KEY');
  });

  it('includes the period dates in the header', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('2026-02-22');
    expect(html).toContain('2026-03-01');
  });

  it('includes responsive CSS media query', () => {
    const html = generateShieldHtmlReport(sampleReport());
    expect(html).toContain('@media');
    expect(html).toContain('max-width:768px');
  });

  it('handles high score (90+) report', () => {
    const html = generateShieldHtmlReport(sampleReport({
      posture: {
        score: 95,
        grade: 'strong',
        factors: [],
        trend: 'stable',
        comparative: null,
      },
    }));
    const parsed = parseEmbeddedData(html);
    expect(parsed.report.posture.score).toBe(95);
    expect(parsed.report.posture.grade).toBe('strong');
  });

  it('handles low score (<50) report', () => {
    const html = generateShieldHtmlReport(sampleReport({
      posture: {
        score: 25,
        grade: 'needs-attention',
        factors: [],
        trend: 'declining',
        comparative: null,
      },
    }));
    const parsed = parseEmbeddedData(html);
    expect(parsed.report.posture.score).toBe(25);
    expect(parsed.report.posture.grade).toBe('needs-attention');
  });
});

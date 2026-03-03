/**
 * Shield HTML Posture Report Generator.
 *
 * Generates a self-contained HTML file with:
 * - Dark theme (slate-900 background, slate-800 cards)
 * - Posture score circular gauge with grade letter
 * - Severity breakdown horizontal bar chart
 * - Agent activity table
 * - Policy violations table with severity filter
 * - Runtime protection, credential exposure, supply chain cards
 * - Event timeline / narrative section
 *
 * Design tokens:
 *   Background: #0f172a (slate-900), Card: #1e293b (slate-800)
 *   Primary: #06b6d4 (teal), Score: teal
 *   Critical: #ef4444, High: #f97316, Medium: #eab308, Low: #3b82f6, Info: #6b7280
 *   Font: system monospace (JetBrains Mono fallback)
 *
 * No external dependencies. No emojis.
 */

import type { WeeklyReport, ReportNarrative } from './types.js';

export function generateShieldHtmlReport(
  report: WeeklyReport,
  narrative?: ReportNarrative | null,
): string {
  const jsonData = JSON.stringify({ report, narrative: narrative ?? null });

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shield Security Report - ${escapeHtml(report.hostname)}</title>
<style>
${CSS}
</style>
</head>
<body>
<script id="report-data" type="application/json">${jsonData.replace(/<\//g, '<\\/')}</script>
<div id="app">
  <header class="header">
    <div class="header-left">
      <h1 class="logo">Shield</h1>
      <span class="header-sep">|</span>
      <span class="header-label">Security Posture Report</span>
    </div>
    <div class="header-right">
      <span class="header-meta">${escapeHtml(report.hostname)} &middot; ${escapeHtml(formatDate(report.periodStart))} to ${escapeHtml(formatDate(report.periodEnd))}</span>
    </div>
  </header>

  <main class="main" id="main-content"></main>

  <footer class="footer">
    <span>Generated ${escapeHtml(formatDate(report.generatedAt))} by OpenA2A Shield</span>
    <span class="footer-sep"> | </span>
    <a href="https://opena2a.org" target="_blank" rel="noopener noreferrer">opena2a.org</a>
  </footer>
</div>
<script>
${JS}
</script>
</body>
</html>`;
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function formatDate(iso: string): string {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
  } catch {
    return iso;
  }
}

// --- Embedded CSS ---

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0f172a;--card:#1e293b;--card-border:#334155;--card-hover:#334155;
  --primary:#06b6d4;--primary-dim:#0891b2;
  --text:#e2e8f0;--muted:#94a3b8;--dim:#64748b;
  --critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;--info:#6b7280;
  --green:#22c55e;--red:#ef4444;--amber:#f59e0b;
  --radius:8px;--gap:16px;
  --font:'JetBrains Mono','Fira Code','SF Mono',Menlo,Consolas,monospace;
}
body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6;font-size:14px}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}

.header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--card-border);position:sticky;top:0;background:var(--bg);z-index:100}
.header-left{display:flex;align-items:center;gap:12px}
.logo{font-size:20px;font-weight:700;color:var(--primary)}
.header-sep{color:var(--card-border)}
.header-label{color:var(--muted);font-size:14px}
.header-right{display:flex;align-items:center;gap:12px}
.header-meta{color:var(--dim);font-size:12px}

.main{max-width:1200px;margin:0 auto;padding:24px}

.footer{text-align:center;padding:24px;color:var(--dim);font-size:12px;border-top:1px solid var(--card-border);margin-top:48px}
.footer-sep{color:var(--card-border);margin:0 4px}

/* Section headings */
.section-title{font-size:16px;font-weight:700;color:var(--text);margin:32px 0 16px;padding-bottom:8px;border-bottom:1px solid var(--card-border)}
.section-title:first-child{margin-top:0}

/* Cards */
.card{background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);padding:20px;margin-bottom:var(--gap)}
.card-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:12px}

/* Stats grid */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:var(--gap);margin-bottom:24px}
.stat-card{background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);padding:20px;text-align:center}
.stat-value{font-size:28px;font-weight:700}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}

/* Posture gauge section */
.posture-section{display:grid;grid-template-columns:280px 1fr;gap:24px;margin-bottom:24px}
.gauge-card{background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);padding:24px;display:flex;flex-direction:column;align-items:center;justify-content:center}
.gauge-card .gauge-label{font-size:13px;color:var(--muted);margin-top:8px}
.gauge-card .gauge-trend{font-size:12px;color:var(--dim);margin-top:4px}

/* Severity bar chart */
.bar-chart{display:flex;flex-direction:column;gap:10px}
.bar-row{display:flex;align-items:center;gap:12px}
.bar-label{width:70px;text-align:right;font-size:12px;font-weight:600;text-transform:uppercase;flex-shrink:0}
.bar-track{flex:1;height:24px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden;position:relative}
.bar-fill{height:100%;border-radius:4px;transition:width .3s ease;display:flex;align-items:center;justify-content:flex-end;padding-right:8px;min-width:0}
.bar-count{font-size:11px;font-weight:700;color:white}

/* Tables */
.data-table{width:100%;border-collapse:collapse;font-size:13px}
.data-table th{text-align:left;padding:10px 12px;color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.05em;border-bottom:2px solid var(--card-border)}
.data-table td{padding:10px 12px;border-bottom:1px solid var(--card-border)}
.data-table tr:last-child td{border-bottom:none}
.data-table tr:hover td{background:rgba(255,255,255,0.02)}

/* Severity badges */
.sev-badge{display:inline-block;font-size:10px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px}
.sev-critical{background:rgba(239,68,68,0.15);color:var(--critical)}
.sev-high{background:rgba(249,115,22,0.15);color:var(--high)}
.sev-medium{background:rgba(234,179,8,0.15);color:var(--medium)}
.sev-low{background:rgba(59,130,246,0.15);color:var(--low)}
.sev-info{background:rgba(107,114,128,0.15);color:var(--info)}

/* Filter controls */
.filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filter-btn{background:transparent;border:1px solid var(--card-border);border-radius:var(--radius);padding:6px 12px;color:var(--muted);cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
.filter-btn:hover{border-color:var(--text);color:var(--text)}
.filter-btn.active{border-color:var(--primary);color:var(--primary)}
.filter-btn[data-sev="critical"].active{border-color:var(--critical);color:var(--critical)}
.filter-btn[data-sev="high"].active{border-color:var(--high);color:var(--high)}
.filter-btn[data-sev="medium"].active{border-color:var(--medium);color:var(--medium)}
.filter-btn[data-sev="low"].active{border-color:var(--low);color:var(--low)}
.filter-btn[data-sev="info"].active{border-color:var(--info);color:var(--info)}

.violation-count{color:var(--muted);font-size:12px;margin-left:auto}

/* Detail cards (runtime, creds, supply chain) */
.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:var(--gap);margin-bottom:24px}
.detail-row{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid rgba(255,255,255,0.05)}
.detail-row:last-child{border-bottom:none}
.detail-key{color:var(--muted);font-size:13px}
.detail-val{font-weight:600;font-size:13px}

/* Narrative */
.narrative-section{margin-top:24px}
.narrative-block{margin-bottom:16px}
.narrative-block h4{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:8px}
.narrative-text{color:var(--text);font-size:13px;line-height:1.7}
.narrative-list{list-style:none;padding:0}
.narrative-list li{padding:4px 0;color:var(--text);font-size:13px}
.narrative-list li::before{content:"--";color:var(--dim);margin-right:8px}
.narrative-concern li::before{color:var(--amber)}
.narrative-highlight li::before{color:var(--green)}
.narrative-rec li::before{color:var(--primary)}

/* Provider list */
.provider-list{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}
.provider-tag{background:rgba(6,182,212,0.1);border:1px solid rgba(6,182,212,0.3);border-radius:4px;padding:2px 10px;font-size:12px;color:var(--primary)}

/* Empty state */
.empty-state{color:var(--dim);font-size:13px;padding:16px 0;text-align:center}

/* Posture factors */
.factor-row{display:flex;align-items:center;gap:12px;padding:6px 0}
.factor-name{width:100px;font-size:12px;color:var(--muted)}
.factor-bar{flex:1;height:8px;background:rgba(255,255,255,0.05);border-radius:4px;overflow:hidden}
.factor-fill{height:100%;border-radius:4px;background:var(--primary)}
.factor-score{width:40px;text-align:right;font-size:12px;font-weight:600}
.factor-detail{font-size:11px;color:var(--dim);width:160px}

/* Active/inactive indicator */
.status-active{color:var(--green);font-weight:600}
.status-inactive{color:var(--red);font-weight:600}

@media(max-width:768px){
  .posture-section{grid-template-columns:1fr}
  .detail-grid{grid-template-columns:1fr}
  .header{flex-direction:column;gap:12px}
  .header-right{width:100%}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
}
`;

// --- Embedded JavaScript ---

const JS = `
(function() {
  'use strict';

  var raw = JSON.parse(document.getElementById('report-data').textContent);
  var report = raw.report;
  var narrative = raw.narrative;

  var activeViolationFilters = new Set(['critical','high','medium','low','info']);

  function init() {
    render();
    bindEvents();
  }

  function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
  }

  // --- Posture gauge SVG ---
  function gaugeCircle(score) {
    var size = 180;
    var cx = size / 2, cy = size / 2;
    var r = 70;
    var sw = 12;
    var circ = 2 * Math.PI * r;
    var pct = Math.max(0, Math.min(100, score)) / 100;
    var dash = pct * circ;
    var gap = circ - dash;

    var color;
    if (score >= 90) color = '#22c55e';
    else if (score >= 70) color = '#3b82f6';
    else if (score >= 50) color = '#eab308';
    else color = '#ef4444';

    var grade = report.posture.grade || '';

    var svg = '<svg width="' + size + '" height="' + size + '" viewBox="0 0 ' + size + ' ' + size + '">';
    // Background circle
    svg += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="' + sw + '"/>';
    // Score arc
    svg += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + color + '" stroke-width="' + sw + '" ';
    svg += 'stroke-dasharray="' + dash + ' ' + gap + '" stroke-dashoffset="' + (circ * 0.25) + '" ';
    svg += 'stroke-linecap="round" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
    // Score text
    svg += '<text x="' + cx + '" y="' + (cy - 8) + '" text-anchor="middle" dominant-baseline="middle" ';
    svg += 'font-size="36" font-weight="700" fill="' + color + '" font-family="var(--font)">' + score + '</text>';
    // Grade letter
    svg += '<text x="' + cx + '" y="' + (cy + 24) + '" text-anchor="middle" dominant-baseline="middle" ';
    svg += 'font-size="18" font-weight="600" fill="' + color + '" font-family="var(--font)">Grade ' + esc(grade) + '</text>';
    svg += '</svg>';
    return svg;
  }

  // --- Severity bar chart ---
  function severityBars() {
    var sev = report.policyEvaluation;
    var violations = sev.topViolations || [];
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (var i = 0; i < violations.length; i++) {
      var v = violations[i];
      counts[v.severity] = (counts[v.severity] || 0) + v.count;
    }
    var maxCount = Math.max(1, counts.critical, counts.high, counts.medium, counts.low, counts.info);

    var colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#3b82f6', info: '#6b7280' };
    var order = ['critical', 'high', 'medium', 'low', 'info'];

    var html = '<div class="bar-chart">';
    for (var j = 0; j < order.length; j++) {
      var s = order[j];
      var c = counts[s] || 0;
      var pct = maxCount > 0 ? (c / maxCount) * 100 : 0;
      html += '<div class="bar-row">';
      html += '<span class="bar-label" style="color:' + colors[s] + '">' + s + '</span>';
      html += '<div class="bar-track">';
      if (c > 0) {
        html += '<div class="bar-fill" style="width:' + Math.max(pct, 5) + '%;background:' + colors[s] + '"><span class="bar-count">' + c + '</span></div>';
      }
      html += '</div>';
      html += '</div>';
    }
    html += '</div>';
    return html;
  }

  // --- Render ---
  function render() {
    var el = document.getElementById('main-content');
    var html = '';

    // Posture Score + Severity Breakdown
    html += '<h2 class="section-title">Posture Score</h2>';
    html += '<div class="posture-section">';
    html += '<div class="gauge-card">' + gaugeCircle(report.posture.score);
    if (report.posture.trend) {
      html += '<div class="gauge-trend">Trend: ' + esc(report.posture.trend) + '</div>';
    }
    html += '</div>';

    // Right side: severity bars + factors
    html += '<div>';
    html += '<div class="card"><div class="card-title">Severity Breakdown</div>' + severityBars() + '</div>';

    // Posture factors
    if (report.posture.factors && report.posture.factors.length > 0) {
      html += '<div class="card"><div class="card-title">Score Factors</div>';
      for (var fi = 0; fi < report.posture.factors.length; fi++) {
        var f = report.posture.factors[fi];
        html += '<div class="factor-row">';
        html += '<span class="factor-name">' + esc(f.name) + '</span>';
        html += '<div class="factor-bar"><div class="factor-fill" style="width:' + f.score + '%"></div></div>';
        html += '<span class="factor-score">' + f.score + '</span>';
        html += '<span class="factor-detail">' + esc(f.detail) + '</span>';
        html += '</div>';
      }
      html += '</div>';
    }
    html += '</div></div>';

    // Summary stats
    html += '<h2 class="section-title">Activity Summary</h2>';
    html += '<div class="stats-grid">';
    html += statCard(report.agentActivity.totalSessions, 'Sessions', 'var(--primary)');
    html += statCard(report.agentActivity.totalActions, 'Actions', 'var(--text)');
    html += statCard(report.policyEvaluation.monitored, 'Monitored', 'var(--muted)');
    html += statCard(report.policyEvaluation.blocked, 'Blocked', 'var(--critical)');
    html += '</div>';

    // Agent Activity
    html += '<h2 class="section-title">Agent Activity</h2>';
    html += agentTable();

    // Policy Violations
    html += '<h2 class="section-title">Policy Violations</h2>';
    html += violationsSection();

    // Detail cards row
    html += '<h2 class="section-title">Protection Details</h2>';
    html += '<div class="detail-grid">';
    html += runtimeCard();
    html += credentialCard();
    html += supplyChainCard();
    html += '</div>';

    // Event Timeline / Narrative
    if (narrative) {
      html += '<h2 class="section-title">Event Timeline</h2>';
      html += narrativeSection();
    }

    el.innerHTML = html;
  }

  function statCard(value, label, color) {
    return '<div class="stat-card"><div class="stat-value" style="color:' + color + '">' + value + '</div><div class="stat-label">' + label + '</div></div>';
  }

  // --- Agent Activity Table ---
  function agentTable() {
    var agents = report.agentActivity.byAgent;
    var keys = Object.keys(agents);
    if (keys.length === 0) {
      return '<div class="card"><div class="empty-state">No agent activity recorded.</div></div>';
    }

    var html = '<div class="card"><table class="data-table">';
    html += '<thead><tr><th>Agent</th><th>Sessions</th><th>Actions</th><th>First Seen</th><th>Last Seen</th><th>Top Actions</th></tr></thead>';
    html += '<tbody>';
    for (var i = 0; i < keys.length; i++) {
      var name = keys[i];
      var a = agents[name];
      var topActs = (a.topActions || []).slice(0, 3).map(function(ta) { return esc(ta.action) + ' (' + ta.count + ')'; }).join(', ');
      html += '<tr>';
      html += '<td>' + esc(name) + '</td>';
      html += '<td>' + a.sessions + '</td>';
      html += '<td>' + a.actions + '</td>';
      html += '<td>' + esc(formatTs(a.firstSeen)) + '</td>';
      html += '<td>' + esc(formatTs(a.lastSeen)) + '</td>';
      html += '<td>' + (topActs || '--') + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }

  function formatTs(iso) {
    if (!iso) return '--';
    try {
      var d = new Date(iso);
      if (isNaN(d.getTime())) return iso;
      return d.toISOString().replace('T', ' ').replace(/\\.\\d+Z$/, ' UTC');
    } catch(e) { return iso; }
  }

  // --- Policy Violations ---
  function violationsSection() {
    var violations = report.policyEvaluation.topViolations || [];
    if (violations.length === 0) {
      return '<div class="card"><div class="empty-state">No policy violations recorded.</div></div>';
    }

    var html = '<div class="card">';

    // Filter bar
    html += '<div class="filter-bar" id="violation-filters">';
    html += '<button class="filter-btn active" data-sev="all">All</button>';
    html += '<button class="filter-btn active" data-sev="critical">Critical</button>';
    html += '<button class="filter-btn active" data-sev="high">High</button>';
    html += '<button class="filter-btn active" data-sev="medium">Medium</button>';
    html += '<button class="filter-btn active" data-sev="low">Low</button>';
    html += '<button class="filter-btn active" data-sev="info">Info</button>';
    html += '<span class="violation-count" id="violation-count">' + violations.length + ' violations</span>';
    html += '</div>';

    html += '<table class="data-table" id="violations-table">';
    html += '<thead><tr><th>Action</th><th>Target</th><th>Agent</th><th>Count</th><th>Severity</th><th>Recommendation</th></tr></thead>';
    html += '<tbody>';
    for (var i = 0; i < violations.length; i++) {
      var v = violations[i];
      html += '<tr class="violation-row" data-severity="' + esc(v.severity) + '">';
      html += '<td>' + esc(v.action) + '</td>';
      html += '<td>' + esc(v.target) + '</td>';
      html += '<td>' + esc(v.agent) + '</td>';
      html += '<td>' + v.count + '</td>';
      html += '<td><span class="sev-badge sev-' + esc(v.severity) + '">' + esc(v.severity) + '</span></td>';
      html += '<td>' + esc(v.recommendation) + '</td>';
      html += '</tr>';
    }
    html += '</tbody></table></div>';
    return html;
  }

  // --- Runtime Protection Card ---
  function runtimeCard() {
    var rt = report.runtimeProtection;
    var html = '<div class="card">';
    html += '<div class="card-title">Runtime Protection (ARP)</div>';
    html += '<div class="detail-row"><span class="detail-key">ARP Status</span><span class="detail-val ' + (rt.arpActive ? 'status-active' : 'status-inactive') + '">' + (rt.arpActive ? 'Active' : 'Inactive') + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Processes Spawned</span><span class="detail-val">' + rt.processesSpawned + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Network Connections</span><span class="detail-val">' + rt.networkConnections + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Anomalies</span><span class="detail-val" style="color:' + (rt.anomalies > 0 ? 'var(--amber)' : 'var(--green)') + '">' + rt.anomalies + '</span></div>';
    html += '</div>';
    return html;
  }

  // --- Credential Exposure Card ---
  function credentialCard() {
    var cred = report.credentialExposure;
    var html = '<div class="card">';
    html += '<div class="card-title">Credential Exposure</div>';
    html += '<div class="detail-row"><span class="detail-key">Access Attempts</span><span class="detail-val">' + cred.accessAttempts + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Unique Credentials</span><span class="detail-val">' + cred.uniqueCredentials + '</span></div>';

    var providers = Object.keys(cred.byProvider || {});
    if (providers.length > 0) {
      html += '<div class="detail-row"><span class="detail-key">By Provider</span><span class="detail-val">&nbsp;</span></div>';
      html += '<div class="provider-list">';
      for (var p = 0; p < providers.length; p++) {
        html += '<span class="provider-tag">' + esc(providers[p]) + ': ' + cred.byProvider[providers[p]] + '</span>';
      }
      html += '</div>';
    }

    html += '</div>';
    return html;
  }

  // --- Supply Chain Card ---
  function supplyChainCard() {
    var sc = report.supplyChain;
    var html = '<div class="card">';
    html += '<div class="card-title">Supply Chain</div>';
    html += '<div class="detail-row"><span class="detail-key">Packages Installed</span><span class="detail-val">' + sc.packagesInstalled + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Advisories Found</span><span class="detail-val" style="color:' + (sc.advisoriesFound > 0 ? 'var(--amber)' : 'var(--green)') + '">' + sc.advisoriesFound + '</span></div>';
    html += '<div class="detail-row"><span class="detail-key">Blocked Installs</span><span class="detail-val" style="color:' + (sc.blockedInstalls > 0 ? 'var(--red)' : 'var(--text)') + '">' + sc.blockedInstalls + '</span></div>';
    html += '</div>';
    return html;
  }

  // --- Narrative Section ---
  function narrativeSection() {
    if (!narrative) return '';

    var html = '<div class="card narrative-section">';

    if (narrative.summary) {
      html += '<div class="narrative-block">';
      html += '<h4>Summary</h4>';
      html += '<div class="narrative-text">' + esc(narrative.summary) + '</div>';
      html += '</div>';
    }

    if (narrative.highlights && narrative.highlights.length > 0) {
      html += '<div class="narrative-block">';
      html += '<h4>Highlights</h4>';
      html += '<ul class="narrative-list narrative-highlight">';
      for (var h = 0; h < narrative.highlights.length; h++) {
        html += '<li>' + esc(narrative.highlights[h]) + '</li>';
      }
      html += '</ul></div>';
    }

    if (narrative.concerns && narrative.concerns.length > 0) {
      html += '<div class="narrative-block">';
      html += '<h4>Concerns</h4>';
      html += '<ul class="narrative-list narrative-concern">';
      for (var c = 0; c < narrative.concerns.length; c++) {
        html += '<li>' + esc(narrative.concerns[c]) + '</li>';
      }
      html += '</ul></div>';
    }

    if (narrative.recommendations && narrative.recommendations.length > 0) {
      html += '<div class="narrative-block">';
      html += '<h4>Recommendations</h4>';
      html += '<ul class="narrative-list narrative-rec">';
      for (var r = 0; r < narrative.recommendations.length; r++) {
        html += '<li>' + esc(narrative.recommendations[r]) + '</li>';
      }
      html += '</ul></div>';
    }

    html += '</div>';
    return html;
  }

  // --- Event binding ---
  function bindEvents() {
    document.addEventListener('click', function(e) {
      if (e.target.classList.contains('filter-btn') && e.target.dataset.sev) {
        var sev = e.target.dataset.sev;
        if (sev === 'all') {
          activeViolationFilters = new Set(['critical','high','medium','low','info']);
          var btns = document.querySelectorAll('#violation-filters .filter-btn');
          for (var b = 0; b < btns.length; b++) btns[b].classList.add('active');
        } else {
          if (activeViolationFilters.has(sev)) {
            activeViolationFilters.delete(sev);
          } else {
            activeViolationFilters.add(sev);
          }
          e.target.classList.toggle('active');
          var allBtn = document.querySelector('#violation-filters .filter-btn[data-sev="all"]');
          if (allBtn) allBtn.classList.toggle('active', activeViolationFilters.size === 5);
        }
        applyViolationFilters();
      }
    });
  }

  function applyViolationFilters() {
    var rows = document.querySelectorAll('.violation-row');
    var visible = 0;
    for (var i = 0; i < rows.length; i++) {
      var sev = rows[i].dataset.severity;
      var show = activeViolationFilters.has(sev);
      rows[i].style.display = show ? '' : 'none';
      if (show) visible++;
    }
    var counter = document.getElementById('violation-count');
    if (counter) counter.textContent = visible + ' of ' + rows.length + ' violations';
  }

  init();
})();
`;

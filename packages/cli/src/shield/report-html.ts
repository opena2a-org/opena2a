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

import type { WeeklyReport, ReportNarrative, PostureTrend } from './types.js';
import type { ClassifiedFinding } from './findings.js';

/**
 * Generate the executive summary text from report data.
 * No LLM needed -- deterministic sentence generation.
 */
export function generateExecutiveSummary(
  report: WeeklyReport,
  findings: ClassifiedFinding[],
  trend: PostureTrend | null,
): string {
  const sentences: string[] = [];

  // Sentence 1: Score + grade + trend
  if (trend) {
    const dir = trend.direction === 'improving' ? 'improved'
      : trend.direction === 'declining' ? 'declined' : 'remained stable';
    sentences.push(
      `Security posture score ${dir} from ${trend.previousScore}/${trend.previousGrade} to ${report.posture.score}/${report.posture.grade} over ${trend.periodDays} day${trend.periodDays !== 1 ? 's' : ''} (delta: ${trend.delta > 0 ? '+' : ''}${trend.delta}).`,
    );
  } else {
    sentences.push(
      `Security posture score: ${report.posture.score}/100 (Grade ${report.posture.grade}). No previous snapshot available for trend comparison.`,
    );
  }

  // Sentence 2: Top finding category + count
  const criticalFindings = findings.filter(f => f.finding.severity === 'critical');
  const highFindings = findings.filter(f => f.finding.severity === 'high');
  if (criticalFindings.length > 0) {
    const totalCrit = criticalFindings.reduce((sum, f) => sum + f.count, 0);
    sentences.push(
      `${totalCrit} critical finding${totalCrit !== 1 ? 's' : ''} across ${criticalFindings.length} categor${criticalFindings.length !== 1 ? 'ies' : 'y'} require immediate attention.`,
    );
  } else if (highFindings.length > 0) {
    const totalHigh = highFindings.reduce((sum, f) => sum + f.count, 0);
    sentences.push(
      `${totalHigh} high-severity finding${totalHigh !== 1 ? 's' : ''} detected. No critical findings.`,
    );
  } else if (findings.length > 0) {
    sentences.push(
      `${findings.length} finding${findings.length !== 1 ? 's' : ''} detected, none above medium severity.`,
    );
  } else {
    sentences.push('No security findings detected in this reporting period.');
  }

  // Sentence 3: Policy posture
  const pe = report.policyEvaluation;
  if (pe.blocked > 0) {
    sentences.push(
      `Policy enforcement is active: ${pe.blocked} action${pe.blocked !== 1 ? 's' : ''} blocked, ${pe.monitored} monitored.`,
    );
  } else if (pe.monitored > 0) {
    sentences.push(
      `Policy is in monitor-only mode: ${pe.monitored} action${pe.monitored !== 1 ? 's' : ''} logged but not blocked.`,
    );
  } else {
    sentences.push('No policy enforcement activity recorded.');
  }

  // Sentence 4: Config integrity
  const ci = report.configIntegrity;
  if (ci.filesMonitored > 0) {
    if (ci.tamperedFiles.length > 0) {
      sentences.push(
        `WARNING: ${ci.tamperedFiles.length} of ${ci.filesMonitored} monitored config file${ci.filesMonitored !== 1 ? 's' : ''} show tampering.`,
      );
    } else {
      sentences.push(
        `All ${ci.filesMonitored} monitored config file${ci.filesMonitored !== 1 ? 's' : ''} have valid signatures.`,
      );
    }
  }

  return sentences.join(' ');
}

export function generateShieldHtmlReport(
  report: WeeklyReport,
  narrative?: ReportNarrative | null,
  findings?: ClassifiedFinding[],
  trend?: PostureTrend | null,
): string {
  const findingsData = findings ?? [];
  const trendData = trend ?? report.posture.trend ?? null;
  const executiveSummary = generateExecutiveSummary(report, findingsData, trendData);
  const jsonData = JSON.stringify({
    report,
    narrative: narrative ?? null,
    findings: findingsData,
    trend: trendData,
    executiveSummary,
  });

  const findingsCount = findingsData.length;
  const violationsCount = (report.policyEvaluation.topViolations || []).length;
  const agentKeys = Object.keys(report.agentActivity.byAgent || {});

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
    <div class="header-top">
      <div class="header-left">
        <h1 class="logo">Shield</h1>
        <span class="header-sep">|</span>
        <span class="header-label">Security Posture Report</span>
      </div>
      <div class="header-right">
        <span class="header-meta">${escapeHtml(report.hostname)} &middot; ${escapeHtml(formatDate(report.periodStart))} to ${escapeHtml(formatDate(report.periodEnd))}</span>
      </div>
    </div>
    <nav class="nav-tabs" id="main-nav">
      <button class="nav-tab active" data-page="overview">Overview</button>
      <button class="nav-tab" data-page="findings">Findings${findingsCount > 0 ? ` <span class="nav-badge">${findingsCount}</span>` : ''}</button>
      <button class="nav-tab" data-page="agents">Agents${agentKeys.length > 0 ? ` <span class="nav-badge">${agentKeys.length}</span>` : ''}</button>
      <button class="nav-tab" data-page="violations">Violations${violationsCount > 0 ? ` <span class="nav-badge nav-badge-warn">${violationsCount}</span>` : ''}</button>
      <button class="nav-tab" data-page="protection">Protection</button>
      <button class="nav-tab" data-page="timeline">Timeline</button>
    </nav>
  </header>

  <main class="main">
    <div class="page active" id="page-overview"></div>
    <div class="page" id="page-findings"></div>
    <div class="page" id="page-agents"></div>
    <div class="page" id="page-violations"></div>
    <div class="page" id="page-protection"></div>
    <div class="page" id="page-timeline"></div>
  </main>

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

.header{position:sticky;top:0;background:var(--bg);z-index:100;border-bottom:1px solid var(--card-border)}
.header-top{display:flex;justify-content:space-between;align-items:center;padding:12px 24px 0}
.header-left{display:flex;align-items:center;gap:12px}
.logo{font-size:20px;font-weight:700;color:var(--primary)}
.header-sep{color:var(--card-border)}
.header-label{color:var(--muted);font-size:14px}
.header-right{display:flex;align-items:center;gap:12px}
.header-meta{color:var(--dim);font-size:12px}

.nav-tabs{display:flex;gap:2px;padding:12px 24px 0;overflow-x:auto}
.nav-tab{background:transparent;border:none;border-bottom:2px solid transparent;padding:10px 16px;color:var(--muted);cursor:pointer;font-family:var(--font);font-size:13px;font-weight:600;transition:all .15s;white-space:nowrap;display:flex;align-items:center;gap:6px}
.nav-tab:hover{color:var(--text);border-bottom-color:var(--card-border)}
.nav-tab.active{color:var(--primary);border-bottom-color:var(--primary)}
.nav-badge{background:var(--card-border);color:var(--text);font-size:10px;padding:1px 6px;border-radius:10px;font-weight:700}
.nav-badge-warn{background:rgba(249,115,22,0.25);color:var(--high)}

.page{display:none}
.page.active{display:block}

.main{max-width:1280px;margin:0 auto;padding:24px}

.overview-top{display:grid;grid-template-columns:260px 1fr 1fr;gap:var(--gap);margin-bottom:24px}
@media(max-width:900px){.overview-top{grid-template-columns:1fr}}

.donut-legend{display:flex;flex-wrap:wrap;gap:12px;margin-top:12px}
.donut-legend-item{display:flex;align-items:center;gap:6px;font-size:12px;color:var(--muted)}
.donut-legend-dot{width:10px;height:10px;border-radius:2px;flex-shrink:0}

.search-box{display:flex;margin-bottom:14px}
.search-input{flex:1;background:var(--bg);border:1px solid var(--card-border);border-radius:var(--radius);padding:8px 12px;color:var(--text);font-family:var(--font);font-size:12px;outline:none;transition:border-color .15s}
.search-input:focus{border-color:var(--primary)}
.search-input::placeholder{color:var(--dim)}

.finding-row{cursor:pointer;transition:background .15s}
.finding-row:hover td{background:rgba(6,182,212,0.04)}
.finding-expand{display:none;background:rgba(0,0,0,0.15)}
.finding-expand.open{display:table-row}
.finding-detail{padding:12px 20px}
.finding-detail-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px}
.finding-meta{font-size:11px;color:var(--muted);margin-bottom:4px;text-transform:uppercase;letter-spacing:0.03em}
.finding-val{font-size:12px;color:var(--text);margin-bottom:10px}
.finding-examples{margin-top:8px}
.finding-example{background:var(--bg);border:1px solid var(--card-border);border-radius:4px;padding:8px 12px;margin-bottom:6px;font-size:11px;overflow-x:auto}

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

/* Compliance badges */
.badge-owasp{background:#f59e0b;color:#000;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700;display:inline-block;margin:1px 2px}
.badge-mitre{background:#8b5cf6;color:#fff;padding:2px 6px;border-radius:3px;font-size:10px;font-weight:700;display:inline-block;margin:1px 2px}
.finding-id{font-family:var(--font);font-size:11px;color:var(--primary);font-weight:600;cursor:help}

/* Remediation command */
.remediation-cmd{display:flex;align-items:center;gap:6px}
.remediation-code{background:rgba(255,255,255,0.05);border:1px solid var(--card-border);border-radius:4px;padding:3px 8px;font-size:11px;font-family:var(--font);color:var(--text);max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.copy-btn{background:transparent;border:1px solid var(--card-border);border-radius:4px;padding:3px 6px;color:var(--muted);cursor:pointer;font-family:var(--font);font-size:10px;transition:all .2s}
.copy-btn:hover{border-color:var(--primary);color:var(--primary)}
.copy-btn.copied{border-color:var(--green);color:var(--green)}

/* Executive summary */
.exec-summary{background:var(--card);border:1px solid var(--card-border);border-radius:var(--radius);padding:20px;margin-bottom:24px}
.exec-summary-title{font-size:13px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:0.05em;margin-bottom:12px}
.exec-summary-text{color:var(--text);font-size:13px;line-height:1.8}

/* Trend indicator */
.trend-indicator{display:inline-flex;align-items:center;gap:6px;font-size:13px;margin-top:8px}
.trend-improving{color:var(--green)}
.trend-declining{color:var(--red)}
.trend-stable{color:var(--muted)}
.trend-delta{font-weight:700}

@media(max-width:768px){
  .posture-section{grid-template-columns:1fr}
  .detail-grid{grid-template-columns:1fr}
  .header-top{flex-direction:column;gap:8px}
  .header-right{width:100%}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
  .finding-detail-grid{grid-template-columns:1fr}
  .nav-tabs{gap:0}
}
`;

// --- Embedded JavaScript ---

const JS = `
(function() {
  'use strict';
  var raw = JSON.parse(document.getElementById('report-data').textContent);
  var report = raw.report;
  var narrative = raw.narrative;
  var findings = raw.findings || [];
  var trend = raw.trend || null;
  var executiveSummary = raw.executiveSummary || '';
  var currentPage = 'overview';
  var activeViolationFilters = new Set(['critical','high','medium','low','info']);
  var pagesRendered = {};

  function init() { renderPage('overview'); bindNav(); }

  function esc(s) { if (!s) return ''; var d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
  function formatTs(iso) { if (!iso) return '--'; try { var d = new Date(iso); if (isNaN(d.getTime())) return iso; return d.toISOString().replace('T',' ').replace(/\\.\\d+Z$/,' UTC'); } catch(e) { return iso; } }
  function scoreColor(s) { return s >= 90 ? 'var(--green)' : s >= 70 ? 'var(--primary)' : s >= 50 ? 'var(--medium)' : 'var(--red)'; }
  function statCard(v, l, c) { return '<div class="stat-card"><div class="stat-value" style="color:'+c+'">'+v+'</div><div class="stat-label">'+l+'</div></div>'; }

  function bindNav() {
    document.getElementById('main-nav').addEventListener('click', function(e) {
      var btn = e.target.closest('.nav-tab'); if (!btn) return;
      var pg = btn.dataset.page; if (!pg || pg === currentPage) return;
      var tabs = document.querySelectorAll('.nav-tab');
      for (var i=0;i<tabs.length;i++) tabs[i].classList.toggle('active', tabs[i].dataset.page===pg);
      var pages = document.querySelectorAll('.page');
      for (var i=0;i<pages.length;i++) pages[i].classList.toggle('active', pages[i].id==='page-'+pg);
      currentPage = pg; renderPage(pg);
    });
  }

  function renderPage(pg) {
    if (pagesRendered[pg]) return; pagesRendered[pg] = true;
    var el = document.getElementById('page-'+pg);
    switch(pg) {
      case 'overview': el.innerHTML = renderOverview(); break;
      case 'findings': el.innerHTML = renderFindings(); bindFindingExpand(); break;
      case 'agents': el.innerHTML = renderAgents(); break;
      case 'violations': el.innerHTML = renderViolations(); bindViolationFilters(); break;
      case 'protection': el.innerHTML = renderProtection(); break;
      case 'timeline': el.innerHTML = renderTimeline(); break;
    }
  }

  // --- Gauge SVG ---
  function gaugeCircle(score) {
    var sz=170,cx=sz/2,cy=sz/2,r=65,sw=10,circ=2*Math.PI*r;
    var pct=Math.max(0,Math.min(100,score))/100,dash=pct*circ,gap=circ-dash;
    var clr = score>=90?'#22c55e':score>=70?'#06b6d4':score>=50?'#eab308':'#ef4444';
    var g = report.posture.grade||'';
    var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';
    s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="'+sw+'"/>';
    s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+clr+'" stroke-width="'+sw+'" stroke-dasharray="'+dash+' '+gap+'" stroke-dashoffset="'+(circ*0.25)+'" stroke-linecap="round" transform="rotate(-90 '+cx+' '+cy+')"/>';
    s+='<text x="'+cx+'" y="'+(cy-6)+'" text-anchor="middle" dominant-baseline="middle" font-size="32" font-weight="700" fill="'+clr+'" font-family="var(--font)">'+score+'</text>';
    s+='<text x="'+cx+'" y="'+(cy+20)+'" text-anchor="middle" dominant-baseline="middle" font-size="14" font-weight="600" fill="'+clr+'" font-family="var(--font)">Grade '+esc(g)+'</text>';
    s+='</svg>'; return s;
  }

  function trendHtml() {
    if (!trend) return '';
    var cls='trend-'+trend.direction;
    var arrow=trend.direction==='improving'?'&#9650;':trend.direction==='declining'?'&#9660;':'&#9654;';
    var sign=trend.delta>0?'+':'';
    return '<div class="trend-indicator '+cls+'">'+arrow+' <span class="trend-delta">'+sign+trend.delta+'</span> from '+trend.previousScore+'/'+esc(trend.previousGrade)+' ('+trend.periodDays+'d)</div>';
  }

  // --- Donut chart ---
  function donutChart() {
    var counts={critical:0,high:0,medium:0,low:0,info:0};
    var violations=report.policyEvaluation.topViolations||[];
    for(var i=0;i<violations.length;i++) counts[violations[i].severity]=(counts[violations[i].severity]||0)+violations[i].count;
    for(var i=0;i<findings.length;i++){var s=findings[i].finding.severity;counts[s]=(counts[s]||0)+findings[i].count;}
    var total=counts.critical+counts.high+counts.medium+counts.low+counts.info;
    if(total===0) return '<div class="empty-state">No findings in this period.</div>';
    var sz=150,cx=sz/2,cy=sz/2,r=50,sw=18,circ=2*Math.PI*r;
    var colors={critical:'#ef4444',high:'#f97316',medium:'#eab308',low:'#3b82f6',info:'#6b7280'};
    var order=['critical','high','medium','low','info'];
    var off=0,svg='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';
    for(var j=0;j<order.length;j++){var sv=order[j],c=counts[sv]||0;if(!c)continue;var p=c/total,d=p*circ,g=circ-d;
      svg+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+colors[sv]+'" stroke-width="'+sw+'" stroke-dasharray="'+d+' '+g+'" stroke-dashoffset="'+(-off+circ*0.25)+'" transform="rotate(-90 '+cx+' '+cy+')"/>';off+=d;}
    svg+='<text x="'+cx+'" y="'+cy+'" text-anchor="middle" dominant-baseline="middle" font-size="18" font-weight="700" fill="var(--text)" font-family="var(--font)">'+total+'</text></svg>';
    var leg='<div class="donut-legend" style="flex-direction:column">';
    for(var k=0;k<order.length;k++){var sv=order[k];if(!counts[sv])continue;leg+='<div class="donut-legend-item"><div class="donut-legend-dot" style="background:'+colors[sv]+'"></div>'+sv.charAt(0).toUpperCase()+sv.slice(1)+': '+counts[sv]+'</div>';}
    leg+='</div>';
    return '<div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap">'+svg+leg+'</div>';
  }

  function factorsHtml() {
    var factors=report.posture.factors||[];if(!factors.length) return '';
    var h='<div class="card"><div class="card-title">Score Factors</div>';
    for(var i=0;i<factors.length;i++){var f=factors[i];var bc=f.score>=70?'var(--green)':f.score>=40?'var(--medium)':'var(--red)';
      h+='<div class="factor-row"><span class="factor-name">'+esc(f.name)+(f.weight?' ('+Math.round(f.weight*100)+'%)':'')+'</span><div class="factor-bar"><div class="factor-fill" style="width:'+f.score+'%;background:'+bc+'"></div></div><span class="factor-score">'+f.score+'</span><span class="factor-detail">'+esc(f.detail)+'</span></div>';}
    h+='</div>'; return h;
  }

  // ======================== OVERVIEW ========================
  function renderOverview() {
    var h='';
    h+='<div class="stats-grid">';
    h+=statCard(report.posture.score+'/100','Score',scoreColor(report.posture.score));
    h+=statCard('Grade '+(report.posture.grade||'--'),'Posture',scoreColor(report.posture.score));
    h+=statCard(report.agentActivity.totalSessions,'Sessions','var(--primary)');
    h+=statCard(report.agentActivity.totalActions,'Events','var(--text)');
    h+=statCard(report.policyEvaluation.monitored,'Monitored','var(--muted)');
    h+=statCard(report.policyEvaluation.blocked,'Blocked',report.policyEvaluation.blocked>0?'var(--red)':'var(--text)');
    h+='</div>';

    h+='<h2 class="section-title">Posture Score</h2>';
    h+='<div class="overview-top">';
    h+='<div class="gauge-card">'+gaugeCircle(report.posture.score)+trendHtml()+'</div>';
    h+='<div class="card"><div class="card-title">Severity Breakdown</div>'+donutChart()+'</div>';
    h+=factorsHtml();
    h+='</div>';

    if(executiveSummary){h+='<div class="exec-summary"><div class="exec-summary-title">Executive Summary</div><div class="exec-summary-text">'+esc(executiveSummary)+'</div></div>';}

    if(findings.length>0){
      h+='<h2 class="section-title">Top Findings</h2><div class="card"><table class="data-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Count</th><th>OWASP</th><th>MITRE</th></tr></thead><tbody>';
      var top=findings.slice(0,5);
      for(var i=0;i<top.length;i++){var f=top[i];h+='<tr><td><span class="finding-id">'+esc(f.finding.id)+'</span></td><td>'+esc(f.finding.title)+'</td><td><span class="sev-badge sev-'+esc(f.finding.severity)+'">'+esc(f.finding.severity)+'</span></td><td>'+f.count+'</td><td><span class="badge-owasp">'+esc(f.finding.owaspAgentic)+'</span></td><td><span class="badge-mitre">'+esc(f.finding.mitreAtlas)+'</span></td></tr>';}
      h+='</tbody></table>';
      if(findings.length>5) h+='<div style="text-align:center;padding:8px;color:var(--dim);font-size:11px;cursor:pointer" onclick="document.querySelector(\\'.nav-tab[data-page=findings]\\').click()">View all '+findings.length+' findings --></div>';
      h+='</div>';
    }
    return h;
  }

  // ======================== FINDINGS ========================
  function renderFindings() {
    if(!findings.length) return '<h2 class="section-title">Classified Findings</h2><div class="card"><div class="empty-state">No security findings classified in this period.</div></div>';
    var h='<h2 class="section-title">Classified Findings ('+findings.length+')</h2>';
    h+='<div class="search-box"><input type="text" class="search-input" id="findings-search" placeholder="Search findings by ID, title, OWASP, MITRE..." oninput="window._filterFindings(this.value)"></div>';
    h+='<div class="card"><table class="data-table" id="findings-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Count</th><th>OWASP</th><th>MITRE</th><th>Remediation</th></tr></thead><tbody>';
    for(var i=0;i<findings.length;i++){var f=findings[i];
      h+='<tr class="finding-row" data-idx="'+i+'" data-search="'+esc((f.finding.id+' '+f.finding.title+' '+f.finding.owaspAgentic+' '+f.finding.mitreAtlas+' '+f.finding.category).toLowerCase())+'">';
      h+='<td><span class="finding-id">'+esc(f.finding.id)+'</span></td><td>'+esc(f.finding.title)+'</td>';
      h+='<td><span class="sev-badge sev-'+esc(f.finding.severity)+'">'+esc(f.finding.severity)+'</span></td><td>'+f.count+'</td>';
      h+='<td><span class="badge-owasp">'+esc(f.finding.owaspAgentic)+'</span></td><td><span class="badge-mitre">'+esc(f.finding.mitreAtlas)+'</span></td>';
      h+='<td><div class="remediation-cmd"><code class="remediation-code" title="'+esc(f.finding.remediation)+'">'+esc(f.finding.remediation)+'</code><button class="copy-btn" data-cmd="'+esc(f.finding.remediation)+'" onclick="event.stopPropagation();copyCmd(this)">Copy</button></div></td></tr>';
      h+='<tr class="finding-expand" id="finding-detail-'+i+'"><td colspan="7"><div class="finding-detail"><div class="finding-detail-grid">';
      h+='<div><div class="finding-meta">Description</div><div class="finding-val">'+esc(f.finding.description)+'</div></div>';
      h+='<div><div class="finding-meta">Category</div><div class="finding-val">'+esc(f.finding.category)+'</div><div class="finding-meta" style="margin-top:8px">Time Range</div><div class="finding-val">'+esc(formatTs(f.firstSeen))+' to '+esc(formatTs(f.lastSeen))+'</div></div></div>';
      if(f.examples&&f.examples.length>0){h+='<div class="finding-examples"><div class="finding-meta">Event Examples ('+f.examples.length+')</div>';
        for(var ei=0;ei<f.examples.length;ei++){var ex=f.examples[ei];h+='<div class="finding-example"><span style="color:var(--dim)">'+esc(formatTs(ex.timestamp))+'</span> <span style="color:var(--primary)">'+esc(ex.source)+'</span>: '+esc(ex.action)+' -> '+esc(ex.target)+' [<span class="sev-badge sev-'+esc(ex.severity)+'" style="font-size:9px;padding:1px 4px">'+esc(ex.severity)+'</span>]</div>';}
        h+='</div>';}
      h+='</div></td></tr>';}
    h+='</tbody></table></div>';return h;
  }

  function bindFindingExpand(){document.addEventListener('click',function(e){var row=e.target.closest('.finding-row');if(!row)return;var idx=row.dataset.idx;if(idx===undefined)return;var det=document.getElementById('finding-detail-'+idx);if(det)det.classList.toggle('open');});}
  window._filterFindings=function(q){q=q.toLowerCase().trim();var rows=document.querySelectorAll('#findings-table .finding-row');var dets=document.querySelectorAll('#findings-table .finding-expand');for(var i=0;i<rows.length;i++){var m=!q||(rows[i].dataset.search||'').indexOf(q)>=0;rows[i].style.display=m?'':'none';if(dets[i]){dets[i].style.display='none';dets[i].classList.remove('open');}}};

  // ======================== AGENTS ========================
  function renderAgents() {
    var agents=report.agentActivity.byAgent;var keys=Object.keys(agents);
    if(!keys.length) return '<h2 class="section-title">Agent Activity</h2><div class="card"><div class="empty-state">No agent activity recorded.</div></div>';
    var h='<h2 class="section-title">Agent Activity ('+keys.length+' agents)</h2>';
    h+='<div class="stats-grid">'+statCard(keys.length,'Agents','var(--primary)')+statCard(report.agentActivity.totalSessions,'Sessions','var(--text)')+statCard(report.agentActivity.totalActions,'Total Actions','var(--text)')+'</div>';
    h+='<div class="card"><table class="data-table"><thead><tr><th>Agent</th><th>Sessions</th><th>Actions</th><th>First Seen</th><th>Last Seen</th><th>Top Actions</th></tr></thead><tbody>';
    for(var i=0;i<keys.length;i++){var name=keys[i],a=agents[name];
      var topActs=(a.topActions||[]).slice(0,4).map(function(ta){return '<span style="color:var(--primary)">'+esc(ta.action)+'</span> <span style="color:var(--dim)">('+ta.count+')</span>';}).join(', ');
      h+='<tr><td style="font-weight:600;color:var(--primary)">'+esc(name)+'</td><td>'+a.sessions+'</td><td>'+a.actions+'</td><td style="font-size:11px;color:var(--dim)">'+esc(formatTs(a.firstSeen))+'</td><td style="font-size:11px;color:var(--dim)">'+esc(formatTs(a.lastSeen))+'</td><td style="font-size:11px">'+(topActs||'--')+'</td></tr>';}
    h+='</tbody></table></div>';return h;
  }

  // ======================== VIOLATIONS ========================
  function renderViolations() {
    var violations=report.policyEvaluation.topViolations||[];
    if(!violations.length) return '<h2 class="section-title">Policy Violations</h2><div class="card"><div class="empty-state">No policy violations recorded.</div></div>';
    var h='<h2 class="section-title">Policy Violations</h2>';
    h+='<div class="stats-grid">'+statCard(violations.length,'Violations','var(--red)')+statCard(report.policyEvaluation.monitored,'Monitored','var(--muted)')+statCard(report.policyEvaluation.blocked,'Blocked',report.policyEvaluation.blocked>0?'var(--red)':'var(--text)')+'</div>';
    h+='<div class="card">';
    h+='<div class="filter-bar" id="violation-filters"><button class="filter-btn active" data-sev="all">All</button><button class="filter-btn active" data-sev="critical">Critical</button><button class="filter-btn active" data-sev="high">High</button><button class="filter-btn active" data-sev="medium">Medium</button><button class="filter-btn active" data-sev="low">Low</button><button class="filter-btn active" data-sev="info">Info</button><span class="violation-count" id="violation-count">'+violations.length+' violations</span></div>';
    h+='<div class="search-box"><input type="text" class="search-input" id="violations-search" placeholder="Search violations..." oninput="window._applyVF()"></div>';
    h+='<table class="data-table" id="violations-table"><thead><tr><th>Finding</th><th>Action</th><th>Target</th><th>Agent</th><th>Count</th><th>Severity</th><th>Compliance</th><th>Remediation</th></tr></thead><tbody>';
    for(var i=0;i<violations.length;i++){var v=violations[i];
      h+='<tr class="violation-row" data-severity="'+esc(v.severity)+'" data-search="'+esc(((v.findingId||'')+' '+v.action+' '+v.target+' '+v.agent).toLowerCase())+'">';
      h+='<td>'+(v.findingId?'<span class="finding-id" title="'+esc(v.recommendation)+'">'+esc(v.findingId)+'</span>':'<span style="color:var(--dim)">--</span>')+'</td>';
      h+='<td>'+esc(v.action)+'</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="'+esc(v.target)+'">'+esc(v.target)+'</td><td>'+esc(v.agent)+'</td><td>'+v.count+'</td>';
      h+='<td><span class="sev-badge sev-'+esc(v.severity)+'">'+esc(v.severity)+'</span></td><td>';
      if(v.compliance&&v.compliance.length>0){for(var ci=0;ci<v.compliance.length;ci++){var tag=v.compliance[ci];if(tag.indexOf('ASI')===0)h+='<span class="badge-owasp">'+esc(tag)+'</span>';else if(tag.indexOf('AML')===0)h+='<span class="badge-mitre">'+esc(tag)+'</span>';}}else h+='--';
      h+='</td><td>';
      if(v.remediationCommand){h+='<div class="remediation-cmd"><code class="remediation-code" title="'+esc(v.remediationCommand)+'">'+esc(v.remediationCommand)+'</code><button class="copy-btn" data-cmd="'+esc(v.remediationCommand)+'" onclick="copyCmd(this)">Copy</button></div>';}else h+=esc(v.recommendation);
      h+='</td></tr>';}
    h+='</tbody></table></div>';return h;
  }

  function bindViolationFilters(){var bar=document.getElementById('violation-filters');if(!bar)return;bar.addEventListener('click',function(e){if(!e.target.classList.contains('filter-btn'))return;var sev=e.target.dataset.sev;if(sev==='all'){activeViolationFilters=new Set(['critical','high','medium','low','info']);var btns=bar.querySelectorAll('.filter-btn');for(var b=0;b<btns.length;b++)btns[b].classList.add('active');}else{if(activeViolationFilters.has(sev))activeViolationFilters.delete(sev);else activeViolationFilters.add(sev);e.target.classList.toggle('active');var ab=bar.querySelector('.filter-btn[data-sev="all"]');if(ab)ab.classList.toggle('active',activeViolationFilters.size===5);}window._applyVF();});}
  window._applyVF=function(){var rows=document.querySelectorAll('.violation-row');var q=((document.getElementById('violations-search')||{}).value||'').toLowerCase().trim();var vis=0;for(var i=0;i<rows.length;i++){var sv=rows[i].dataset.severity;var sm=activeViolationFilters.has(sv);var qm=!q||(rows[i].dataset.search||'').indexOf(q)>=0;var show=sm&&qm;rows[i].style.display=show?'':'none';if(show)vis++;}var c=document.getElementById('violation-count');if(c)c.textContent=vis+' of '+rows.length+' violations';};

  // ======================== PROTECTION ========================
  function renderProtection() {
    var h='<h2 class="section-title">Protection Details</h2><div class="detail-grid">';
    var rt=report.runtimeProtection;
    h+='<div class="card"><div class="card-title">Runtime Protection (ARP)</div>';
    h+=dr('ARP Status',rt.arpActive?'<span class="status-active">Active</span>':'<span class="status-inactive">Inactive</span>');
    h+=dr('Processes Spawned',rt.processesSpawned)+dr('Network Connections',rt.networkConnections);
    h+=dr('Anomalies','<span style="color:'+(rt.anomalies>0?'var(--amber)':'var(--green)')+'">'+rt.anomalies+'</span>')+'</div>';
    var cred=report.credentialExposure;
    h+='<div class="card"><div class="card-title">Credential Exposure</div>';
    h+=dr('Access Attempts',cred.accessAttempts)+dr('Unique Credentials',cred.uniqueCredentials);
    var providers=Object.keys(cred.byProvider||{});
    if(providers.length>0){h+='<div class="detail-row"><span class="detail-key">By Provider</span><span class="detail-val">&nbsp;</span></div><div class="provider-list">';for(var p=0;p<providers.length;p++)h+='<span class="provider-tag">'+esc(providers[p])+': '+cred.byProvider[providers[p]]+'</span>';h+='</div>';}
    h+='</div>';
    var sc=report.supplyChain;
    h+='<div class="card"><div class="card-title">Supply Chain</div>';
    h+=dr('Packages Installed',sc.packagesInstalled)+dr('Advisories Found','<span style="color:'+(sc.advisoriesFound>0?'var(--amber)':'var(--green)')+'">'+sc.advisoriesFound+'</span>');
    h+=dr('Blocked Installs','<span style="color:'+(sc.blockedInstalls>0?'var(--red)':'var(--text)')+'">'+sc.blockedInstalls+'</span>')+'</div>';
    var ci=report.configIntegrity;
    h+='<div class="card"><div class="card-title">Config Integrity</div>';
    h+=dr('Files Monitored',ci.filesMonitored);
    h+=dr('Signature Status',ci.signatureStatus==='signed'||ci.signatureStatus==='valid'?'<span class="status-active">Valid</span>':ci.signatureStatus==='unsigned'?'<span style="color:var(--amber)">Unsigned</span>':'<span class="status-inactive">'+esc(ci.signatureStatus)+'</span>');
    if(ci.tamperedFiles&&ci.tamperedFiles.length>0){h+=dr('Tampered Files','<span class="status-inactive">'+ci.tamperedFiles.length+'</span>');for(var t=0;t<ci.tamperedFiles.length;t++)h+='<div style="color:var(--red);font-size:12px;padding:2px 0">'+esc(ci.tamperedFiles[t])+'</div>';}
    else if(ci.filesMonitored>0) h+=dr('Integrity','<span class="status-active">All files valid</span>');
    h+='</div></div>';return h;
  }
  function dr(k,v){return '<div class="detail-row"><span class="detail-key">'+esc(k)+'</span><span class="detail-val">'+v+'</span></div>';}

  // ======================== TIMELINE ========================
  function renderTimeline() {
    if(!narrative) return '<h2 class="section-title">Event Timeline</h2><div class="card"><div class="empty-state">No narrative analysis available. Use --analyze flag to generate AI-powered event analysis.</div></div>';
    var h='<h2 class="section-title">Event Timeline</h2><div class="card">';
    if(narrative.summary){h+='<div class="narrative-block"><h4>Summary</h4><div class="narrative-text">'+esc(narrative.summary)+'</div></div>';}
    if(narrative.highlights&&narrative.highlights.length>0){h+='<div class="narrative-block"><h4>Highlights</h4><ul class="narrative-list narrative-highlight">';for(var i=0;i<narrative.highlights.length;i++)h+='<li>'+esc(narrative.highlights[i])+'</li>';h+='</ul></div>';}
    if(narrative.concerns&&narrative.concerns.length>0){h+='<div class="narrative-block"><h4>Concerns</h4><ul class="narrative-list narrative-concern">';for(var i=0;i<narrative.concerns.length;i++)h+='<li>'+esc(narrative.concerns[i])+'</li>';h+='</ul></div>';}
    if(narrative.recommendations&&narrative.recommendations.length>0){h+='<div class="narrative-block"><h4>Recommendations</h4><ul class="narrative-list narrative-rec">';for(var i=0;i<narrative.recommendations.length;i++)h+='<li>'+esc(narrative.recommendations[i])+'</li>';h+='</ul></div>';}
    h+='</div>';return h;
  }

  // --- Copy command ---
  window.copyCmd=function(btn){var cmd=btn.getAttribute('data-cmd');if(!cmd)return;if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(cmd).then(function(){btn.textContent='OK';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);});}else{var ta=document.createElement('textarea');ta.value=cmd;ta.style.position='fixed';ta.style.left='-9999px';document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);btn.textContent='OK';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);}};

  init();
})();
`;

/**
 * Interactive HTML report generator (ScoutSuite-style).
 *
 * Generates a self-contained HTML file with:
 * - Dark theme matching HMA website design language
 * - Embedded JSON data (no external dependencies)
 * - Hash-based SPA navigation (#dashboard, #findings, #finding-CRED-001)
 * - Severity filtering and text search
 * - Audience toggle (Executive / Engineering)
 * - SVG donut chart for severity breakdown
 *
 * Design tokens from hackmyagent-web:
 *   Background: #0a0a0a, Card: #171717, Border: #262626
 *   Primary: #14b8a6 (teal), Muted: #a3a3a3
 *   Critical: #ef4444, High: #f97316, Medium: #eab308, Low: #3b82f6
 *   Font: system monospace (JetBrains Mono fallback)
 */

export interface InteractiveReportFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  explanation?: string;
  businessImpact?: string;
  category: string;
  file?: string;
  line?: number;
  fix?: string;
  passed: boolean;
  evidence?: string;
}

export interface InteractiveReportData {
  metadata: {
    generatedAt: string;
    toolVersion: string;
    targetName: string;
    scanType: string;
  };
  summary: {
    totalFindings: number;
    bySeverity: Record<string, number>;
    score?: number;
    grade?: string;
  };
  findings: InteractiveReportFinding[];
}

/**
 * Generate a self-contained interactive HTML report.
 */
export function generateInteractiveHtml(data: InteractiveReportData): string {
  const jsonData = JSON.stringify(data);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenA2A Security Report - ${escapeHtml(data.metadata.targetName)}</title>
<style>
${CSS}
</style>
</head>
<body>
<script id="report-data" type="application/json">${escapeHtml(jsonData)}</script>
<div id="app">
  <header class="header">
    <div class="header-left">
      <h1 class="logo">OpenA2A</h1>
      <span class="header-sep">|</span>
      <span class="header-label">Security Report</span>
    </div>
    <div class="header-right">
      <div class="audience-toggle" id="audience-toggle">
        <button class="toggle-btn active" data-audience="engineering">Engineering</button>
        <button class="toggle-btn" data-audience="executive">Executive</button>
      </div>
      <nav class="nav">
        <a href="#dashboard" class="nav-link active" data-view="dashboard">Dashboard</a>
        <a href="#findings" class="nav-link" data-view="findings">Findings</a>
      </nav>
    </div>
  </header>

  <main class="main">
    <div id="view-dashboard" class="view active"></div>
    <div id="view-findings" class="view"></div>
  </main>

  <footer class="footer">
    <span>Generated ${escapeHtml(data.metadata.generatedAt)} by OpenA2A v${escapeHtml(data.metadata.toolVersion)}</span>
    <span class="footer-sep"> | </span>
    <a href="https://opena2a.org/star" target="_blank" rel="noopener noreferrer">Open Source</a>
    <span class="footer-sep"> | </span>
    <a href="https://github.com/opena2a-org/opena2a" target="_blank" rel="noopener noreferrer">GitHub</a>
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

// --- Embedded CSS ---

const CSS = `
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0a;--card:#171717;--border:#262626;--border-hover:#404040;
  --primary:#14b8a6;--primary-dim:#0d9488;
  --text:#e5e5e5;--muted:#a3a3a3;--dim:#737373;
  --critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;--info:#6b7280;
  --radius:8px;--gap:16px;
  --font:'JetBrains Mono','Fira Code','SF Mono',Menlo,Consolas,monospace;
}
body{font-family:var(--font);background:var(--bg);color:var(--text);line-height:1.6;font-size:14px}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}

.header{display:flex;justify-content:space-between;align-items:center;padding:16px 24px;border-bottom:1px solid var(--border);position:sticky;top:0;background:var(--bg);z-index:100}
.header-left{display:flex;align-items:center;gap:12px}
.logo{font-size:18px;font-weight:700;color:var(--primary)}
.header-sep{color:var(--border)}
.header-label{color:var(--muted);font-size:14px}
.header-right{display:flex;align-items:center;gap:24px}

.audience-toggle{display:flex;border:1px solid var(--border);border-radius:var(--radius);overflow:hidden}
.toggle-btn{background:transparent;border:none;color:var(--muted);padding:6px 14px;cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
.toggle-btn:hover{color:var(--text)}
.toggle-btn.active{background:var(--primary-dim);color:white}

.nav{display:flex;gap:4px}
.nav-link{color:var(--muted);padding:6px 12px;border-radius:var(--radius);font-size:13px;transition:all .2s}
.nav-link:hover{color:var(--text);background:var(--card);text-decoration:none}
.nav-link.active{color:var(--primary);background:var(--card)}

.main{max-width:1200px;margin:0 auto;padding:24px}
.view{display:none}
.view.active{display:block}

.footer{text-align:center;padding:24px;color:var(--dim);font-size:12px;border-top:1px solid var(--border);margin-top:48px}
.footer-sep{color:var(--border);margin:0 4px}

/* Dashboard */
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:var(--gap);margin-bottom:24px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:20px}
.stat-value{font-size:32px;font-weight:700}
.stat-label{color:var(--muted);font-size:12px;margin-top:4px}

.chart-section{display:grid;grid-template-columns:300px 1fr;gap:24px;margin-bottom:24px}
.chart-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px;display:flex;flex-direction:column;align-items:center}
.chart-card h3{margin-bottom:16px;font-size:14px;color:var(--muted)}
.chart-legend{margin-top:16px;width:100%}
.legend-item{display:flex;align-items:center;gap:8px;padding:4px 0;font-size:13px}
.legend-dot{width:10px;height:10px;border-radius:50%;flex-shrink:0}

.action-items{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:24px}
.action-items h3{font-size:14px;color:var(--muted);margin-bottom:12px}
.action-item{padding:12px 0;border-bottom:1px solid var(--border)}
.action-item:last-child{border-bottom:none}
.action-item-title{font-weight:600;margin-bottom:4px}
.action-item-desc{color:var(--muted);font-size:13px}

/* Score gauge (executive) */
.score-section{text-align:center;margin-bottom:24px}
.score-value{font-size:64px;font-weight:700}
.score-label{font-size:14px;color:var(--muted)}

/* Findings */
.findings-toolbar{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.search-input{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);padding:8px 12px;color:var(--text);font-family:var(--font);font-size:13px;width:280px;outline:none}
.search-input:focus{border-color:var(--primary)}
.filter-btn{background:transparent;border:1px solid var(--border);border-radius:var(--radius);padding:6px 12px;color:var(--muted);cursor:pointer;font-family:var(--font);font-size:12px;transition:all .2s}
.filter-btn:hover{border-color:var(--text);color:var(--text)}
.filter-btn.active{border-color:var(--primary);color:var(--primary)}
.filter-btn[data-severity="critical"].active{border-color:var(--critical);color:var(--critical)}
.filter-btn[data-severity="high"].active{border-color:var(--high);color:var(--high)}
.filter-btn[data-severity="medium"].active{border-color:var(--medium);color:var(--medium)}
.filter-btn[data-severity="low"].active{border-color:var(--low);color:var(--low)}

.finding-count{color:var(--muted);font-size:13px;margin-left:auto}

.finding-card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);margin-bottom:8px;overflow:hidden;transition:border-color .2s}
.finding-card:hover{border-color:var(--border-hover)}
.finding-card[data-severity="critical"]{border-left:3px solid var(--critical)}
.finding-card[data-severity="high"]{border-left:3px solid var(--high)}
.finding-card[data-severity="medium"]{border-left:3px solid var(--medium)}
.finding-card[data-severity="low"]{border-left:3px solid var(--low)}
.finding-card[data-severity="info"]{border-left:3px solid var(--info)}

.finding-header{display:flex;align-items:center;gap:12px;padding:14px 16px;cursor:pointer;user-select:none}
.finding-header:hover{background:rgba(255,255,255,0.02)}
.finding-severity{font-size:11px;font-weight:700;text-transform:uppercase;padding:2px 8px;border-radius:4px;flex-shrink:0}
.sev-critical{background:rgba(239,68,68,0.15);color:var(--critical)}
.sev-high{background:rgba(249,115,22,0.15);color:var(--high)}
.sev-medium{background:rgba(234,179,8,0.15);color:var(--medium)}
.sev-low{background:rgba(59,130,246,0.15);color:var(--low)}
.sev-info{background:rgba(107,114,128,0.15);color:var(--info)}

.finding-title{flex:1;font-weight:500}
.finding-id{color:var(--dim);font-size:12px;flex-shrink:0}
.finding-chevron{color:var(--dim);transition:transform .2s;font-size:12px}
.finding-card.expanded .finding-chevron{transform:rotate(90deg)}

.finding-body{display:none;padding:0 16px 16px;border-top:1px solid var(--border)}
.finding-card.expanded .finding-body{display:block}
.finding-section{margin-top:12px}
.finding-section-label{font-size:11px;text-transform:uppercase;color:var(--dim);margin-bottom:4px;letter-spacing:0.05em}
.finding-text{color:var(--muted);font-size:13px}
.finding-code{background:var(--bg);border:1px solid var(--border);border-radius:4px;padding:12px;font-size:12px;overflow-x:auto;margin-top:4px;white-space:pre-wrap}
.finding-location{color:var(--primary);font-size:13px}

/* Executive-only */
.exec-only{display:none}
.audience-executive .exec-only{display:block}
.audience-executive .eng-only{display:none}
.eng-only{display:block}

@media(max-width:768px){
  .chart-section{grid-template-columns:1fr}
  .header{flex-direction:column;gap:12px}
  .header-right{width:100%;justify-content:space-between}
  .stats-grid{grid-template-columns:repeat(2,1fr)}
}
`;

// --- Embedded JavaScript ---

const JS = `
(function() {
  'use strict';

  var data = JSON.parse(document.getElementById('report-data').textContent);
  var currentView = 'dashboard';
  var currentAudience = 'engineering';
  var activeFilters = new Set(['critical','high','medium','low','info']);
  var searchTerm = '';

  function init() {
    renderDashboard();
    renderFindings();
    bindEvents();
    handleHash();
    window.addEventListener('hashchange', handleHash);
  }

  function handleHash() {
    var hash = location.hash.slice(1) || 'dashboard';
    if (hash.startsWith('finding-')) {
      switchView('findings');
      setTimeout(function() {
        var el = document.querySelector('[data-finding-id="' + hash.replace('finding-','') + '"]');
        if (el) { el.classList.add('expanded'); el.scrollIntoView({behavior:'smooth',block:'center'}); }
      }, 100);
    } else if (hash === 'findings' || hash === 'dashboard') {
      switchView(hash);
    }
  }

  function switchView(view) {
    currentView = view;
    document.querySelectorAll('.view').forEach(function(v) { v.classList.remove('active'); });
    document.getElementById('view-' + view).classList.add('active');
    document.querySelectorAll('.nav-link').forEach(function(l) {
      l.classList.toggle('active', l.dataset.view === view);
    });
  }

  function bindEvents() {
    // Nav links
    document.querySelectorAll('.nav-link').forEach(function(link) {
      link.addEventListener('click', function(e) {
        e.preventDefault();
        switchView(this.dataset.view);
        history.pushState(null, '', '#' + this.dataset.view);
      });
    });

    // Audience toggle
    document.querySelectorAll('.toggle-btn').forEach(function(btn) {
      btn.addEventListener('click', function() {
        currentAudience = this.dataset.audience;
        document.querySelectorAll('.toggle-btn').forEach(function(b) { b.classList.remove('active'); });
        this.classList.add('active');
        document.getElementById('app').className = 'audience-' + currentAudience;
        renderDashboard();
      });
    });

    // Severity filters
    document.addEventListener('click', function(e) {
      if (e.target.classList.contains('filter-btn') && e.target.dataset.severity) {
        var sev = e.target.dataset.severity;
        if (sev === 'all') {
          activeFilters = new Set(['critical','high','medium','low','info']);
          document.querySelectorAll('.filter-btn').forEach(function(b) { b.classList.add('active'); });
        } else {
          if (activeFilters.has(sev)) { activeFilters.delete(sev); } else { activeFilters.add(sev); }
          e.target.classList.toggle('active');
          var allBtn = document.querySelector('.filter-btn[data-severity="all"]');
          if (allBtn) allBtn.classList.toggle('active', activeFilters.size === 5);
        }
        applyFilters();
      }
    });

    // Finding accordion
    document.addEventListener('click', function(e) {
      var header = e.target.closest('.finding-header');
      if (header) {
        header.parentElement.classList.toggle('expanded');
      }
    });

    // Search
    var searchInput = document.getElementById('search-input');
    if (searchInput) {
      searchInput.addEventListener('input', function() {
        searchTerm = this.value.toLowerCase();
        applyFilters();
      });
    }
  }

  function applyFilters() {
    var cards = document.querySelectorAll('.finding-card');
    var visible = 0;
    cards.forEach(function(card) {
      var sev = card.dataset.severity;
      var text = card.textContent.toLowerCase();
      var show = activeFilters.has(sev) && (!searchTerm || text.indexOf(searchTerm) !== -1);
      card.style.display = show ? '' : 'none';
      if (show) visible++;
    });
    var counter = document.getElementById('finding-count');
    if (counter) counter.textContent = visible + ' of ' + data.findings.filter(function(f){return !f.passed}).length + ' findings';
  }

  // --- Dashboard ---

  function renderDashboard() {
    var el = document.getElementById('view-dashboard');
    var failedFindings = data.findings.filter(function(f) { return !f.passed; });
    var bySev = data.summary.bySeverity;
    var score = data.summary.score;
    var grade = data.summary.grade;

    var html = '';

    // Executive: score gauge
    if (currentAudience === 'executive' && (score !== undefined || grade)) {
      html += '<div class="score-section">';
      if (score !== undefined) {
        var scoreColor = score >= 80 ? 'var(--primary)' : score >= 50 ? 'var(--medium)' : 'var(--critical)';
        html += '<div class="score-value" style="color:' + scoreColor + '">' + score + '</div>';
        html += '<div class="score-label">Security Score' + (grade ? ' - Grade ' + grade : '') + '</div>';
      }
      html += '</div>';
    }

    // Stats grid
    html += '<div class="stats-grid">';
    html += statCard(data.summary.totalFindings, 'Total Findings', 'var(--text)');
    html += statCard(bySev.critical || 0, 'Critical', 'var(--critical)');
    html += statCard(bySev.high || 0, 'High', 'var(--high)');
    html += statCard(bySev.medium || 0, 'Medium', 'var(--medium)');
    html += statCard(bySev.low || 0, 'Low', 'var(--low)');
    html += '</div>';

    // Chart + action items
    html += '<div class="chart-section">';
    html += '<div class="chart-card"><h3>Severity Breakdown</h3>' + donutChart(bySev) + chartLegend(bySev) + '</div>';
    html += '<div class="action-items"><h3>Top Action Items</h3>' + actionItems(failedFindings) + '</div>';
    html += '</div>';

    el.innerHTML = html;
  }

  function statCard(value, label, color) {
    return '<div class="stat-card"><div class="stat-value" style="color:' + color + '">' + value + '</div><div class="stat-label">' + label + '</div></div>';
  }

  function donutChart(bySev) {
    var total = (bySev.critical||0) + (bySev.high||0) + (bySev.medium||0) + (bySev.low||0) + (bySev.info||0);
    if (total === 0) return '<svg width="160" height="160"><circle cx="80" cy="80" r="60" fill="none" stroke="var(--border)" stroke-width="20"/></svg>';

    var r = 60, cx = 80, cy = 80, sw = 20;
    var circ = 2 * Math.PI * r;
    var segments = [
      {key:'critical',color:'var(--critical)'},{key:'high',color:'var(--high)'},
      {key:'medium',color:'var(--medium)'},{key:'low',color:'var(--low)'},{key:'info',color:'var(--info)'}
    ];
    var svg = '<svg width="160" height="160" viewBox="0 0 160 160">';
    var offset = 0;
    segments.forEach(function(seg) {
      var count = bySev[seg.key] || 0;
      if (count === 0) return;
      var pct = count / total;
      var dash = pct * circ;
      var gap = circ - dash;
      svg += '<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+seg.color+'" stroke-width="'+sw+'" ' +
        'stroke-dasharray="'+dash+' '+gap+'" stroke-dashoffset="'+(-(offset))+'" transform="rotate(-90 '+cx+' '+cy+')"/>';
      offset += dash;
    });
    svg += '</svg>';
    return svg;
  }

  function chartLegend(bySev) {
    var items = [
      {key:'critical',label:'Critical',color:'var(--critical)'},
      {key:'high',label:'High',color:'var(--high)'},
      {key:'medium',label:'Medium',color:'var(--medium)'},
      {key:'low',label:'Low',color:'var(--low)'},
      {key:'info',label:'Info',color:'var(--info)'}
    ];
    var html = '<div class="chart-legend">';
    items.forEach(function(item) {
      html += '<div class="legend-item"><span class="legend-dot" style="background:'+item.color+'"></span>' +
        '<span>'+item.label+'</span><span style="margin-left:auto;color:var(--muted)">'+(bySev[item.key]||0)+'</span></div>';
    });
    html += '</div>';
    return html;
  }

  function actionItems(findings) {
    var critical = findings.filter(function(f){return f.severity==='critical'}).slice(0,3);
    if (critical.length === 0) critical = findings.slice(0,3);
    if (critical.length === 0) return '<div class="action-item"><div class="action-item-title" style="color:var(--primary)">No action items</div><div class="action-item-desc">All checks passed.</div></div>';

    var html = '';
    critical.forEach(function(f) {
      html += '<div class="action-item">';
      html += '<div class="action-item-title">' + esc(f.title) + '</div>';
      if (currentAudience === 'executive' && f.businessImpact) {
        html += '<div class="action-item-desc">' + esc(f.businessImpact) + '</div>';
      } else {
        html += '<div class="action-item-desc">' + esc(f.description) + '</div>';
      }
      html += '</div>';
    });
    return html;
  }

  // --- Findings ---

  function renderFindings() {
    var el = document.getElementById('view-findings');
    var failedFindings = data.findings.filter(function(f) { return !f.passed; });

    var html = '<div class="findings-toolbar">';
    html += '<input type="text" class="search-input" id="search-input" placeholder="Search findings...">';
    html += '<button class="filter-btn active" data-severity="all">All</button>';
    html += '<button class="filter-btn active" data-severity="critical">Critical</button>';
    html += '<button class="filter-btn active" data-severity="high">High</button>';
    html += '<button class="filter-btn active" data-severity="medium">Medium</button>';
    html += '<button class="filter-btn active" data-severity="low">Low</button>';
    html += '<span class="finding-count" id="finding-count">' + failedFindings.length + ' findings</span>';
    html += '</div>';

    failedFindings.forEach(function(f) {
      html += findingCard(f);
    });

    if (failedFindings.length === 0) {
      html += '<div class="stat-card" style="text-align:center;padding:48px"><div class="stat-value" style="color:var(--primary)">0</div><div class="stat-label">No findings. All checks passed.</div></div>';
    }

    el.innerHTML = html;
  }

  function findingCard(f) {
    var html = '<div class="finding-card" data-severity="' + f.severity + '" data-finding-id="' + esc(f.id) + '">';
    html += '<div class="finding-header">';
    html += '<span class="finding-severity sev-' + f.severity + '">' + f.severity + '</span>';
    html += '<span class="finding-title">' + esc(f.title) + '</span>';
    html += '<span class="finding-id">' + esc(f.id) + '</span>';
    html += '<span class="finding-chevron">&#9654;</span>';
    html += '</div>';

    html += '<div class="finding-body">';

    // Description (always shown)
    html += '<div class="finding-section"><div class="finding-section-label">Description</div>';
    html += '<div class="finding-text">' + esc(f.description) + '</div></div>';

    // Explanation (executive-friendly)
    if (f.explanation) {
      html += '<div class="finding-section exec-only"><div class="finding-section-label">Why This Matters</div>';
      html += '<div class="finding-text">' + esc(f.explanation) + '</div></div>';
    }

    // Business impact (executive)
    if (f.businessImpact) {
      html += '<div class="finding-section exec-only"><div class="finding-section-label">Business Impact</div>';
      html += '<div class="finding-text">' + esc(f.businessImpact) + '</div></div>';
    }

    // Location (engineering only)
    if (f.file) {
      html += '<div class="finding-section eng-only"><div class="finding-section-label">Location</div>';
      html += '<div class="finding-location">' + esc(f.file) + (f.line ? ':' + f.line : '') + '</div></div>';
    }

    // Fix / remediation (engineering only)
    if (f.fix) {
      html += '<div class="finding-section eng-only"><div class="finding-section-label">Remediation</div>';
      html += '<div class="finding-code">' + esc(f.fix) + '</div></div>';
    }

    // Evidence
    if (f.evidence) {
      html += '<div class="finding-section eng-only"><div class="finding-section-label">Evidence</div>';
      html += '<div class="finding-code">' + esc(f.evidence) + '</div></div>';
    }

    html += '</div></div>';
    return html;
  }

  function esc(s) {
    if (!s) return '';
    var d = document.createElement('div');
    d.textContent = s;
    return d.innerHTML;
  }

  init();
})();
`;

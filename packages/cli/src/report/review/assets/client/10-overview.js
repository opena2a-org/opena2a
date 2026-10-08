function renderOverview() {
  var h = '';
  var sevCounts = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  };
  var findings = report.findings || [];
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    if (s in sevCounts) sevCounts[s]++;
  }
  h += scoreBanner(report.compositeScore, report.recoverySummary);
  h += '<div class="stats-grid">';
  h += statCard(findings.length, 'Scan Findings', findings.length > 0 ? 'var(--amber)' : 'var(--green)');
  h += statCard(sevCounts.critical, 'Critical', sevCounts.critical > 0 ? 'var(--critical)' : 'var(--text)');
  h += statCard(sevCounts.high, 'High', sevCounts.high > 0 ? 'var(--high)' : 'var(--text)');
  h += statCard(sevCounts.medium, 'Medium', sevCounts.medium > 0 ? 'var(--medium)' : 'var(--text)');
  h += '</div>';
  h += '<h2 class="section-title">Phase Results</h2><div class="phase-grid">';
  var phases = report.phases || [];
  for (var i = 0; i < phases.length; i++) h += phaseCard(phases[i]);
  h += '</div>';
  var detectScore = report.detectData ? report.detectData.governanceScore : 100;
  var dims = [
    { name: 'Hygiene', weight: 30, score: report.initData.trustScore, tab: 'hygiene' },
    { name: 'Shield', weight: 20, score: report.shieldData.postureScore, tab: 'shield' },
    { name: 'Credentials', weight: 20, score: phases.length > 1 ? phases[1].score : 0, tab: 'credentials' },
    { name: 'Integrity', weight: 15, score: phases.length > 2 ? phases[2].score : 0, tab: 'hygiene' },
    { name: 'Shadow AI', weight: 15, score: detectScore, tab: 'shadowai' }
  ];
  h += '<div class="score-explainer"><div style="font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px">Score Breakdown</div><div style="display:flex;flex-direction:column;gap:10px">';
  for (var i = 0; i < dims.length; i++) {
    var d = dims[i];
    var clr = scoreColor(d.score);
    h += '<button type="button" class="breakdown-row" onclick="goToTab(&quot;' + d.tab + '&quot;)"><span style="display:flex;align-items:baseline;gap:6px"><span class="breakdown-name" style="font-size:13px;color:var(--muted)">' + esc(d.name) + '</span></span><span style="position:relative;height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden"><span style="position:absolute;left:0;top:0;height:100%;width:' + d.score + '%;background:' + clr + ';border-radius:4px;transition:width 0.3s"></span></span><span style="text-align:right;font-size:14px;font-weight:700;color:' + clr + '">' + d.score + '<span style="font-size:11px;color:var(--dim);font-weight:400">/100</span></span><span style="text-align:right;font-size:11px;color:var(--dim)">x ' + d.weight + '%</span></button>';
  }
  h += '</div><div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid rgba(51,65,85,0.4);margin-top:12px;padding-top:8px"><div style="display:flex;gap:12px;font-size:12px;color:var(--dim)"><span><strong style="color:var(--green)">A</strong> 90+</span><span><strong style="color:var(--primary)">B</strong> 80+</span><span><strong style="color:var(--medium)">C</strong> 70+</span><span><strong style="color:var(--high)">D</strong> 60+</span><span><strong style="color:var(--red)">F</strong> &lt;60</span></div><div style="font-size:12px;color:var(--dim)">Click a row to view details</div></div></div>';
  var actions = report.actionItems || [];
  var actionImpact = {
    'critical': 'Immediate risk of credential compromise or data breach',
    'high': 'Significant security gap that attackers can exploit',
    'medium': 'Moderate risk that weakens your security posture',
    'low': 'Minor improvement to harden your defenses',
    'info': 'Recommended best practice'
  };
  if (actions.length > 0) {
    h += '<h2 class="section-title">Action Items</h2><div class="card">';
    for (var i = 0; i < actions.length; i++) {
      var a = actions[i];
      var impact = actionImpact[a.severity] || '';
      h += '<div class="action-item"><div class="action-priority">#' + a.priority + '</div><div class="action-content"><div class="action-desc"><span class="sev-badge sev-' + esc(a.severity) + '">' + esc(a.severity) + '</span> ' + esc(a.description) + '</div>' + (impact ? '<div class="check-desc">' + esc(impact) + '</div>' : '') + cmdBlock(a.command) + '<button type="button" class="action-link" onclick="goToTab(&quot;' + esc(a.tab) + '&quot;)">View details</button></div></div>';
    }
    h += '</div>';
  }
  if (findings.length > 0) {
    h += '<h2 class="section-title">Findings</h2><div class="card"><table class="data-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Detail</th></tr></thead><tbody>';
    var top = findings.slice(0, 10);
    for (var i = 0; i < top.length; i++) {
      var f = top[i];
      h += '<tr><td>' + esc(f.id) + '</td><td>' + esc(f.title) + '</td><td><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td><td>' + esc(f.source) + '</td><td style="font-size:11px;color:var(--muted)">' + esc(f.detail) + '</td></tr>';
    }
    h += '</tbody></table></div>';
  }
  return h;
}

function renderCredentials() {
  var data = report.credentialData;
  if (data && data.totalFindings === 0 && data.filesScanned === 0) return '<div class="card"><div class="empty-state">No files were scanned for credentials, so this is not a clean result. The credential check opens source and config files, and everything in this directory is a file type or folder it skips (for example images, archives, lockfiles, dependency and test folders, and dotfiles other than .env). Run the review on the folder that holds your code:</div>' + cmdBlock('opena2a review <project-dir>') + '</div>';
  if (!data || data.totalFindings === 0) return '<div class="card"><div class="empty-state">No hardcoded credentials found. Your project is clean.</div></div>';
  var h = '<div class="section-intro">Hardcoded credentials in source code are the #1 cause of security breaches in AI projects. Keys pushed to git are scraped by bots within minutes. Findings below are grouped by credential type.</div>';
  h += '<div class="stats-grid">';
  h += statCard(data.totalFindings, 'Total Findings', data.totalFindings > 0 ? 'var(--red)' : 'var(--green)');
  h += statCard(data.bySeverity.critical || 0, 'Critical', (data.bySeverity.critical || 0) > 0 ? 'var(--critical)' : 'var(--text)');
  h += statCard(data.bySeverity.high || 0, 'High', (data.bySeverity.high || 0) > 0 ? 'var(--high)' : 'var(--text)');
  h += statCard(data.bySeverity.medium || 0, 'Medium', (data.bySeverity.medium || 0) > 0 ? 'var(--medium)' : 'var(--text)');
  h += '</div>';
  var matches = data.matches || [];
  var grouped = {};
  for (var i = 0; i < matches.length; i++) {
    var m = matches[i];
    var key = m.findingId || m.title;
    if (!grouped[key]) {
      grouped[key] = { finding: m, files: [], count: 0 };
    }
    grouped[key].count++;
    grouped[key].files.push(m.filePath + (m.line ? ':' + m.line : ''));
  }
  var sevOrder = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3
  };
  var groups = Object.values(grouped).sort(function(a, b) {
    return (sevOrder[a.finding.severity] || 9) - (sevOrder[b.finding.severity] || 9);
  });
  h += '<h2 class="section-title">Credential Findings (' + groups.length + ' types across ' + data.totalFindings + ' files)<button class="export-btn" onclick="exportCsv(&quot;credentials&quot;)">Export CSV</button></h2>';
  h += '<table class="data-table" style="display:none"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Env Var</th><th>Occurrences</th><th>Files</th></tr></thead><tbody>';
  for (var i = 0; i < groups.length; i++) {
    var g = groups[i];
    var m = g.finding;
    h += '<tr><td>' + esc(m.findingId) + '</td><td>' + esc(m.title) + '</td><td>' + esc(m.severity) + '</td><td>' + esc(m.envVar) + '</td><td>' + g.count + '</td><td>' + g.files.join('; ') + '</td></tr>';
  }
  h += '</tbody></table>';
  for (var i = 0; i < groups.length; i++) {
    var g = groups[i];
    var m = g.finding;
    h += '<div class="cred-card"><div class="cred-card-header"><span class="sev-badge sev-' + esc(m.severity) + '">' + esc(m.severity) + '</span><span class="cred-card-title">' + esc(m.title) + '</span><span style="color:var(--dim);font-size:12px">' + esc(m.findingId) + ' &mdash; ' + g.count + ' occurrence' + (g.count > 1 ? 's' : '') + '</span></div><div class="cred-card-meta"><div><div class="cred-card-meta-label">Migrate to</div><div class="cred-card-meta-value env">' + esc(m.envVar) + '</div></div></div>';
    if (m.explanation || m.businessImpact) {
      h += '<div class="cred-card-detail">';
      if (m.explanation) h += '<div class="cred-card-detail-label">Why this matters</div><div class="cred-card-detail-text">' + esc(m.explanation) + '</div>';
      if (m.businessImpact) h += '<div class="cred-card-detail-label">Business impact</div><div class="cred-card-detail-text">' + esc(m.businessImpact) + '</div>';
      h += '</div>';
    }
    var showFiles = g.files.slice(0, 5);
    h += '<div style="padding:8px 12px;font-size:11px;color:var(--dim);border-top:1px solid rgba(51,65,85,0.3)">';
    for (var j = 0; j < showFiles.length; j++) {
      h += esc(showFiles[j]) + '<br>';
    }
    if (g.count > 5) {
      h += '<button type="button" class="expand-toggle" aria-expanded="false" onclick="toggleExpand(this)">+ ' + (g.count - 5) + ' more files</button><div class="file-list-full">';
      for (var j = 5; j < g.files.length; j++) {
        h += esc(g.files[j]) + '<br>';
      }
      h += '</div>';
    }
    h += '</div></div>';
  }
  if (data.driftFindings && data.driftFindings.length > 0) {
    var driftGrouped = {};
    for (var i = 0; i < data.driftFindings.length; i++) {
      var d = data.driftFindings[i];
      var key = d.findingId || 'drift';
      if (!driftGrouped[key]) {
        driftGrouped[key] = { finding: d, count: 0, files: [] };
      }
      driftGrouped[key].count++;
      driftGrouped[key].files.push(d.filePath + (d.line ? ':' + d.line : ''));
    }
    var driftGroups = Object.values(driftGrouped);
    h += '<h2 class="section-title">Scope Drift (' + driftGroups.length + ' types)</h2><div class="card"><p style="color:var(--muted);font-size:12px;margin-bottom:8px;line-height:1.5">Scope drift occurs when a key provisioned for one service silently grants access to AI services.</p><table class="data-table"><thead><tr><th>ID</th><th>Occurrences</th><th>Sample Files</th></tr></thead><tbody>';
    for (var i = 0; i < driftGroups.length; i++) {
      var dg = driftGroups[i];
      h += '<tr><td>' + esc(dg.finding.findingId) + '</td><td>' + dg.count + '</td><td style="font-size:11px;color:var(--muted)">' + dg.files.slice(0, 3).map(function(f) {
        return esc(f);
      }).join(', ') + (dg.count > 3 ? ' + ' + (dg.count - 3) + ' more' : '') + '</td></tr>';
    }
    h += '</tbody></table></div>';
  }
  h += '<h2 class="section-title">Remediation</h2><div class="card">' + cmdBlock('opena2a protect') + '<p style="color:var(--muted);font-size:12px;margin-top:8px">Migrate hardcoded credentials to environment variables or encrypted vault.</p></div>';
  return h;
}

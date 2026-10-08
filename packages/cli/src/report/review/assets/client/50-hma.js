function renderHma() {
  var hma = report.hmaData;
  if (!hma || !hma.available) {
    return '<div class="section-intro">HackMyAgent runs 204 security checks across 30 categories against AI agent setups, testing for credential exposure, prompt injection, tool misuse, and OWASP Top 10 for LLM vulnerabilities.</div><div class="cta-card"><div class="cta-title">HackMyAgent Not Installed</div><div class="cta-desc">Install HMA to run comprehensive security scans against your AI agent.</div>' + cmdBlock('npm install -g hackmyagent') + '<p style="color:var(--muted);font-size:13px;margin-top:12px;text-align:center">Then re-run: <code style="color:var(--primary)">opena2a review</code></p></div>';
  }
  function isCommand(s) {
    if (!s) return false;
    var lc = s.trim().toLowerCase();
    return /^(hackmyagent|npx |npm |opena2a |git |run |curl |mkdir )/.test(lc);
  }
  function fixCell(f) {
    if (!f.fix) return '<span style="color:var(--dim);font-size:11px">No fix available</span>';
    if (isCommand(f.fix)) return cmdBlock(f.fix);
    var h = '<div style="font-size:12px;color:var(--muted);line-height:1.4">' + esc(f.fix) + '</div>';
    if (f.category === 'skill' || f.category === 'supply') {
      h += '<div style="margin-top:4px">' + cmdBlock('hackmyagent check ' + (f.sampleFiles && f.sampleFiles[0] ? esc(f.sampleFiles[0].split(':')[0]) : '<skill-path>')) + '</div>';
    }
    return h;
  }
  function positivePanel(lines) {
    var out = '<div style="font-size:11px;color:var(--muted);margin-top:6px;padding:6px 8px;background:rgba(239,68,68,0.06);border-left:2px solid var(--red);border-radius:2px"><div style="font-size:10px;color:var(--dim);margin-bottom:2px;text-transform:uppercase;letter-spacing:0.4px">Evidence</div>';
    for (var k = 0; k < lines.length; k++) {
      var ln = lines[k];
      out += '<div style="font-family:var(--font);font-size:11px"><span style="color:var(--dim)">L' + esc(String(ln.n)) + ':</span> ' + esc(ln.content) + '</div>';
      if (ln.why) out += '<div style="font-size:10px;color:var(--muted);margin-left:30px;margin-bottom:2px;font-style:italic">' + esc(ln.why) + '</div>';
    }
    out += '</div>';
    return out;
  }
  function absencePanel(observed) {
    return '<div style="font-size:11px;color:var(--muted);margin-top:6px;padding:6px 8px;background:rgba(234,179,8,0.06);border-left:2px solid var(--medium);border-radius:2px"><div style="font-size:10px;color:var(--dim);margin-bottom:2px;text-transform:uppercase;letter-spacing:0.4px">Observed but missing defense</div>' + esc((observed && observed.summary) || '') + '</div>';
  }
  function whyAndEvidence(f) {
    var why = (f.rationale && f.rationale.plainEnglish) || f.guidance || legacyRiskKb[f.checkId] || '';
    var out = why ? '<div style="font-size:11px;color:var(--amber);margin-top:4px;line-height:1.4">' + esc(why) + '</div>' : '';
    if (f.evidence && f.evidence.kind === 'positive' && f.evidence.lines && f.evidence.lines.length) {
      out += positivePanel(f.evidence.lines);
    } else if (f.evidence && f.evidence.kind === 'absence' && f.evidence.observed) {
      out += absencePanel(f.evidence.observed);
    } else if (f.evidence && f.evidence.kind === 'mixed') {
      if (f.evidence.positive && f.evidence.positive.lines && f.evidence.positive.lines.length) {
        out += positivePanel(f.evidence.positive.lines);
      }
      if (f.evidence.absence && f.evidence.absence.observed) {
        out += absencePanel(f.evidence.absence.observed);
      }
    }
    return out;
  }
  var h = '<div class="section-intro">HackMyAgent scanned your project with 204+ security checks across 30 categories. Results below show unique issue types, grouped by check ID.</div>';
  h += '<div class="stats-grid">';
  h += statCard(hma.score + '/' + hma.maxScore, 'HMA Score', scoreColor(hma.score));
  h += statCard(hma.totalChecks, 'Total Checks', 'var(--primary)');
  h += statCard(hma.failed, 'Failed', hma.failed > 0 ? 'var(--red)' : 'var(--green)');
  h += statCard(hma.passed, 'Passed', 'var(--green)');
  h += '</div>';
  var bs = hma.bySeverity || {};
  h += '<h2 class="section-title">Severity Breakdown</h2><div class="stats-grid">';
  h += statCard(bs.critical || 0, 'Critical', (bs.critical || 0) > 0 ? 'var(--critical)' : 'var(--text)');
  h += statCard(bs.high || 0, 'High', (bs.high || 0) > 0 ? 'var(--high)' : 'var(--text)');
  h += statCard(bs.medium || 0, 'Medium', (bs.medium || 0) > 0 ? 'var(--medium)' : 'var(--text)');
  h += statCard(bs.low || 0, 'Low', 'var(--text)');
  h += '</div>';
  var bc = hma.byCategory || {};
  var cats = Object.keys(bc).sort(function(a, b) {
    return bc[b] - bc[a];
  });
  if (cats.length > 0) {
    h += '<h2 class="section-title">Categories</h2><div class="card">';
    var maxCat = bc[cats[0]] || 1;
    for (var i = 0; i < cats.length; i++) {
      var c = cats[i];
      var pct = Math.round((bc[c] / maxCat) * 100);
      h += '<div style="display:grid;grid-template-columns:100px 1fr 50px;align-items:center;gap:10px;padding:6px 0;border-bottom:1px solid rgba(51,65,85,0.3)"><div style="font-size:12px;color:var(--muted);text-transform:capitalize">' + esc(c) + '</div><div style="position:relative;height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden"><div style="position:absolute;left:0;top:0;height:100%;width:' + pct + '%;background:var(--primary);border-radius:3px"></div></div><div style="text-align:right;font-size:13px;font-weight:600;color:var(--text)">' + bc[c] + '</div></div>';
    }
    h += '</div>';
  }
  var tf = hma.topFindings || [];
  if (tf.length > 0) {
    var showCount = Math.min(10, tf.length);
    h += '<h2 class="section-title">Issues by Check (' + tf.length + ' unique)<button class="export-btn" onclick="exportCsv(&quot;hma&quot;)">Export CSV</button></h2><div class="card"><table class="data-table hma-table"><colgroup><col class="col-check"><col class="col-name"><col class="col-severity"><col class="col-category"><col class="col-occurrences"><col class="col-fix"></colgroup><thead><tr><th>Check</th><th>Name</th><th>Severity</th><th class="col-category-th">Category</th><th>Occurrences</th><th>Fix</th></tr></thead><tbody>';
    for (var i = 0; i < tf.length; i++) {
      var f = tf[i];
      var rowStyle = i >= showCount ? 'style="display:none" class="hma-extra-row"' : '';
      var filesHtml = '<div style="font-size:10px;color:var(--dim);margin-top:4px">';
      var showFiles = f.sampleFiles ? f.sampleFiles.slice(0, 3) : [];
      for (var j = 0; j < showFiles.length; j++) {
        filesHtml += esc(showFiles[j]) + '<br>';
      }
      if (f.count > 3 && f.sampleFiles) {
        filesHtml += '<button type="button" class="expand-toggle" aria-expanded="false" onclick="toggleExpand(this)">+ ' + (f.count - 3) + ' more</button><div class="file-list-full">';
        for (var j = 3; j < f.sampleFiles.length; j++) {
          filesHtml += esc(f.sampleFiles[j]) + '<br>';
        }
        if (f.count > f.sampleFiles.length) {
          filesHtml += '<span style="color:var(--dim)">(' + (f.count - f.sampleFiles.length) + ' not shown)</span>';
        }
        filesHtml += '</div>';
      }
      filesHtml += '</div>';
      h += '<tr ' + rowStyle + '><td style="white-space:nowrap">' + esc(f.checkId) + '</td><td>' + esc(f.name) + '<div style="font-size:11px;color:var(--dim);margin-top:2px">' + esc(f.description) + '</div>' + whyAndEvidence(f) + '</td><td><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span></td><td style="text-transform:capitalize" class="col-category-td">' + esc(f.category) + (f.attackClass ? ' <span style="color:var(--dim);font-size:10px;text-transform:none">&middot; ' + esc(f.attackClass) + '</span>' : '') + '</td><td style="text-align:center"><span style="font-weight:700;font-size:15px">' + f.count + '</span>' + filesHtml + '</td><td>' + fixCell(f) + '</td></tr>';
    }
    h += '</tbody></table>';
    if (tf.length > showCount) {
      h += '<div style="text-align:center;padding:10px"><button class="export-btn" onclick="toggleHmaRows(this)" style="float:none">+ Show all ' + tf.length + ' checks</button></div>';
    }
    h += '</div>';
  }
  h += '<h2 class="section-title">How to Fix These Issues</h2>';
  h += '<div class="card"><div class="card-title" style="color:var(--primary)">1. Credential Management</div><p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">If your skills or tools need access to API keys, database credentials, or cloud tokens, never store them in source files or .env files accessible to AI tools. Use a credential broker that provides keys on-demand with audit logging.</p>' + cmdBlock('npx secretless-ai init') + '<p style="color:var(--dim);font-size:11px;margin-top:4px">Secretless AI moves credentials out of AI-accessible context and provides them through a secure broker.</p></div>';
  h += '<div class="card"><div class="card-title" style="color:var(--primary)">2. Skill Verification</div><p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">Unsigned and unverified skills can be modified without detection. Sign your skills, verify publishers, and pin content hashes to detect tampering. Review any skill that requests filesystem, network, or credential access.</p>' + cmdBlock('hackmyagent check <skill-path>') + '<p style="color:var(--dim);font-size:11px;margin-top:4px">Inspects a skill file for dangerous patterns before installation.</p></div>';
  h += '<div class="card"><div class="card-title" style="color:var(--primary)">3. Supply Chain Protection</div><p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">Register skills with a trusted registry, enable version drift detection, and block known malicious patterns. The ClawHavoc campaign actively targets AI tool users through compromised skills.</p>' + cmdBlock('hackmyagent secure --fix') + '<p style="color:var(--dim);font-size:11px;margin-top:4px">Auto-fixes all fixable issues: creates .gitignore patterns, adds hash pins, and flags unverified publishers.</p></div>';
  h += '<div class="card"><div class="card-title" style="color:var(--primary)">4. Runtime Boundaries</div><p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">Enable sandbox execution, restrict elevated permissions, and monitor agent behavior at runtime. An agent with unrestricted access is one prompt injection away from full system compromise.</p>' + cmdBlock('opena2a runtime start') + '<p style="color:var(--dim);font-size:11px;margin-top:4px">Starts runtime protection: monitors process spawns, network connections, and file access.</p></div>';
  return h;
}

// Scan details: per analyzer, whether it ran, how long it took and what it
// read, then how the score is computed, from the weights the score itself uses.
// A row says what was covered; what was found is in Findings. No row carries a
// pass or fail mark: several analyzers also measure which OpenA2A tools are set
// up, and that is not a result about this project.
var DIMENSION_LABEL = {
  trust: 'Project hygiene',
  credentials: 'Credentials',
  integrity: 'Config integrity',
  shield: 'Shield runtime findings',
  hma: 'HMA scan',
  shadowAi: 'Project MCP and AI config'
};
var ANALYZER_READ = {
  'Project Scan': function() {
    var init = report.initData || {};
    var parts = (init.hygieneChecks || []).filter(function(c) {
      return c.label !== 'Credential scan' && c.label !== 'Security config';
    }).map(function(c) { return c.label + ': ' + c.detail; });
    if (init.envFiles) parts.push(plural(init.envFiles.length, 'env file'));
    if (init.advisoryCount > 0) parts.push('advisories matched: ' + init.advisoryCount + ' (see Findings)');
    return parts.length > 0 ? parts.join('; ') + '.' : '';
  },
  'Credentials': function() {
    var cred = report.credentialData || {};
    var cov = cred.coverage;
    var s = 'Credential patterns: ' + plural(cred.filesScanned, 'file') + ' read, ' + plural(cred.totalFindings, 'provider-format key') + '.';
    if (cov) s += ' ' + plural(cov.placeholdersSkipped, 'value') + ' skipped as placeholders or examples.';
    if (cov && cov.skippedDirs.length > 0) s += ' Folders not entered: ' + cov.skippedDirs.join(', ') + '.';
    return s;
  },
  'Config Integrity': function() {
    var g = report.guardData || {};
    if (g.signatureStatus === 'valid') return plural(g.filesMonitored, 'signed file') + ' checked; every signature is valid.';
    if (g.signatureStatus === 'tampered') return g.tamperedFiles.length + ' of ' + plural(g.filesMonitored, 'signed file') + ' changed since signing (see Findings).';
    var n = (g.candidates || []).length;
    return 'No signatures in this project' + (n > 0 ? '; ' + plural(n, 'file') + ' could be signed (see Optional hardening)' : '') + '.';
  },
  'Shield Analysis': function() {
    var sh = report.shieldData || {};
    var s = plural(sh.eventCount, 'Shield event') + ' read.';
    if (sh.chainBroken) {
      var n = sh.untrustedEventsExcluded;
      s += ' The event log hash chain breaks at event ' + sh.brokenAt + '; ' + plural(n, 'event') + ' from there on ' + (n === 1 ? 'was' : 'were') + ' not classified.';
    }
    return s + ' The runtime view (events, monitoring, policy state) is not part of this review: `opena2a shield report` shows it.';
  },
  'HMA Scan': function() {
    var hma = report.hmaData || {};
    var run = hma.run || {};
    if (!hma.available) return 'Did not run' + (run.reason ? ' (' + run.reason + ')' : '') + '.';
    var version = run.version ? ' ' + String(run.version).replace(/^hackmyagent\s+/i, '') : '';
    return 'HMA' + version + ' ran ' + plural(hma.totalChecks, 'check') + '; ' + hma.failed + ' failed (see Findings). HMA score ' + hma.score + ' of ' + hma.maxScore + '.';
  },
  'Shadow AI': function() {
    var d = report.detectData || {};
    var servers = d.mcpServers || [];
    var mine = servers.filter(isProjectServer).length;
    var id = d.identity || {};
    var s = 'In this project: ' + plural(mine, 'MCP server') + ', ' + plural((d.aiConfigs || []).length, 'AI config file') + '.';
    if (d.identity) s += ' Governance files: agent identities ' + id.aimIdentities + ', MCP identities ' + id.mcpIdentities + ', SOUL.md ' + id.soulFiles + ', capability policies ' + id.capabilityPolicies + '.';
    return s + ' On this machine, not scored: ' + plural((d.agents || []).length, 'running AI tool') + ', ' + plural(servers.length - mine, 'MCP server') + ' (see Inventory).';
  }
};
function analyzerRow(p) {
  var read = ANALYZER_READ[p.name] ? ANALYZER_READ[p.name]() : '';
  var state = p.status === 'skip' ? 'skipped' : 'ran in ' + (p.durationMs / 1000).toFixed(1) + ' s';
  return textRow(esc(p.name), '<span class="ff-conf">' + state + '</span>' + (read ? '<div>' + richText(read) + '</div>' : ''));
}
function scoreModelCard(m) {
  var h = '<div class="card"><table class="data-table"><thead><tr><th>Area</th><th>Weight</th><th>Score</th></tr></thead><tbody>';
  for (var i = 0; i < m.weights.length; i++) {
    var w = m.weights[i];
    h += '<tr><td>' + esc(DIMENSION_LABEL[w.dimension] || w.dimension) + '</td><td>' + Math.round(w.weight * 100) + '%</td><td>' + (w.score == null ? 'did not run' : esc(w.score)) + '</td></tr>';
  }
  var s = 'The score is the average of these areas by weight' + (m.weightSet === 'withoutHma' ? ', with the weights for a run without HMA' : '') + ': ' + m.weightedScore + ' of 100.';
  s += ' An analyzer that judges the project itself and scores below ' + m.floorBand + ' holds the score at its own.';
  var held = m.floorHeldBy || [];
  if (held.length > 0) s += ' Here ' + joinWords(held.map(function(n) { return FLOOR_LABEL[n] || n; })) + (held.length === 1 ? ' holds' : ' hold') + ' it at ' + report.compositeScore + '.';
  return h + '</tbody></table><p class="sum-checked">' + esc(s) + '</p></div>';
}
function renderScanDetails() {
  var h = '<section class="sd" aria-labelledby="details-title"><h2 class="section-title" id="details-title">Scan details</h2>';
  h += '<div class="ff-card">' + textRow('Directory', esc(report.directory)) + (report.phases || []).map(analyzerRow).join('') + '</div>';
  var m = report.scoreModel;
  if (m && m.weights) h += '<h2 class="section-title">How the score is computed</h2>' + scoreModelCard(m);
  return h + '</section>';
}

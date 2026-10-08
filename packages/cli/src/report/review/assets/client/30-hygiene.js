var hygieneDescriptions = {
  'Credential scan': 'Detects API keys and secrets hardcoded in source files',
  '.gitignore': 'Prevents sensitive files from being committed to version control',
  '.env protection': 'Ensures .env files (which store secrets) are excluded from git',
  'Lock file': 'Pins exact dependency versions to prevent supply chain attacks',
  'Security config': 'OpenA2A configuration enables automated security monitoring'
};
function findHygieneDesc(label) {
  if (!label) return '';
  var lc = label.toLowerCase();
  for (var key in hygieneDescriptions) {
    if (lc.indexOf(key.toLowerCase()) >= 0) return hygieneDescriptions[key];
  }
  return '';
}
function renderHygiene() {
  var init = report.initData;
  var h = '<div class="section-intro">Project hygiene measures foundational security practices. These checks do not require any OpenA2A tools -- they are standard development practices that prevent accidental exposure.</div>';
  h += '<div class="stats-grid">';
  h += statCard(init.trustScore + '/100', 'Trust Score', scoreColor(init.trustScore));
  h += statCard(init.postureScore + '/100', 'Project Posture', scoreColor(init.postureScore));
  h += statCard(init.riskLevel, 'Risk Level', init.riskLevel === 'SECURE' || init.riskLevel === 'LOW' ? 'var(--green)' : init.riskLevel === 'MEDIUM' ? 'var(--medium)' : 'var(--red)');
  h += '</div>';
  h += '<div class="overview-top"><div class="gauge-card">' + gaugeCircle(init.trustScore, 'out of 100') + '</div><div><h2 class="section-title">Hygiene Checks</h2><div class="card">';
  var checks = init.hygieneChecks || [];
  for (var i = 0; i < checks.length; i++) {
    var c = checks[i];
    var statusClr = c.status === 'pass' ? 'var(--green)' : c.status === 'fail' ? 'var(--red)' : c.status === 'warn' ? 'var(--medium)' : 'var(--dim)';
    var desc = findHygieneDesc(c.label);
    h += '<div class="hygiene-row"><div><span class="hygiene-label">' + esc(c.label) + '</span>' + (desc ? '<div class="check-desc">' + esc(desc) + '</div>' : '') + '</div><span style="color:' + statusClr + '">' + esc(c.detail) + '</span></div>';
  }
  h += '</div></div></div>';
  h += '<div class="score-explainer"><div style="font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Trust Score Breakdown</div>';
  h += '<div style="display:grid;grid-template-columns:1fr auto auto;gap:4px 16px;font-size:12px;align-items:center">';
  h += '<div style="color:var(--muted)">Start</div><div></div><div style="color:var(--text);font-weight:600;text-align:right">100</div>';
  var deductions = [
    { label: '.gitignore', checkLabel: '.gitignore', penalty: -15 },
    { label: '.env protection', checkLabel: '.env protection', penalty: -10 },
    { label: 'Lock file', checkLabel: 'Lock file', penalty: -5 },
    {
      label: 'Security config',
      checkLabel: 'Security config',
      penalty: 5
    }
  ];
  for (var i = 0; i < deductions.length; i++) {
    var d = deductions[i];
    var check = null;
    for (var j = 0; j < checks.length; j++) {
      if (checks[j].label === d.checkLabel) {
        check = checks[j];
        break;
      }
    }
    var applied = false;
    if (d.penalty > 0) {
      applied = check && check.status === 'pass';
    } else {
      applied = !check || check.status !== 'pass';
    }
    if (applied) {
      var clr = d.penalty > 0 ? 'var(--green)' : 'var(--red)';
      h += '<div style="color:var(--muted)">' + esc(d.label) + '</div><div style="font-size:11px;color:' + clr + '">' + (d.penalty > 0 ? 'applied' : 'deducted') + '</div><div style="color:' + clr + ';text-align:right;font-weight:600">' + (d.penalty > 0 ? '+' : '') + d.penalty + '</div>';
    } else {
      h += '<div style="color:var(--dim);text-decoration:line-through">' + esc(d.label) + '</div><div style="font-size:11px;color:var(--green)">passed</div><div style="color:var(--dim);text-align:right">--</div>';
    }
  }
  h += '<div style="color:var(--text);font-weight:700;border-top:1px solid var(--card-border);padding-top:4px;margin-top:4px">Final</div><div style="border-top:1px solid var(--card-border);padding-top:4px;margin-top:4px"></div><div style="color:' + scoreColor(init.trustScore) + ';font-weight:700;text-align:right;border-top:1px solid var(--card-border);padding-top:4px;margin-top:4px">' + init.trustScore + '</div>';
  h += '</div></div>';
  h += '<div class="stats-grid">';
  h += statCard(init.activeTools + '/' + init.totalTools, 'OpenA2A Tools Active', 'var(--primary)');
  var advLabel = init.advisoryCount > 0 ? init.advisoryCount + ' found' : '0 found';
  h += statCard(advLabel, 'Advisories', init.advisoryCount > 0 ? 'var(--amber)' : 'var(--green)');
  h += '</div>';
  if (init.matchedPackages && init.matchedPackages.length > 0) {
    h += '<div class="card"><div class="card-title">Affected Packages</div><div style="font-size:12px;color:var(--muted)">' + init.matchedPackages.map(function(p) {
      return esc(p);
    }).join(', ') + '</div></div>';
  } else {
    h += '<div class="card" style="font-size:12px;color:var(--dim)">Advisories checked against project dependencies via the OpenA2A Registry. No matching advisories found.</div>';
  }
  var guard = report.guardData;
  if (guard) {
    h += '<h2 class="section-title">Config Integrity</h2>';
    if (guard.signatureStatus === 'valid') {
      h += '<div class="card"><div class="stats-grid">';
      h += statCard('Active', 'ConfigGuard', 'var(--green)');
      h += statCard(guard.filesMonitored, 'Files Monitored', 'var(--primary)');
      h += statCard(guard.tamperedFiles ? guard.tamperedFiles.length : 0, 'Tampered', (guard.tamperedFiles && guard.tamperedFiles.length > 0) ? 'var(--red)' : 'var(--green)');
      h += '</div>';
      if (guard.tamperedFiles && guard.tamperedFiles.length > 0) {
        h += '<div style="margin-top:8px"><div style="font-size:12px;color:var(--dim);margin-bottom:4px">Tampered files:</div>';
        for (var i = 0; i < guard.tamperedFiles.length; i++) {
          h += '<div style="font-size:12px;color:var(--red)">' + esc(guard.tamperedFiles[i]) + '</div>';
        }
        h += cmdBlock('opena2a guard diff && opena2a guard resign') + '</div>';
      } else {
        h += '<div style="font-size:12px;color:var(--muted);margin-top:4px">All monitored files have valid signatures.</div>';
      }
      h += '</div>';
    } else {
      h += '<div class="card"><div class="hygiene-row"><span class="hygiene-label">ConfigGuard</span><span style="color:var(--dim)">Not active &mdash; sign configs to detect unauthorized changes</span></div><div style="margin-top:4px">' + cmdBlock('opena2a guard sign') + '</div></div>';
    }
  }
  h += '<h2 class="section-title">Project Info</h2><div class="card"><div class="hygiene-row"><span class="hygiene-label">Project</span><span>' + esc(init.projectName || 'unnamed') + '</span></div><div class="hygiene-row"><span class="hygiene-label">Type</span><span>' + esc(init.projectType) + '</span></div><div class="hygiene-row"><span class="hygiene-label">Version</span><span>' + esc(init.projectVersion || '--') + '</span></div></div>';
  return h;
}

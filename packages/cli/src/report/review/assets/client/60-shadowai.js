function renderShadowAi() {
  var data = report.detectData;
  if (!data) return '<div class="card"><div class="empty-state">Shadow AI detection data not available.</div></div>';
  var capDescs = {
    'filesystem': 'Can read and write files',
    'shell-access': 'Can run commands on this computer',
    'database': 'Can read and modify databases',
    'network': 'Can make requests to external services',
    'browser': 'Can control a web browser',
    'source-control': 'Can access code repositories',
    'messaging': 'Can send messages',
    'payments': 'Can access payment systems',
    'cloud-services': 'Can access cloud infrastructure'
  };
  var h = '<div class="section-intro">Shadow AI detection discovers AI agents running on this machine, MCP servers configured across all platforms, and AI configuration files in the project. It assesses governance posture and identifies gaps in identity, behavioral rules, and capability policies.</div>';
  var govScore = data.governanceScore;
  h += '<div class="stats-grid">';
  h += statCard(govScore + '/100', 'Governance Score', scoreColor(govScore));
  h += statCard(data.agents ? data.agents.length : 0, 'AI Agents', 'var(--primary)');
  h += statCard(data.mcpServers ? data.mcpServers.length : 0, 'MCP Servers', 'var(--primary)');
  h += statCard(data.aiConfigs ? data.aiConfigs.length : 0, 'AI Configs', 'var(--primary)');
  h += '</div>';
  h += governanceBanner(govScore, data.recoverablePoints);
  var agents = data.agents || [];
  var mcpServers = data.mcpServers || [];
  if (agents.length > 0 || mcpServers.length > 0) {
    h += '<h2 class="section-title">What This Means</h2><div class="card">';
    if (agents.length > 0) {
      var governed = 0;
      for (var i = 0; i < agents.length; i++) {
        if (agents[i].governanceStatus === 'governed') governed++;
      }
      var ungoverned = agents.length - governed;
      if (ungoverned === 0) {
        h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">Your ' + (agents.length === 1 ? 'AI agent has' : 'AI agents have') + ' governance in place. Actions are bounded by the rules you defined.</p>';
      } else if (governed > 0) {
        h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">' + agents.length + ' AI tool' + (agents.length !== 1 ? 's are' : ' is') + ' running on this machine. ' + governed + ' ' + (governed === 1 ? 'has' : 'have') + ' governance rules, ' + ungoverned + ' ' + (ungoverned === 1 ? 'does' : 'do') + ' not.</p>';
      } else {
        h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">' + agents.length + ' AI tool' + (agents.length !== 1 ? 's are' : ' is') + ' running without governance. There are no documented rules limiting what ' + (agents.length === 1 ? 'it' : 'they') + ' can do in this project.</p>';
      }
    }
    if (mcpServers.length > 0) {
      var verified = 0;
      for (var i = 0; i < mcpServers.length; i++) {
        if (mcpServers[i].verified) verified++;
      }
      var unverified = mcpServers.length - verified;
      h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">' + mcpServers.length + ' MCP server' + (mcpServers.length !== 1 ? 's give' : ' gives') + ' your AI agents additional capabilities (file access, database queries, API calls, etc.).</p>';
      if (unverified > 0 && verified > 0) {
        h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">' + verified + ' ' + (verified === 1 ? 'has' : 'have') + ' verified identities, ' + unverified + ' ' + (unverified === 1 ? 'does' : 'do') + ' not.</p>';
      } else if (unverified === mcpServers.length) {
        h += '<p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:8px">None have verified identities, so there is no tamper-evident record of which server version is installed.</p>';
      }
    }
    h += '</div>';
  }
  h += '<h2 class="section-title">Running AI Agents</h2>';
  if (agents.length === 0) {
    h += '<div class="card"><div class="empty-state">No AI agents detected on this machine.</div></div>';
  } else {
    h += '<div class="card"><table class="data-table"><thead><tr><th>Name</th><th>Identity</th><th>Governance</th></tr></thead><tbody>';
    for (var i = 0; i < agents.length; i++) {
      var a = agents[i];
      var idClr = a.identityStatus === 'identified' ? 'var(--green)' : 'var(--medium)';
      var govClr = a.governanceStatus === 'governed' ? 'var(--green)' : 'var(--medium)';
      h += '<tr><td>' + esc(a.name) + '</td><td style="color:' + idClr + '">' + esc(a.identityStatus) + '</td><td style="color:' + govClr + '">' + esc(a.governanceStatus) + '</td></tr>';
    }
    h += '</tbody></table></div>';
  }
  h += '<h2 class="section-title">MCP Servers</h2>';
  if (mcpServers.length === 0) {
    h += '<div class="card"><div class="empty-state">No MCP server configurations found.</div></div>';
  } else {
    var projectMcp = [];
    var globalMcp = [];
    for (var i = 0; i < mcpServers.length; i++) {
      if (mcpServers[i].source.indexOf('(project)') >= 0) projectMcp.push(mcpServers[i]);
      else globalMcp.push(mcpServers[i]);
    }
    if (projectMcp.length > 0) {
      h += '<div class="card"><div class="card-title">Project-local (' + projectMcp.length + ')</div><table class="data-table"><thead><tr><th>Name</th><th>Transport</th><th>Verified</th><th>Capabilities</th><th>Risk</th></tr></thead><tbody>';
      for (var i = 0; i < projectMcp.length; i++) {
        var s = projectMcp[i];
        var verStr = s.verified ? '<span style="color:var(--green)">verified</span>' : '<span style="color:var(--dim)">no</span>';
        var realCaps = (s.capabilities || []).filter(function(c) {
          return c !== 'unknown';
        });
        var capsHtml = '';
        for (var j = 0; j < realCaps.length; j++) {
          var desc = capDescs[realCaps[j]] || realCaps[j];
          capsHtml += '<div style="font-size:11px;color:var(--muted);margin:1px 0">' + esc(desc) + '</div>';
        }
        if (realCaps.length === 0) capsHtml = '<span style="color:var(--dim)">--</span>';
        h += '<tr><td>' + esc(s.name) + '</td><td>' + esc(s.transport) + '</td><td>' + verStr + '</td><td>' + capsHtml + '</td><td><span class="sev-badge sev-' + esc(s.risk) + '">' + esc(s.risk) + '</span></td></tr>';
      }
      h += '</tbody></table></div>';
    }
    if (globalMcp.length > 0) {
      h += '<div class="card"><div class="card-title">Machine-wide (' + globalMcp.length + ')</div><table class="data-table"><thead><tr><th>Name</th><th>Source</th><th>Transport</th><th>Capabilities</th><th>Risk</th></tr></thead><tbody>';
      for (var i = 0; i < globalMcp.length; i++) {
        var s = globalMcp[i];
        var realCaps = (s.capabilities || []).filter(function(c) {
          return c !== 'unknown';
        });
        var capsHtml = '';
        for (var j = 0; j < realCaps.length; j++) {
          var desc = capDescs[realCaps[j]] || realCaps[j];
          capsHtml += '<div style="font-size:11px;color:var(--muted);margin:1px 0">' + esc(desc) + '</div>';
        }
        if (realCaps.length === 0) capsHtml = '<span style="color:var(--dim)">--</span>';
        h += '<tr><td>' + esc(s.name) + '</td><td style="font-size:11px;color:var(--dim)">' + esc(s.source) + '</td><td>' + esc(s.transport) + '</td><td>' + capsHtml + '</td><td><span class="sev-badge sev-' + esc(s.risk) + '">' + esc(s.risk) + '</span></td></tr>';
      }
      h += '</tbody></table></div>';
    }
  }
  var aiConfigs = data.aiConfigs || [];
  if (aiConfigs.length > 0) {
    h += '<h2 class="section-title">AI Config Files</h2><div class="card"><table class="data-table"><thead><tr><th>File</th><th>Tool</th><th>Risk</th><th>Details</th></tr></thead><tbody>';
    for (var i = 0; i < aiConfigs.length; i++) {
      var c = aiConfigs[i];
      var highlight = c.risk === 'critical' || c.risk === 'high';
      var rowStyle = highlight ? 'background:rgba(239,68,68,0.04)' : '';
      h += '<tr style="' + rowStyle + '"><td>' + esc(c.file) + '</td><td>' + esc(c.tool) + '</td><td><span class="sev-badge sev-' + esc(c.risk) + '">' + esc(c.risk) + '</span></td><td style="font-size:12px;color:var(--muted)">' + esc(c.details) + '</td></tr>';
    }
    h += '</tbody></table></div>';
  }
  var findings = data.findings || [];
  if (findings.length > 0) {
    h += '<h2 class="section-title">Findings</h2>';
    for (var i = 0; i < findings.length; i++) {
      var f = findings[i];
      h += '<div class="card" style="margin-bottom:8px"><div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span><span style="font-size:14px;font-weight:600">' + esc(f.title) + '</span></div><p style="color:var(--muted);font-size:13px;line-height:1.6;margin-bottom:10px">' + esc(f.whyItMatters) + '</p>' + cmdBlock(f.remediation) + '</div>';
    }
  }
  if (agents.length === 0 && mcpServers.length === 0 && aiConfigs.length === 0 && findings.length === 0) {
    h += '<div class="card"><div class="empty-state">No shadow AI detected. Your project has full governance coverage.</div></div>';
  }
  return h;
}

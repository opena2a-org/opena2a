// Inventory: what exists, not what is wrong. First the MCP servers and AI
// config files this project declares, then the AI tools and MCP servers found
// on the machine that ran the review. Those are listed apart: they are not part
// of the project and count toward neither its findings nor its score.
var CAPABILITY = {
  'filesystem': 'reads and writes files',
  'shell-access': 'runs commands',
  'database': 'reads and changes databases',
  'network': 'calls external services',
  'browser': 'controls a web browser',
  'source-control': 'accesses code repositories',
  'messaging': 'sends messages',
  'payments': 'accesses payment systems',
  'cloud-services': 'accesses cloud infrastructure'
};
function isProjectServer(s) {
  return String(s.source).indexOf('(project)') >= 0;
}
/** `pathCol`: the column that holds a file path. It may break anywhere; other cells keep their words whole. */
function inventoryTable(title, heads, rows, none, pathCol) {
  var h = '<div class="card"><h3 class="card-title">' + title + ' (' + rows.length + ')</h3>';
  if (rows.length === 0) return h + '<p class="inv-none">' + esc(none) + '</p></div>';
  h += '<table class="data-table"><thead><tr>' + heads.map(function(t) { return '<th>' + t + '</th>'; }).join('') + '</tr></thead><tbody>';
  for (var i = 0; i < rows.length; i++) {
    h += '<tr>' + rows[i].map(function(c, n) { return '<td' + (n === pathCol ? ' class="path"' : '') + '>' + esc(c) + '</td>'; }).join('') + '</tr>';
  }
  return h + '</tbody></table></div>';
}
function serverRows(servers) {
  return servers.map(function(s) {
    var caps = (s.capabilities || []).filter(function(c) { return c !== 'unknown'; });
    var access = caps.map(function(c) { return CAPABILITY[c] || c; }).join(', ') || 'not inferred';
    return [s.name + ' (' + s.transport + ')', String(s.source).replace(/\s*\(project\)\s*$/, ''), access];
  });
}
function renderInventory() {
  var d = report.detectData || {};
  var servers = d.mcpServers || [];
  var serverHeads = ['Name (transport)', 'Declared in', 'Inferred access'];
  var h = '<section aria-labelledby="inv-project"><h2 class="section-title" id="inv-project">In this project</h2>';
  h += inventoryTable('MCP servers', serverHeads, serverRows(servers.filter(isProjectServer)), 'No MCP servers are declared in ' + report.directory + '.', 1);
  h += inventoryTable('AI config files', ['File', 'Tool', 'Notes'], (d.aiConfigs || []).map(function(c) {
    return [c.file, c.tool, c.details];
  }), 'No AI config files were found in ' + report.directory + '.', 0);
  h += '</section><section aria-labelledby="inv-machine"><h2 class="section-title" id="inv-machine">On this machine, not part of this project</h2>';
  h += '<p class="section-intro">Found on the machine that ran this review. They are not part of ' + esc(report.projectName || report.directory) + ' and count toward neither its findings nor its score.</p>';
  h += inventoryTable('Running AI tools', ['Name', 'Kind'], (d.agents || []).map(function(a) {
    return [a.name, a.category];
  }), 'No running AI tools were detected.');
  h += inventoryTable('MCP servers configured outside this project', serverHeads, serverRows(servers.filter(function(s) {
    return !isProjectServer(s);
  })), 'No MCP servers are configured outside this project.', 1);
  return h + '</section>';
}

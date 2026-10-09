// Summary and Fix first. The verdict, the score with only the recovery that was
// re-scored, what was checked, then at most three findings to fix first. Every
// value comes from the report JSON; a field without data is left out, never
// filled with a generic sentence.
var SEV_ORDER = ['critical', 'high', 'medium', 'low'];
var SOURCE_LABEL = {
  'hma': 'HMA',
  'credential-scan': 'credential scan',
  'shield': 'Shield',
  'shadow-ai': 'Shadow AI',
  'hygiene': 'hygiene',
  'guard': 'guard',
  'advisories': 'advisories'
};
var FLOOR_LABEL = { 'HMA Scan': 'HMA' };
/** Escaped text with `code` spans marked up. */
function richText(s) {
  return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
}
function plural(n, word) {
  return n + ' ' + word + (n === 1 ? '' : 's');
}
function joinWords(items) {
  if (items.length < 2) return items.join('');
  return items.slice(0, -1).join(', ') + ' and ' + items[items.length - 1];
}
/** "2-3" for a run of consecutive item numbers, "1 and 3" otherwise. */
function itemNumbers(nums) {
  var run = nums.length > 1 && nums[nums.length - 1] - nums[0] === nums.length - 1;
  return run ? nums[0] + '-' + nums[nums.length - 1] : joinWords(nums.map(String));
}
/** Severities in display order: the four known ones, then any other. */
function severityKeys(counts) {
  var keys = SEV_ORDER.slice();
  for (var k in counts) {
    if (keys.indexOf(k) < 0) keys.push(k);
  }
  return keys;
}
function severityCounts(findings) {
  var counts = {};
  for (var i = 0; i < findings.length; i++) {
    var s = findings[i].severity;
    counts[s] = (counts[s] || 0) + 1;
  }
  return counts;
}
function verdictSentence(counts, total) {
  if (total === 0) return 'No findings.';
  var urgent = [];
  if (counts.critical) urgent.push(counts.critical + ' critical');
  if (counts.high) urgent.push(counts.high + ' high');
  var n = (counts.critical || 0) + (counts.high || 0);
  if (n > 0) return 'Not ready to ship: ' + joinWords(urgent) + ' finding' + (n === 1 ? '' : 's') + '.';
  var rest = severityKeys(counts).filter(function(k) { return counts[k]; }).map(function(k) { return counts[k] + ' ' + k; });
  return 'No critical or high findings. ' + joinWords(rest) + ' finding' + (total === 1 ? '' : 's') + ' to review.';
}
function countsLine(counts) {
  return '<p class="sum-counts">' + severityKeys(counts).map(function(k) {
    var n = counts[k] || 0;
    var cls = n === 0 ? 'sum-zero' : 'sev-badge sev-' + (SEV_ORDER.indexOf(k) >= 0 ? k : 'info');
    return '<span class="sum-count"><span class="' + cls + '">' + esc(k) + '</span> ' + n + '</span>';
  }).join('') + '</p>';
}
function hmaRun() {
  return report.hmaData && report.hmaData.run ? report.hmaData.run : null;
}
/** Why the verdict is provisional, or degraded, one sentence per analyzer. */
function summaryNotices() {
  var notes = [];
  if (report.provisional) {
    var run = hmaRun();
    notes.push('Provisional: HMA did not run' + (run && run.reason ? ' (' + run.reason + ')' : '') + '. HMA-only threats are not reflected in this score.');
  }
  var phases = report.phases || [];
  for (var i = 0; i < phases.length; i++) {
    if (phases[i].provisional && phases[i].provisionalReason) notes.push(phases[i].name + ': ' + phases[i].provisionalReason);
  }
  return notes;
}
function recoveryLabel(r) {
  if (!r) return '';
  if (r.kind === 'computed') return '+' + r.points;
  if (r.kind === 'atLeast') return 'at least +' + r.points;
  if (r.kind === 'none') return 'no score change';
  return 'measured on the next run';
}
function scoreSentences(top) {
  var model = report.scoreModel;
  var s = (report.provisional ? 'Provisional score ' : 'Score ') + report.compositeScore + ' of 100.';
  var held = model && model.floorHeldBy && model.floorHeldBy.length > 0;
  if (held) {
    var who = joinWords(model.floorHeldBy.map(function(n) { return FLOOR_LABEL[n] || n; }));
    s += ' The score is held at ' + report.compositeScore + ' because ' + who + ' scored this tree ' + report.compositeScore + ' of 100. It rises once ' + (model.floorHeldBy.length === 1 ? 'that score reaches ' : 'those scores reach ') + model.floorBand + '; fixes in other areas do not change the score until then.';
  }
  var first = top.length > 0 ? top[0].recovery : null;
  if (first && first.kind === 'computed') s += ' +' + first.points + ' available from the first fix.';
  if (first && first.kind === 'atLeast') s += ' At least +' + first.points + ' available from the first fix.';
  // An "at least" share beyond the first item is measured on the next run too.
  var later = [];
  var allHma = true;
  for (var i = 0; i < top.length; i++) {
    var k = top[i].recovery && top[i].recovery.kind;
    if (k !== 'nextRun' && !(k === 'atLeast' && i > 0)) continue;
    later.push(i + 1);
    allHma = allHma && (top[i].foundBy || []).some(function(b) { return b.source === 'hma'; });
  }
  if (later.length > 0) {
    s += ' ' + (later.length === 1 ? 'Item ' + later[0] + ' is' : 'Items ' + itemNumbers(later) + ' are') + ' measured on the next run' + (allHma ? '; HMA does not report per-check weights.' : '.');
  }
  return s;
}
function checkedSentence() {
  var phases = report.phases || [];
  var ran = phases.filter(function(p) { return p.status !== 'skip'; });
  var ms = 0;
  for (var i = 0; i < ran.length; i++) ms += ran[i].durationMs || 0;
  var parts = ['Checked: ' + (ran.length === phases.length ? plural(ran.length, 'analyzer') : ran.length + ' of ' + plural(phases.length, 'analyzer')) + ' in ' + (ms / 1000).toFixed(1) + ' s.'];
  var hma = report.hmaData;
  if (hma && hma.available && typeof hma.totalChecks === 'number') {
    var version = hma.run && hma.run.version ? ' ' + String(hma.run.version).replace(/^hackmyagent\s+/i, '') : '';
    parts.push('HMA' + version + ' ran ' + plural(hma.totalChecks, 'check') + '.');
  }
  var cred = report.credentialData;
  if (cred && typeof cred.filesScanned === 'number') parts.push(plural(cred.filesScanned, 'file') + ' read for credentials.');
  var det = report.detectData;
  if (det) {
    var servers = (det.mcpServers || []).filter(function(m) { return String(m.source).indexOf('(project)') >= 0; }).length;
    var configs = (det.aiConfigs || []).length;
    parts.push(servers + configs === 0 ? 'No MCP servers or AI config files in this project.' : 'In this project: ' + plural(servers, 'MCP server') + ', ' + plural(configs, 'AI config file') + '.');
  }
  return parts.join(' ');
}
function renderSummary(findings, top) {
  var counts = severityCounts(findings);
  var h = '<section class="card summary" aria-labelledby="summary-title"><h2 class="sum-verdict" id="summary-title">' + esc(verdictSentence(counts, findings.length)) + '</h2>';
  var notes = summaryNotices();
  for (var i = 0; i < notes.length; i++) h += '<p class="sum-notice">' + esc(notes[i]) + '</p>';
  if (report.shieldData && report.shieldData.chainBroken) h += commandRow('Check', { command: 'opena2a shield selfcheck', tool: 'opena2a' }, "Runs Shield's integrity checks.");
  h += countsLine(counts);
  h += '<p class="sum-score">' + esc(scoreSentences(top)) + '</p>';
  h += '<p class="sum-checked">' + esc(checkedSentence()) + '</p>';
  return h + '</section>';
}
/** One command row: the command, its tool, a labelled Copy button, then a note. */
function commandRow(key, c, note) {
  var label = key + ' command';
  var h = '<div class="ff-row"><div class="ff-key">' + key + '</div><div class="ff-val"><div class="cmd-block"' + (key === 'Fix' ? ' data-fix' : '') + '><span class="cmd-text">' + esc(c.command) + '</span><span class="cmd-tool">' + esc(c.tool) + '</span><button type="button" class="copy-btn" aria-label="Copy ' + esc(label) + '" data-cmd="' + esc(c.command) + '" onclick="copyCmd(this)">Copy</button></div>';
  if (note) h += '<div class="ff-note">' + richText(note) + '</div>';
  return h + '</div></div>';
}
function textRow(key, text) {
  return '<div class="ff-row"><div class="ff-key">' + key + '</div><div class="ff-val">' + text + '</div></div>';
}
function foundByText(f) {
  return (f.foundBy || []).map(function(b) {
    var src = SOURCE_LABEL[b.source] || b.source;
    var id = b.source === 'hygiene' ? '"' + b.checkId + '"' : b.checkId;
    var lines = b.lines && b.lines.length > 0 ? ' (' + (b.lines.length === 1 ? 'line ' : 'lines ') + b.lines.join(', ') + ')' : '';
    return src + ' ' + id + lines;
  }).join(' · ');
}
function place(file, line) {
  return file == null ? '' : file + (line != null ? ':' + line : '');
}
function evidenceRow(ev) {
  if (!ev || ev.length === 0) return '';
  return textRow('Evidence', ev.map(function(e) {
    var at = place(e.file, e.line);
    return '<code>' + (at ? esc(at) + '  ' : '') + esc(e.text) + '</code>';
  }).join('<br>'));
}
/** Recovery that was re-scored; other kinds are named in the card's head only. */
function recoveryRow(r) {
  if (r && r.kind === 'computed') return textRow('Recovery', esc('+' + r.points + ' (' + r.from + ' -> ' + r.to + ', re-scored)'));
  if (r && r.kind === 'atLeast') return textRow('Recovery', esc('at least +' + r.points + ' (' + r.from + ' -> ' + r.to + ' re-scored; the rest is measured on the next run)'));
  return '';
}
function fixFirstCard(f, n) {
  var h = '<article class="ff-card" id="ff-' + esc(f.fingerprint) + '" aria-labelledby="ff-title-' + n + '">';
  h += '<div class="ff-head"><span class="ff-num">' + n + '</span><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span><span class="ff-conf">' + esc(f.confidence || 'not rated') + '</span><span class="ff-rec">' + esc(recoveryLabel(f.recovery)) + '</span></div>';
  h += '<h3 class="ff-title" id="ff-title-' + n + '">' + esc(f.title) + '</h3>';
  if (f.reason) h += textRow('Why here', richText(f.reason));
  if (f.fix) h += commandRow('Fix', f.fix, f.fix.changes);
  else if (f.advice) h += textRow('Fix', richText(f.advice));
  if (f.then) h += commandRow('Then', f.then, f.then.changes);
  if (f.verify) h += commandRow('Verify', f.verify, f.verify.expect ? 'Expect: ' + f.verify.expect : '');
  h += recoveryRow(f.recovery);
  h += textRow('Found by', esc(foundByText(f)));
  var locs = f.locations || [];
  var ev = f.evidence || [];
  if (locs.length > 0 || ev.length > 0) {
    h += '<details class="ff-details"><summary>Where and evidence</summary>';
    if (locs.length > 0) {
      var shown = locs.slice(0, 5).map(function(l) { return esc(place(l.file, l.line)); }).join('<br>');
      h += textRow('Where', shown + (locs.length > 5 ? '<br>+' + (locs.length - 5) + ' more' : ''));
    }
    h += evidenceRow(ev);
    if (f.occurrences > 1) h += textRow('Occurrences', String(f.occurrences));
    h += '</details>';
  }
  return h + '</article>';
}
function renderOverview() {
  var findings = report.reportFindings || [];
  var byFp = {};
  for (var i = 0; i < findings.length; i++) byFp[findings[i].fingerprint] = findings[i];
  var top = (report.fixFirst || []).map(function(fp) { return byFp[fp]; }).filter(Boolean);
  var h = renderSummary(findings, top);
  h += '<section aria-labelledby="fix-first-title"><h2 class="section-title" id="fix-first-title">Fix first</h2>';
  if (top.length === 0) h += '<p class="empty-state">No findings to fix.</p>';
  for (var j = 0; j < top.length; j++) h += fixFirstCard(top[j], j + 1);
  if (findings.length > top.length) {
    h += '<p class="ff-more">' + esc(plural(findings.length - top.length, 'more finding')) + '.<button type="button" class="ff-tab-link" onclick="goToTab(&quot;findings&quot;)">View all ' + plural(findings.length, 'finding') + '</button></p>';
  }
  return h + '</section>';
}

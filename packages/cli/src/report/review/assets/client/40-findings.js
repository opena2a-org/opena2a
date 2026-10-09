// Findings: every analyzer's results in one list, in the report's priority
// order. Each finding is a native <details>, so Enter and Space open it and
// the browser's find can reach its text. #f-<fingerprint> opens and scrolls
// to one finding.
function findingDetails(f) {
  var h = '<details class="fd" id="f-' + esc(f.fingerprint) + '">';
  h += '<summary><span class="sev-badge sev-' + esc(f.severity) + '">' + esc(f.severity) + '</span> <span class="ff-conf">' + esc(f.confidence || 'not rated') + '</span> <span class="fd-title">' + esc(f.title) + '</span> <span class="ff-rec">' + esc(recoveryLabel(f.recovery)) + '</span></summary>';
  var locs = f.locations || [];
  if (locs.length > 0) h += textRow('Where', locs.map(function(l) { return esc(place(l.file, l.line)); }).join('<br>'));
  if (f.reason) h += textRow('Why here', richText(f.reason));
  h += evidenceRow(f.evidence);
  if (f.fix) h += commandRow('Fix', f.fix, f.fix.changes);
  if (f.advice) h += textRow(f.fix ? 'Advice' : 'Fix', richText(f.advice));
  if (f.then) h += commandRow('Then', f.then, f.then.changes);
  if (f.verify) h += commandRow('Verify', f.verify, f.verify.expect ? 'Expect: ' + f.verify.expect : '');
  h += recoveryRow(f.recovery);
  h += textRow('Found by', esc(foundByText(f)));
  h += textRow('Category', esc(f.category));
  if (f.occurrences > 1) h += textRow('Occurrences', String(f.occurrences));
  h += textRow('Link', '<a href="#f-' + esc(f.fingerprint) + '">#f-' + esc(f.fingerprint) + '</a>');
  return h + '</details>';
}
function renderFindings() {
  var findings = report.reportFindings || [];
  var h = '<section aria-labelledby="findings-title"><h2 class="section-title" id="findings-title">Findings (' + findings.length + ')</h2>';
  var notes = summaryNotices();
  for (var i = 0; i < notes.length; i++) h += '<p class="sum-notice">' + esc(notes[i]) + '</p>';
  var cred = report.credentialData;
  if (cred && cred.filesScanned === 0) {
    h += '<p class="sum-notice">No files were scanned for credentials in ' + esc(report.directory) + ', so this is not a clean result. The credential check opens source and config files, and everything in this directory is a file type or folder it skips (for example images, archives, lockfiles, dependency and test folders, and dotfiles other than .env). Run the review on the folder that holds your code:</p>' + cmdBlock('opena2a review <project-dir>');
  }
  if (findings.length === 0) return h + '<p class="empty-state">No findings. ' + esc(checkedSentence()) + '</p></section>';
  return h + findings.map(findingDetails).join('') + '</section>';
}
/** Opens the Findings tab at one finding and scrolls to it. */
window.openFinding = function(fp) {
  window.goToTab('findings');
  var d = document.getElementById('f-' + fp);
  if (!d) return;
  d.open = true;
  d.scrollIntoView({ block: 'start' });
  d.querySelector('summary').focus({ preventScroll: true });
};

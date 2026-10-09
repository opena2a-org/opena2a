// Optional hardening: OpenA2A protections that are not enabled here. Nothing
// was detected for them, so they are not findings and carry no severity. Each
// names its command, what that changes when it is known, and its effect on the
// score as it was re-scored, "no score change" included.
function hardeningCard(item, n) {
  var h = '<article class="ff-card" aria-labelledby="oh-title-' + n + '">';
  h += '<div class="ff-head"><span class="ff-conf">optional</span><span class="ff-rec">' + esc(recoveryLabel(item.recovery)) + '</span></div>';
  h += '<h3 class="ff-title" id="oh-title-' + n + '">' + esc(item.title) + '</h3>';
  h += textRow('Why', richText(item.reason));
  h += commandRow('Run', item.fix, item.fix.changes);
  return h + recoveryRow(item.recovery) + '</article>';
}
function renderHardening() {
  var items = report.optionalHardening || [];
  var h = '<section aria-labelledby="hardening-title"><h2 class="section-title" id="hardening-title">Optional hardening</h2>';
  h += '<p class="section-intro">OpenA2A protections that are not enabled in this project. Nothing was detected for them, so they are not findings. Each one names its command and its effect on the score.</p>';
  if (items.length === 0) {
    var on = [];
    var guard = report.guardData || {};
    if (guard.signatureStatus === 'valid') on.push(plural(guard.filesMonitored, 'config file') + ' signed');
    if (report.shieldData && report.shieldData.policyLoaded) on.push('a Shield policy loaded');
    return h + '<p class="empty-state">Nothing to suggest' + (on.length > 0 ? ': ' + esc(joinWords(on)) : '') + '.</p></section>';
  }
  for (var i = 0; i < items.length; i++) h += hardeningCard(items[i], i + 1);
  return h + '</section>';
}

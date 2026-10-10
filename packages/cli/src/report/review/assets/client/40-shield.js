function renderShield() {
  var shield = report.shieldData;
  var h = '<div class="section-intro">Shield classifies the events in its event log into findings.</div>';
  h += '<div class="stats-grid">';
  h += statCard(shield.shieldPostureScore + '/100', 'Shield Posture', scoreColor(shield.shieldPostureScore));
  h += statCard(shield.eventCount, 'Events (7d)', 'var(--primary)');
  h += statCard(shield.classifiedFindings ? shield.classifiedFindings.length : 0, 'Shield Findings', shield.classifiedFindings && shield.classifiedFindings.length > 0 ? 'var(--amber)' : 'var(--green)');
  h += statCard(shield.policyLoaded ? 'Loaded' : 'None', 'Policy', shield.policyLoaded ? 'var(--green)' : 'var(--dim)');
  h += statCard(shield.policyMode || '--', 'Mode', 'var(--muted)');
  h += statCard(shield.integrityStatus || 'healthy', 'Integrity', shield.integrityStatus === 'healthy' ? 'var(--green)' : 'var(--red)');
  if (shield.chainBroken) h += statCard(shield.untrustedEventsExcluded, 'Excluded (Chain Break)', 'var(--red)');
  h += '</div>';
  if (shield.chainBroken) {
    h += '<div class="card" style="border-color:var(--red)"><div class="card-title">Event log hash chain broken</div><div class="section-intro">The chain breaks at index ' + esc(String(shield.brokenAt)) + '. The ' + esc(String(shield.untrustedEventsExcluded)) + ' events at and after that point are untrusted (forged, tampered, or corrupted) and were excluded from classification, so the counts on this page describe only what survived verification. Scores are floored at what the same log would have scored with an intact chain, so the break cannot improve them.</div>' + cmdBlock('opena2a shield selfcheck') + '</div>';
  }
  var cf = shield.classifiedFindings || [];
  if (cf.length > 0) {
    h += '<h2 class="section-title">Classified Findings</h2><div class="card"><table class="data-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Count</th><th>Remediation</th></tr></thead><tbody>';
    for (var i = 0; i < cf.length; i++) {
      var f = cf[i];
      var badges = '';
      if (f.finding.owaspAgentic) badges += '<span class="badge-owasp">' + esc(f.finding.owaspAgentic) + '</span>';
      if (f.finding.mitreAtlas) badges += '<span class="badge-mitre">' + esc(f.finding.mitreAtlas) + '</span>';
      h += '<tr><td>' + esc(f.finding.id) + '</td><td>' + esc(f.finding.title) + (badges ? ' ' + badges : '') + '</td><td><span class="sev-badge sev-' + esc(f.finding.severity) + '">' + esc(f.finding.severity) + '</span></td><td>' + f.count + '</td><td>' + (f.finding.remediationNote ? '<div style="font-size:12px;color:var(--muted);line-height:1.5;margin-bottom:6px">' + esc(f.finding.remediationNote) + '</div>' : '') + cmdBlock(f.finding.remediation) + '</td></tr>';
      if (f.finding.description) h += '<tr><td colspan="5" class="finding-desc">' + esc(f.finding.description) + '</td></tr>';
    }
    h += '</tbody></table></div>';
  }
  var arp = shield.arpStats;
  if (arp && arp.totalEvents > 0) {
    h += '<h2 class="section-title">Runtime Protection (ARP)</h2><div class="card"><div class="arp-grid"><div class="arp-stat"><div class="arp-stat-value">' + arp.totalEvents + '</div><div class="arp-stat-label">Total Events</div></div><div class="arp-stat"><div class="arp-stat-value" style="color:var(--amber)">' + arp.anomalies + '</div><div class="arp-stat-label">Anomalies</div></div><div class="arp-stat"><div class="arp-stat-value" style="color:var(--red)">' + arp.violations + '</div><div class="arp-stat-label">Violations</div></div><div class="arp-stat"><div class="arp-stat-value">' + arp.processEvents + '</div><div class="arp-stat-label">Process</div></div><div class="arp-stat"><div class="arp-stat-value">' + arp.networkEvents + '</div><div class="arp-stat-label">Network</div></div><div class="arp-stat"><div class="arp-stat-value">' + arp.enforcements + '</div><div class="arp-stat-label">Enforcements</div></div></div></div>';
  } else {
    h += '<h2 class="section-title">Runtime Protection (ARP)</h2><div class="section-intro">ARP monitors process spawns, network connections, and file access in real time.</div><div class="card"><div class="empty-state">No ARP events in the last 7 days. Start runtime monitoring:</div>' + cmdBlock('opena2a runtime start') + '</div>';
  }
  if (!shield.policyLoaded) {
    h += '<h2 class="section-title">Policy</h2><div class="cta-card"><div class="cta-title">No Security Policy</div><div class="cta-desc">Initialize Shield to enable adaptive security policy.</div>' + cmdBlock('opena2a shield init') + '</div>';
  }
  return h;
}

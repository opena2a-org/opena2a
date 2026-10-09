var report = JSON.parse(document.getElementById('report-data').textContent);
var pagesRendered = {};
function esc(s) {
  return s == null ? '' : String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function scoreColor(s) {
  return s >= 90 ? 'var(--green)' : s >= 70 ? 'var(--primary)' : s >= 50 ? 'var(--medium)' : 'var(--red)';
}
document.getElementById('main-nav').addEventListener('click', function(e) {
  var btn = e.target.closest('.nav-tab');
  if (!btn) return;
  var pg = btn.getAttribute('data-page');
  document.querySelectorAll('.nav-tab').forEach(function(t) {
    t.classList.toggle('active', t === btn);
  });
  document.querySelectorAll('.page').forEach(function(p) {
    p.classList.toggle('active', p.id === 'page-' + pg);
  });
  renderPage(pg);
  markScrollers();
});
function renderPage(pg) {
  if (pagesRendered[pg]) return;
  pagesRendered[pg] = true;
  var el = document.getElementById('page-' + pg);
  switch (pg) {
    case 'overview':
      el.innerHTML = renderOverview();
      break;
    case 'findings':
      el.innerHTML = renderFindings();
      break;
    case 'inventory':
      el.innerHTML = renderInventory();
      break;
    case 'hardening':
      el.innerHTML = renderHardening();
      break;
    case 'details':
      el.innerHTML = renderScanDetails();
      break;
  }
  wrapTables(el);
}
function wrapTables(el) {
  var tables = el.querySelectorAll('table.data-table');
  for (var i = 0; i < tables.length; i++) {
    var t = tables[i];
    var w = document.createElement('div');
    w.className = 'table-scroll';
    t.parentNode.insertBefore(w, t);
    w.appendChild(t);
  }
}
function markScrollers() {
  var ws = document.querySelectorAll('.page.active .table-scroll');
  for (var i = 0; i < ws.length; i++) {
    var w = ws[i];
    if (w.scrollWidth > w.clientWidth + 1) {
      w.setAttribute('tabindex', '0');
      w.setAttribute('role', 'region');
      w.setAttribute('aria-label', 'Table, scrolls sideways');
    } else {
      w.removeAttribute('tabindex');
      w.removeAttribute('role');
      w.removeAttribute('aria-label');
    }
  }
}
window.addEventListener('resize', markScrollers);
window.toggleHmaRows = function(btn) {
  var rows = document.querySelectorAll('.hma-extra-row');
  var hidden = rows[0] && rows[0].style.display === 'none';
  for (var i = 0; i < rows.length; i++) {
    rows[i].style.display = hidden ? '' : 'none';
  }
  btn.textContent = hidden ? 'Show fewer' : '+ Show all checks';
};
var legacyRiskKb = {
  'SKILL-010': 'When a skill reads .env files, it can steal API keys, database passwords, and cloud credentials. Attackers use this to access your accounts, billing, and infrastructure. If the skill is compromised or malicious, every secret in your environment is exposed.',
  'SKILL-005': 'Skills that access ~/.ssh, ~/.aws, or credential files can impersonate you across every service you use. A single compromised skill could access your servers, cloud accounts, and private repositories.',
  'SKILL-012': 'Accessing cryptocurrency wallets or seed phrases gives an attacker irreversible access to your funds. Unlike passwords, stolen crypto keys cannot be rotated or recovered.',
  'SKILL-002': 'Remote fetch-and-execute means the skill downloads code from the internet and runs it. The remote server can change that code at any time, turning a safe skill into a backdoor without any update on your end.',
  'SKILL-004': 'Writing files outside the sandbox lets a skill modify system configs, install malware, or overwrite other applications. This breaks the isolation boundary that protects your system.',
  'SKILL-007': 'ClickFix social engineering tricks users into copying and pasting malicious commands. The skill appears helpful while guiding users to compromise their own systems.',
  'SKILL-006': 'Data exfiltration patterns (base64 encoding + HTTP POST to external servers) are how stolen credentials and source code leave your machine. Even if detection catches the theft later, the data is already gone.',
  'SKILL-011': 'Browser data contains saved passwords, session tokens, and cookies. A skill with browser access can hijack your authenticated sessions across every website you use.',
  'SKILL-008': 'Reverse shells give an attacker a live terminal on your machine. They can run any command, install persistence, and pivot to other systems on your network.',
  'HEARTBEAT-001': 'Heartbeat URLs let skills phone home to external servers. Without verification, an attacker can redirect the heartbeat to a malicious server that sends new instructions to the skill.',
  'HEARTBEAT-004': 'Heartbeats requesting dangerous capabilities (shell access, filesystem write) can be remotely activated. The skill stays dormant until the heartbeat server tells it to act.',
  'CONFIG-001': 'Session files contain authentication tokens. If exposed, anyone with the file can impersonate your logged-in session without needing your password.',
  'CONFIG-004': 'Plaintext API keys in config files are the most common cause of credential breaches. Automated scrapers find them within minutes of a git push.',
  'CONFIG-007': 'Unrestricted elevated execution means AI agents can run any command with no approval. A prompt injection or compromised tool can escalate to full system access.',
  'SUPPLY-003': 'This skill matches patterns from known malicious campaigns. It may have been installed legitimately but contains code sequences associated with active threats.',
  'SUPPLY-005': 'This skill contacts IP addresses used by the ClawHavoc command-and-control infrastructure. This is a strong indicator of compromise.',
  'SUPPLY-006': 'References to known malware payload filenames indicate the skill may download or deploy malicious executables.',
  'GIT-002': 'Without .env, .pem, and .key in .gitignore, a single careless commit pushes your secrets to git history. Even if deleted later, secrets remain in git history forever.',
  'SKILL-003': 'Scheduled tasks run without user awareness. A malicious skill that installs a cron job or heartbeat can persist after the skill itself is removed.',
  'HEARTBEAT-002': 'Without hash pinning, a man-in-the-middle can modify heartbeat responses. The skill trusts whatever it receives, even if it has been tampered with.',
  'HEARTBEAT-003': 'Unsigned heartbeat files can be replaced by an attacker. A signed heartbeat proves it came from the original publisher and has not been modified.',
  'CONFIG-006': 'Auto-following untrusted agents means your system automatically trusts new agents without review. A malicious agent can join and immediately have access.',
  'CONFIG-008': 'Disabling the sandbox removes the primary defense against malicious tools. Every tool runs with full system access instead of restricted permissions.',
  'SUPPLY-001': 'Unverified publishers cannot be held accountable. Anyone can publish a skill claiming to be from a trusted organization.',
  'SUPPLY-004': 'Without an installed hash, you cannot detect if a skill has been modified after installation. A supply chain attacker can silently replace skill code.',
  'SUPPLY-007': 'Social engineering instructions that guide users to execute commands are a hallmark of the ClawHavoc campaign targeting AI tool users.',
  'SUPPLY-008': 'Password-protected archives bypass antivirus scanning. This is a standard malware distribution technique.',
  'GIT-001': 'Without .gitignore, every file in your project can be accidentally committed, including secrets, credentials, and private keys.',
  'SKILL-001': 'Unsigned skills cannot prove who created them or that they have not been tampered with. You are trusting code with no chain of custody.',
  'SCAN-001': 'Oversized files may be used to evade security scanning. Scanners skip large files, which attackers exploit to hide malicious content.',
  'SUPPLY-002': 'Skills not listed in a trusted registry have no community vetting. Anyone can distribute them without accountability.'
};
window.toggleExpand = function(el) {
  var target = el.nextElementSibling;
  if (target) {
    var open = target.classList.toggle('open');
    el.textContent = open ? 'collapse' : '+ show all';
    el.setAttribute('aria-expanded', String(open));
  }
};
window.exportCsv = function(tabName) {
  var rows = [];
  var LF = String.fromCharCode(10);
  var table = document.querySelector('#page-' + tabName + ' table.data-table');
  if (!table) {
    return;
  }
  var headers = [];
  table.querySelectorAll('thead th').forEach(function(th) {
    headers.push(th.textContent.trim());
  });
  rows.push(headers.join(','));
  table.querySelectorAll('tbody tr').forEach(function(tr) {
    var cells = [];
    tr.querySelectorAll('td').forEach(function(td) {
      var t = td.textContent.trim().replace(/"/g, '""');
      cells.push('"' + t + '"');
    });
    if (cells.length > 0) rows.push(cells.join(','));
  });
  var csv = rows[0];
  for (var i = 1; i < rows.length; i++) {
    csv += LF + rows[i];
  }
  var blob = new Blob([csv], { type: 'text/csv' });
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'opena2a-review-' + tabName + '.csv';
  a.click();
};
window.copyCmd = function(btn) {
  var cmd = btn.getAttribute('data-cmd');
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(cmd).then(function() {
      btn.textContent = 'OK';
      btn.classList.add('copied');
      setTimeout(function() {
        btn.textContent = 'Copy';
        btn.classList.remove('copied');
      }, 1500);
    });
  } else {
    var ta = document.createElement('textarea');
    ta.value = cmd;
    ta.style.position = 'fixed';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    btn.textContent = 'OK';
    btn.classList.add('copied');
    setTimeout(function() {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1500);
  }
};
window.goToTab = function(tab) {
  var btn = document.querySelector('.nav-tab[data-page="' + tab + '"]');
  if (btn) {
    btn.click();
    btn.focus();
  }
};
function gaugeCircle(score, label) {
  var sz = 170, cx = sz / 2, cy = sz / 2, r = 65, sw = 10, circ = 2 * Math.PI * r;
  var pct = Math.max(0, Math.min(100, score)) / 100, dash = pct * circ, gap = circ - dash;
  var clr = score >= 90 ? '#22c55e' : score >= 70 ? '#06b6d4' : score >= 50 ? '#eab308' : '#ef4444';
  var s = '<svg width="' + sz + '" height="' + sz + '" viewBox="0 0 ' + sz + ' ' + sz + '">';
  s += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="' + sw + '"/>';
  s += '<circle cx="' + cx + '" cy="' + cy + '" r="' + r + '" fill="none" stroke="' + clr + '" stroke-width="' + sw + '" stroke-dasharray="' + dash + ' ' + gap + '" stroke-dashoffset="' + (circ * 0.25) + '" stroke-linecap="round" transform="rotate(-90 ' + cx + ' ' + cy + ')"/>';
  s += '<text x="' + cx + '" y="' + (cy - 6) + '" text-anchor="middle" dominant-baseline="middle" font-size="32" font-weight="700" fill="' + clr + '" font-family="var(--font)">' + score + '</text>';
  s += '<text x="' + cx + '" y="' + (cy + 20) + '" text-anchor="middle" dominant-baseline="middle" font-size="14" font-weight="600" fill="' + clr + '" font-family="var(--font)">' + esc(label || ('out of 100')) + '</text>';
  s += '</svg>';
  return s;
}
function cmdBlock(cmd) {
  return '<div class="cmd-block"><span class="cmd-text">' + esc(cmd) + '</span><button class="copy-btn" data-cmd="' + esc(cmd) + '" onclick="copyCmd(this)">Copy</button></div>';
}
function statCard(value, label, color) {
  return '<div class="stat-card"><div class="stat-value" style="color:' + color + '">' + esc(String(value)) + '</div><div class="stat-label">' + esc(label) + '</div></div>';
}
function scoreBanner(score, recoverySummary) {
  var clr = scoreColor(score);
  var h = '<div class="score-banner"><div class="score-banner-num" style="color:' + clr + '">' + score + '</div><div class="score-banner-bar"><div class="score-banner-label"><span>Composite Score</span><span>' + score + '/100</span></div><div class="score-banner-track"><div class="score-banner-fill" style="width:' + score + '%;background:' + clr + '"></div></div></div>';
  if (recoverySummary && recoverySummary.totalRecoverable > 0) {
    var recovBg = score >= 70 ? 'rgba(6,182,212,0.15)' : score >= 50 ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)';
    h += '<div class="score-banner-grade" style="color:' + clr + ';background:' + recovBg + '">+' + recoverySummary.totalRecoverable + ' recoverable</div>';
  }
  h += '</div>';
  return h;
}
function governanceBanner(score, recoverablePoints) {
  var clr = scoreColor(score);
  var h = '<div class="score-banner"><div class="score-banner-num" style="color:' + clr + '">' + score + '</div><div class="score-banner-bar"><div class="score-banner-label"><span>Governance Score</span><span>' + score + '/100</span></div><div class="score-banner-track"><div class="score-banner-fill" style="width:' + score + '%;background:' + clr + '"></div></div></div>';
  if (recoverablePoints > 0) {
    var projected = Math.min(100, score + recoverablePoints);
    var recovBg = score >= 70 ? 'rgba(6,182,212,0.15)' : score >= 50 ? 'rgba(234,179,8,0.15)' : 'rgba(239,68,68,0.15)';
    h += '<div class="score-banner-grade" style="color:' + clr + ';background:' + recovBg + '">path to ' + projected + '</div>';
  }
  h += '</div>';
  return h;
}
var phaseDescriptions = {
  'Project Scan': 'Checks .gitignore, lock files, security config, and dependency advisories',
  'Credentials': 'Scans source files for hardcoded API keys, tokens, and secrets',
  'Config Integrity': 'Verifies cryptographic signatures on monitored config files',
  'Shield Analysis': 'Analyzes 7 days of security events, policy violations, and ARP detections',
  'HMA Scan': 'Runs HackMyAgent security checks against your AI agent endpoints',
  'Shadow AI': 'Detects AI agents, MCP servers, and AI configs; checks governance posture'
};
function phaseCard(phase) {
  var statusCls = 'status-' + phase.status;
  var time = phase.status === 'skip' ? '--' : (phase.durationMs / 1000).toFixed(1) + 's';
  var desc = phaseDescriptions[phase.name] || '';
  return '<div class="phase-card"><div style="display:flex;justify-content:space-between;align-items:center"><div class="phase-name">' + esc(phase.name) + '</div><span class="status-badge ' + statusCls + '">' + esc(phase.status) + '</span></div><div class="phase-detail">' + esc(phase.detail) + '</div>' + (desc ? '<div class="phase-desc">' + esc(desc) + '</div>' : '') + '<div class="phase-time">' + esc(time) + '</div></div>';
}

/**
 * Unified Review HTML Dashboard Generator.
 *
 * Generates a self-contained HTML file with:
 * - Dark theme (#0f172a bg, #1e293b cards, teal primary)
 * - 6-tab navigation (Overview, Credentials, Hygiene, Integrity, Shield, HMA)
 * - Composite score gauge with grade
 * - Phase status cards with timing
 * - Cross-tab navigation
 * - Copy buttons for remediation commands
 *
 * No external dependencies. No emojis. Monospace font.
 */

import type { ReviewReport } from '../commands/review.js';

function esc(s: string | null | undefined): string {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function generateReviewHtml(report: ReviewReport): string {
  const jsonData = JSON.stringify(report).replace(/<\//g, '<\\/');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenA2A Security Review - ${esc(report.projectName ?? 'Project')}</title>
<style>
:root {
  --bg: #0f172a;
  --card: #1e293b;
  --card-border: #334155;
  --primary: #06b6d4;
  --text: #e2e8f0;
  --muted: #94a3b8;
  --dim: #64748b;
  --critical: #ef4444;
  --high: #f97316;
  --medium: #eab308;
  --low: #3b82f6;
  --info: #6b7280;
  --green: #22c55e;
  --red: #ef4444;
  --amber: #f59e0b;
  --font: 'JetBrains Mono','Fira Code','SF Mono',Menlo,Consolas,monospace;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;}
.container{max-width:1200px;margin:0 auto;padding:16px 20px;}
.header{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--card-border);margin-bottom:16px;}
.header-title{font-size:20px;font-weight:700;color:var(--primary);}
.header-meta{font-size:12px;color:var(--dim);}
.nav{display:flex;gap:2px;margin-bottom:16px;border-bottom:1px solid var(--card-border);padding-bottom:0;}
.nav-tab{background:none;border:none;color:var(--dim);font-family:var(--font);font-size:13px;padding:8px 14px;cursor:pointer;border-bottom:2px solid transparent;transition:all 0.15s;}
.nav-tab:hover{color:var(--text);}
.nav-tab.active{color:var(--primary);border-bottom-color:var(--primary);}
.page{display:none;}
.page.active{display:block;}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:16px;margin-bottom:12px;}
.card-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:10px;}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-bottom:16px;}
.stat-card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:12px 14px;text-align:center;}
.stat-value{font-size:24px;font-weight:700;}
.stat-label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-top:2px;}
.score-banner{display:flex;align-items:center;gap:24px;background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:20px 24px;margin-bottom:16px;}
.score-banner-num{font-size:48px;font-weight:700;line-height:1;letter-spacing:-1px;}
.score-banner-grade{font-size:20px;font-weight:700;line-height:1;padding:6px 14px;border-radius:4px;letter-spacing:0.5px;}
.score-banner-bar{flex:1;display:flex;flex-direction:column;gap:6px;}
.score-banner-track{height:6px;background:rgba(255,255,255,0.06);border-radius:3px;overflow:hidden;}
.score-banner-fill{height:100%;border-radius:3px;transition:width 0.3s;}
.score-banner-label{font-size:12px;color:var(--dim);display:flex;justify-content:space-between;}
.phase-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:8px;margin-bottom:16px;}
.phase-card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:12px 14px;}
.phase-name{font-size:13px;font-weight:600;margin-bottom:4px;}
.phase-detail{font-size:12px;color:var(--muted);}
.phase-time{font-size:11px;color:var(--dim);margin-top:4px;}
.status-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:0.3px;}
.status-pass{background:rgba(34,197,94,0.15);color:var(--green);}
.status-warn{background:rgba(234,179,8,0.15);color:var(--medium);}
.status-fail{background:rgba(239,68,68,0.15);color:var(--red);}
.status-skip{background:rgba(107,114,128,0.15);color:var(--info);}
.sev-badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;text-transform:uppercase;}
.sev-critical{background:rgba(239,68,68,0.15);color:var(--critical);}
.sev-high{background:rgba(249,115,22,0.15);color:var(--high);}
.sev-medium{background:rgba(234,179,8,0.15);color:var(--medium);}
.sev-low{background:rgba(59,130,246,0.15);color:var(--low);}
.sev-info{background:rgba(107,114,128,0.15);color:var(--info);}
.data-table{width:100%;border-collapse:collapse;font-size:13px;}
.data-table th{text-align:left;padding:8px 10px;color:var(--dim);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:0.5px;border-bottom:1px solid var(--card-border);}
.data-table td{padding:8px 10px;border-bottom:1px solid rgba(51,65,85,0.4);vertical-align:top;}
.data-table tr:last-child td{border-bottom:none;}
.data-table tr:hover td{background:rgba(6,182,212,0.03);}
.gauge-card{display:flex;flex-direction:column;align-items:center;padding:10px;}
.section-title{font-size:16px;font-weight:700;color:var(--text);margin:16px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--card-border);}
.copy-btn{background:none;border:1px solid var(--dim);color:var(--dim);font-family:var(--font);font-size:11px;padding:2px 8px;border-radius:4px;cursor:pointer;margin-left:6px;transition:all 0.15s;}
.copy-btn:hover{border-color:var(--primary);color:var(--primary);}
.copy-btn.copied{border-color:var(--green);color:var(--green);}
.cmd-block{display:flex;align-items:center;background:rgba(0,0,0,0.3);padding:6px 10px;border-radius:4px;margin:4px 0;font-size:13px;color:var(--primary);}
.cmd-text{flex:1;}
.action-item{display:flex;align-items:flex-start;gap:10px;padding:8px 0;border-bottom:1px solid rgba(51,65,85,0.3);}
.action-item:last-child{border-bottom:none;}
.action-priority{font-size:10px;font-weight:700;color:var(--dim);min-width:20px;}
.action-content{flex:1;}
.action-desc{font-size:13px;margin-bottom:4px;}
.action-link{font-size:12px;color:var(--primary);cursor:pointer;text-decoration:underline;}
.empty-state{color:var(--dim);font-size:13px;padding:20px;text-align:center;}
.cta-card{background:var(--card);border:1px dashed var(--primary);border-radius:6px;padding:20px;text-align:center;}
.cta-title{font-size:16px;font-weight:700;color:var(--primary);margin-bottom:8px;}
.cta-desc{font-size:13px;color:var(--muted);margin-bottom:12px;}
.overview-top{display:grid;grid-template-columns:auto 1fr;gap:12px;margin-bottom:16px;}
@media(max-width:768px){.overview-top{grid-template-columns:1fr;}.phase-grid{grid-template-columns:repeat(2,1fr);}.stats-grid{grid-template-columns:repeat(2,1fr);}}
.hygiene-row{display:flex;justify-content:space-between;align-items:flex-start;padding:8px 0;border-bottom:1px solid rgba(51,65,85,0.3);font-size:13px;}
.hygiene-row:last-child{border-bottom:none;}
.hygiene-label{color:var(--muted);}
.arp-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:8px;margin-top:8px;}
.arp-stat{text-align:center;padding:8px;background:rgba(0,0,0,0.2);border-radius:4px;}
.arp-stat-value{font-size:18px;font-weight:700;color:var(--primary);}
.arp-stat-label{font-size:11px;color:var(--dim);text-transform:uppercase;}
.header-subtitle{font-size:13px;color:var(--dim);margin-top:4px;}
.section-intro{font-size:13px;color:var(--muted);margin-bottom:12px;line-height:1.5;}
.score-explainer{background:var(--card);border:1px dashed var(--card-border);border-radius:6px;padding:14px 16px;margin-bottom:12px;font-size:13px;color:var(--muted);line-height:1.6;}
.score-explainer strong{color:var(--text);}
.check-desc{font-size:12px;color:var(--dim);margin-top:2px;}
.phase-desc{font-size:12px;color:var(--dim);margin-top:4px;line-height:1.4;}
.finding-desc{font-size:12px;color:var(--muted);padding:4px 10px 8px;line-height:1.4;}
.cred-card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:14px 16px;margin-bottom:8px;}
.cred-card-header{display:flex;align-items:center;gap:8px;margin-bottom:6px;flex-wrap:wrap;}
.cred-card-title{font-size:14px;font-weight:600;color:var(--text);}
.cred-card-meta{display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;font-size:12px;margin-bottom:8px;}
.cred-card-meta-label{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:0.3px;}
.cred-card-meta-value{color:var(--muted);}
.cred-card-meta-value.env{color:var(--primary);font-weight:600;}
.cred-card-detail{border-top:1px solid rgba(51,65,85,0.4);padding-top:8px;margin-top:4px;}
.cred-card-detail-label{font-size:11px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:0.3px;margin-bottom:2px;}
.cred-card-detail-text{font-size:12px;color:var(--muted);line-height:1.5;margin-bottom:6px;}
.badge-owasp{display:inline-block;background:rgba(245,158,11,0.15);color:#f59e0b;font-size:11px;font-weight:700;padding:2px 6px;border-radius:10px;margin-right:4px;}
.badge-mitre{display:inline-block;background:rgba(139,92,246,0.15);color:#8b5cf6;font-size:11px;font-weight:700;padding:2px 6px;border-radius:10px;margin-right:4px;}
.footer{border-top:1px solid var(--card-border);margin-top:32px;padding:16px 0;text-align:center;font-size:12px;color:var(--dim);}
.footer a{color:var(--primary);text-decoration:none;}
.footer a:hover{text-decoration:underline;}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div>
      <div class="header-title">OpenA2A Security Review</div>
      <div class="header-subtitle">Security review of <strong style="color:var(--text)">${esc(report.projectName ?? report.directory)}</strong> -- composite score from 5 automated checks. Higher is better.</div>
    </div>
    <div class="header-meta">${esc(report.timestamp)}</div>
  </div>
  <nav class="nav" id="main-nav">
    <button class="nav-tab active" data-page="overview">Overview</button>
    <button class="nav-tab" data-page="credentials">Credentials</button>
    <button class="nav-tab" data-page="hygiene">Hygiene</button>
    <button class="nav-tab" data-page="integrity">Integrity</button>
    <button class="nav-tab" data-page="shield">Shield</button>
    <button class="nav-tab" data-page="hma">HMA</button>
  </nav>
  <div class="page active" id="page-overview"></div>
  <div class="page" id="page-credentials"></div>
  <div class="page" id="page-hygiene"></div>
  <div class="page" id="page-integrity"></div>
  <div class="page" id="page-shield"></div>
  <div class="page" id="page-hma"></div>
  <div class="footer">Generated by <a href="https://opena2a.org" target="_blank" rel="noopener">OpenA2A</a> -- Open Agent-to-Agent Security Platform</div>
</div>

<script id="report-data" type="application/json">${jsonData}</script>
<script>
(function(){
  var report = JSON.parse(document.getElementById('report-data').textContent);
  var pagesRendered = {};

  function esc(s){return s==null?'':String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}
  function scoreColor(s){return s>=90?'var(--green)':s>=70?'var(--primary)':s>=50?'var(--medium)':'var(--red)';}

  // Tab navigation
  document.getElementById('main-nav').addEventListener('click',function(e){
    var btn=e.target.closest('.nav-tab');if(!btn)return;
    var pg=btn.getAttribute('data-page');
    document.querySelectorAll('.nav-tab').forEach(function(t){t.classList.toggle('active',t===btn);});
    document.querySelectorAll('.page').forEach(function(p){p.classList.toggle('active',p.id==='page-'+pg);});
    renderPage(pg);
  });

  function renderPage(pg){
    if(pagesRendered[pg])return;pagesRendered[pg]=true;
    var el=document.getElementById('page-'+pg);
    switch(pg){
      case 'overview':el.innerHTML=renderOverview();break;
      case 'credentials':el.innerHTML=renderCredentials();break;
      case 'hygiene':el.innerHTML=renderHygiene();break;
      case 'integrity':el.innerHTML=renderIntegrity();break;
      case 'shield':el.innerHTML=renderShield();break;
      case 'hma':el.innerHTML=renderHma();break;
    }
  }

  // Copy command
  window.copyCmd=function(btn){
    var cmd=btn.getAttribute('data-cmd');
    if(navigator.clipboard&&navigator.clipboard.writeText){
      navigator.clipboard.writeText(cmd).then(function(){
        btn.textContent='OK';btn.classList.add('copied');
        setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);
      });
    }else{
      var ta=document.createElement('textarea');ta.value=cmd;ta.style.position='fixed';ta.style.left='-9999px';
      document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);
      btn.textContent='OK';btn.classList.add('copied');
      setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);
    }
  };

  // Cross-tab navigation
  window.goToTab=function(tab){
    var btn=document.querySelector('.nav-tab[data-page="'+tab+'"]');
    if(btn)btn.click();
  };

  // Gauge SVG
  function gaugeCircle(score,grade){
    var sz=170,cx=sz/2,cy=sz/2,r=65,sw=10,circ=2*Math.PI*r;
    var pct=Math.max(0,Math.min(100,score))/100,dash=pct*circ,gap=circ-dash;
    var clr=score>=90?'#22c55e':score>=70?'#06b6d4':score>=50?'#eab308':'#ef4444';
    var s='<svg width="'+sz+'" height="'+sz+'" viewBox="0 0 '+sz+' '+sz+'">';
    s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="rgba(255,255,255,0.05)" stroke-width="'+sw+'"/>';
    s+='<circle cx="'+cx+'" cy="'+cy+'" r="'+r+'" fill="none" stroke="'+clr+'" stroke-width="'+sw+'" stroke-dasharray="'+dash+' '+gap+'" stroke-dashoffset="'+(circ*0.25)+'" stroke-linecap="round" transform="rotate(-90 '+cx+' '+cy+')"/>';
    s+='<text x="'+cx+'" y="'+(cy-6)+'" text-anchor="middle" dominant-baseline="middle" font-size="32" font-weight="700" fill="'+clr+'" font-family="var(--font)">'+score+'</text>';
    s+='<text x="'+cx+'" y="'+(cy+20)+'" text-anchor="middle" dominant-baseline="middle" font-size="14" font-weight="600" fill="'+clr+'" font-family="var(--font)">Grade '+esc(grade)+'</text>';
    s+='</svg>';return s;
  }

  function cmdBlock(cmd){
    return '<div class="cmd-block"><span class="cmd-text">'+esc(cmd)+'</span><button class="copy-btn" data-cmd="'+esc(cmd)+'" onclick="copyCmd(this)">Copy</button></div>';
  }

  function statCard(value,label,color){
    return '<div class="stat-card"><div class="stat-value" style="color:'+color+'">'+esc(String(value))+'</div><div class="stat-label">'+esc(label)+'</div></div>';
  }

  function scoreBanner(score,grade){
    var clr=scoreColor(score);
    var gradeBg=score>=90?'rgba(34,197,94,0.15)':score>=70?'rgba(6,182,212,0.15)':score>=50?'rgba(234,179,8,0.15)':'rgba(239,68,68,0.15)';
    var h='<div class="score-banner">';
    h+='<div class="score-banner-num" style="color:'+clr+'">'+score+'</div>';
    h+='<div class="score-banner-bar">';
    h+='<div class="score-banner-label"><span>Composite Score</span><span>'+score+'/100</span></div>';
    h+='<div class="score-banner-track"><div class="score-banner-fill" style="width:'+score+'%;background:'+clr+'"></div></div>';
    h+='</div>';
    h+='<div class="score-banner-grade" style="color:'+clr+';background:'+gradeBg+'">'+esc(grade)+'</div>';
    h+='</div>';
    return h;
  }

  var phaseDescriptions={
    'Project Scan':'Checks .gitignore, lock files, security config, and dependency advisories',
    'Credentials':'Scans source files for hardcoded API keys, tokens, and secrets',
    'Config Integrity':'Verifies cryptographic signatures on monitored config files',
    'Shield Analysis':'Analyzes 7 days of security events, policy violations, and ARP detections',
    'HMA Scan':'Runs HackMyAgent security checks against your AI agent endpoints'
  };
  function phaseCard(phase){
    var statusCls='status-'+phase.status;
    var time=phase.status==='skip'?'--':(phase.durationMs/1000).toFixed(1)+'s';
    var desc=phaseDescriptions[phase.name]||'';
    return '<div class="phase-card"><div style="display:flex;justify-content:space-between;align-items:center"><div class="phase-name">'+esc(phase.name)+'</div><span class="status-badge '+statusCls+'">'+esc(phase.status)+'</span></div><div class="phase-detail">'+esc(phase.detail)+'</div>'+(desc?'<div class="phase-desc">'+esc(desc)+'</div>':'')+'<div class="phase-time">'+esc(time)+'</div></div>';
  }

  // ======================== OVERVIEW ========================
  function renderOverview(){
    var h='';
    // Score banner
    var sevCounts={critical:0,high:0,medium:0,low:0};
    var findings=report.findings||[];
    for(var i=0;i<findings.length;i++){var s=findings[i].severity;if(s in sevCounts)sevCounts[s]++;}
    h+=scoreBanner(report.compositeScore,report.grade);
    h+='<div class="stats-grid">';
    h+=statCard(findings.length,'Findings',findings.length>0?'var(--amber)':'var(--green)');
    h+=statCard(sevCounts.critical,'Critical',sevCounts.critical>0?'var(--critical)':'var(--text)');
    h+=statCard(sevCounts.high,'High',sevCounts.high>0?'var(--high)':'var(--text)');
    h+=statCard(sevCounts.medium,'Medium',sevCounts.medium>0?'var(--medium)':'var(--text)');
    h+='</div>';

    // Phase cards (full width, 5 columns)
    h+='<h2 class="section-title">Phase Results</h2><div class="phase-grid">';
    var phases=report.phases||[];
    for(var i=0;i<phases.length;i++) h+=phaseCard(phases[i]);
    h+='</div>';

    // Score breakdown -- show actual score, weight, weighted contribution per dimension
    var dims=[
      {name:'Hygiene',weight:35,score:report.initData.trustScore,tab:'hygiene'},
      {name:'Shield',weight:25,score:report.shieldData.postureScore,tab:'shield'},
      {name:'Credentials',weight:22,score:phases.length>1?phases[1].score:0,tab:'credentials'},
      {name:'Integrity',weight:18,score:phases.length>2?phases[2].score:0,tab:'integrity'}
    ];
    h+='<div class="score-explainer">';
    h+='<div style="font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:12px">Score Breakdown</div>';
    h+='<div style="display:flex;flex-direction:column;gap:10px">';
    for(var i=0;i<dims.length;i++){
      var d=dims[i];
      var weighted=Math.round(d.score*d.weight/100);
      var clr=scoreColor(d.score);
      h+='<div style="display:grid;grid-template-columns:100px 1fr 60px 50px;align-items:center;gap:10px;cursor:pointer" onclick="goToTab(&quot;'+d.tab+'&quot;)">';
      h+='<div style="display:flex;align-items:baseline;gap:6px"><span style="font-size:13px;color:var(--muted)">'+esc(d.name)+'</span></div>';
      h+='<div style="position:relative;height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden"><div style="position:absolute;left:0;top:0;height:100%;width:'+d.score+'%;background:'+clr+';border-radius:4px;transition:width 0.3s"></div></div>';
      h+='<div style="text-align:right;font-size:14px;font-weight:700;color:'+clr+'">'+d.score+'<span style="font-size:11px;color:var(--dim);font-weight:400">/100</span></div>';
      h+='<div style="text-align:right;font-size:11px;color:var(--dim)">x '+d.weight+'%</div>';
      h+='</div>';
    }
    h+='</div>';
    h+='<div style="display:flex;justify-content:space-between;align-items:center;border-top:1px solid rgba(51,65,85,0.4);margin-top:12px;padding-top:8px">';
    h+='<div style="display:flex;gap:12px;font-size:12px;color:var(--dim)">';
    h+='<span><strong style="color:var(--green)">A</strong> 90+</span>';
    h+='<span><strong style="color:var(--primary)">B</strong> 80+</span>';
    h+='<span><strong style="color:var(--medium)">C</strong> 70+</span>';
    h+='<span><strong style="color:var(--high)">D</strong> 60+</span>';
    h+='<span><strong style="color:var(--red)">F</strong> &lt;60</span>';
    h+='</div>';
    h+='<div style="font-size:12px;color:var(--dim)">Click a row to view details</div>';
    h+='</div>';
    h+='</div>';

    // Action items
    var actions=report.actionItems||[];
    var actionImpact={
      'critical':'Immediate risk of credential compromise or data breach',
      'high':'Significant security gap that attackers can exploit',
      'medium':'Moderate risk that weakens your security posture',
      'low':'Minor improvement to harden your defenses',
      'info':'Recommended best practice'
    };
    if(actions.length>0){
      h+='<h2 class="section-title">Action Items</h2><div class="card">';
      for(var i=0;i<actions.length;i++){
        var a=actions[i];
        var impact=actionImpact[a.severity]||'';
        h+='<div class="action-item"><div class="action-priority">#'+a.priority+'</div><div class="action-content"><div class="action-desc"><span class="sev-badge sev-'+esc(a.severity)+'">'+esc(a.severity)+'</span> '+esc(a.description)+'</div>'+(impact?'<div class="check-desc">'+esc(impact)+'</div>':'')+cmdBlock(a.command)+'<span class="action-link" onclick="goToTab(&quot;'+esc(a.tab)+'&quot;)">View details</span></div></div>';
      }
      h+='</div>';
    }

    // Top findings
    if(findings.length>0){
      h+='<h2 class="section-title">Findings</h2><div class="card"><table class="data-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Source</th><th>Detail</th></tr></thead><tbody>';
      var top=findings.slice(0,10);
      for(var i=0;i<top.length;i++){var f=top[i];
        h+='<tr><td>'+esc(f.id)+'</td><td>'+esc(f.title)+'</td><td><span class="sev-badge sev-'+esc(f.severity)+'">'+esc(f.severity)+'</span></td><td>'+esc(f.source)+'</td><td style="font-size:11px;color:var(--muted)">'+esc(f.detail)+'</td></tr>';
      }
      h+='</tbody></table></div>';
    }
    return h;
  }

  // ======================== CREDENTIALS ========================
  function renderCredentials(){
    var data=report.credentialData;
    if(!data||data.totalFindings===0){
      return '<div class="card"><div class="empty-state">No hardcoded credentials found. Your project is clean.</div></div>';
    }
    var h='<div class="section-intro">Hardcoded credentials in source code are the #1 cause of security breaches in AI projects. Keys pushed to git are scraped by bots within minutes. Each finding below is a credential that should be moved to environment variables.</div>';
    h+='<div class="stats-grid">';
    h+=statCard(data.totalFindings,'Total Findings',data.totalFindings>0?'var(--red)':'var(--green)');
    h+=statCard(data.bySeverity.critical||0,'Critical',(data.bySeverity.critical||0)>0?'var(--critical)':'var(--text)');
    h+=statCard(data.bySeverity.high||0,'High',(data.bySeverity.high||0)>0?'var(--high)':'var(--text)');
    h+=statCard(data.bySeverity.medium||0,'Medium',(data.bySeverity.medium||0)>0?'var(--medium)':'var(--text)');
    h+='</div>';

    h+='<h2 class="section-title">Credential Findings</h2>';
    var matches=data.matches||[];
    for(var i=0;i<matches.length;i++){
      var m=matches[i];
      h+='<div class="cred-card">';
      h+='<div class="cred-card-header"><span class="sev-badge sev-'+esc(m.severity)+'">'+esc(m.severity)+'</span><span class="cred-card-title">'+esc(m.title)+'</span><span style="color:var(--dim);font-size:12px">'+esc(m.findingId)+'</span></div>';
      h+='<div class="cred-card-meta">';
      h+='<div><div class="cred-card-meta-label">File</div><div class="cred-card-meta-value">'+esc(m.filePath)+':'+m.line+'</div></div>';
      h+='<div><div class="cred-card-meta-label">Migrate to</div><div class="cred-card-meta-value env">'+esc(m.envVar)+'</div></div>';
      h+='</div>';
      if(m.explanation||m.businessImpact){
        h+='<div class="cred-card-detail">';
        if(m.explanation){h+='<div class="cred-card-detail-label">Why this matters</div><div class="cred-card-detail-text">'+esc(m.explanation)+'</div>';}
        if(m.businessImpact){h+='<div class="cred-card-detail-label">Business impact</div><div class="cred-card-detail-text">'+esc(m.businessImpact)+'</div>';}
        h+='</div>';
      }
      h+='</div>';
    }

    // Drift
    if(data.driftFindings&&data.driftFindings.length>0){
      h+='<h2 class="section-title">Scope Drift</h2>';
      h+='<div class="card"><p style="color:var(--muted);font-size:12px;margin-bottom:8px;line-height:1.5">Scope drift occurs when a key provisioned for one service (e.g., Google Maps) silently grants access to AI services (e.g., Gemini). The key\\\'s permissions are wider than intended, expanding your attack surface without any code change.</p>';
      h+='<table class="data-table"><thead><tr><th>ID</th><th>File</th><th>Line</th></tr></thead><tbody>';
      for(var i=0;i<data.driftFindings.length;i++){
        var d=data.driftFindings[i];
        h+='<tr><td>'+esc(d.findingId)+'</td><td style="font-size:11px;color:var(--muted)">'+esc(d.filePath)+'</td><td>'+d.line+'</td></tr>';
      }
      h+='</tbody></table></div>';
    }

    h+='<h2 class="section-title">Remediation</h2>';
    h+='<div class="card">'+cmdBlock('opena2a protect')+'<p style="color:var(--muted);font-size:12px;margin-top:8px">Migrate hardcoded credentials to environment variables or encrypted vault.</p></div>';
    return h;
  }

  // ======================== HYGIENE ========================
  var hygieneDescriptions={
    'Credential scan':'Detects API keys and secrets hardcoded in source files',
    'credentials':'Detects API keys and secrets hardcoded in source files',
    '.gitignore':'Prevents sensitive files from being committed to version control',
    'gitignore':'Prevents sensitive files from being committed to version control',
    '.env protection':'Ensures .env files (which store secrets) are excluded from git',
    'env protection':'Ensures .env files (which store secrets) are excluded from git',
    'Lock file':'Pins exact dependency versions to prevent supply chain attacks',
    'lock file':'Pins exact dependency versions to prevent supply chain attacks',
    'Security config':'OpenA2A configuration enables automated security monitoring',
    'security config':'OpenA2A configuration enables automated security monitoring'
  };
  function findHygieneDesc(label){
    if(!label)return '';
    var lc=label.toLowerCase();
    for(var key in hygieneDescriptions){if(lc.indexOf(key.toLowerCase())>=0)return hygieneDescriptions[key];}
    return '';
  }
  function renderHygiene(){
    var init=report.initData;
    var h='<div class="section-intro">Project hygiene measures foundational security practices. These checks do not require any OpenA2A tools -- they are standard development practices that prevent accidental exposure.</div>';
    h+='<div class="stats-grid">';
    h+=statCard(init.trustScore+'/100','Trust Score',scoreColor(init.trustScore));
    h+=statCard('Grade '+init.grade,'Trust Grade',scoreColor(init.trustScore));
    h+=statCard(init.postureScore+'/100','Posture Score',scoreColor(init.postureScore));
    h+=statCard(init.riskLevel,'Risk Level',init.riskLevel==='SECURE'||init.riskLevel==='LOW'?'var(--green)':init.riskLevel==='MEDIUM'?'var(--medium)':'var(--red)');
    h+='</div>';

    h+='<div class="overview-top">';
    h+='<div class="gauge-card">'+gaugeCircle(init.trustScore,init.grade)+'</div>';
    h+='<div>';
    h+='<h2 class="section-title">Hygiene Checks</h2>';
    h+='<div class="card">';
    var checks=init.hygieneChecks||[];
    for(var i=0;i<checks.length;i++){
      var c=checks[i];
      var statusClr=c.status==='pass'?'var(--green)':c.status==='fail'?'var(--red)':c.status==='warn'?'var(--medium)':'var(--dim)';
      var desc=findHygieneDesc(c.label);
      h+='<div class="hygiene-row"><div><span class="hygiene-label">'+esc(c.label)+'</span>'+(desc?'<div class="check-desc">'+esc(desc)+'</div>':'')+'</div><span style="color:'+statusClr+'">'+esc(c.detail)+'</span></div>';
    }
    h+='</div>';
    h+='</div></div>';

    h+='<div class="score-explainer">';
    h+='<div style="font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:8px">Trust Score Formula</div>';
    h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 16px;font-size:12px">';
    h+='<div style="color:var(--muted)">Start</div><div style="color:var(--text);font-weight:600">100</div>';
    h+='<div style="color:var(--muted)">Missing .gitignore</div><div style="color:var(--red)">-15</div>';
    h+='<div style="color:var(--muted)">Unprotected .env</div><div style="color:var(--red)">-10</div>';
    h+='<div style="color:var(--muted)">No lock file</div><div style="color:var(--amber)">-5</div>';
    h+='<div style="color:var(--muted)">Security config</div><div style="color:var(--green)">+5 bonus</div>';
    h+='</div>';
    h+='</div>';

    h+='<div class="stats-grid">';
    h+=statCard(init.activeTools+'/'+init.totalTools,'Active Tools','var(--primary)');
    h+=statCard(init.advisoryCount,'Advisories',init.advisoryCount>0?'var(--amber)':'var(--green)');
    h+='</div>';

    h+='<h2 class="section-title">Project Info</h2>';
    h+='<div class="card">';
    h+='<div class="hygiene-row"><span class="hygiene-label">Project</span><span>'+esc(init.projectName||'unnamed')+'</span></div>';
    h+='<div class="hygiene-row"><span class="hygiene-label">Type</span><span>'+esc(init.projectType)+'</span></div>';
    h+='<div class="hygiene-row"><span class="hygiene-label">Version</span><span>'+esc(init.projectVersion||'--')+'</span></div>';
    h+='</div>';
    return h;
  }

  // ======================== INTEGRITY ========================
  function renderIntegrity(){
    var guard=report.guardData;
    var h='<div class="section-intro">ConfigGuard signs your configuration files with SHA-256 hashes. If anyone (or any agent) modifies a signed file, the tampering is immediately detectable. This is your first line of defense against configuration drift.</div>';
    var statusClr=guard.signatureStatus==='valid'?'var(--green)':guard.signatureStatus==='tampered'?'var(--red)':'var(--dim)';
    var statusLabel=guard.signatureStatus==='valid'?'Active':guard.signatureStatus==='tampered'?'Tampered':'Unsigned';

    h+='<div class="stats-grid">';
    h+=statCard(statusLabel,'Signature Status',statusClr);
    h+=statCard(guard.filesMonitored,'Files Monitored','var(--primary)');
    h+=statCard(guard.tamperedFiles?guard.tamperedFiles.length:0,'Tampered',(guard.tamperedFiles&&guard.tamperedFiles.length>0)?'var(--red)':'var(--green)');
    h+='</div>';

    if(guard.signatureStatus==='unsigned'){
      h+='<div class="cta-card"><div class="cta-title">ConfigGuard Not Active</div><div class="cta-desc">Sign your config files to detect unauthorized modifications.</div>'+cmdBlock('opena2a guard sign')+'</div>';
    }else if(guard.signatureStatus==='tampered'){
      h+='<h2 class="section-title">Tampered Files</h2>';
      h+='<div class="card"><table class="data-table"><thead><tr><th>File</th><th>Status</th></tr></thead><tbody>';
      for(var i=0;i<guard.tamperedFiles.length;i++){
        h+='<tr><td>'+esc(guard.tamperedFiles[i])+'</td><td><span class="sev-badge sev-critical">tampered</span></td></tr>';
      }
      h+='</tbody></table></div>';
      h+='<h2 class="section-title">Remediation</h2>';
      h+='<div class="card">'+cmdBlock('opena2a guard diff')+'<p style="color:var(--muted);font-size:12px;margin:4px 0">Review changes, then resign:</p>'+cmdBlock('opena2a guard resign')+'</div>';
    }else{
      h+='<div class="card"><div class="empty-state">All '+guard.filesMonitored+' monitored files have valid signatures.</div></div>';
    }
    return h;
  }

  // ======================== SHIELD ========================
  function renderShield(){
    var shield=report.shieldData;
    var h='<div class="section-intro">Shield is the unified security orchestration layer. It collects events from all OpenA2A tools (ARP, ConfigGuard, Secretless, HMA) into a tamper-evident log and classifies them into actionable findings.</div>';
    h+='<div class="stats-grid">';
    h+=statCard(shield.postureScore+'/100','Posture Score',scoreColor(shield.postureScore));
    h+=statCard(shield.eventCount,'Events (7d)','var(--primary)');
    h+=statCard(shield.classifiedFindings?shield.classifiedFindings.length:0,'Findings',shield.classifiedFindings&&shield.classifiedFindings.length>0?'var(--amber)':'var(--green)');
    h+=statCard(shield.policyLoaded?'Loaded':'None','Policy',shield.policyLoaded?'var(--green)':'var(--dim)');
    h+=statCard(shield.policyMode||'--','Mode','var(--muted)');
    h+=statCard(shield.integrityStatus||'healthy','Integrity',shield.integrityStatus==='healthy'?'var(--green)':'var(--red)');
    h+='</div>';

    // Classified findings
    var cf=shield.classifiedFindings||[];
    if(cf.length>0){
      h+='<h2 class="section-title">Classified Findings</h2>';
      h+='<div class="card"><table class="data-table"><thead><tr><th>ID</th><th>Title</th><th>Severity</th><th>Count</th><th>Remediation</th></tr></thead><tbody>';
      for(var i=0;i<cf.length;i++){
        var f=cf[i];
        var badges='';
        if(f.finding.owaspAgentic)badges+='<span class="badge-owasp">'+esc(f.finding.owaspAgentic)+'</span>';
        if(f.finding.mitreAtlas)badges+='<span class="badge-mitre">'+esc(f.finding.mitreAtlas)+'</span>';
        h+='<tr><td>'+esc(f.finding.id)+'</td><td>'+esc(f.finding.title)+(badges?' '+badges:'')+'</td><td><span class="sev-badge sev-'+esc(f.finding.severity)+'">'+esc(f.finding.severity)+'</span></td><td>'+f.count+'</td><td>'+cmdBlock(f.finding.remediation)+'</td></tr>';
        if(f.finding.description){
          h+='<tr><td colspan="5" class="finding-desc">'+esc(f.finding.description)+'</td></tr>';
        }
      }
      h+='</tbody></table></div>';
    }

    // ARP stats
    var arp=shield.arpStats;
    if(arp&&arp.totalEvents>0){
      h+='<h2 class="section-title">Runtime Protection (ARP)</h2>';
      h+='<div class="card"><div class="arp-grid">';
      h+='<div class="arp-stat"><div class="arp-stat-value">'+arp.totalEvents+'</div><div class="arp-stat-label">Total Events</div></div>';
      h+='<div class="arp-stat"><div class="arp-stat-value" style="color:var(--amber)">'+arp.anomalies+'</div><div class="arp-stat-label">Anomalies</div></div>';
      h+='<div class="arp-stat"><div class="arp-stat-value" style="color:var(--red)">'+arp.violations+'</div><div class="arp-stat-label">Violations</div></div>';
      h+='<div class="arp-stat"><div class="arp-stat-value">'+arp.processEvents+'</div><div class="arp-stat-label">Process</div></div>';
      h+='<div class="arp-stat"><div class="arp-stat-value">'+arp.networkEvents+'</div><div class="arp-stat-label">Network</div></div>';
      h+='<div class="arp-stat"><div class="arp-stat-value">'+arp.enforcements+'</div><div class="arp-stat-label">Enforcements</div></div>';
      h+='</div></div>';
    }else{
      h+='<h2 class="section-title">Runtime Protection (ARP)</h2>';
      h+='<div class="section-intro">ARP (Agent Runtime Protection) monitors process spawns, network connections, and file access in real time. It detects anomalous agent behavior before damage occurs.</div>';
      h+='<div class="card"><div class="empty-state">No ARP events in the last 7 days. Start runtime monitoring:</div>'+cmdBlock('opena2a runtime start')+'</div>';
    }

    if(!shield.policyLoaded){
      h+='<h2 class="section-title">Policy</h2>';
      h+='<div class="cta-card"><div class="cta-title">No Security Policy</div><div class="cta-desc">Initialize Shield to enable adaptive security policy.</div>'+cmdBlock('opena2a shield init')+'</div>';
    }
    return h;
  }

  // ======================== HMA ========================
  function renderHma(){
    var hma=report.hmaData;
    if(!hma||!hma.available){
      var h='<div class="section-intro">HackMyAgent runs 150+ security checks against AI agent endpoints, testing for prompt injection, tool misuse, excessive agency, and OWASP Top 10 for LLM vulnerabilities.</div>';
      h+='<div class="cta-card"><div class="cta-title">HackMyAgent Not Installed</div>';
      h+='<div class="cta-desc">Install HMA to run comprehensive security scans against your AI agent.</div>';
      h+=cmdBlock('npm install -g hackmyagent');
      h+='<p style="color:var(--muted);font-size:13px;margin-top:12px;text-align:center">Then re-run: <code style="color:var(--primary)">opena2a review</code></p>';
      h+='</div>';
      return h;
    }
    var h='<div class="stats-grid">';
    h+=statCard(hma.score+'/100','HMA Score',scoreColor(hma.score));
    h+=statCard('Available','Status','var(--green)');
    h+='</div>';
    h+='<div class="card"><div class="empty-state">HMA is available. Run a full scan for detailed results:</div>'+cmdBlock('opena2a scan secure')+'</div>';
    return h;
  }

  // Initial render
  renderPage('overview');
})();
</script>
</body>
</html>`;
}

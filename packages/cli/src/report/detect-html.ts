/**
 * Shadow AI Agent Audit -- HTML Executive Report Generator.
 * Self-contained HTML, dark theme, monospace font, no emojis, no external deps.
 */

import type { DetectResult } from '../commands/detect.js';
import * as os from 'node:os';

function esc(s: string | null | undefined): string {
  if (!s) return '';
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

export function generateDetectHtml(result: DetectResult): string {
  const jsonData = JSON.stringify(result).replace(/<\//g, '<\\/');
  const hostname = esc(os.hostname());
  const username = esc(os.userInfo().username);
  const ts = esc(result.scanTimestamp.replace('T', ' ').replace(/\.\d+Z$/, ' UTC'));
  const dir = esc(result.scanDirectory);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Shadow AI Agent Audit</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--card-border:#334155;--primary:#06b6d4;--text:#e2e8f0;--muted:#94a3b8;--dim:#64748b;--critical:#ef4444;--high:#f97316;--medium:#eab308;--low:#3b82f6;--green:#22c55e;--red:#ef4444;--amber:#f59e0b;--font:'JetBrains Mono','Fira Code','SF Mono',Menlo,Consolas,monospace;}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:var(--text);font-family:var(--font);font-size:14px;line-height:1.6;}
.container{max-width:1000px;margin:0 auto;padding:24px 20px;}
.header{display:flex;align-items:center;justify-content:space-between;padding:12px 0;border-bottom:1px solid var(--card-border);margin-bottom:20px;}
.header-title{font-size:20px;font-weight:700;color:var(--primary);}
.header-meta{font-size:12px;color:var(--dim);text-align:right;line-height:1.5;}
.card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:16px;margin-bottom:12px;}
.card-title{font-size:14px;font-weight:700;color:var(--text);margin-bottom:10px;}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;margin-bottom:16px;}
.stat-card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:12px 14px;text-align:center;}
.stat-value{font-size:28px;font-weight:700;}
.stat-label{font-size:11px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-top:2px;}
.score-banner{display:flex;align-items:center;gap:24px;background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:20px 24px;margin-bottom:16px;}
.score-banner-num{font-size:48px;font-weight:700;line-height:1;letter-spacing:-1px;}
.score-banner-bar{flex:1;display:flex;flex-direction:column;gap:6px;}
.score-banner-track{height:8px;background:rgba(255,255,255,0.06);border-radius:4px;overflow:hidden;}
.score-banner-fill{height:100%;border-radius:4px;}
.score-banner-label{font-size:12px;color:var(--dim);display:flex;justify-content:space-between;}
.score-banner-recovery{font-size:14px;font-weight:600;color:var(--green);white-space:nowrap;}
.section-title{font-size:16px;font-weight:700;color:var(--text);margin:20px 0 8px;padding-bottom:4px;border-bottom:1px solid var(--card-border);}
.sev-badge{display:inline-block;font-size:11px;font-weight:600;padding:2px 8px;border-radius:10px;text-transform:uppercase;}
.sev-critical{background:rgba(239,68,68,0.15);color:var(--critical);}
.sev-high{background:rgba(249,115,22,0.15);color:var(--high);}
.sev-medium{background:rgba(234,179,8,0.15);color:var(--medium);}
.sev-low{background:rgba(59,130,246,0.15);color:var(--low);}
.status-badge{display:inline-block;font-size:11px;font-weight:700;padding:2px 8px;border-radius:10px;text-transform:uppercase;letter-spacing:0.3px;}
.status-pass{background:rgba(34,197,94,0.15);color:var(--green);}
.status-warn{background:rgba(234,179,8,0.15);color:var(--medium);}
.cmd-block{display:flex;align-items:center;background:rgba(0,0,0,0.3);padding:6px 10px;border-radius:4px;margin:4px 0;font-size:13px;color:var(--primary);}
.cmd-text{flex:1;}
.copy-btn{background:none;border:1px solid var(--dim);color:var(--dim);font-family:var(--font);font-size:11px;padding:2px 8px;border-radius:4px;cursor:pointer;margin-left:6px;}
.copy-btn:hover{border-color:var(--primary);color:var(--primary);}
.copy-btn.copied{border-color:var(--green);color:var(--green);}
.finding-card{background:var(--card);border:1px solid var(--card-border);border-radius:6px;padding:16px;margin-bottom:10px;}
.finding-header{display:flex;align-items:center;gap:10px;margin-bottom:8px;}
.finding-title{font-size:14px;font-weight:600;}
.finding-detail{font-size:13px;color:var(--muted);margin-bottom:6px;}
.finding-why{font-size:13px;color:var(--text);margin-bottom:10px;line-height:1.5;border-left:2px solid var(--card-border);padding-left:10px;}
.agent-row{display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid rgba(51,65,85,0.3);font-size:13px;}
.agent-row:last-child{border-bottom:none;}
.agent-name{font-weight:600;min-width:160px;}
.mcp-group{margin-bottom:12px;}
.mcp-group-title{font-size:12px;color:var(--dim);text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;font-weight:600;}
.mcp-row{padding:6px 0;border-bottom:1px solid rgba(51,65,85,0.2);font-size:13px;}
.mcp-row:last-child{border-bottom:none;}
.mcp-name{font-weight:600;color:var(--text);}
.mcp-caps{font-size:12px;color:var(--muted);margin-top:2px;}
.means-text{font-size:14px;color:var(--text);line-height:1.6;margin-bottom:8px;}
.identity-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid rgba(51,65,85,0.3);font-size:13px;}
.identity-row:last-child{border-bottom:none;}
.identity-label{color:var(--muted);}
.config-row{padding:8px 0;border-bottom:1px solid rgba(51,65,85,0.3);font-size:13px;}
.config-row:last-child{border-bottom:none;}
.config-file{font-weight:600;color:var(--text);}
.config-detail{font-size:12px;color:var(--muted);margin-top:2px;}
.footer{text-align:center;padding:20px 0;font-size:11px;color:var(--dim);border-top:1px solid var(--card-border);margin-top:24px;}
.footer a{color:var(--primary);text-decoration:none;}
@media(max-width:768px){.stats-grid{grid-template-columns:repeat(2,1fr);}.score-banner{flex-direction:column;align-items:flex-start;}}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="header-title">Shadow AI Agent Audit</div>
    <div class="header-meta">${hostname} | ${username}<br>${dir}<br>${ts}</div>
  </div>
  <div id="report"></div>
  <div class="footer">Generated by <a href="https://opena2a.org">opena2a detect</a></div>
</div>
<script type="application/json" id="detect-data">${jsonData}</script>
<script>
(function(){
  var report=JSON.parse(document.getElementById('detect-data').textContent);
  var s=report.summary;var score=s.governanceScore;
  var projected=Math.min(100,score+s.recoverablePoints);
  var capDescs={'filesystem':'Can read and write files','shell-access':'Can run commands on this computer','database':'Can read and modify databases','network':'Can make requests to external services','browser':'Can control a web browser','source-control':'Can access code repositories','messaging':'Can send messages','payments':'Can access payment systems','cloud-services':'Can access cloud infrastructure'};
  function sc(v){return v>=70?'var(--green)':v>=40?'var(--amber)':'var(--red)';}
  function esc(t){var d=document.createElement('div');d.textContent=t;return d.innerHTML;}

  var h='<div class="score-banner"><div class="score-banner-num" style="color:'+sc(score)+'">'+score+'</div><div class="score-banner-bar"><div class="score-banner-label"><span>Governance Score</span><span>'+score+'/100</span></div><div class="score-banner-track"><div class="score-banner-fill" style="width:'+score+'%;background:'+sc(score)+'"></div></div>';
  if(s.recoverablePoints>0&&report.findings.length>0){h+='<div class="score-banner-recovery">Path to '+projected+'/100 by addressing '+report.findings.length+' finding'+(report.findings.length!==1?'s':'')+'</div>';}
  h+='</div></div>';

  var fCount=report.findings.length;
  h+='<div class="stats-grid"><div class="stat-card"><div class="stat-value" style="color:'+(s.ungoverned>0?'var(--amber)':'var(--green)')+'">'+s.totalAgents+'</div><div class="stat-label">AI Agents</div></div><div class="stat-card"><div class="stat-value">'+s.mcpServers+'</div><div class="stat-label">MCP Servers</div></div><div class="stat-card"><div class="stat-value">'+s.aiConfigs+'</div><div class="stat-label">AI Configs</div></div><div class="stat-card"><div class="stat-value" style="color:'+(fCount>0?'var(--amber)':'var(--green)')+'">'+fCount+'</div><div class="stat-label">Findings</div></div></div>';

  h+='<div class="card"><div class="card-title">What This Means</div>';
  if(s.totalAgents>0){if(s.ungoverned===0){h+='<div class="means-text">Your AI agents have governance in place. Actions are bounded by the rules you defined.</div>';}else{h+='<div class="means-text">'+s.totalAgents+' AI tool'+(s.totalAgents!==1?'s are':' is')+' running. '+s.ungoverned+' '+(s.ungoverned===1?'has':'have')+' no governance rules limiting what '+(s.ungoverned===1?'it':'they')+' can do.</div>';}}
  if(s.mcpServers>0){h+='<div class="means-text">'+s.mcpServers+' MCP server'+(s.mcpServers!==1?'s give':' gives')+' your AI agents additional capabilities (file access, database queries, API calls, etc.).</div>';if(s.unverifiedServers>0){h+='<div class="means-text">'+s.unverifiedServers+' '+(s.unverifiedServers===1?'has':'have')+' no verified identity.</div>';}}
  h+='</div>';

  if(report.findings.length>0){h+='<h2 class="section-title">Findings ('+report.findings.length+')</h2>';for(var i=0;i<report.findings.length;i++){var f=report.findings[i];h+='<div class="finding-card"><div class="finding-header"><span class="sev-badge sev-'+f.severity+'">'+f.severity+'</span><span class="finding-title">'+esc(f.title)+'</span></div>';if(f.detail){h+='<div class="finding-detail">'+esc(f.detail)+'</div>';}if(f.whyItMatters){h+='<div class="finding-why">'+esc(f.whyItMatters)+'</div>';}h+='<div class="cmd-block"><span class="cmd-text">'+esc(f.remediation)+'</span><button class="copy-btn" data-cmd="'+esc(f.remediation)+'" onclick="copyCmd(this)">Copy</button></div></div>';}}else{h+='<div class="card" style="border-color:var(--green);"><div class="card-title" style="color:var(--green);">All Clear</div><div class="means-text">All detected AI tools have governance in place.</div></div>';}

  h+='<h2 class="section-title">Running AI Agents</h2><div class="card">';
  if(report.agents.length===0){h+='<div style="color:var(--dim);font-size:13px;">No AI agents detected</div>';}else{for(var j=0;j<report.agents.length;j++){var a=report.agents[j];h+='<div class="agent-row"><span class="agent-name">'+esc(a.name)+'</span><span class="status-badge '+(a.identityStatus==='identified'?'status-pass':'status-warn')+'">'+a.identityStatus+'</span> <span class="status-badge '+(a.governanceStatus==='governed'?'status-pass':'status-warn')+'">'+a.governanceStatus+'</span></div>';}}
  h+='</div>';

  var pMcp=report.mcpServers.filter(function(x){return x.source.indexOf('(project)')!==-1;});
  var gMcp=report.mcpServers.filter(function(x){return x.source.indexOf('(project)')===-1;});
  h+='<h2 class="section-title">MCP Servers ('+report.mcpServers.length+')</h2><div class="card">';
  if(report.mcpServers.length===0){h+='<div style="color:var(--dim);">No MCP servers found</div>';}
  if(pMcp.length>0){h+='<div class="mcp-group"><div class="mcp-group-title">Project-local ('+pMcp.length+')</div>';for(var k=0;k<pMcp.length;k++){var sv=pMcp[k];var caps=(sv.capabilities||[]).filter(function(c){return c!=='unknown';});h+='<div class="mcp-row"><div class="mcp-name">'+esc(sv.name)+(sv.verified?' <span class="status-badge status-pass">verified</span>':'')+'</div>';if(caps.length>0){h+='<div class="mcp-caps">'+caps.map(function(c){return capDescs[c]||c;}).join(' | ')+'</div>';}h+='</div>';}h+='</div>';}
  if(gMcp.length>0){h+='<div class="mcp-group"><div class="mcp-group-title">Machine-wide ('+gMcp.length+')</div>';var sens=gMcp.filter(function(x){return(x.capabilities||[]).some(function(c){return['shell-access','database','payments','cloud-services'].indexOf(c)!==-1;});});if(sens.length>0){for(var m=0;m<sens.length;m++){var sm=sens[m];var sc2=(sm.capabilities||[]).filter(function(c){return c!=='unknown';});h+='<div class="mcp-row"><div class="mcp-name">'+esc(sm.name)+'</div>';if(sc2.length>0){h+='<div class="mcp-caps">'+sc2.map(function(c){return capDescs[c]||c;}).join(' | ')+'</div>';}h+='</div>';}var ot=gMcp.length-sens.length;if(ot>0){h+='<div style="color:var(--dim);font-size:12px;padding:6px 0;">+ '+ot+' more with standard access</div>';}}else{h+='<div style="color:var(--dim);font-size:12px;">'+gMcp.length+' server'+(gMcp.length!==1?'s':'')+' with standard access</div>';}h+='</div>';}
  h+='</div>';

  var nw=(report.aiConfigs||[]).filter(function(c){return c.risk!=='low';});
  if(nw.length>0){h+='<h2 class="section-title">AI Config Files</h2><div class="card">';for(var n=0;n<nw.length;n++){var cfg=nw[n];h+='<div class="config-row"><div class="config-file">'+esc(cfg.file)+' <span class="sev-badge sev-'+cfg.risk+'">'+cfg.risk+'</span></div><div class="config-detail">'+esc(cfg.tool)+' -- '+esc(cfg.details)+'</div></div>';}h+='</div>';}

  var id=report.identity;
  h+='<h2 class="section-title">Identity &amp; Governance</h2><div class="card">';
  h+='<div class="identity-row"><span class="identity-label">Agent identity</span><span style="color:'+(id.aimIdentities>0?'var(--green)':'var(--amber)')+';">'+(id.aimIdentities>0?'Registered':'Not registered')+'</span></div>';
  h+='<div class="identity-row"><span class="identity-label">Behavioral rules (SOUL.md)</span><span style="color:'+(id.soulFiles>0?'var(--green)':'var(--amber)')+';">'+(id.soulFiles>0?id.soulFiles+' defined':'None')+'</span></div>';
  if(id.capabilityPolicies>0){h+='<div class="identity-row"><span class="identity-label">Capability policies</span><span style="color:var(--green);">'+id.capabilityPolicies+' policy file(s)</span></div>';}
  if(id.mcpIdentities>0){h+='<div class="identity-row"><span class="identity-label">MCP identities</span><span style="color:var(--green);">'+id.mcpIdentities+' signed</span></div>';}
  h+='</div>';

  document.getElementById('report').innerHTML=h;

  window.copyCmd=function(btn){var cmd=btn.getAttribute('data-cmd');if(navigator.clipboard){navigator.clipboard.writeText(cmd);}else{var ta=document.createElement('textarea');ta.value=cmd;document.body.appendChild(ta);ta.select();document.execCommand('copy');document.body.removeChild(ta);}btn.textContent='OK';btn.classList.add('copied');setTimeout(function(){btn.textContent='Copy';btn.classList.remove('copied');},1500);};
})();
</script>
</body>
</html>`;
}

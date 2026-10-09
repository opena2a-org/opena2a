renderPage('overview');
markScrollers();
function openFromHash() {
  var m = /^#f-([0-9a-f]{8})$/.exec(window.location ? window.location.hash : '');
  if (m) window.openFinding(m[1]);
}
window.addEventListener('hashchange', openFromHash);
openFromHash();

// The report's client script is formatted; tests match its code as tokens
// without layout whitespace: `window.goToTab=function(tab){`.
import ts from 'typescript';

export function compactJs(js: string): string {
  const sf = ts.createSourceFile('client.js', js, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  let out = '';
  const visit = (n: ts.Node): void => {
    const kids = n.getChildren(sf);
    if (kids.length > 0) return kids.forEach(visit);
    const text = n.getText(sf);
    if (/[\w$]$/.test(out) && /^[\w$]/.test(text)) out += ' ';
    out += text;
  };
  visit(sf);
  return out;
}

/** The report's last <script> element, compacted. */
export const compactReportScript = (html: string): string =>
  compactJs(html.slice(html.lastIndexOf('<script>') + 8, html.lastIndexOf('</script>')));

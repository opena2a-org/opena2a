// Scratch helper (not committed): extract a tarball from the npm cacache by
// index key substring, into a destination directory.
import { readFileSync, readdirSync, statSync, mkdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const CACHE = '/fleet/work/devsecflow-abdel/home/.npm/_cacache';
const [pattern, dest] = process.argv.slice(2);

const entries = new Map();
(function walk(d) {
  for (const f of readdirSync(d)) {
    const p = path.join(d, f);
    if (statSync(p).isDirectory()) walk(p);
    else {
      for (const line of readFileSync(p, 'utf8').split('\n')) {
        const i = line.indexOf('\t');
        if (i === -1) continue;
        try {
          const e = JSON.parse(line.slice(i + 1));
          if (e.key && e.integrity) entries.set(e.key, e.integrity);
        } catch {}
      }
    }
  }
})(path.join(CACHE, 'index-v5'));

const matches = [...entries.keys()].filter((k) => k.includes(pattern));
if (matches.length === 0) {
  console.error('no cache entry matches', pattern);
  process.exit(1);
}
const key = matches[0];
const integrity = entries.get(key);
const hex = Buffer.from(integrity.replace(/^sha512-/, ''), 'base64').toString('hex');
const content = path.join(CACHE, 'content-v2', 'sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
mkdirSync(dest, { recursive: true });
execFileSync('tar', ['-xzf', content, '-C', dest]);
console.log('extracted', key, '->', dest);

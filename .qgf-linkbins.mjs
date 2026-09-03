// Scratch helper (not committed): create node_modules/.bin links the way npm
// would, for a tree whose reification finished but whose script phase was
// interrupted. Handles the root node_modules and each workspace's.
import { readFileSync, readdirSync, existsSync, mkdirSync, symlinkSync, chmodSync, rmSync, statSync } from 'node:fs';
import path from 'node:path';

const ROOT = process.cwd();

function linkBinsFor(nmDir) {
  if (!existsSync(nmDir)) return 0;
  const binDir = path.join(nmDir, '.bin');
  mkdirSync(binDir, { recursive: true });
  let count = 0;
  const packages = [];
  for (const entry of readdirSync(nmDir)) {
    if (entry === '.bin' || entry === '.package-lock.json') continue;
    if (entry.startsWith('@')) {
      const scopeDir = path.join(nmDir, entry);
      if (!statSync(scopeDir).isDirectory()) continue;
      for (const sub of readdirSync(scopeDir)) packages.push(path.join(scopeDir, sub));
    } else {
      packages.push(path.join(nmDir, entry));
    }
  }
  for (const pkgDir of packages) {
    const pj = path.join(pkgDir, 'package.json');
    if (!existsSync(pj)) continue;
    let manifest;
    try { manifest = JSON.parse(readFileSync(pj, 'utf8')); } catch { continue; }
    let bins = manifest.bin;
    if (!bins) continue;
    if (typeof bins === 'string') bins = { [manifest.name.split('/').pop()]: bins };
    for (const [name, rel] of Object.entries(bins)) {
      const target = path.resolve(pkgDir, rel);
      if (!existsSync(target)) continue;
      const link = path.join(binDir, name);
      try { rmSync(link, { force: true }); } catch {}
      try {
        symlinkSync(path.relative(binDir, target), link);
        chmodSync(target, 0o755);
        count += 1;
      } catch {}
    }
  }
  return count;
}

let total = linkBinsFor(path.join(ROOT, 'node_modules'));
for (const ws of readdirSync(path.join(ROOT, 'packages'))) {
  total += linkBinsFor(path.join(ROOT, 'packages', ws, 'node_modules'));
}
console.log(`linked ${total} bin entries`);

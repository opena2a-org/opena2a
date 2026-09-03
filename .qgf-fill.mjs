// Scratch helper (not committed): fill node_modules gaps from the local npm
// cacache, preferring the lockfile's exact version, else the newest cached.
// LOCAL-ONLY convenience for an offline sandbox; CI installs from the lockfile.
import { readFileSync, existsSync, mkdirSync, rmSync, readdirSync, renameSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';

const CACHE = '/fleet/work/devsecflow-abdel/home/.npm/_cacache';
const index = JSON.parse(readFileSync('/tmp/cache-index.json', 'utf8'));
const byUrl = new Map(index);

function cachedVersionsOf(name) {
  const prefix = `make-fetch-happen:request-cache:https://registry.npmjs.org/${name}/-/`;
  const out = [];
  for (const [key, integrity] of byUrl) {
    if (!key.startsWith(prefix)) continue;
    const m = /-(\d+\.\d+\.\d+(?:-[\w.]+)?)\.tgz$/.exec(key);
    if (m) out.push({ version: m[1], integrity });
  }
  return out;
}

function contentPath(integrity) {
  const hex = Buffer.from(integrity.replace(/^sha512-/, ''), 'base64').toString('hex');
  return path.join(CACHE, 'content-v2', 'sha512', hex.slice(0, 2), hex.slice(2, 4), hex.slice(4));
}

const lock = JSON.parse(readFileSync('package-lock.json', 'utf8'));

const wanted = process.argv.slice(2); // package names (root node_modules position)
for (const name of wanted) {
  const dest = path.join('node_modules', name);
  if (existsSync(path.join(dest, 'package.json'))) {
    console.log(`skip ${name} (already present)`);
    continue;
  }
  const want = lock.packages[`node_modules/${name}`]?.version;
  const cached = cachedVersionsOf(name);
  if (cached.length === 0) {
    console.log(`MISS ${name} (nothing cached; lockfile wants ${want})`);
    continue;
  }
  const exact = cached.find((c) => c.version === want);
  const pick = exact ?? cached.sort((a, b) => a.version.localeCompare(b.version, undefined, { numeric: true })).at(-1);
  const tmp = `.qgf-scratch/fill-${name.replace(/[/@]/g, '_')}`;
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  execFileSync('tar', ['-xzf', contentPath(pick.integrity), '-C', tmp]);
  const root = readdirSync(tmp)[0]; // usually "package"
  mkdirSync(path.dirname(dest), { recursive: true });
  // Preserve an existing nested node_modules shell if npm already made one.
  const nested = path.join(dest, 'node_modules');
  const keepNested = existsSync(nested) ? `.qgf-scratch/nested-${name.replace(/[/@]/g, '_')}` : null;
  if (keepNested) renameSync(nested, keepNested);
  rmSync(dest, { recursive: true, force: true });
  renameSync(path.join(tmp, root), dest);
  if (keepNested) renameSync(keepNested, path.join(dest, 'node_modules'));
  rmSync(tmp, { recursive: true, force: true });
  console.log(`filled ${name}@${pick.version}${exact ? '' : ` (lockfile wants ${want ?? '?'})`}`);
}

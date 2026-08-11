import { execFileSync } from 'node:child_process';

// MIN_HMA_VERSION is the oldest hackmyagent ON THE USER'S PATH whose `check`
// output opena2a-cli is willing to vouch for. Scope, deliberately narrow:
//   - This guard probes the PATH binary (the execFileSync below takes no path),
//     which is exactly the binary spawnHmaCheck (index.ts) and
//     spawnHmaCheckFromRouter (router.ts) go on to spawn. It warns; it does not
//     block, and no other spawn site consults it.
//   - It does NOT read the bundled copy that `await import('hackmyagent')`
//     resolves (soul.ts, benchmark.ts, init.ts, detect.ts, guard-harden.ts,
//     self-register.ts). That copy is pinned in package.json and is a SEPARATE
//     number — do not couple them.
//   - It cannot see a nested copy under another dependency (e.g.
//     node_modules/ai-trust/node_modules/hackmyagent). Nothing here says
//     anything about those; they are disclosed in CHANGELOG.md instead.
//
// Derivation — the later of two independently verifiable constraints:
//   1. Not deprecated by us. The first non-deprecated published version is
//      0.26.0. Verify: `npm view hackmyagent@0.25.2 deprecated` is non-empty,
//      `npm view hackmyagent@0.26.0 deprecated` is empty.
//   2. No known defect in the `check` path we delegate to. hackmyagent#373
//      (`check --json` exits 0 on critical findings) is first fixed in 0.26.1,
//      and opena2a-cli returns the spawned exit code verbatim, so below 0.26.1
//      `opena2a check <pkg> --json` cannot fail a CI job.
//      Verify: in the hackmyagent repo, `git tag --contains 436f7cc | sort -V |
//      head -1` returns v0.26.1; see that release's CHANGELOG "Security" notes.
//   max(0.26.0, 0.26.1) = 0.26.1.
//
// Deliberately NOT in this floor: hackmyagent#406 (`attack` reports SECURE for
// a target it never reached; first fixed in 0.27.0, commit 8ef9171). opena2a-cli
// exposes no `attack` verb and both call sites spawn only `check`, so #406
// cannot reach a user through this binary. A 0.27.0 floor would warn a user
// whose opena2a-cli surface is measurably sound.
//
// Superseded: 0.16.7 was the HMA_CHECK_COMMAND / HMA_FULL_SCAN_HINT env-var
// contract version. Those vars still ship, and that floor is subsumed because
// 0.26.1 > 0.16.7. The old message's "GitHub repo scanning may not work"
// overstated it — the contract governs footer and hint text, not scanning.
export const MIN_HMA_VERSION = '0.26.1';

let versionChecked = false;

/**
 * Check that the hackmyagent on PATH meets the minimum opena2a-cli vouches for.
 * Warns once per process if it is below the floor. Advisory only — it never
 * blocks the spawn, because a below-floor scanner still produces useful output;
 * the defect it warns about is the exit code, not the report.
 */
export function checkMinHmaVersion(): void {
  if (versionChecked) return;
  versionChecked = true;

  try {
    const raw = execFileSync('hackmyagent', ['--version'], {
      timeout: 5000,
      encoding: 'utf8',
    }).trim();
    const match = raw.match(/(\d+\.\d+\.\d+)/);
    if (!match) return;
    const installed = match[1];
    const [iMaj, iMin, iPat] = installed.split('.').map(Number);
    const [rMaj, rMin, rPat] = MIN_HMA_VERSION.split('.').map(Number);
    if (iMaj < rMaj || (iMaj === rMaj && iMin < rMin) || (iMaj === rMaj && iMin === rMin && iPat < rPat)) {
      process.stderr.write(
        `\nWarning: hackmyagent ${installed} is on PATH; opena2a-cli vouches for >=${MIN_HMA_VERSION}.\n` +
        `opena2a check <target> runs this binary and returns its exit code verbatim; the fix for\n` +
        `hackmyagent#373 (--json exits 0 despite critical findings) first ships in ${MIN_HMA_VERSION}.\n` +
        `Verify: hackmyagent --version    Fix: npm install -g hackmyagent@latest\n\n`,
      );
    }
  } catch {
    // hackmyagent not found — spawnHmaCheck will handle that error
  }
}

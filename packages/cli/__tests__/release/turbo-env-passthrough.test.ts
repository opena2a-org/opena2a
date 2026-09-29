/**
 * The GitHub token set on the CI `npm run test` step reaches exactly one
 * turbo task, opena2a-cli#test, and turbo forwards nothing else by
 * declaration.
 *
 * The root `test` script runs `turbo run test`. turbo 2.9.14 runs tasks in
 * strict env mode, which forwards a built-in set of variables (among the
 * names probed: CI, GITHUB_*, RUNNER_*, VERCEL_*) and strips GH_TOKEN unless
 * it is declared. Without a declaration, the GH_TOKEN that ci.yml sets never
 * reaches scripts/release-artifact-review.mjs, whose consumer-closure check
 * then calls api.github.com unauthenticated, shares the hosted runner's
 * per-IP rate limit, and reports `precondition`, which the clean-fixture and
 * own-tarball cases correctly fail. main went red that way on 2026-09-27
 * (fb6fa889) and 2026-09-29 (00f7422e).
 *
 * packages/cli/turbo.json declares GH_TOKEN for this package's test task.
 * The token is a credential, so this test holds the declaration to an exact
 * allowlist. From one dry run of the root script's own turbo arguments, with
 * placeholder token values:
 *   - every env name any task declares, in every field turbo reports for it,
 *     is exactly {GH_TOKEN} for opena2a-cli#test and nothing for any other
 *     task;
 *   - the global env declarations (globalEnv, globalPassThroughEnv) are
 *     empty;
 *   - the run and every task are in strict env mode (loose mode, including a
 *     --env-mode=loose flag on the root script, forwards the whole
 *     environment).
 * Any new env declaration at any level, of any name or pattern, turns this
 * red and has to be added here visibly.
 *
 * What this test does not control: turbo's built-in forwarded set, which a
 * dry run does not report, and ci.yml, which is a gate file reviewed on its
 * own path.
 */
import { describe, expect, it } from 'vitest';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..', '..');
const TURBO = path.join(REPO_ROOT, 'node_modules', '.bin', 'turbo');
const TOKEN_TASK = 'opena2a-cli#test';
const TOKEN_TASK_ALLOWED = ['GH_TOKEN'];

type NameList = string[] | null | undefined;

interface EnvVariables {
  specified?: { env?: NameList; passThroughEnv?: NameList };
  configured?: NameList;
  inferred?: NameList;
  passthrough?: NameList;
}

interface DryTask {
  taskId: string;
  envMode?: string;
  resolvedTaskDefinition?: { env?: NameList; passThroughEnv?: NameList };
  environmentVariables?: EnvVariables;
}

interface DryPlan {
  envMode?: string;
  globalCacheInputs?: { environmentVariables?: EnvVariables };
  tasks: DryTask[];
}

/** Names (split at `=`) across the given lists; a null list reads as empty. */
function names(...lists: NameList[]): string[] {
  const out = new Set<string>();
  for (const list of lists) for (const entry of list ?? []) out.add(entry.split('=')[0]);
  return [...out].sort();
}

function envVariableNames(ev: EnvVariables | undefined): string[] {
  return names(ev?.specified?.env, ev?.specified?.passThroughEnv, ev?.configured, ev?.inferred, ev?.passthrough);
}

function taskNames(task: DryTask): string[] {
  return names(
    task.resolvedTaskDefinition?.env,
    task.resolvedTaskDefinition?.passThroughEnv,
    envVariableNames(task.environmentVariables)
  );
}

/** The turbo arguments of the root `test` script, e.g. ['run', 'test', '--concurrency=1']. */
function rootTurboArgs(): string[] | null {
  const pkg = JSON.parse(readFileSync(path.join(REPO_ROOT, 'package.json'), 'utf8')) as {
    scripts?: Record<string, string>;
  };
  for (const segment of (pkg.scripts?.test ?? '').split('&&')) {
    const words = segment.trim().split(/\s+/);
    if (words[0] === 'turbo') return words.slice(1);
  }
  return null;
}

describe('turbo forwards GH_TOKEN to opena2a-cli#test and declares nothing else', () => {
  it('holds every turbo env declaration to an exact allowlist, in strict mode', () => {
    expect(existsSync(TURBO), `turbo binary missing at ${TURBO}; run npm ci`).toBe(true);
    const args = rootTurboArgs();
    expect(args, 'the root package.json test script has no `turbo ...` segment').not.toBeNull();

    const res = spawnSync(TURBO, [...args!, '--dry=json'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      // Placeholders, never a real credential: the dry run only reports
      // which names turbo will forward.
      env: { ...process.env, GH_TOKEN: 'dry-run-placeholder', GITHUB_TOKEN: 'dry-run-placeholder' },
    });
    expect(res.status, `turbo dry run failed\n${res.stderr}`).toBe(0);
    const plan = JSON.parse(res.stdout) as DryPlan;

    // Global declarations: the object must be present (absent is not empty).
    const globalEnv = plan.globalCacheInputs?.environmentVariables;
    expect(globalEnv, 'the dry run reports no globalCacheInputs.environmentVariables').toBeDefined();
    expect(envVariableNames(globalEnv), 'turbo.json declares global env (globalEnv / globalPassThroughEnv)').toEqual([]);

    // Per-task declarations: exactly {GH_TOKEN} on the token task, nothing elsewhere.
    const tokenTask = plan.tasks.find((t) => t.taskId === TOKEN_TASK);
    expect(tokenTask, `${TOKEN_TASK} is not in the turbo plan`).toBeDefined();
    expect(
      taskNames(tokenTask!),
      `${TOKEN_TASK} must receive exactly ${TOKEN_TASK_ALLOWED.join(', ')} by declaration (packages/cli/turbo.json)`
    ).toEqual(TOKEN_TASK_ALLOWED);
    const declaredElsewhere = plan.tasks
      .filter((t) => t.taskId !== TOKEN_TASK)
      .map((t) => ({ task: t.taskId, names: taskNames(t) }))
      .filter((t) => t.names.length > 0);
    expect(declaredElsewhere, 'a task other than opena2a-cli#test declares env').toEqual([]);

    // Strict mode for the run and for every task.
    expect(plan.envMode, 'the turbo run is not in strict env mode').toBe('strict');
    const notStrict = plan.tasks.filter((t) => t.envMode !== 'strict').map((t) => `${t.taskId}=${t.envMode}`);
    expect(notStrict, 'a task is not in strict env mode, which forwards the whole environment').toEqual([]);
  });
});

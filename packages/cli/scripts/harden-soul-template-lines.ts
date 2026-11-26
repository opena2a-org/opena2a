/**
 * Derive every line `harden-soul` can write, from the generator itself.
 *
 * `opena2a harden-soul` calls hackmyagent's `SoulScanner.hardenSoul`. That
 * generator writes:
 *   - a header and one section per domain when it creates SOUL.md
 *     (`DOMAIN_TEMPLATES[*].content`), and
 *   - an "(Additional Governance)" block of control remediations when it
 *     augments an existing file (`CONTROL_DEFS[*].remediation`).
 *
 * The lines are taken from those exported template sources and from running
 * the generator in both modes on scratch directories, so nothing here is
 * typed by hand. The tier / profile marker lines carry values the generator
 * fills in (`--profile` is free text), so they are not template lines and are
 * left out.
 *
 * `src/util/harden-soul-lines.ts` holds the SHA-256 digests of the result
 * (`npm run gen:harden-soul-lines`); a test compares the two, so a template
 * line added upstream fails the suite until the set is regenerated.
 */
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { normaliseSoulLine } from '../src/util/soul-line.js';

/** Lines whose content the generator fills in rather than copies. */
const FILLED_IN_LINE = /<!--\s*soul:(tier|profile)=/i;

interface Hma {
  SoulScanner: new () => {
    hardenSoul(dir: string, opts: { dryRun?: boolean }): Promise<{ content?: string }>;
  };
  DOMAIN_TEMPLATES: Record<string, { heading: string; content: string }>;
  CONTROL_DEFS: Array<{ remediation?: string }>;
}

async function loadHma(): Promise<Hma> {
  const mod: Record<string, unknown> = await import('hackmyagent');
  const hma = (mod.SoulScanner ? mod : mod.default) as Hma;
  if (!hma?.SoulScanner || !hma.DOMAIN_TEMPLATES || !hma.CONTROL_DEFS) {
    throw new Error('hackmyagent does not export SoulScanner, DOMAIN_TEMPLATES and CONTROL_DEFS');
  }
  return hma;
}

async function generate(hma: Hma, existing: string | null): Promise<string> {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'harden-soul-lines-'));
  try {
    if (existing !== null) fs.writeFileSync(path.join(dir, 'SOUL.md'), existing, 'utf-8');
    const result = await new hma.SoulScanner().hardenSoul(dir, { dryRun: true });
    return result.content ?? '';
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** Every distinct, non-empty, normalised line the generator can write, sorted. */
export async function deriveHardenSoulLines(): Promise<string[]> {
  const hma = await loadHma();
  const sources: string[] = [];

  for (const template of Object.values(hma.DOMAIN_TEMPLATES)) sources.push(template.content);
  for (const def of hma.CONTROL_DEFS) if (def.remediation) sources.push(def.remediation);

  // A fresh file: header plus every domain section.
  sources.push(await generate(hma, null));
  // An existing file with every domain heading and no body: the generator
  // augments each domain with its remediation block.
  const headingsOnly = Object.values(hma.DOMAIN_TEMPLATES).map(t => t.heading).join('\n\n') + '\n';
  sources.push(await generate(hma, headingsOnly));

  const lines = new Set<string>();
  for (const text of sources) {
    for (const raw of text.split(/\r\n|\r|\n/)) {
      const line = normaliseSoulLine(raw);
      if (line && !FILLED_IN_LINE.test(line)) lines.add(line);
    }
  }
  return [...lines].sort();
}

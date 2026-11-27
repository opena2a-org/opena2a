/**
 * One way to show a Registry trust answer in `detect --registry`,
 * `mcp audit`, `mcp verify` and `verify`: the level's word beside its number,
 * in the tone `check` gives it, and for a Blocked or Warning answer the one
 * command the user can run next.
 *
 * The words and tones are not written here. The word is cli-ui's
 * `trustLevelLabel`, the tone is the one cli-ui's check block gives the
 * Level line, and "not scanned" is cli-ui's `NO_SCAN_RESULT_SHORT_TEXT`, so
 * these commands print what `check` prints. cli-ui is pure ESM and this CLI
 * is CommonJS, so a command loads it once with `loadTrustUi()` and passes it
 * in.
 *
 * A Listed answer (level 2, or verdict "listed") is a record nobody scanned:
 * it is shown as not scanned and in a dim tone, never in the colour of a bad
 * result, and its score of 0 is never printed.
 */

import { bold, dim, green, red, yellow } from './colors.js';

/** The highest trust level on the Registry's 0-4 scale. */
export const TOP_TRUST_LEVEL = 4;

/** The parts of @opena2a/cli-ui this module reads. */
export interface TrustUi {
  trustLevelLabel(level: number): string;
  normalizeVerdict(verdict: string): string;
  renderCheckBlock(input: {
    name: string;
    trustLevel: number;
    trustScore: number;
    verdict: string;
  }): { lines: Array<{ label: string; tone: string }> };
  NO_SCAN_RESULT_SHORT_TEXT: string;
}

export async function loadTrustUi(): Promise<TrustUi> {
  return import('@opena2a/cli-ui');
}

export type TrustTone = 'good' | 'warning' | 'critical' | 'dim' | 'default';

/** How a trust answer is shown. Serialisable, so a JSON document can carry it. */
export interface TrustAnswerView {
  /** The level shown, 0-4: the Registry's, or lower when its verdict is worse. */
  level: number;
  /** The level's word: Blocked, Warning, Listed, Scanned or Verified. */
  word: string;
  /** `Blocked (level 0 of 4)`; a Listed answer adds `, not scanned`. */
  label: string;
  /** True for a record the Registry lists and never scanned. */
  notScanned: boolean;
  tone: TrustTone;
  /** What the answer asks of the user: `do not use`, `review before use`, or null. */
  advice: string | null;
  /** The command to run next for a Blocked or Warning answer, else null. */
  nextStep: string | null;
}

/** The fields of a Registry answer that decide how it is shown. */
export interface TrustAnswerFields {
  trustLevel?: unknown;
  verdict?: unknown;
}

/** A name a shell reads as one word without quotes: an npm package name. */
const BARE_WORD = /^@?[A-Za-z0-9][A-Za-z0-9._~-]*(\/[A-Za-z0-9._~-]+)?$/;

/**
 * The next step for a Blocked or Warning answer: `opena2a check <package>`,
 * which reads the package's Registry record in full and scans it locally when
 * the Registry has no fresh result. The name comes from a config file or the
 * Registry, so anything that is not a plain package name is single-quoted.
 */
export function trustNextStep(packageName: string): string {
  const word = BARE_WORD.test(packageName)
    ? packageName
    : `'${packageName.replace(/'/g, `'\\''`)}'`;
  return `opena2a check ${word}`;
}

function levelOf(raw: unknown): number | null {
  return typeof raw === 'number' && Number.isInteger(raw) && raw >= 0 && raw <= TOP_TRUST_LEVEL ? raw : null;
}

/**
 * Describe a trust answer, or return null when it carries neither a level nor
 * a verdict that names one (nothing to put a word to).
 *
 * The level shown is the Registry's, lowered to Blocked or Warning when the
 * verdict says so: a blocked verdict is never shown under a better word.
 */
export function describeTrustAnswer(
  ui: TrustUi,
  answer: TrustAnswerFields,
  packageName: string | null,
): TrustAnswerView | null {
  const reported = levelOf(answer.trustLevel);
  const family = typeof answer.verdict === 'string' ? ui.normalizeVerdict(answer.verdict) : '';

  let level: number | null = reported;
  if (family === 'blocked') level = 0;
  else if (family === 'warning') level = Math.min(level ?? 1, 1);
  else if (family === 'listed' && (level === null || level > 2)) level = 2;
  if (level === null) return null;

  const word = ui.trustLevelLabel(level);
  const notScanned = level === 2;
  const label = `${word} (level ${level} of ${TOP_TRUST_LEVEL})${notScanned ? `, ${ui.NO_SCAN_RESULT_SHORT_TEXT}` : ''}`;

  // The tone `check` gives this level. Listed is the one exception: it says
  // nothing was examined, so it is not shown in the colour of a finding.
  const block = ui.renderCheckBlock({ name: packageName ?? '', trustLevel: level, trustScore: 0, verdict: family });
  const levelTone = block.lines.find((l) => l.label === 'Level')?.tone;
  const tone: TrustTone = notScanned ? 'dim' : isTone(levelTone) ? levelTone : 'default';

  const advice = level === 0 ? 'do not use' : level === 1 ? 'review before use' : null;
  const nextStep = advice !== null && packageName ? trustNextStep(packageName) : null;

  return { level, word, label, notScanned, tone, advice, nextStep };
}

function isTone(value: unknown): value is TrustTone {
  return value === 'good' || value === 'warning' || value === 'critical' || value === 'dim' || value === 'default';
}

/** This CLI's colour for a tone (colors.js honours NO_COLOR and a non-TTY stdout). */
export function toneColor(tone: TrustTone): (text: string) => string {
  switch (tone) {
    case 'good': return green;
    case 'warning': return yellow;
    case 'critical': return (text: string) => bold(red(text));
    case 'dim': return dim;
    default: return (text: string) => text;
  }
}

/** `Blocked (level 0 of 4), do not use`, coloured by its tone. */
export function paintTrustAnswer(view: TrustAnswerView): string {
  const text = view.advice ? `${view.label}, ${view.advice}` : view.label;
  return toneColor(view.tone)(text);
}

/** `Next: opena2a check <package>` for a Blocked or Warning answer, else null. */
export function trustNextStepLine(view: TrustAnswerView | null | undefined): string | null {
  if (!view?.nextStep) return null;
  return `${toneColor(view.tone)('Next:')} ${view.nextStep}`;
}

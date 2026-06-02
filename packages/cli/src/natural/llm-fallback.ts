import { bold, cyan, yellow, gray, dim, green } from '../util/colors.js';
import { HMA_CHECK_COUNT } from '../util/canonical.js';
import { classifyWithNanoMindDaemon } from './nanomind-classifier.js';
import type { NanoMindAttackClass } from './nanomind-types.js';

/**
 * Returned by {@link handleNaturalLanguage} when the NanoMind classifier
 * refuses the input at the trust boundary. The caller renders a CISO-readable
 * block message and does NOT dispatch a command.
 *
 * Only the canonical, safe-to-render signals are carried: the attack-class
 * enum (a fixed union), the confidence, and the model version. The daemon's
 * `evidence` and `remediation` strings are deliberately absent -- they can
 * carry attacker-influenced bytes (see the trust-boundary note in
 * nanomind-classifier.ts) and must never reach the terminal. `modelVersion`
 * is daemon-supplied so it is sanitized at the render boundary, not here.
 */
export interface NaturalLanguageBlock {
  blocked: true;
  attackClass: Exclude<NanoMindAttackClass, ''>;
  confidence: number;
  modelVersion: string;
}

/** Render tone for a single line of the classifier block message. */
export type ClassifierBlockTone = 'critical' | 'default' | 'dim';

/** One structured line of the block message. The caller owns terminal color. */
export interface ClassifierBlockLine {
  text: string;
  tone: ClassifierBlockTone;
}

/** Human-readable label for each canonical attack class. */
const ATTACK_CLASS_LABEL: Record<Exclude<NanoMindAttackClass, ''>, string> = {
  prompt_injection: 'prompt injection',
  tool_misuse: 'tool misuse',
  exfiltration_pattern: 'data exfiltration',
  data_extraction: 'data extraction',
};

/**
 * Build the CISO Rule 11 block message (observation + verdict + remediation)
 * as structured lines. PURE -- no terminal I/O, no color, no cli-ui import;
 * the caller maps tones to chalk and writes the lines.
 *
 * `modelVersion` is the only daemon-supplied (untrusted) field, so the caller
 * passes `sanitize` (cli-ui's `sanitizeForTerminal`) and it is applied here
 * before the version reaches a rendered line. `attackClass` is a fixed enum
 * and `confidence` is a number, so neither can carry hostile bytes.
 *
 * Remediation deliberately does NOT cite a `--no-classify` flag (not shipped
 * in this release): citing an unregistered flag would be a CISO Rule 11
 * dead-end. The natural-language router is a convenience layer, so the always
 * available escape hatch is to run the intended command explicitly.
 */
export function buildClassifierBlockLines(
  block: NaturalLanguageBlock,
  sanitize: (s: string) => string,
): ClassifierBlockLine[] {
  const pct = (block.confidence * 100).toFixed(1);
  const label = ATTACK_CLASS_LABEL[block.attackClass];
  const safeVersion = sanitize(block.modelVersion);
  return [
    { text: 'Input refused at the trust boundary', tone: 'critical' },
    {
      text: `NanoMind flagged this input as ${label} (${block.attackClass}) with ${pct}% confidence.`,
      tone: 'default',
    },
    { text: 'Refusing to translate it into a command.', tone: 'default' },
    {
      text: 'Rephrase the request, or run the intended command explicitly (for example: opena2a scan secure).',
      tone: 'default',
    },
    { text: `Model: ${safeVersion}`, tone: 'dim' },
  ];
}

/** Terminal primitives the block formatter needs, injected by the CLI entry. */
export interface ClassifierBlockPrimitives {
  /** cli-ui verdictColor: maps a verdict string to a chalk paint fn. */
  verdictColor: (verdict: string) => (text: string) => string;
  /** cli-ui divider: section rule with an optional label. */
  divider: (label?: string) => string;
  /** A dim/gray paint fn for de-emphasized lines. */
  gray: (text: string) => string;
  /** cli-ui sanitizeForTerminal: strips terminal-control bytes. */
  sanitize: (s: string) => string;
}

/**
 * Compose the full, ready-to-write block message string from a
 * {@link NaturalLanguageBlock}. The cli-ui primitives are injected (the CLI is
 * CommonJS and cli-ui is pure ESM, so they arrive via the entry's dynamic
 * import) which also keeps this composition pure and unit-testable with the
 * real primitives -- proving the sanitizer is actually applied on the render
 * path, not just inside the line builder. The CLI entry only writes the
 * returned string and sets the (non-zero) exit code.
 */
export function formatClassifierBlock(
  block: NaturalLanguageBlock,
  primitives: ClassifierBlockPrimitives,
): string {
  const { verdictColor, divider, gray, sanitize } = primitives;
  const out: string[] = [divider('Security')];
  for (const line of buildClassifierBlockLines(block, sanitize)) {
    const paint =
      line.tone === 'critical'
        ? verdictColor('blocked')
        : line.tone === 'dim'
          ? gray
          : (s: string) => s;
    out.push('  ' + paint(line.text));
  }
  out.push('');
  return out.join('\n');
}

const SYSTEM_PROMPT = `You are OpenA2A CLI, an AI agent security platform. Given a user's natural language query, suggest the most appropriate CLI command.

Available commands:
- opena2a scan secure -- Full security scan (${HMA_CHECK_COUNT} checks)
- opena2a scan attack -- Attack mode (adversarial testing)
- opena2a protect -- Detect and migrate credentials to vault
- opena2a secrets init -- Set up credential protection
- opena2a secrets scan -- Find hardcoded credentials
- opena2a runtime start -- Runtime monitoring (process/network/filesystem)
- opena2a benchmark -- OASB security benchmark (222 scenarios)
- opena2a registry check <pkg> -- Trust registry lookup
- opena2a train -- Launch DVAA training environment
- opena2a crypto scan -- Cryptographic inventory / PQC readiness
- opena2a identity -- Agent identity management
- opena2a broker start -- Start credential broker daemon
- opena2a init -- Project initialization
- opena2a status -- Security status overview

Respond with ONLY a JSON object: {"command":"<command>","reason":"<one-sentence reason>"}`;

interface LLMSuggestion {
  command: string;
  reason: string;
}

/**
 * Check if LLM features have been consented to. If not, prompt for consent
 * on first encounter (TTY only). Returns true if LLM calls are allowed.
 */
async function ensureLlmConsent(): Promise<boolean> {
  // Non-TTY or CI: no consent possible
  if (!process.stdin.isTTY || process.env.CI) {
    return false;
  }

  // Check existing consent
  try {
    const shared = await import('@opena2a/shared');
    const mod = 'default' in shared ? (shared as any).default : shared;

    if (mod.isLlmEnabled()) {
      return true;
    }

    // First encounter: explain and ask
    process.stdout.write('\n' + bold('LLM-assisted command matching') + '\n\n');
    process.stdout.write(
      'When your input does not match any known command, OpenA2A can\n' +
      'use Claude Haiku to suggest the best match.\n\n'
    );
    process.stdout.write(dim('Model: ') + 'Claude Haiku (claude-haiku-4-5)\n');
    process.stdout.write(dim('Estimated cost: ') + '~150 tokens, ~$0.0002 per call\n');
    process.stdout.write(dim('Data: ') + 'Uses your ANTHROPIC_API_KEY. No data is stored or shared.\n\n');

    try {
      const { confirm } = await import('@inquirer/prompts');
      const enabled = await confirm({
        message: 'Enable LLM-assisted command matching?',
        default: false,
      });

      mod.setLlmEnabled(enabled);

      if (enabled) {
        process.stdout.write(green('LLM features enabled.') + '\n\n');
        return true;
      } else {
        process.stdout.write(dim('LLM features disabled. ') +
          'You can enable later: ' + cyan('opena2a config llm on') + '\n\n');
        return false;
      }
    } catch {
      return false;
    }
  } catch {
    // shared not available, allow LLM (backward compat)
    return true;
  }
}

export async function llmFallback(input: string): Promise<LLMSuggestion | null> {
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return null;
  }

  // Check consent before making API call
  const consented = await ensureLlmConsent();
  if (!consented) {
    return null;
  }

  try {
    const response = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 150,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: input }],
      }),
      signal: AbortSignal.timeout(5000),
    });

    if (!response.ok) return null;

    const data = await response.json() as {
      content: Array<{ type: string; text: string }>;
    };

    const text = data.content?.[0]?.text;
    if (!text) return null;

    const parsed = JSON.parse(text) as LLMSuggestion;
    if (parsed.command && parsed.reason) {
      return parsed;
    }

    return null;
  } catch {
    return null;
  }
}

/**
 * Prompt user to confirm a matched command. Returns true if confirmed.
 * In non-TTY / CI mode, does not auto-execute -- returns false.
 */
async function confirmExecution(command: string): Promise<boolean> {
  if (!process.stdin.isTTY || process.env.CI) {
    process.stdout.write(`${gray('Run with:')} ${cyan(command)}\n`);
    return false;
  }

  try {
    const { confirm } = await import('@inquirer/prompts');
    return confirm({
      message: `Run ${command}?`,
      default: true,
    });
  } catch {
    return false;
  }
}

export async function handleNaturalLanguage(
  input: string,
): Promise<string | NaturalLanguageBlock | null> {
  // Trust-boundary classification (CHIEF-CA). The NanoMind classifier runs
  // FIRST -- before any static intent matching or LLM fallback -- so
  // adversarial free-form input is refused before it can be translated into a
  // command. NanoMind is the foundational semantic layer here, not a
  // post-processor.
  //
  // The classifier is defense-in-depth: a null result (daemon unreachable,
  // timeout, schema violation, SSRF rejection, empty input) means "not
  // blocked" and the normal intent flow proceeds unchanged. This is the
  // CHIEF-CDS silent-fallback contract -- a missing daemon never errors or
  // logs to stderr.
  // 1500ms (vs the 5000ms adapter default) bounds the worst-case stall on
  // this interactive hot path: a healthy local daemon answers in single-digit
  // ms, but a wedged or hostile process bound to the loopback port could
  // otherwise hang every natural-language command for 5s before fail-open.
  const classification = await classifyWithNanoMindDaemon(input, { timeoutMs: 1500 });
  if (classification?.blocked && classification.attackClass !== '') {
    return {
      blocked: true,
      attackClass: classification.attackClass,
      confidence: classification.confidence,
      modelVersion: classification.modelVersion,
    };
  }

  // First try static intent matching
  const { matchIntent } = await import('./intent-map.js');
  const staticMatch = matchIntent(input);

  if (staticMatch) {
    process.stdout.write(`\n${bold('Matched:')} ${cyan(staticMatch.command)}\n`);
    process.stdout.write(`${gray(staticMatch.description)}\n\n`);
    const confirmed = await confirmExecution(staticMatch.command);
    return confirmed ? staticMatch.command : null;
  }

  // Try LLM fallback
  process.stderr.write(`${gray('Analyzing...')}\n`);
  const llmResult = await llmFallback(input);

  if (llmResult) {
    process.stdout.write(`\n${bold('Suggested:')} ${cyan(llmResult.command)}\n`);
    process.stdout.write(`${gray(llmResult.reason)}\n\n`);
    process.stdout.write(`${yellow('Note:')} This suggestion was generated by AI.\n`);
    const confirmed = await confirmExecution(llmResult.command);
    return confirmed ? llmResult.command : null;
  }

  process.stdout.write(`Could not understand: "${input}"\n`);
  process.stdout.write(`Try: opena2a ~${input.split(' ')[0]} (semantic search)\n`);
  process.stdout.write(`     opena2a --help (list all commands)\n`);
  return null;
}

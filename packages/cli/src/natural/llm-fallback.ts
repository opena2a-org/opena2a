import { bold, cyan, yellow, gray, dim, green } from '../util/colors.js';

const SYSTEM_PROMPT = `You are OpenA2A CLI, an AI agent security platform. Given a user's natural language query, suggest the most appropriate CLI command.

Available commands:
- opena2a scan secure -- Full security scan (150+ checks)
- opena2a scan attack -- Attack mode (adversarial testing)
- opena2a protect -- Detect and migrate credentials to vault
- opena2a secrets init -- Set up credential protection
- opena2a secrets scan -- Find hardcoded credentials
- opena2a runtime start -- Runtime monitoring (process/network/filesystem)
- opena2a benchmark -- OASB security benchmark (222 scenarios)
- opena2a registry check <pkg> -- Trust registry lookup
- opena2a research <target> -- Autonomous security research
- opena2a hunt <target> -- Autonomous vulnerability hunter
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

export async function handleNaturalLanguage(input: string): Promise<string | null> {
  // First try static intent matching
  const { matchIntent } = await import('./intent-map.js');
  const staticMatch = matchIntent(input);

  if (staticMatch) {
    process.stdout.write(`\n${bold('Matched:')} ${cyan(staticMatch.command)}\n`);
    process.stdout.write(`${gray(staticMatch.description)}\n\n`);
    process.stdout.write(`${gray('Run this command? [Y/n]')} `);
    return staticMatch.command;
  }

  // Try LLM fallback
  process.stderr.write(`${gray('Analyzing...')}\n`);
  const llmResult = await llmFallback(input);

  if (llmResult) {
    process.stdout.write(`\n${bold('Suggested:')} ${cyan(llmResult.command)}\n`);
    process.stdout.write(`${gray(llmResult.reason)}\n\n`);
    process.stdout.write(`${yellow('Note:')} This suggestion was generated by AI.\n`);
    process.stdout.write(`${gray('Run this command? [Y/n]')} `);
    return llmResult.command;
  }

  process.stdout.write(`Could not understand: "${input}"\n`);
  process.stdout.write(`Try: opena2a ~${input.split(' ')[0]} (semantic search)\n`);
  process.stdout.write(`     opena2a --help (list all commands)\n`);
  return null;
}

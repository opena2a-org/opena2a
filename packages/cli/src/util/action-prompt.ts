import { bold, cyan, dim, green, red, yellow } from './colors.js';

export interface ActionPromptOptions {
  /** Unique ID for remembering user's choice */
  actionId: string;
  /** Title displayed to user */
  title: string;
  /** Steps that will be executed (shown as numbered list) */
  steps: string[];
  /** Rollback instructions if something fails */
  rollback: string[];
  /** The function to execute */
  execute: () => Promise<{ success: boolean; message: string }>;
  /** CI mode (skip all prompts) */
  ci?: boolean;
}

/**
 * Offer an action to the user with full transparency: show what will happen,
 * how to undo it, and let them choose.
 *
 * Behavior:
 * - CI or non-TTY: skip silently (returns false)
 * - Remembered choice = false: skip silently
 * - Remembered choice = true: auto-execute
 * - Otherwise: show plan + rollback, ask for confirmation
 */
export async function offerAction(options: ActionPromptOptions): Promise<boolean> {
  // CI or non-TTY: skip silently
  if (options.ci || !process.stdin.isTTY) {
    return false;
  }

  // Check remembered choice
  let rememberedChoice: boolean | undefined;
  try {
    const shared = await import('@opena2a/shared');
    const mod = 'default' in shared ? (shared as any).default : shared;
    rememberedChoice = mod.getRememberedChoice(options.actionId);
  } catch {
    // shared not available, proceed without memory
  }

  if (rememberedChoice === false) {
    return false;
  }

  if (rememberedChoice === true) {
    // Auto-execute
    const result = await options.execute();
    if (result.success) {
      process.stdout.write(green(result.message) + '\n');
    } else {
      process.stderr.write(red(result.message) + '\n');
    }
    return result.success;
  }

  // Show plan to user
  process.stdout.write('\n' + bold(options.title) + '\n\n');

  process.stdout.write(cyan('What will happen:') + '\n');
  for (let i = 0; i < options.steps.length; i++) {
    process.stdout.write(`  ${i + 1}. ${options.steps[i]}\n`);
  }

  process.stdout.write('\n' + dim('If anything goes wrong:') + '\n');
  for (const step of options.rollback) {
    process.stdout.write(`  - ${step}\n`);
  }
  process.stdout.write('\n');

  // Ask for confirmation
  let confirmed = false;
  try {
    const { confirm } = await import('@inquirer/prompts');
    confirmed = await confirm({
      message: 'Proceed?',
      default: false,
    });
  } catch (err) {
    if (err instanceof Error && err.message.includes('User force closed')) {
      return false;
    }
    // Fallback: decline
    return false;
  }

  if (!confirmed) {
    // Offer to remember the decline
    try {
      const { confirm: confirmRemember } = await import('@inquirer/prompts');
      const remember = await confirmRemember({
        message: 'Remember this choice and skip next time?',
        default: false,
      });
      if (remember) {
        try {
          const shared = await import('@opena2a/shared');
          const mod = 'default' in shared ? (shared as any).default : shared;
          mod.setRememberedChoice(options.actionId, false);
        } catch {
          // ignore
        }
      }
    } catch {
      // ignore
    }
    return false;
  }

  // Execute
  const result = await options.execute();
  if (result.success) {
    process.stdout.write(green(result.message) + '\n');
  } else {
    process.stderr.write(red(result.message) + '\n');
  }

  // Offer to remember the acceptance (only on first successful run)
  try {
    const { confirm: confirmRemember } = await import('@inquirer/prompts');
    const remember = await confirmRemember({
      message: 'Always do this automatically next time?',
      default: false,
    });
    if (remember) {
      try {
        const shared = await import('@opena2a/shared');
        const mod = 'default' in shared ? (shared as any).default : shared;
        mod.setRememberedChoice(options.actionId, true);
      } catch {
        // ignore
      }
    }
  } catch {
    // ignore
  }

  return result.success;
}

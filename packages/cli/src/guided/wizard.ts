import { bold, cyan, gray, dim } from '../util/colors.js';

interface WizardCategory {
  label: string;
  description: string;
  commands: WizardCommand[];
}

interface WizardCommand {
  label: string;
  command: string;
  description: string;
}

const CATEGORIES: WizardCategory[] = [
  {
    label: 'Scan & Harden',
    description: 'Find and fix security issues in AI agents',
    commands: [
      { label: 'Full security scan', command: 'opena2a scan secure', description: '150+ security checks with auto-fix' },
      { label: 'Attack mode', command: 'opena2a scan attack', description: 'Adversarial testing against your agent' },
      { label: 'Security benchmark', command: 'opena2a benchmark', description: 'OASB benchmark (222 attack scenarios)' },
      { label: 'Credential scan', command: 'opena2a secrets scan', description: 'Find hardcoded secrets in your codebase' },
    ],
  },
  {
    label: 'Protect & Monitor',
    description: 'Shield credentials and monitor runtime behavior',
    commands: [
      { label: 'Migrate credentials to vault', command: 'opena2a protect', description: 'Detect and encrypt hardcoded credentials' },
      { label: 'Set up Secretless', command: 'opena2a secrets init', description: 'Protect credentials from AI coding tools' },
      { label: 'Runtime monitoring', command: 'opena2a runtime start', description: 'Monitor process, network, filesystem' },
      { label: 'Start credential broker', command: 'opena2a broker start', description: 'Identity-aware credential resolution' },
    ],
  },
  {
    label: 'Verify & Comply',
    description: 'Check trust scores and compliance posture',
    commands: [
      { label: 'Trust registry lookup', command: 'opena2a registry check', description: 'Check package security data' },
      { label: 'Agent identity', command: 'opena2a identity', description: 'Create and manage agent identities' },
      { label: 'Crypto scan', command: 'opena2a crypto scan', description: 'Cryptographic inventory and PQC readiness' },
      { label: 'Project status', command: 'opena2a status', description: 'Security status overview' },
    ],
  },
  {
    label: 'Research & Train',
    description: 'Autonomous security research and training',
    commands: [
      { label: 'Autonomous research', command: 'opena2a research', description: 'Launch security research agent' },
      { label: 'Vulnerability hunter', command: 'opena2a hunt', description: 'Multi-turn attack decomposition' },
      { label: 'Training lab', command: 'opena2a train', description: 'Launch DVAA vulnerable agent' },
    ],
  },
];

export async function runWizard(): Promise<string | null> {
  // Check if interactive prompts are available
  if (!process.stdin.isTTY) {
    process.stdout.write('Interactive mode requires a TTY.\n');
    process.stdout.write('Run: opena2a --help\n');
    return null;
  }

  try {
    const { select } = await import('@inquirer/prompts');

    // Stage 1: Pick category
    const categoryChoices = CATEGORIES.map(cat => ({
      name: `${cat.label} -- ${cat.description}`,
      value: cat.label,
    }));

    const selectedCategory = await select({
      message: 'What would you like to do?',
      choices: categoryChoices,
    });

    const category = CATEGORIES.find(c => c.label === selectedCategory);
    if (!category) return null;

    // Stage 2: Pick command
    const commandChoices = category.commands.map(cmd => ({
      name: `${cmd.label} -- ${cmd.description}`,
      value: cmd.command,
    }));

    const selectedCommand = await select({
      message: `${category.label}:`,
      choices: commandChoices,
    });

    // Intercept attack mode to provide guided walkthrough
    if (selectedCommand === 'opena2a scan attack') {
      const { runAttackWalkthrough } = await import('./attack-walkthrough.js');
      return runAttackWalkthrough();
    }

    // Show the expert command
    process.stdout.write(`\n${gray('Next time:')} ${cyan(selectedCommand)}\n\n`);

    return selectedCommand;
  } catch (err) {
    // User cancelled (Ctrl+C)
    if (err instanceof Error && err.message.includes('User force closed')) {
      return null;
    }
    // @inquirer/prompts not installed
    return runFallbackWizard();
  }
}

function runFallbackWizard(): string | null {
  process.stdout.write('\nAvailable categories:\n\n');

  for (let i = 0; i < CATEGORIES.length; i++) {
    const cat = CATEGORIES[i];
    process.stdout.write(`  ${bold(`${i + 1}.`)} ${cat.label}\n`);
    process.stdout.write(`     ${gray(cat.description)}\n`);
    for (const cmd of cat.commands) {
      process.stdout.write(`     ${dim('-')} ${cyan(cmd.command)} ${gray(`-- ${cmd.description}`)}\n`);
    }
    process.stdout.write('\n');
  }

  process.stdout.write(`${gray('Run any command above, or use')} opena2a ~<query> ${gray('to search.')}\n`);
  return null;
}

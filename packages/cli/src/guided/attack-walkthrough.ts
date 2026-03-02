/**
 * Guided attack walkthrough for novice users.
 *
 * Instead of immediately dispatching `opena2a scan attack`, walk users
 * through what attack testing is, what agent type they have, and what
 * phases the test will run. Returns the fully-formed command string.
 */

import { bold, cyan, dim, gray, yellow } from '../util/colors.js';

interface AttackPhase {
  name: string;
  description: string;
}

const ATTACK_PHASES: AttackPhase[] = [
  {
    name: 'Prompt Injection Testing',
    description: 'Tests whether your agent follows malicious instructions\n' +
      '     hidden in user input or tool responses.',
  },
  {
    name: 'Data Exfiltration',
    description: 'Attempts to extract sensitive information like system\n' +
      '     prompts, environment variables, or user data.',
  },
  {
    name: 'Tool Abuse',
    description: 'Tests if your agent can be tricked into calling\n' +
      '     dangerous tools or exceeding its intended permissions.',
  },
];

const AGENT_TYPES = [
  {
    label: 'MCP Server (tool-calling agent)',
    value: 'mcp',
    targetPrompt: 'MCP server URL (e.g., http://localhost:3010):',
  },
  {
    label: 'API Agent (HTTP endpoint)',
    value: 'api',
    targetPrompt: 'API endpoint URL (e.g., http://localhost:8080/api):',
  },
  {
    label: 'Chat Agent (system prompt based)',
    value: 'chat',
    targetPrompt: 'System prompt file path (optional, press Enter to skip):',
  },
] as const;

/**
 * Run the interactive attack walkthrough. Returns the command string
 * to execute, or null if the user cancels.
 */
export async function runAttackWalkthrough(): Promise<string | null> {
  if (!process.stdin.isTTY) {
    process.stdout.write('Attack walkthrough requires a TTY.\n');
    process.stdout.write('Direct usage: opena2a scan attack <target-url>\n');
    return null;
  }

  try {
    const { select, input, confirm } = await import('@inquirer/prompts');

    // Step 1: Explain
    process.stdout.write('\n' + bold('Attack Simulation') + '\n\n');
    process.stdout.write(
      'Attack testing probes your AI agent with crafted adversarial inputs\n' +
      'to find security weaknesses before real attackers do.\n\n'
    );
    process.stdout.write(dim('  - Nothing is permanently modified\n'));
    process.stdout.write(dim('  - Tests run against your local/staging agent\n'));
    process.stdout.write(dim('  - Results are not shared externally\n'));
    process.stdout.write('\n');

    // Step 2: Agent type
    const agentType = await select({
      message: 'What type of agent are you testing?',
      choices: AGENT_TYPES.map(t => ({
        name: t.label,
        value: t.value,
      })),
    });

    const typeConfig = AGENT_TYPES.find(t => t.value === agentType)!;

    // Step 3: Target details
    const target = await input({
      message: typeConfig.targetPrompt,
    });

    if (!target && agentType !== 'chat') {
      process.stdout.write(yellow('A target URL is required for this agent type.') + '\n');
      return null;
    }

    // Step 4: Show phases
    process.stdout.write('\n' + bold('Test Phases') + '\n\n');
    for (let i = 0; i < ATTACK_PHASES.length; i++) {
      const phase = ATTACK_PHASES[i];
      process.stdout.write(`  ${cyan(`Phase ${i + 1}`)} - ${bold(phase.name)}\n`);
      process.stdout.write(`     ${phase.description}\n\n`);
    }

    // Step 5: Confirm
    const proceed = await confirm({
      message: 'Start attack simulation?',
      default: true,
    });

    if (!proceed) {
      return null;
    }

    // Step 6: Build and return command
    const targetArg = target || '.';
    const command = `opena2a scan attack ${targetArg} --target-type ${agentType}`;

    process.stdout.write('\n' + gray('Command: ') + cyan(command) + '\n\n');

    return command;
  } catch (err) {
    if (err instanceof Error && err.message.includes('User force closed')) {
      return null;
    }
    // Fallback: show manual usage
    process.stdout.write('\nUsage: opena2a scan attack <target-url> --target-type mcp|api|chat\n');
    return null;
  }
}

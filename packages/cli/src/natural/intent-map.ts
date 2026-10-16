export interface IntentMapping {
  patterns: RegExp[];
  command: string;
  description: string;
}

// The credential nouns a request can name: "secrets", "API keys", "tokens".
const CREDENTIAL = String.raw`(secrets?|credentials?|(api\s*)?keys?|tokens?|passwords?)`;

/**
 * Natural-language intents, tried in order; the first matching pattern wins.
 *
 * Order carries the safety contract: a request to find or scan for
 * credentials resolves to the read-only `opena2a secrets scan` before any
 * mapping that changes the project can see it, and `opena2a protect` is
 * reached only from a request to move, migrate or fix credentials. Every
 * example in src/semantic/command-index.json resolves to the command it is
 * listed under (__tests__/natural/command-index-examples.test.ts).
 */
export const INTENT_MAPPINGS: readonly IntentMapping[] = [
  // Key scope drift: a read-only preview of what protect would report.
  {
    patterns: [
      /\b(google|gcp|gemini|aws|bedrock)\b.*\bdrift\b/i,
      /\b(key|scope|credential)\s+drift\b/i,
    ],
    command: 'opena2a protect . --dry-run',
    description: 'Report credentials and key scope drift without changing files',
  },

  // Credential scan: find, detect, search, scan, check or look for
  // credentials. Read-only.
  {
    patterns: [
      new RegExp(String.raw`\b(find|detect|search|scan|check|look\s+for)\b.*\b${CREDENTIAL}\b`, 'i'),
    ],
    command: 'opena2a secrets scan',
    description: 'Find hardcoded credentials in project files',
  },

  // Credential migration: move, migrate or fix credentials. Changes files.
  {
    patterns: [
      new RegExp(String.raw`\b(move|migrate)\s+(my\s+|the\s+|all\s+)?(\w+\s+)?${CREDENTIAL}`, 'i'),
      /\b(move|migrate)\b.*\bvault\b/i,
      new RegExp(String.raw`\bfix\s+(my\s+|the\s+)?(hardcoded\s+|leaked\s+|exposed\s+)?${CREDENTIAL}\b`, 'i'),
    ],
    command: 'opena2a protect',
    description: 'Migrate credentials to encrypted vault',
  },

  // Secrets management intents: keep credentials out of AI tools.
  {
    patterns: [
      /\b(set\s*up|init|initialize|configure)\s+(secretless|secret\s+management|credential\s+protection)\b/i,
      /\bsecretless\b/i,
      new RegExp(String.raw`\b(protect|hide|encrypt|secure|manage)\s+(my\s+|the\s+|all\s+)?(\w+\s+)?${CREDENTIAL}\b`, 'i'),
      /\bstop\s+ai\s+(from\s+)?(reading|seeing|accessing)\s+(my\s+)?(secrets?|keys?|credentials?)\b/i,
    ],
    command: 'opena2a secrets init',
    description: 'Initialize Secretless credential protection',
  },

  // Credential exposure named without a verb ("hardcoded secrets",
  // "my keys are exposed"): a scan, not a migration. Read-only.
  {
    patterns: [
      new RegExp(String.raw`\b(hardcoded|leaked|exposed)\s+${CREDENTIAL}\b`, 'i'),
      /\b(secrets?|credentials?|(api\s*)?keys?)\s+(are|is)\s+(exposed|leaked|visible|unsafe)\b/i,
    ],
    command: 'opena2a secrets scan',
    description: 'Find hardcoded credentials in project files',
  },

  // Transcript and log redaction. Changes files.
  {
    patterns: [
      /\b(clean|redact|scrub)\b.*\b(transcripts?|logs?)\b/i,
      /\bdata\s+loss\s+prevention\b/i,
      /\bdlp\b/i,
    ],
    command: 'opena2a secrets clean',
    description: 'Scan and redact credentials in AI tool transcripts',
  },

  // Project posture assessment. Read-only. A bare "scan project" lands here;
  // a scan that names what to look for goes to the mappings that follow.
  {
    patterns: [
      /\bassess\s+(my\s+|this\s+|the\s+)?project\b/i,
      /\bsecurity\s+posture\b/i,
      /^\s*scan\s+(my\s+|this\s+|the\s+)?project\s*[.?!]?\s*$/i,
    ],
    command: 'opena2a init',
    description: 'Assess your project security posture (read-only scan)',
  },

  // Scanning intents
  {
    patterns: [
      /\b(is|are)\s+(my|this|the)\s+\w+\s+(safe|secure|vulnerable|protected)\b/i,
      /\b(scan|check|audit|analyze|inspect|review|harden|secure)\s+(my|this|the)?\s*(\w+\s+){0,2}(agent|server|project|app|code)\b/i,
      /\b(find|fix)\s+(vulnerabilities|security\s+issues|problems|bugs)\b/i,
      /\bsecurity\s+(scan|check|audit|assessment|review)\b/i,
      /\bhow\s+secure\s+is\b/i,
      /\bvulnerability\s+(scan|check|assessment)\b/i,
    ],
    command: 'opena2a scan secure',
    description: 'Run a full security scan',
  },

  // Attack testing intents
  {
    patterns: [
      /\b(attack|pentest|pen\s*test|red\s*team|break|exploit|hack)\s+(my|this|the)?\s*\w*\b/i,
      /\b(pentest|pen\s*test|red\s*team)(ing)?\b/i,
      /\btest\s+(against|for)\s+(attacks|exploits|adversarial)\b/i,
      /\badversarial\s+(test|testing)\b/i,
    ],
    command: 'opena2a scan attack',
    description: 'Run attack mode testing',
  },

  // Runtime monitoring intents
  {
    patterns: [
      /\b(monitor|watch|observe|track)\s+(my|this|the)?\s*(agent|process|network|runtime)\b/i,
      /\bruntime\s+(protection|monitoring|guard)\b/i,
      /\b(process|network|filesystem)\s+(monitoring|tracking)\b/i,
    ],
    command: 'opena2a runtime start',
    description: 'Start runtime monitoring',
  },

  // Benchmark intents
  {
    patterns: [
      /\b(benchmark|score|grade|assess|evaluate|rate)\s+(my|this|the)?\s*(agent|security|compliance)\b/i,
      /\boasb\b/i,
      /\bcompliance\s+(check|benchmark|score)\b/i,
      /\bsecurity\s+(score|grade|rating)\b/i,
    ],
    command: 'opena2a benchmark',
    description: 'Run OASB security benchmark',
  },

  // Registry/trust intents
  {
    patterns: [
      /\b(is|check\s+if)\s+\w+\s+(safe|trusted|malicious|suspicious)\b/i,
      /\bcheck\s+if\b.*\b(safe|trusted|malicious|suspicious)\b/i,
      /\btrust\s+(score|check|verify|lookup)\b/i,
      /\bsupply\s*chain\s+(check|security|risk)\b/i,
      /\bpackage\s+(safe|trust|security)\b/i,
      /\b(verify|check)\s+(a\s+|the\s+|my\s+|this\s+)?(dependency|dependencies|package|packages)\b/i,
    ],
    command: 'opena2a registry check',
    description: 'Query trust registry for package security data',
  },

  // Training intents
  {
    patterns: [
      /\b(practice|train|learn|ctf|lab)\s*(on)?\s*(security|hacking|vulnerable|agent)?\b/i,
      /\bdvaa\b/i,
      /\bvulnerable\s+agent\s+(lab|training|practice)\b/i,
    ],
    command: 'opena2a train',
    description: 'Launch DVAA training environment',
  },

  // Crypto/quantum intents
  {
    patterns: [
      /\b(quantum|post-quantum|pqc)\s+(ready|readiness|scan|check|assessment)\b/i,
      /\bcrypto(graphic)?\s+(scan|inventory|check|audit)\b/i,
      /\btls\s+(scan|check|config|configuration)\b/i,
      /\bweak\s+(crypto|encryption|cipher)\b/i,
    ],
    command: 'opena2a crypto scan',
    description: 'Run cryptographic inventory and PQC readiness scan',
  },

  // Credential broker intents
  {
    patterns: [
      /\b(credential|secret)s?\s+(broker|proxy)\b/i,
      /\bidentity[-\s]aware\s+(secrets?|credentials?)\b/i,
    ],
    command: 'opena2a broker start',
    description: 'Start the identity-aware credential broker daemon',
  },

  // Session intents: who is signed in, sign in, sign out. Before the
  // identity intents, whose `aim` pattern would take "login to AIM".
  {
    patterns: [
      /\bwho\s*am\s*i\b/i,
      /\bam\s+i\s+(logged|signed)\s+in\b/i,
      /\b(check|show)\s+(my\s+)?(auth|authentication|login)\s+(status|state)\b/i,
    ],
    command: 'opena2a whoami',
    description: 'Show the account this CLI is signed in to',
  },
  {
    patterns: [
      /\b(log\s*out|sign\s*out)\b/i,
      /\bremove\s+(my\s+|stored\s+|saved\s+)?credentials\b(?!\s+(from|in)\b)/i,
    ],
    command: 'opena2a logout',
    description: 'Sign out and remove the stored credentials',
  },
  {
    patterns: [
      /\b(log\s*in|sign\s*in)\b/i,
      /\bauthenticate\b/i,
    ],
    command: 'opena2a login',
    description: 'Sign in to an AIM server',
  },

  // Identity intents
  {
    patterns: [
      /\b(create|register|manage)\s+(my\s+|an?\s+|the\s+)?(agent\s+)?(identity|identities|id|certificates?)\b/i,
      /\bregister\s+(my|this|the|an?)\s+agent\b/i,
      /\bagent\s+identity\b/i,
      /\baim\b/i,
    ],
    command: 'opena2a identity',
    description: 'Manage agent identity via AIM',
  },

  // Config integrity / guard intents
  {
    patterns: [
      /\b(check|verify|validate)\s+(config|configuration)\s+(integrity|tamper|signatures?)\b/i,
      /\b(sign|protect)\s+(my\s+)?(config|configuration)\s+files?\b/i,
      /\bconfig\s+(guard|signing|integrity|tamper(ing)?)\b/i,
      /\btamper\s+(detection|proof|evident)\b/i,
    ],
    command: 'opena2a guard verify',
    description: 'Verify config file integrity signatures',
  },

  // Status/overview intents
  {
    patterns: [
      /\b(what(?:'s|\s+is)?|show(?:\s+me)?|display)\s+(the\s+|my\s+)?(\w+\s+)?(status|overview|summary|dashboard)\b/i,
      /\b(project|security)\s+(overview|summary|dashboard)\b/i,
      /\bhow\s+(am|are)\s+(i|we)\s+doing\b/i,
    ],
    command: 'opena2a status',
    description: 'Show project security status',
  },

  // CLI settings intents. Read-only: `config show` prints the settings,
  // including the registry URL, and the commands that change them.
  {
    patterns: [
      /\b(change|update|edit|view|show)\s+(my\s+|the\s+)?(cli\s+)?(settings|config|configuration|preferences)\b/i,
      /\bconfigure\s+(contribute|contributions?|telemetry|llm)\b/i,
      /\bset\s+(the\s+)?registry\s+url\b/i,
    ],
    command: 'opena2a config show',
    description: 'Show the OpenA2A configuration',
  },

  // Setup/init intents. The 11-step setup changes the project, so it needs
  // a request that names what to set up, or a fixed onboarding phrase. A
  // lone verb never matches: `opena2a nanomind setup`, a command another tool
  // printed, used to resolve here because `set\s*up` matched the bare token.
  {
    patterns: [
      /\bget\s+started\b/i,
      /\bhow\s+do\s+i\s+(start|begin|use)\b/i,
      /\bquick\s*start\b/i,
      /\bfirst\s+time\s+(setup|user|here|using)\b/i,
      /\b(set\s*up|initialize|install|onboard)\s+(\w+\s+){0,2}(security|project|shield|opena2a)\b/i,
      /\bsecurity\s+setup\b/i,
    ],
    command: 'opena2a shield init',
    description: 'Full security setup: scan, protect, sign, policy, hooks (11 steps)',
  },
];

/**
 * Commands that change the project, the keychain, stored credentials or a
 * running daemon. A natural-language match for one of these is confirmed
 * with the default set to no; a read-only match keeps the default yes.
 * Entries are command paths without the `opena2a` prefix.
 */
export const MUTATING_COMMANDS: readonly string[] = [
  'protect', 'shield init', 'secrets init', 'secrets clean',
  'guard sign', 'guard resign', 'harden-soul', 'harden-skill', 'fix-all',
  'runtime start', 'broker start', 'identity init', 'identity create',
  'login', 'logout',
];

/**
 * True when `command` (`opena2a guard sign config.json`) runs a command in
 * {@link MUTATING_COMMANDS}, or asks for `--fix`. `--dry-run` makes any
 * command read-only.
 */
export function isMutatingCommand(command: string): boolean {
  const tokens = command.trim().replace(/^opena2a\s+/, '').split(/\s+/);
  if (tokens.includes('--dry-run')) return false;
  if (tokens.includes('--fix')) return true;
  return MUTATING_COMMANDS.some(entry => {
    const path = entry.split(' ');
    return path.every((part, i) => tokens[i] === part);
  });
}

export interface IntentResult {
  command: string;
  description: string;
  confidence: 'high' | 'medium' | 'low';
}

export function matchIntent(input: string): IntentResult | null {
  for (const mapping of INTENT_MAPPINGS) {
    for (const pattern of mapping.patterns) {
      if (pattern.test(input)) {
        return {
          command: mapping.command,
          description: mapping.description,
          confidence: 'high',
        };
      }
    }
  }

  return null;
}

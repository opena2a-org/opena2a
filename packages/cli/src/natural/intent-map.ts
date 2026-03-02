interface IntentMapping {
  patterns: RegExp[];
  command: string;
  description: string;
}

const INTENT_MAPPINGS: IntentMapping[] = [
  // Scanning intents
  {
    patterns: [
      /\b(is|are)\s+(my|this|the)\s+\w+\s+(safe|secure|vulnerable|protected)\b/i,
      /\b(scan|check|audit|analyze|inspect|review)\s+(my|this|the)?\s*(agent|server|project|app|code)\b/i,
      /\bfind\s+(vulnerabilities|security\s+issues|problems|bugs)\b/i,
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
      /\btest\s+(against|for)\s+(attacks|exploits|adversarial)\b/i,
      /\badversarial\s+(test|testing)\b/i,
    ],
    command: 'opena2a scan attack',
    description: 'Run attack mode testing',
  },

  // Credential protection intents
  {
    patterns: [
      /\b(protect|hide|encrypt|secure|manage)\s+(my|the)?\s*(secrets?|credentials?|api\s*keys?|tokens?|passwords?)\b/i,
      /\b(secrets?|credentials?|api\s*keys?)\s+(are|is)\s+(exposed|leaked|visible|unsafe)\b/i,
      /\bstop\s+ai\s+(from\s+)?(reading|seeing|accessing)\s+(my\s+)?(secrets?|keys?)\b/i,
      /\bhardcoded\s+(secrets?|credentials?|keys?)\b/i,
      /\b(move|migrate)\s+(secrets?|credentials?)\s+to\s+vault\b/i,
    ],
    command: 'opena2a protect',
    description: 'Migrate credentials to encrypted vault',
  },

  // Secrets management intents
  {
    patterns: [
      /\b(set\s*up|init|initialize|configure)\s+(secretless|secret\s+management|credential\s+protection)\b/i,
      /\bsecretless\b/i,
    ],
    command: 'opena2a secrets init',
    description: 'Initialize Secretless credential protection',
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
    ],
    command: 'opena2a benchmark',
    description: 'Run OASB security benchmark',
  },

  // Registry/trust intents
  {
    patterns: [
      /\b(is|check\s+if)\s+\w+\s+(safe|trusted|malicious|suspicious)\b/i,
      /\btrust\s+(score|check|verify|lookup)\b/i,
      /\bsupply\s*chain\s+(check|security|risk)\b/i,
      /\bpackage\s+(safe|trust|security)\b/i,
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

  // Identity intents
  {
    patterns: [
      /\b(create|register|manage)\s+(agent\s+)?(identity|id|certificate)\b/i,
      /\bagent\s+identity\b/i,
      /\baim\b/i,
    ],
    command: 'opena2a identity',
    description: 'Manage agent identity via AIM',
  },

  // Status/overview intents
  {
    patterns: [
      /\b(what|show|display)\s+(is|me)?\s*(the)?\s*(status|overview|summary|dashboard)\b/i,
      /\bhow\s+(am|are)\s+(i|we)\s+doing\b/i,
    ],
    command: 'opena2a status',
    description: 'Show project security status',
  },

  // Setup/init intents
  {
    patterns: [
      /\b(get\s+started|set\s*up|initialize|onboard|first\s+time)\b/i,
      /\bhow\s+do\s+i\s+(start|begin|use)\b/i,
      /\bquick\s*start\b/i,
    ],
    command: 'opena2a init',
    description: 'Initialize OpenA2A security in your project',
  },
];

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

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

interface CommandEntry {
  id: string;
  path: string;
  description: string;
  tags: string[];
  synonyms: string[];
  domains: string[];
  examples: string[];
}

const WEIGHTS = {
  tag: 10,
  synonym: 8,
  domain: 5,
  example: 3,
  description: 2,
};

// Domain expansion map: query terms -> related domains
const DOMAIN_MAP: Record<string, string[]> = {
  api: ['agent', 'mcp', 'credentials'],
  key: ['credentials', 'secrets', 'config'],
  token: ['credentials', 'secrets'],
  password: ['credentials', 'secrets'],
  secret: ['credentials', 'secrets', 'vault'],
  vulnerable: ['scan', 'attack', 'training'],
  safe: ['scan', 'security', 'hardening'],
  llm: ['agent', 'ai', 'mcp'],
  openai: ['credentials', 'ai', 'llm'],
  anthropic: ['credentials', 'ai', 'llm'],
  claude: ['credentials', 'ai', 'cursor', 'claude-code'],
  cursor: ['credentials', 'ai', 'claude-code'],
  mcp: ['agent', 'mcp', 'security'],
  docker: ['training', 'dvaa'],
  npm: ['supply-chain', 'npm'],
  pip: ['supply-chain', 'pypi'],
  owasp: ['compliance', 'owasp', 'benchmark'],
  mitre: ['compliance', 'mitre', 'benchmark'],
  quantum: ['cryptography', 'pqc', 'tls'],
  tls: ['cryptography', 'tls', 'certificate'],
  stripe: ['credentials', 'config'],
  aws: ['credentials', 'config'],
  github: ['credentials', 'git', 'supply-chain'],
};

let cachedIndex: CommandEntry[] | null = null;

function loadIndex(): CommandEntry[] {
  if (cachedIndex) return cachedIndex;

  // Try multiple locations to find the command index
  const candidates = [
    resolve(__dirname, 'command-index.json'),
    resolve(__dirname, '..', 'semantic', 'command-index.json'),
    resolve(__dirname, '..', 'src', 'semantic', 'command-index.json'),
  ];

  for (const indexPath of candidates) {
    try {
      const raw = readFileSync(indexPath, 'utf-8');
      cachedIndex = JSON.parse(raw);
      return cachedIndex!;
    } catch {
      // Try next candidate
    }
  }

  return [];
}

function tokenize(query: string): string[] {
  return query
    .toLowerCase()
    .replace(/[^a-z0-9\s-]/g, '')
    .split(/\s+/)
    .filter(t => t.length > 1);
}

function expandTokens(tokens: string[]): string[] {
  const expanded = new Set(tokens);
  for (const token of tokens) {
    const related = DOMAIN_MAP[token];
    if (related) {
      for (const r of related) expanded.add(r);
    }
  }
  return [...expanded];
}

interface SearchResult {
  entry: CommandEntry;
  score: number;
  matchedOn: string[];
}

export function search(query: string, limit: number = 5): SearchResult[] {
  const index = loadIndex();
  if (index.length === 0) return [];

  const tokens = tokenize(query);
  const expanded = expandTokens(tokens);

  const results: SearchResult[] = [];

  for (const entry of index) {
    let score = 0;
    const matchedOn: string[] = [];

    for (const token of expanded) {
      // Tag match
      if (entry.tags.some(t => t.includes(token) || token.includes(t))) {
        score += WEIGHTS.tag;
        matchedOn.push(`tag:${token}`);
      }

      // Synonym match
      if (entry.synonyms.some(s => s.includes(token) || token.includes(s))) {
        score += WEIGHTS.synonym;
        matchedOn.push(`synonym:${token}`);
      }

      // Domain match
      if (entry.domains.some(d => d.includes(token) || token.includes(d))) {
        score += WEIGHTS.domain;
        matchedOn.push(`domain:${token}`);
      }

      // Description match
      if (entry.description.toLowerCase().includes(token)) {
        score += WEIGHTS.description;
        matchedOn.push(`description:${token}`);
      }

      // Example match
      if (entry.examples.some(e => e.toLowerCase().includes(token))) {
        score += WEIGHTS.example;
        matchedOn.push(`example:${token}`);
      }
    }

    if (score > 0) {
      results.push({ entry, score, matchedOn });
    }
  }

  results.sort((a, b) => b.score - a.score);
  return results.slice(0, limit);
}

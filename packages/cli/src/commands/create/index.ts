/**
 * opena2a create -- Scaffolding command for secure skills and components.
 *
 * Currently supports:
 * - `create skill [name]` -- interactive wizard to scaffold a signed skill
 */

import { red, dim } from '../../util/colors.js';

// --- Types ---

export interface CreateOptions {
  type: string;
  name?: string;
  template?: string;
  output?: string;
  noSign?: boolean;
  ci?: boolean;
  format?: string;
  verbose?: boolean;
}

// --- Supported types ---

const SUPPORTED_TYPES = ['skill'];

// --- Main ---

export async function create(opts: CreateOptions): Promise<number> {
  const typeLower = opts.type.toLowerCase();

  if (!SUPPORTED_TYPES.includes(typeLower)) {
    process.stderr.write(red(`Unknown type: ${opts.type}\n`));
    process.stderr.write(`Supported types: ${SUPPORTED_TYPES.join(', ')}\n`);
    process.stderr.write(dim(`Example: opena2a create skill my-skill\n`));
    return 1;
  }

  switch (typeLower) {
    case 'skill': {
      const { createSkill } = await import('./skill.js');
      return createSkill({
        name: opts.name,
        template: opts.template,
        output: opts.output,
        noSign: opts.noSign,
        ci: opts.ci,
        format: opts.format,
        verbose: opts.verbose,
      });
    }
    default:
      return 1;
  }
}

// --- Testable internals ---

export const _internals = {
  SUPPORTED_TYPES,
};

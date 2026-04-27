/**
 * MCP narrative block — renders "What is this MCP?" with tool list,
 * path/network/persistence/auth scope, and side effects.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3.4-§3.6).
 *
 * The opening prose ("Filesystem MCP server. Exposes 7 tools to a
 * connected agent:") is intentionally minimal in v1 — the McpNarrative
 * type has no descriptive `behaviorDescription` field today, so the
 * renderer composes a deterministic opener from the tools count.
 * Future schema bumps can add prose; until then the labelled rows
 * (Path scope, Network, Persistence, Auth) carry the meaning.
 */

export interface McpToolLike {
  name: string;
  signature: string;
  description: string;
  destructive: boolean;
}

export interface McpNarrativeLike {
  mcpName: string;
  tools: McpToolLike[];
  pathScope: string;
  network: string;
  persistence: string;
  auth: string;
  sideEffects: string[];
}

export type McpNarrativeTone =
  | "default"
  | "good"
  | "warning"
  | "critical"
  | "dim";

export interface McpNarrativeLine {
  /** Indent: 0 = section row, 1 = tool list item. */
  indent: 0 | 1;
  /** Pre-padded label, empty for opener / tool list / continuation. */
  label: string;
  value: string;
  tone: McpNarrativeTone;
}

export interface RenderedMcpNarrative {
  header: string;
  /** Width to which `label` strings have been padded (for caller alignment). */
  labelWidth: number;
  lines: McpNarrativeLine[];
}

const MCP_LABELS = ["Path scope", "Network", "Persistence", "Auth", "Side effects"];

function widthFor(labels: string[]): number {
  let max = 0;
  for (const l of labels) if (l.length > max) max = l.length;
  return Math.min(max + 3, 24);
}

function pad(label: string, width: number): string {
  if (label === "") return "";
  const withColon = `${label}:`;
  if (withColon.length >= width) return `${withColon} `;
  return withColon + " ".repeat(width - withColon.length);
}

/**
 * Format the opener line. With at least one tool:
 *   "MCP server. Exposes 7 tools to a connected agent:"
 * Without tools:
 *   "MCP server. No tools exposed."
 */
function openerFor(narrative: McpNarrativeLike): string {
  const n = narrative.tools.length;
  if (n === 0) return "MCP server. No tools exposed.";
  return `MCP server. Exposes ${n} tool${n === 1 ? "" : "s"} to a connected agent:`;
}

/**
 * Compute the column width for tool signatures — longest signature
 * length, capped at 32, so "write_file(path, content)" lines up with
 * "read_file(path)" without forcing the whole row off-screen.
 */
function signatureWidth(tools: McpToolLike[]): number {
  let max = 0;
  for (const t of tools) {
    if (t.signature.length > max) max = t.signature.length;
  }
  return Math.min(max + 2, 32);
}

function toneForTool(tool: McpToolLike): McpNarrativeTone {
  return tool.destructive ? "warning" : "default";
}

export function renderMcpNarrativeBlock(
  narrative: McpNarrativeLike,
): RenderedMcpNarrative {
  const labelWidth = widthFor(MCP_LABELS);
  const lines: McpNarrativeLine[] = [];

  lines.push({
    indent: 0,
    label: "",
    value: openerFor(narrative),
    tone: "default",
  });

  // Tool list — indent 1, padded signature column for alignment.
  if (narrative.tools.length > 0) {
    const sigWidth = signatureWidth(narrative.tools);
    for (const t of narrative.tools) {
      const sig = t.signature.padEnd(sigWidth, " ");
      const desc = t.description && t.description.length > 0
        ? `— ${t.description}`
        : "";
      lines.push({
        indent: 1,
        label: "",
        value: `- ${sig}${desc}`.trimEnd(),
        tone: toneForTool(t),
      });
    }
  }

  lines.push({
    indent: 0,
    label: pad("Path scope", labelWidth),
    value:
      narrative.pathScope && narrative.pathScope.length > 0
        ? narrative.pathScope
        : "not specified",
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Network", labelWidth),
    value:
      narrative.network && narrative.network.length > 0
        ? narrative.network
        : "none",
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Persistence", labelWidth),
    value:
      narrative.persistence && narrative.persistence.length > 0
        ? narrative.persistence
        : "none",
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Auth", labelWidth),
    value:
      narrative.auth && narrative.auth.length > 0 ? narrative.auth : "none",
    tone: "default",
  });

  if (narrative.sideEffects && narrative.sideEffects.length > 0) {
    lines.push({
      indent: 0,
      label: pad("Side effects", labelWidth),
      value: narrative.sideEffects.join("; "),
      tone: "warning",
    });
  }

  return { header: "What is this MCP?", labelWidth, lines };
}

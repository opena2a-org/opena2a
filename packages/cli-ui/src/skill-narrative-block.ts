/**
 * Skill narrative block — renders "What is this skill?" + the
 * "How this skill could be misused" misuse paragraph.
 *
 * Brief: opena2a-org/briefs/check-rich-context-skills-mcp-v1.md (§3.1, §3.2).
 *
 * Two distinct blocks live here so the orchestrator can decide
 * independently whether to render the misuse paragraph (it may be
 * empty when the registry-cached NanoMind v3 summary is OOD per
 * `project_nanomind_v05_intelreport_task_mismatch.md`).
 *
 * All caller-supplied strings are sanitized via `sanitizeForTerminal`
 * — registry-sourced narrative fields are untrusted and could embed
 * ANSI / OSC-8 / control bytes.
 */
import { sanitizeArray, sanitizeForTerminal } from "./terminal-safe.js";

/**
 * Permission delta entry — local mirror of `PermissionStatus` from
 * check-core.
 */
export interface PermissionStatusLike {
  name: string;
  declared: boolean;
  used: boolean;
  status: "used" | "unused" | "undeclared";
  note?: string;
}

export interface ToolCallCountLike {
  tool: string;
  count: number;
}

export interface SkillNarrativeLike {
  skillName: string;
  activationPhrases: string[];
  behaviorDescription: string;
  permissions: PermissionStatusLike[];
  externalServices: string[];
  persistence: string;
  toolCallsObserved: ToolCallCountLike[];
  misuseNarrative: string;
}

export type SkillNarrativeTone =
  | "default"
  | "good"
  | "warning"
  | "critical"
  | "dim";

export interface SkillNarrativeLine {
  /** Indent level: 0 = section row, 1 = sub-row (permissions, tool calls). */
  indent: 0 | 1;
  /**
   * Optional label (e.g. "Skill name", "Activates on"). When present,
   * the renderer column-aligns labels across rows. Empty string for
   * continuation rows or unlabeled rows.
   */
  label: string;
  /** Right-hand value. May contain inline punctuation. */
  value: string;
  tone: SkillNarrativeTone;
}

export interface RenderedSkillNarrative {
  /**
   * Section header label — "What is this skill?".
   */
  header: string;
  /**
   * Width to pad labels to. Caller uses this to align labels across
   * rows; the renderer pre-pads `label` strings, so callers can simply
   * concatenate `label + value`.
   */
  labelWidth: number;
  lines: SkillNarrativeLine[];
}

const DASH = "[—]";

function permissionStatusMarker(p: PermissionStatusLike): string {
  switch (p.status) {
    case "used":
      return "[used]";
    case "unused":
      return "[unused]";
    case "undeclared":
      return "[undeclared]";
    default:
      return DASH;
  }
}

function permissionTone(p: PermissionStatusLike): SkillNarrativeTone {
  if (p.status === "unused" && p.declared) return "warning";
  if (p.status === "undeclared" && p.used) return "critical";
  if (p.status === "used") return "good";
  return "default";
}

/**
 * Compose the activation phrase list for inline rendering. Quotes each
 * phrase, joins with `, `. The renderer expects the orchestrator to
 * wrap long lines if needed; we don't soft-wrap here since the wrap
 * policy depends on terminal width which the caller owns.
 */
function formatActivationPhrases(phrases: string[]): string {
  if (phrases.length === 0) return "no activation phrases declared";
  return sanitizeArray(phrases)
    .map((p) => `"${p}"`)
    .join(", ");
}

function formatToolCalls(tcs: ToolCallCountLike[]): string {
  if (tcs.length === 0) return "no tool calls observed";
  return tcs
    .map((t) => `${sanitizeForTerminal(t.tool)} x${t.count}`)
    .join(", ");
}

function formatExternalServices(services: string[]): string {
  if (services.length === 0) return "none";
  return sanitizeArray(services).join(", ");
}

const SKILL_LABELS = [
  "Skill name",
  "Activates on",
  "What it does",
  "Permissions declared",
  "External services",
  "Persistence",
  "Tool calls observed",
];

function widthFor(labels: string[]): number {
  let max = 0;
  for (const l of labels) if (l.length > max) max = l.length;
  // "<label>:" + 2 spaces.
  return Math.min(max + 3, 24);
}

function pad(label: string, width: number): string {
  if (label === "") return "";
  const withColon = `${label}:`;
  if (withColon.length >= width) return `${withColon} `;
  return withColon + " ".repeat(width - withColon.length);
}

export function renderSkillNarrativeBlock(
  narrative: SkillNarrativeLike,
): RenderedSkillNarrative {
  const labelWidth = widthFor(SKILL_LABELS);
  const lines: SkillNarrativeLine[] = [];

  lines.push({
    indent: 0,
    label: pad("Skill name", labelWidth),
    value: narrative.skillName ? sanitizeForTerminal(narrative.skillName) : "(unknown)",
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Activates on", labelWidth),
    value: formatActivationPhrases(narrative.activationPhrases),
    tone: "default",
  });

  if (narrative.behaviorDescription && narrative.behaviorDescription.length > 0) {
    lines.push({
      indent: 0,
      label: pad("What it does", labelWidth),
      value: sanitizeForTerminal(narrative.behaviorDescription),
      tone: "default",
    });
  } else {
    lines.push({
      indent: 0,
      label: pad("What it does", labelWidth),
      value: "Comprehension data not yet available.",
      tone: "dim",
    });
  }

  // Permissions block — labelled row + sub-rows per permission.
  if (narrative.permissions.length > 0) {
    lines.push({
      indent: 0,
      label: pad("Permissions declared", labelWidth),
      value: "",
      tone: "default",
    });
    // Sub-rows: column-align permission name (cap 18 chars) + status marker.
    let nameWidth = 0;
    for (const p of narrative.permissions) {
      if (p.name.length > nameWidth) nameWidth = p.name.length;
    }
    nameWidth = Math.min(nameWidth, 18);
    for (const p of narrative.permissions) {
      const safeName = sanitizeForTerminal(p.name);
      const padded = safeName.padEnd(nameWidth, " ");
      const marker = permissionStatusMarker(p);
      const note = p.note && p.note.length > 0
        ? `   ${sanitizeForTerminal(p.note)}`
        : "";
      lines.push({
        indent: 1,
        label: "",
        value: `- ${padded}  ${marker}${note}`,
        tone: permissionTone(p),
      });
    }
  }

  lines.push({
    indent: 0,
    label: pad("External services", labelWidth),
    value: formatExternalServices(narrative.externalServices),
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Persistence", labelWidth),
    value:
      narrative.persistence && narrative.persistence.length > 0
        ? sanitizeForTerminal(narrative.persistence)
        : "none",
    tone: "default",
  });

  lines.push({
    indent: 0,
    label: pad("Tool calls observed", labelWidth),
    value: formatToolCalls(narrative.toolCallsObserved),
    tone: "default",
  });

  return { header: "What is this skill?", labelWidth, lines };
}

/**
 * Render the misuse-narrative paragraph. Returns null when the
 * narrative is empty so the orchestrator can omit the section
 * entirely (no "Comprehension data not yet available" placeholder
 * here — empty narrative means the block doesn't render).
 */
export interface RenderedMisuseNarrative {
  header: string;
  paragraph: string;
}

export function renderSkillMisuseNarrative(
  narrative: SkillNarrativeLike,
): RenderedMisuseNarrative | null {
  const text = (narrative.misuseNarrative || "").trim();
  if (text.length === 0) return null;
  return {
    header: "How this skill could be misused",
    paragraph: sanitizeForTerminal(text),
  };
}

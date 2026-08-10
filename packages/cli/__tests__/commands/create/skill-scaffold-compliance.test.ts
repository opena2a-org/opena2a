/**
 * opena2a#259 — `skill create` scaffolding scored 53-55/100 with 5 HIGH findings
 * and the artifact label `malicious`.
 *
 * `skill create` -> `scan` is the documented quickstart, so the tool reported
 * its own pristine output as "Not safe as-is". Same family as #251: following
 * our own tool makes our own numbers bad.
 *
 * Every expectation below is pinned to the specific hackmyagent 0.25.1 check it
 * satisfies, measured against the scanner rather than guessed. Measured on the
 * generated scaffold (OPENA2A_CORPUS_DETERMINISTIC=1, so home-directory
 * findings from hackmyagent#337 are excluded):
 *
 *   before: 55/100, 5 high, `skill · malicious`
 *   after:  69/100, 1 high, `skill · unknown`   (7 constraints recognised)
 *
 * Honest accounting of what moved. The governance sections are a real change
 * to the artifact: for prompt-injection resistance the prose IS the control,
 * so AST-PROMPT-002/003/004 clearing reflects a genuinely more constrained
 * skill. The `.gitignore` is real. The SKILL-003 and HEARTBEAT-006 changes are
 * weaker: the generated skill still has a 7-day heartbeat, and moving the
 * declaration into HEARTBEAT.md is following hackmyagent's stated remediation
 * ("Move scheduled task configuration to a separate heartbeat config file")
 * rather than changing behaviour. `activeHours:` currently has no consumer in
 * this repo -- it satisfies HEARTBEAT-006 and documents intent, nothing more.
 *
 * The one remaining HIGH is `Unsigned Heartbeat`, which needs an AIM/Ed25519
 * identity the scaffold cannot conjure. That is the "two meanings of signed"
 * half of #259 and is tracked separately; what is fixed here is the false
 * claim that the scaffold had already signed those files.
 */
import { describe, it, expect } from 'vitest';

import {
  generateSkillMd,
  generateHeartbeatMd,
  generateGitignore,
} from '../../../src/commands/create/templates.js';

function skillMd(): string {
  return generateSkillMd({
    name: 'tskill',
    description: 'A new OpenA2A skill',
    capabilities: [],
    permissions: {},
    bodyContent: '## Overview\n\nA basic skill.\n',
  });
}

describe('skill create scaffolding starts compliant (#259)', () => {
  it('declares a trust hierarchy (AST-PROMPT-004 "No Trust Hierarchy")', () => {
    const md = skillMd();
    expect(md).toMatch(/##\s*Trust Hierarchy/i);
    // The analyzer reads the artifact's OWN constraints -- a sibling SOUL.md
    // does not clear this check, so the section must live in SKILL.md.
    expect(md).toMatch(/authority/i);
  });

  it('declares injection resistance (AST-PROMPT-003 "Missing Injection Resistance")', () => {
    const md = skillMd();
    // The check accepts a constraint matching
    //   (override|ignore) AND (never|must not|shall not|forbidden)
    const constraintLines = md.split('\n').filter(l => l.trim().startsWith('-'));
    const hasOverrideResistance = constraintLines.some(l => {
      const t = l.toLowerCase();
      return (t.includes('override') || t.includes('ignore')) &&
        (t.includes('never') || t.includes('must not') || t.includes('shall not') || t.includes('forbidden'));
    });
    expect(hasOverrideResistance).toBe(true);
  });

  it('states that instructions are immutable and outrank other input', () => {
    expect(skillMd()).toMatch(/immutable/i);
  });

  it('does not declare a heartbeat in SKILL.md frontmatter (SKILL-003)', () => {
    // SKILL-003 is a per-line regex (/heartbeat|cron|schedule|.../i) over
    // SKILL.md. hackmyagent's own guidance is that schedule configuration
    // belongs in a separate file -- and the scaffold already writes
    // HEARTBEAT.md, so the frontmatter block was duplication that tripped the
    // check for nothing.
    const frontmatter = skillMd().split('---')[1] ?? '';
    expect(frontmatter).not.toMatch(/heartbeat/i);
  });

  it('trips no SKILL-003 line pattern anywhere in SKILL.md', () => {
    // Guard the whole file, not just the frontmatter: the governance prose
    // added above must not reintroduce the finding via a word like "schedule".
    const pattern = /heartbeat|cron|schedule|every\s+\d+\s*(min|hour|sec)/i;
    const offenders = skillMd().split('\n').filter(l => pattern.test(l));
    expect(offenders).toEqual([]);
  });

  it('keeps the interval in HEARTBEAT.md, where the generated test reads it', () => {
    // Negative control: removing the frontmatter must not orphan the schedule.
    // The scaffold's own skill.test.ts asserts `Interval: 7d` in HEARTBEAT.md,
    // so dropping it here would make the generated project fail its own tests.
    const hb = generateHeartbeatMd('tskill');
    expect(hb).toContain('Status: active');
    expect(hb).toContain('Interval: 7d');
  });

  it('bounds the heartbeat to active hours (HEARTBEAT-006)', () => {
    expect(generateHeartbeatMd('tskill')).toMatch(/activeHours:\s*\d{2}:\d{2}-\d{2}:\d{2}/);
  });

  it('does not use the word "schedule" in HEARTBEAT.md (SKILL-003 overlap)', () => {
    // HEARTBEAT-006 accepts `activeHours:` OR `schedule:`. Choosing the latter
    // would satisfy it while tripping SKILL-003's line regex -- one finding
    // traded for another.
    expect(generateHeartbeatMd('tskill')).not.toMatch(/schedule/i);
  });

  it('ships a .gitignore covering the credential paths (GIT-001/GIT-002)', () => {
    const gi = generateGitignore();
    for (const pattern of ['.env', '*.key', '*.pem', 'secrets.json']) {
      expect(gi.split('\n')).toContain(pattern);
    }
  });

  it('does not ignore .env.example, which is meant to be committed', () => {
    // Negative control: a blanket `.env*` would suppress the placeholder
    // template protect writes and users are supposed to commit.
    const lines = generateGitignore().split('\n');
    expect(lines).not.toContain('.env*');
    expect(lines).not.toContain('.env.example');
  });

  it('still produces parseable frontmatter with the required keys', () => {
    // Negative control for the frontmatter edit.
    const frontmatter = skillMd().split('---')[1] ?? '';
    expect(frontmatter).toMatch(/name:\s*tskill/);
    expect(frontmatter).toMatch(/version:\s*1\.0\.0/);
    expect(frontmatter).toMatch(/capabilities:/);
    expect(frontmatter).toMatch(/permissions:/);
  });
});

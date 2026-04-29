import { describe, it, expect } from 'vitest';
import { isKnownExample, findRealMatch } from './match.js';
import { CREDENTIAL_PATTERNS } from './patterns.js';

function patternByName(name: string) {
  const p = CREDENTIAL_PATTERNS.find(p => p.name === name);
  if (!p) throw new Error(`pattern ${name} not found`);
  return p;
}

describe('isKnownExample (issue #50 — comment-marker precedence)', () => {
  it('does NOT treat a line with # but no "example" as a known example', () => {
    // Python comment line with a credential-shaped value but no "example" marker.
    // Previous buggy precedence `(A && B) || C` would enter the inner block on any
    // line containing `#`. Regression guard: must return false here.
    const line = '# rotate AKIAREALKEY1234567890 next sprint';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('DOES treat a line with "example //" as a known example', () => {
    const line = 'const key = "AKIASOMEOTHERKEY12345"; // example placeholder';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('treats the AKIAIOSFODNN7EXAMPLE public example as a known example', () => {
    const line = 'See AKIAIOSFODNN7EXAMPLE in the AWS docs.';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });
});

describe('isKnownExample (0.1.1 — block-comment markers)', () => {
  // The 4 false-positive cases from hackmyagent dogfooding (2026-04-29) all
  // came back to the comment-marker branch only recognizing `//` and `#`. The
  // rules expanded to JSDoc/HTML/Python doc-comment markers below.

  it('JSDoc continuation `* example AKIA...` is allowlisted', () => {
    const line = ' * example: AKIAEXAMPLEKEY1234567 in this docstring';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('JSDoc continuation with leading whitespace `   * example` is allowlisted', () => {
    const line = '   * example AKIAEXAMPLEKEY1234567 indented';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('block-comment open `/* example AKIA...` is allowlisted', () => {
    const line = '/* example: AKIAEXAMPLEKEY1234567 */';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('HTML comment `<!-- example AKIA... -->` is allowlisted', () => {
    const line = '<!-- example AKIAEXAMPLEKEY1234567 in HTML -->';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('Python triple-single-quote docstring with example AKIA... is allowlisted', () => {
    const line = "'''example: AKIAEXAMPLEKEY1234567'''";
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('Python triple-double-quote docstring with example AKIA... is allowlisted', () => {
    const line = '"""example: AKIAEXAMPLEKEY1234567"""';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('multiplication line `x * y` containing real AKIA but no comment marker is NOT allowlisted', () => {
    // Negative test: `*` only counts as a comment marker when it leads the line
    // (after whitespace). Real code with `*` operator must still fire.
    const line = 'const computed = AKIAREALKEY1234567890 * multiplier;';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('JSDoc line without "example" token is NOT allowlisted', () => {
    // The example-gate is preserved: a comment containing a real credential
    // but no "example" token still fires. This guards against silently
    // suppressing real credentials that happen to live in a JSDoc block.
    const line = ' * Real API key follows: AKIAREALKEY1234567890';
    const match = line.match(/AKIA[0-9A-Z]{16}/)!;
    expect(isKnownExample(line, match)).toBe(false);
  });
});

describe('isKnownExample (0.1.1 — bare "fake" placeholder)', () => {
  // Original bug: bare-fake-prefixed sk-proj values were missed because
  // PLACEHOLDER_INDICATORS only had `'fake_'` and `'fake-'` — the bare prefix
  // `fake` followed by digits/letters slipped through.
  // Real-shaped strings constructed dynamically (per src/patterns.test.ts:12-13)
  // to avoid GitHub Push Protection.
  const fakeOpenaiProjValue = ['sk-', 'proj-', 'fake1234567890abcdefghijklmnop'].join('');
  const fakeGlpatUnderscore = ['glpat-', 'fake_', '1234567890abcdefghij'].join('');
  const fakeGlpatHyphen = ['glpat-', 'fake-', '1234567890abcdefghij'].join('');

  it('sk-proj-fake-prefixed value is allowlisted', () => {
    const line = `OPENAI_API_KEY=${fakeOpenaiProjValue}`;
    const pattern = patternByName('OpenAI Project Key');
    const match = line.match(pattern.regex)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('GitLab PAT with embedded `fake_` is allowlisted (bare fake subsumes legacy fake_)', () => {
    // glpat- regex includes `_` and `-` in the body, so the legacy `fake_` form
    // can actually appear inside a match. Bare `fake` continues to catch it.
    const line = `GITLAB_TOKEN=${fakeGlpatUnderscore}`;
    const pattern = patternByName('GitLab PAT');
    const match = line.match(pattern.regex)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('GitLab PAT with embedded `fake-` is allowlisted (bare fake subsumes legacy fake-)', () => {
    const line = `GITLAB_TOKEN=${fakeGlpatHyphen}`;
    const pattern = patternByName('GitLab PAT');
    const match = line.match(pattern.regex)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });
});

describe('isKnownExample (0.1.1 — localhost+demo-password DB connection strings)', () => {
  // Tutorial fixtures use `postgres://admin:password123@localhost:5432/mydb`
  // shape. Real prod credentials should never combine localhost with a demo
  // password, so this combination is the allowlist signal.

  it('postgres + admin/password123 + localhost is allowlisted', () => {
    const line = 'DATABASE_URL=postgres://admin:password123@localhost:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(match).not.toBeNull();
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('mysql + root/admin + 127.0.0.1 is allowlisted', () => {
    const line = 'MYSQL_URL=mysql://root:admin@127.0.0.1:3306/mydb';
    const pattern = patternByName('MySQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('mongodb+srv with localhost+demo password is allowlisted', () => {
    const line = 'MONGO_URI=mongodb+srv://demo:demo@localhost/db';
    const pattern = patternByName('MongoDB Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('redis with localhost+changeme is allowlisted', () => {
    const line = 'REDIS_URL=redis://default:changeme@localhost:6379/0';
    const pattern = patternByName('Redis Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('production hostname with demo password is NOT allowlisted', () => {
    // The host gate is the second filter — demo password alone is not enough.
    // A real-prod connection string with a misconfigured weak password must
    // still fire (this IS a finding worth surfacing).
    const line = 'DATABASE_URL=postgres://admin:password123@db.production.internal:5432/app';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('localhost-prefix-attack `localhost.evil.com` is NOT allowlisted', () => {
    // Anchored host check defeats this bypass — the value still fires.
    const line = 'DATABASE_URL=postgres://admin:password@localhost.evil.com:5432/app';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('localhost with REAL password (not in DEMO_PASSWORDS) is NOT allowlisted', () => {
    // Localhost alone does NOT make a value safe — only localhost+demo
    // combination does. A localhost binding with a real credential-strength
    // password (e.g. 24-byte random) must still fire.
    const line = 'DATABASE_URL=postgres://app:H4Wj8z9KqMpL2nXr7sBv5tNc@localhost:5432/dev';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(false);
  });

  it('uppercase LOCALHOST hostname is allowlisted (DNS is case-insensitive)', () => {
    const line = 'DATABASE_URL=postgres://admin:password123@LOCALHOST:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('capitalized demo password `Password123` with localhost is allowlisted (Phase 4.5 fix)', () => {
    // Adversarial review case: case-sensitive Set lookup would have missed
    // capitalized demo passwords. Real tutorials sometimes capitalize.
    const line = 'DATABASE_URL=postgres://admin:Password123@localhost:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('IPv6 loopback `[::1]` with demo password is allowlisted (Phase 4.5 fix)', () => {
    // Adversarial review case: IPv6 loopback is the same trust class as
    // 127.0.0.1; tutorials occasionally use it.
    const line = 'DATABASE_URL=postgres://admin:password@[::1]:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('IPv6 non-loopback `[::2]` with demo password is NOT allowlisted', () => {
    // Negative test: only the loopback bracket form is recognized.
    const line = 'DATABASE_URL=postgres://admin:password@[::2]:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(false);
  });
});

describe('findRealMatch (issue #51 — known-example shadowing)', () => {
  it('mixed-pattern line: AWS example + real GitHub PAT returns the PAT', () => {
    // Intentionally NO `//` or `#` markers — we're testing that the KNOWN_EXAMPLE_KEYS
    // match for AKIAIOSFODNN7EXAMPLE does not shadow the real GitHub PAT later on
    // the same line. (Lines with comment+example context are an orthogonal case
    // handled by isKnownExample directly.)
    const line = 'const old = "AKIAIOSFODNN7EXAMPLE"; const new_ = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";';
    const awsPattern = patternByName('AWS Access Key');
    const ghPattern = patternByName('GitHub Token');

    // AWS pattern: only match is the public example -> no real match
    expect(findRealMatch(line, awsPattern)).toBeNull();
    // GitHub pattern: match is real
    const ghMatch = findRealMatch(line, ghPattern);
    expect(ghMatch).not.toBeNull();
    expect(ghMatch![0]).toBe('ghp_abcdefghijklmnopqrstuvwxyz1234567890');
  });

  it('multi-match same-pattern line: example AKIAIOSFODNN7EXAMPLE before real AKIA key returns the real one', () => {
    // AWS Access Key pattern ships without /g; findRealMatch must still iterate
    // every match on the line and skip the example to find the real key.
    const line = 'const keys = ["AKIAIOSFODNN7EXAMPLE", "AKIAREALKEY1234567890"];';
    const awsPattern = patternByName('AWS Access Key');
    const match = findRealMatch(line, awsPattern);
    expect(match).not.toBeNull();
    // AWS regex is AKIA[0-9A-Z]{16} — match is exactly 20 chars, trailing digits truncated.
    expect(match![0]).toBe('AKIAREALKEY123456789');
  });

  it('returns null when every match on the line is a known example', () => {
    const line = '// examples: AKIAIOSFODNN7EXAMPLE';
    const awsPattern = patternByName('AWS Access Key');
    expect(findRealMatch(line, awsPattern)).toBeNull();
  });
});

describe('findRealMatch (0.1.1 — multi-real per-pattern-category coverage)', () => {
  // Issue #127 item 3: at least one multi-real fixture per pattern category so
  // a future regex edit that breaks the `/g` promotion is caught with a precise
  // per-category diagnostic.

  // Build real-looking tokens dynamically to avoid GitHub Push Protection
  // (precedent: src/patterns.test.ts:12-13). PP scans source bytes, so as long
  // as the credential-prefix + body don't appear contiguously in source, the
  // shape is invisible to the secret scanner. Both the placeholder fixtures
  // AND the real-looking ones are split — PP doesn't recognize 'example' or
  // 'PLACEHOLDER' substrings as allowlist signals; it scans for the literal
  // regex shape.
  const realOpenaiProj = ['sk-', 'proj-', 'Real1234567890abcdefghijklmn'].join('');
  const fakeOpenaiProj = ['sk-', 'proj-', 'fake1234567890abcdefghijklmnop'].join('');
  const realGitHubPat = ['ghp', '_RealAbcdefghijklmnopqrstuvwxyz012345'].join('');
  const fakeGitHubPat = ['ghp', '_fakeAbcdefghijklmnopqrstuvwxyz01234567'].join('');
  const realStripeLive = ['sk_', 'live_', 'RealKey1234567890abcdefghijkl'].join('');
  const fakeStripeLive = ['sk_', 'live_', 'examplePLACEHOLDER1234abcd'].join('');
  const realGoogleApi = ['AIza', 'SyB_RealValue_abcdefghijklmnop12345'].join('');
  const fakeGoogleApi = ['AIza', 'placeholder_replaceme_1234567890abc'].join('');
  const realLinear = ['lin_', 'api_', 'RealKeyAbcdefghijklmnopqrstuvwxyz0123456789ABCDEF'].join('');
  const fakeLinear = ['lin_', 'api_', 'examplePLACEHOLDER12345678901234567890abcdefgh'].join('');
  const realSendGrid = ['SG', '.AbcdefghijklmnopqrstuV.', 'RealKey1234567890abcdefghijklmnopqrstuvwxyz'].join('');
  const fakeSendGrid = ['SG', '.placeholder0123456789012.', 'placeholder0123456789012345678901234567890123456'].join('');

  // Each row: a line containing a known-example match (allowlisted) followed
  // by a real-looking match for the SAME pattern. findRealMatch must return
  // the real one (proving the /g promotion iterates past the example).
  const cases: Array<{ category: string; pattern: string; line: string; expected: string }> = [
    {
      category: 'ai-ml',
      pattern: 'OpenAI Project Key',
      line: `old=${fakeOpenaiProj} new=${realOpenaiProj}`,
      expected: realOpenaiProj,
    },
    {
      category: 'cloud',
      pattern: 'AWS Access Key',
      line: 'aws_examples="AKIAIOSFODNN7EXAMPLE" aws_real="AKIAREALKEY1234567890"',
      expected: 'AKIAREALKEY123456789',
    },
    {
      category: 'communication',
      // SendGrid format: SG.<22 alnum>.<43 alnum>
      pattern: 'SendGrid Key',
      line: `old=${fakeSendGrid} new=${realSendGrid}`,
      expected: realSendGrid,
    },
    {
      category: 'developer',
      // ghp_<36 alnum>; the bare 'fake' substring marks the first match as placeholder.
      pattern: 'GitHub Token',
      line: `old=${fakeGitHubPat} new=${realGitHubPat}`,
      expected: realGitHubPat,
    },
    {
      category: 'payment',
      pattern: 'Stripe Live Key',
      line: `old=${fakeStripeLive} new=${realStripeLive}`,
      expected: realStripeLive,
    },
    {
      category: 'database',
      pattern: 'PostgreSQL Connection String',
      line: 'demo=postgres://admin:password123@localhost:5432/mydb prod=postgres://app:H4Wj8z9KqMpL2nXr7sBv5tNc@db.prod.internal:5432/app',
      expected: 'postgres://app:H4Wj8z9KqMpL2nXr7sBv5tNc@db.prod.internal:5432/app',
    },
    {
      category: 'auth',
      // AIza<35 alnum/_-> — both halves must total exactly 35 chars after AIza.
      pattern: 'Google API Key',
      line: `placeholder=${fakeGoogleApi} real=${realGoogleApi}`,
      expected: realGoogleApi,
    },
    {
      category: 'monitoring',
      pattern: 'Linear API Key',
      line: `placeholder=${fakeLinear} real=${realLinear}`,
      expected: realLinear,
    },
  ];

  for (const c of cases) {
    it(`${c.category} (${c.pattern}) — allowlisted+real on same line returns the real match`, () => {
      const pattern = patternByName(c.pattern);
      const result = findRealMatch(c.line, pattern);
      expect(result, `expected non-null match for ${c.pattern}`).not.toBeNull();
      expect(result![0]).toBe(c.expected);
    });
  }
});

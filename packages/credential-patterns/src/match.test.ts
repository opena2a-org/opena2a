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

  it('#127: treats the AWS canonical secret-key example wJalrXUtnFEMI... as a known example', () => {
    // Paired with AKIAIOSFODNN7EXAMPLE in the AWS IAM User Guide canonical
    // example. AWS docs reference verified 2026-05-21.
    const line = 'const secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";';
    const match = line.match(/wJalr[A-Za-z0-9/+]+EXAMPLEKEY/)!;
    expect(match).not.toBeNull();
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

  it('capitalized demo password `Password123` with localhost is allowlisted', () => {
    // Adversarial review case: case-sensitive Set lookup would have missed
    // capitalized demo passwords. Real tutorials sometimes capitalize.
    const line = 'DATABASE_URL=postgres://admin:Password123@localhost:5432/mydb';
    const pattern = patternByName('PostgreSQL Connection String');
    const match = line.match(pattern.regex)!;
    expect(isKnownExample(line, match)).toBe(true);
  });

  it('IPv6 loopback `[::1]` with demo password is allowlisted', () => {
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

describe('isKnownExample — name-gated value-awareness + entropy floor (aws-secret 0.1.2)', () => {
  const awsSecret = CREDENTIAL_PATTERNS.find(p => p.id === 'aws-secret')!;
  const REAL = 'abcdEFGH1234ijklMNOP5678qrstUVWX90ABcdef'; // 40-char, high entropy
  const matchOf = (line: string) =>
    line.match(new RegExp(awsSecret.regex.source, awsSecret.regex.flags + 'g'))
      ? [...line.matchAll(new RegExp(awsSecret.regex.source, awsSecret.regex.flags + 'g'))][0]
      : null;

  it('aws-secret pattern exists with a capturing group for the value', () => {
    expect(awsSecret).toBeTruthy();
    const m = matchOf(`aws_secret_access_key = "${REAL}"`);
    expect(m?.[1]).toBe(REAL);
  });

  it('a real name-gated AWS secret is NOT a known example (findRealMatch returns it)', () => {
    const line = `aws_secret_access_key = "${REAL}"`;
    expect(isKnownExample(line, matchOf(line)!)).toBe(false);
    expect(findRealMatch(line, awsSecret)).not.toBeNull();
  });

  it('the AWS docs example secret IS suppressed via the captured value (KNOWN_EXAMPLE_KEYS)', () => {
    const line = 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(isKnownExample(line, matchOf(line)!)).toBe(true);
    expect(findRealMatch(line, awsSecret)).toBeNull();
  });

  it('low-entropy sentinels (40 zeros / DEADBEEF run) are suppressed by the entropy floor', () => {
    for (const v of ['0'.repeat(40), 'DEADBEEF'.repeat(5)]) {
      const line = `aws_secret_access_key = "${v}"`;
      expect(isKnownExample(line, matchOf(line)!), `value=${v}`).toBe(true);
      expect(findRealMatch(line, awsSecret)).toBeNull();
    }
  });

  it('value-only patterns (no group 1) are unaffected — a real AKIA key still matches', () => {
    const akia = CREDENTIAL_PATTERNS.find(p => p.id === 'aws-access')!;
    const line = 'AKIAREALKEY1234567890';
    const m = line.match(akia.regex)!;
    expect(isKnownExample(line, m)).toBe(false); // match[1] undefined -> match[0], unchanged
  });
});

describe('isKnownExample — a placeholder word glued to a complete token', () => {
  // A body written as a floor ({24} or {36} plus an open run) takes a word
  // that directly follows the token into the match. The whole-value placeholder
  // test then dropped the token in front of it, which is the evasion a
  // `.replace('sample', '')` at runtime turns back into the live token. With
  // the pattern passed, the part before the word is tested as a match of its
  // own. The values are not real tokens: the bodies are the alphabet. FAKE
  const SLACK_GLUED = ['xoxb-', '1234567890-1234567890-', 'abcdefghijklmnopqrstuvwxsample'].join(''); // FAKE
  const GHO_GLUED = ['gho_', 'abcdefghijklmnopqrstuvwxyz1234567890sample'].join(''); // FAKE
  const GHP_XXX = ['ghp_', 'abcdefghijklmnopqrstuvwxyz1234567890xxx'].join(''); // FAKE
  const GHS_GLUED = ['ghs_', 'abcdefghijklmnopqrstuvwxyz1234567890sample'].join(''); // FAKE
  const GHP_SHORT_XXX = ['ghp_', 'abcdefghijklmnopqrstuvwxyz1234567xxx'].join(''); // FAKE: 33 body characters, then xxx
  // A body that was already a floor ({20,}) took the word in before as well.
  const GITLAB_GLUED = 'glpat-abcdefghijklmnopqrstsample'; // FAKE
  // The token's own last character begins the word: 23 body characters then
  // `x`, and the `xx` after it completes `xxx`; 35 then `s`, and `ample`.
  const SLACK_TAIL_XXX = ['xoxb-', '1234567890-1234567890-', 'abcdefghijklmnopqrstuvwxxx'].join(''); // FAKE
  const SLACK_TAIL_SAMPLE = ['xoxb-', '1234567890-1234567890-', 'abcdefghijklmnopqrstuvwsample'].join(''); // FAKE
  const GHP_TAIL_XXX = ['ghp_', 'abcdefghijklmnopqrstuvwxyz123456789xxx'].join(''); // FAKE
  const GHP_TAIL_SAMPLE = ['ghp_', 'abcdefghijklmnopqrstuvwxyz123456789sample'].join(''); // FAKE
  // The word begins two characters before the fixed length ends: 34 body
  // characters then `sa`, and `mple` after it.
  const GHP_TAIL_SA_MPLE = ['ghp_', 'abcdefghijklmnopqrstuvwxyz12345678sample'].join(''); // FAKE

  it('findRealMatch keeps a slack / gho_ / ghp_ / ghs_ / glpat- token that a placeholder word follows', () => {
    const cases: Array<[string, string]> = [
      ['slack', SLACK_GLUED],
      ['github-oauth', GHO_GLUED],
      ['github-pat', GHP_XXX],
      ['github-app', GHS_GLUED],
      ['gitlab', GITLAB_GLUED],
    ];
    for (const [id, token] of cases) {
      const pattern = CREDENTIAL_PATTERNS.find(p => p.id === id)!;
      const line = `const token = "${token}";`;
      const m = findRealMatch(line, pattern);
      expect(m, `${id} dropped as a placeholder`).not.toBeNull();
      expect(m![0]).toBe(token);
    }
  });

  it('keeps a slack / ghp_ token whose own last character begins the glued word', () => {
    const cases: Array<[string, string, string]> = [
      ['slack', SLACK_TAIL_XXX, 'xx'],
      ['slack', SLACK_TAIL_SAMPLE, 'ample'],
      ['github-pat', GHP_TAIL_XXX, 'xx'],
      ['github-pat', GHP_TAIL_SAMPLE, 'ample'],
    ];
    for (const [id, token, rest] of cases) {
      const pattern = CREDENTIAL_PATTERNS.find(p => p.id === id)!;
      const line = `const token = "${token}";`;
      const m = findRealMatch(line, pattern);
      expect(m, `${id} …${token.slice(-rest.length - 1)} dropped as a placeholder`).not.toBeNull();
      // The reported value is the token plus the rest of the word (`xx`,
      // `ample`), as for a word that starts after the token.
      expect(m![0]).toBe(token);
    }
  });

  it('keeps a ghp_ token when the glued word begins two characters before the fixed length ends', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'github-pat')!;
    const m = findRealMatch(`const token = "${GHP_TAIL_SA_MPLE}";`, pattern);
    expect(m, 'github-pat …sa + mple dropped as a placeholder').not.toBeNull();
    expect(m![0]).toBe(GHP_TAIL_SA_MPLE);
  });

  it('isKnownExample without the pattern keeps the whole-value test (unchanged result)', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'slack')!;
    const line = `const token = "${SLACK_GLUED}";`;
    const m = line.match(pattern.regex)!;
    expect(isKnownExample(line, m)).toBe(true);
    expect(isKnownExample(line, m, pattern)).toBe(false);
  });

  it('still suppresses a placeholder word inside the fixed-length part of the token', () => {
    // 33 body characters then xxx: the part before the word is not a complete
    // ghp_ token, so the value is a placeholder as before.
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'github-pat')!;
    expect(findRealMatch(`const token = "${GHP_SHORT_XXX}";`, pattern)).toBeNull();
  });

  it('still suppresses a placeholder word at the start of the body', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'github-pat')!;
    const line = ['const token = "ghp_', 'placeholderabcdefghijklmnopqrstuvwxyz";'].join(''); // FAKE
    expect(findRealMatch(line, pattern)).toBeNull();
  });

  it('still suppresses a value whose secret part is the word: Discord webhook, Slack app token, database host', () => {
    // The last part of each pattern has a one-character floor, so the fixed
    // part plus the word's first character would be a complete match.
    const cases: Array<[string, string]> = [
      ['discord-webhook', 'https://discord.com/api/webhooks/123456789012345678/your_webhook_token'], // FAKE
      ['slack-app', 'xapp-1-A0123456789-1234567890123-xxxxxxxxxxxxxxxx'], // FAKE
      ['postgres', 'postgres://user:password@your-host:5432/mydb'], // FAKE
    ];
    for (const [id, value] of cases) {
      const pattern = CREDENTIAL_PATTERNS.find(p => p.id === id)!;
      expect(findRealMatch(`const value = "${value}";`, pattern), `${id} reported`).toBeNull();
    }
  });

  it('still suppresses a word that begins before a floor pattern is complete', () => {
    // 10 body characters, then a word that runs past the 20-character floor.
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'gitlab')!;
    const line = 'const token = "glpat-ABCDEFGHIJjust-for-testing";'; // FAKE
    expect(findRealMatch(line, pattern)).toBeNull();
  });

  it('still suppresses a glued token on a line that marks it as an example in a comment', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'slack')!;
    const line = `const token = "${SLACK_GLUED}"; // example`;
    expect(findRealMatch(line, pattern)).toBeNull();
  });

  it('still suppresses a glued value whose token part has low entropy', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'github-pat')!;
    const line = ['const token = "ghp_', '000000000000000000000000000000000000sample";'].join(''); // FAKE
    expect(findRealMatch(line, pattern)).toBeNull();
  });

  it('leaves a name-gated pattern alone: the anchored pattern cannot match the value by itself', () => {
    const pattern = CREDENTIAL_PATTERNS.find(p => p.id === 'aws-secret')!;
    // Group 1 is the 40-character value, 34 letters and digits then `sample`.
    const line = 'aws_secret_access_key = "abcdefghijklmnopqrstuvwxyz01234567sample"'; // FAKE
    expect(findRealMatch(line, pattern)).toBeNull();
  });
});

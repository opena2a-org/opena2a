import { describe, it, expect } from 'vitest';
import {
  firstDuplicateMember,
  foldKey,
  topLevelMemberSpan,
  StrictParseError,
  MAX_SCAN_DEPTH,
} from './strict-parse.js';
import { LocalAtxVerifier, type AtxTrustAnchors } from './atx.js';

const emptyAnchors: AtxTrustAnchors = { trustedIssuers: [], publicKeys: [] };

describe('foldKey', () => {
  it('lowercases ASCII', () => {
    expect(foldKey('TrustLevel')).toBe('trustlevel');
    expect(foldKey('TRUSTLEVEL')).toBe('trustlevel');
    expect(foldKey('agent_id-9')).toBe('agent_id-9');
  });

  it('folds the two non-ASCII code points that land on ASCII', () => {
    expect(foldKey('K')).toBe('k'); // Kelvin sign
    expect(foldKey('ſ')).toBe('s'); // long s
    expect(foldKey('taſk')).toBe(foldKey('task'));
  });

  it('uses the simple lowercase for U+0130 (matching Go/Java, not JS full mapping)', () => {
    expect(foldKey('İ')).toBe('i');
    expect('İ'.toLowerCase()).not.toBe('i'); // the divergence this guards
  });

  it('lowercases other non-ASCII 1:1 and passes non-letters through', () => {
    expect(foldKey('Ä')).toBe('ä');
    expect(foldKey('ΣΩ')).toBe('σω');
    expect(foldKey('名前')).toBe('名前');
  });
});

describe('firstDuplicateMember', () => {
  it('returns null for clean credentials', () => {
    expect(firstDuplicateMember('{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}')).toBeNull();
    expect(firstDuplicateMember('{}')).toBeNull();
    expect(firstDuplicateMember('  {"x":[1,2,{"y":"z"}]}  ')).toBeNull();
    expect(firstDuplicateMember('"scalar"')).toBeNull();
    expect(firstDuplicateMember('null')).toBeNull();
  });

  it('reports an exact duplicate at the top level', () => {
    expect(firstDuplicateMember('{"trustLevel":4,"trustLevel":9}')).toBe('trustLevel');
  });

  it('reports a case-variant (fold-colliding) duplicate', () => {
    expect(firstDuplicateMember('{"TRUSTLEVEL":9,"trustLevel":4}')).toBe('trustLevel');
  });

  it('reports Kelvin-sign and long-s fold collisions', () => {
    expect(firstDuplicateMember('{"k":1,"K":2}')).toBe('K');
    expect(firstDuplicateMember('{"task":1,"taſk":2}')).toBe('taſk');
  });

  it('reports duplicates at any depth', () => {
    expect(firstDuplicateMember('{"a":{"b":{"c":1,"c":2}}}')).toBe('c');
    expect(firstDuplicateMember('{"a":[{"x":1},{"y":1,"Y":2}]}')).toBe('Y');
  });

  it('decodes escapes in member names before folding (escape smuggle)', () => {
    // "trustLevel" decodes to "trustLevel": JSON.parse collapses the
    // pair, so the scan must collide it too.
    expect(firstDuplicateMember('{"trustLevel":4,"trust\\u004Cevel":9}')).toBe('trustLevel');
    expect(firstDuplicateMember('{"a\\u0062":1,"ab":2}')).toBe('ab');
  });

  it('treats escaped and case-variant names together', () => {
    expect(firstDuplicateMember('{"aa":1,"a\\u0041":2}')).toBe('aA');
  });

  it('does not collide distinct names, including __proto__/constructor', () => {
    expect(firstDuplicateMember('{"__proto__":1,"constructor":2,"toString":3}')).toBeNull();
    expect(firstDuplicateMember('{"__proto__":1,"__proto__":2}')).toBe('__proto__');
  });

  it('same names in sibling objects are not duplicates', () => {
    expect(firstDuplicateMember('[{"a":1},{"a":2}]')).toBeNull();
  });

  it('throws StrictParseError on malformed input', () => {
    for (const bad of [
      '',
      '   ',
      '{',
      '[1,2',
      '{"a":}',
      '{"a"1}',
      "{'a':1}",
      '{"a":1,}',
      '[1,]',
      '{"a":1} {}',
      '{"a":1}x',
      '{"a":"\\q"}',
      '{"a":"\\u12g4"}',
      '{"a":"unterminated}',
      '{"a\u0001b":1}',
      '\uFEFF{}',
    ]) {
      expect(() => firstDuplicateMember(bad), JSON.stringify(bad)).toThrow(StrictParseError);
    }
  });

  it('accepts nesting up to MAX_SCAN_DEPTH open containers and rejects beyond', () => {
    const nested = (n: number): string => '['.repeat(n) + ']'.repeat(n);
    expect(firstDuplicateMember(nested(MAX_SCAN_DEPTH))).toBeNull();
    expect(() => firstDuplicateMember(nested(MAX_SCAN_DEPTH + 1))).toThrow(StrictParseError);
  });

  it('scans a duplicate hidden at depth just inside the bound', () => {
    // A scan that silently abandoned deep subtrees (Go-style abort without
    // reject) would miss this duplicate while JSON.parse still collapses it.
    const openers = '{"a":'.repeat(MAX_SCAN_DEPTH - 1);
    const closers = '}'.repeat(MAX_SCAN_DEPTH - 1);
    const deepDup = `${openers}{"x":1,"X":2}${closers}`;
    expect(firstDuplicateMember(deepDup)).toBe('X');
  });
});

describe('topLevelMemberSpan', () => {
  it('returns the raw span of a top-level member value, duplicates preserved', () => {
    const text = '{"name":"f","atx":{"a":1,"A":2},"expected":{}}';
    const span = topLevelMemberSpan(text, 'atx');
    expect(span).not.toBeNull();
    expect(text.slice(span!.start, span!.end)).toBe('{"a":1,"A":2}');
  });

  it('captures scalar, string, and array member values', () => {
    const text = '{"s":"x{y","n":-1.5e3,"arr":[{"k":[1]},2]}';
    expect(text.slice(topLevelMemberSpan(text, 's')!.start, topLevelMemberSpan(text, 's')!.end)).toBe('"x{y"');
    expect(text.slice(topLevelMemberSpan(text, 'n')!.start, topLevelMemberSpan(text, 'n')!.end)).toBe('-1.5e3');
    expect(text.slice(topLevelMemberSpan(text, 'arr')!.start, topLevelMemberSpan(text, 'arr')!.end)).toBe(
      '[{"k":[1]},2]',
    );
  });

  it('is null for absent members and non-object roots', () => {
    expect(topLevelMemberSpan('{"a":1}', 'atx')).toBeNull();
    expect(topLevelMemberSpan('[1,2]', 'atx')).toBeNull();
    // nested "atx" members do not count as top-level
    expect(topLevelMemberSpan('{"wrap":{"atx":1}}', 'atx')).toBeNull();
  });
});

describe('LocalAtxVerifier.verifyCredential', () => {
  const verifier = new LocalAtxVerifier(emptyAnchors);

  it('rejects a duplicate member as MALFORMED naming the member, before any field is read', () => {
    const r = verifier.verifyCredential('{"atcVersion":"1.1","trustLevel":4,"TRUSTLEVEL":9}');
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('MALFORMED');
    expect(r.reason).toContain('TRUSTLEVEL');
  });

  it('rejects every degenerate credential as MALFORMED and never throws', () => {
    // Ports the Java LocalAtxVerifierConformanceTest degenerate matrix (the
    // Java adversarial round caught an NPE on the JSON literal `null`).
    for (const bad of ['null', '5', '"x"', 'true', '[]', '', '   ', '[{"a":1}]']) {
      const r = verifier.verifyCredential(bad);
      expect(r.valid, JSON.stringify(bad)).toBe(false);
      expect(r.rejectCategory, JSON.stringify(bad)).toBe('MALFORMED');
    }
  });

  it('rejects null/undefined/non-string arguments as MALFORMED', () => {
    for (const bad of [null, undefined, 42, {}, [], Symbol('x')]) {
      const r = verifier.verifyCredential(bad as never);
      expect(r.valid).toBe(false);
      expect(r.rejectCategory).toBe('MALFORMED');
    }
  });

  it('rejects a Proxy with a throwing getPrototypeOf trap as MALFORMED (no escape)', () => {
    // Adversarial round 1: `instanceof Uint8Array` invokes the trap; the throw
    // must not escape verifyCredential.
    const hostile = new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('boom');
        },
      },
    );
    const r = verifier.verifyCredential(hostile as never);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('MALFORMED');
  });

  it('rejects invalid UTF-8 bytes as MALFORMED', () => {
    const r = verifier.verifyCredential(new Uint8Array([0x7b, 0xff, 0xfe, 0x7d]));
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('MALFORMED');
  });

  it('rejects BOM-prefixed bytes as MALFORMED, matching the string entry form', () => {
    // Adversarial round 2: the default TextDecoder strips a leading BOM, which
    // gave identical wire bytes two different verdicts by entry form (and
    // diverged from the Go/Python reference verifiers, which reject a BOM).
    const bomJson = new Uint8Array([0xef, 0xbb, 0xbf, 0x7b, 0x7d]); // BOM + "{}"
    const r = verifier.verifyCredential(bomJson);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('MALFORMED');
    expect(verifier.verifyCredential('\uFEFF{}')).toEqual(r);
  });

  it('accepts Uint8Array input equivalently to string input', () => {
    const json = '{"atcVersion":"0.9"}';
    const fromString = verifier.verifyCredential(json);
    const fromBytes = verifier.verifyCredential(new TextEncoder().encode(json));
    expect(fromBytes).toEqual(fromString);
    // and proves delegation reached verify(atx): version gate, not MALFORMED
    expect(fromString.rejectCategory).toBe('UNSUPPORTED_VERSION');
  });

  it('rejects pathologically deep input cleanly (no RangeError escapes)', () => {
    const deep = '['.repeat(300_000) + ']'.repeat(300_000);
    const r = verifier.verifyCredential(deep);
    expect(r.valid).toBe(false);
    expect(r.rejectCategory).toBe('MALFORMED');
  });
});

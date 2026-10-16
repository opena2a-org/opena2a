import { describe, expect, it } from "vitest";
import {
  DISPLAY_HAZARD_SOURCE,
  escapeForDisplay,
  escapeJsonDisplayHazards,
  escapePathForDisplay,
  excerptLinesForDisplay,
  hasDisplayHazard,
  quotePathForDisplay,
  sanitizeForTerminal,
} from "../src/index.js";

// Every hazard is built from its code point at runtime: a literal control
// byte in this file would be invisible in the diff that reviews it.
const cp = (...codes: number[]): string => String.fromCodePoint(...codes);
const ESC = cp(0x1b);
const LF = cp(0x0a);
const CR = cp(0x0d);
const RLO = cp(0x202e);
const ZWSP = cp(0x200b);
// U+2764 HEAVY BLACK HEART is Extended_Pictographic.
const HEART = cp(0x2764);

// The one hostile name every CLI's end-to-end test renders.
const HOSTILE_NAME =
  "rep" + ESC + "[2J" + "ort" + RLO + "gnp.elif" + ZWSP + "name" + LF + "x";
const HOSTILE_RENDER = "rep\\e[2Jort\\u202egnp.elif\\u200bname\\nx";

// hackmyagent's alphabet, copied verbatim from src/ui/display-safe.ts.
const HACKMYAGENT_SOURCE =
  "[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}\\u{115F}\\u{1160}\\u{3164}\\u{FFA0}\\u{FE00}-\\u{FE0D}\\u{E0000}-\\u{EFFFF}]"
  + "|(?<!\\p{Extended_Pictographic})[\\u{FE0E}\\u{FE0F}]";
// The blank-rendering characters secretless-ai escapes and hackmyagent did
// not: the combining grapheme joiner, the Khmer inherent vowels, the
// Mongolian free variation selectors and vowel separator, the blank Braille
// pattern.
const SECRETLESS_BLANKS = "\\u{034F}\\u{17B4}\\u{17B5}\\u{180B}-\\u{180F}\\u{2800}";

describe("escapePathForDisplay on the shared hostile name", () => {
  it("renders it on one line with every hazard visible", () => {
    expect(escapePathForDisplay(HOSTILE_NAME)).toBe(HOSTILE_RENDER);
    expect(escapeForDisplay(HOSTILE_NAME)).toBe(HOSTILE_RENDER);
    expect(hasDisplayHazard(HOSTILE_NAME)).toBe(true);
  });
});

describe("the hazard alphabet", () => {
  it("is hackmyagent's with the blank-rendering characters added", () => {
    expect(DISPLAY_HAZARD_SOURCE).toBe(
      HACKMYAGENT_SOURCE.replace(
        "\\u{E0000}-\\u{EFFFF}]",
        "\\u{E0000}-\\u{EFFFF}" + SECRETLESS_BLANKS + "]",
      ),
    );
  });

  it("escapes exactly hackmyagent's code points plus eight, after a letter and after a pictograph", () => {
    const hackmyagent = new RegExp(HACKMYAGENT_SOURCE, "u");
    // U+180E is already a format character, so the range adds four.
    const added = [0x034f, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180f, 0x2800];
    for (const before of ["a", HEART]) {
      const onlyHere: number[] = [];
      const onlyHackmyagent: number[] = [];
      for (let code = 0; code <= 0x10ffff; code++) {
        const text = before + String.fromCodePoint(code);
        const here = hasDisplayHazard(text);
        const there = hackmyagent.test(text);
        if (here && !there) onlyHere.push(code);
        if (there && !here) onlyHackmyagent.push(code);
      }
      // After a pictograph, hackmyagent's narrower exemption holds: only
      // U+FE0E and U+FE0F print raw there.
      expect(onlyHere).toEqual(added);
      expect(onlyHackmyagent).toEqual([]);
    }
  });
});

// One row per probe row of the measured behaviour table: [input, render].
const PROBE_ROWS: Array<{ row: string; cases: Array<[string, string]> }> = [
  { row: "LF U+000A escapes", cases: [["a" + LF + "b", "a\\nb"]] },
  { row: "TAB U+0009 escapes", cases: [["a" + cp(0x09) + "b", "a\\tb"]] },
  { row: "CR U+000D escapes", cases: [["a" + CR + "b", "a\\rb"]] },
  {
    row: "ESC, BEL, NUL and DEL escape",
    cases: [
      ["a" + ESC + "b", "a\\eb"],
      ["a" + cp(0x07) + "b", "a\\x07b"],
      ["a" + cp(0x00) + "b", "a\\0b"],
      ["a" + cp(0x7f) + "b", "a\\x7fb"],
    ],
  },
  {
    row: "a CSI sequence and an OSC-8 link escape with every byte visible",
    cases: [
      ["a" + ESC + "[2Jb", "a\\e[2Jb"],
      [
        ESC + "]8;;https://example.test/" + ESC + "\\" + "link" + ESC + "]8;;" + ESC + "\\",
        "\\e]8;;https://example.test/\\e\\link\\e]8;;\\e\\",
      ],
    ],
  },
  {
    row: "C1 CSI U+009B and NEL U+0085 escape",
    cases: [
      ["a" + cp(0x9b) + "b", "a\\x9bb"],
      ["a" + cp(0x85) + "b", "a\\x85b"],
    ],
  },
  {
    row: "RLO, LRI, ZWSP, ZWJ, BOM and SHY escape",
    cases: [
      ["a" + RLO + "b", "a\\u202eb"],
      ["a" + cp(0x2066) + "b", "a\\u2066b"],
      ["a" + ZWSP + "b", "a\\u200bb"],
      ["a" + cp(0x200d) + "b", "a\\u200db"],
      ["a" + cp(0xfeff) + "b", "a\\ufeffb"],
      ["a" + cp(0x00ad) + "b", "a\\xadb"],
    ],
  },
  {
    row: "LS U+2028 and PS U+2029 escape",
    cases: [
      ["a" + cp(0x2028) + "b", "a\\u2028b"],
      ["a" + cp(0x2029) + "b", "a\\u2029b"],
    ],
  },
  {
    row: "the blank-rendering U+034F, U+17B4, U+17B5, U+180B-180F and U+2800 escape",
    cases: [
      ["a" + cp(0x034f) + "b", "a\\u034fb"],
      ["a" + cp(0x17b4) + "b", "a\\u17b4b"],
      ["a" + cp(0x17b5) + "b", "a\\u17b5b"],
      ["a" + cp(0x180b) + "b", "a\\u180bb"],
      ["a" + cp(0x180c) + "b", "a\\u180cb"],
      ["a" + cp(0x180d) + "b", "a\\u180db"],
      ["a" + cp(0x180e) + "b", "a\\u180eb"],
      ["a" + cp(0x180f) + "b", "a\\u180fb"],
      ["a" + cp(0x2800) + "b", "a\\u2800b"],
    ],
  },
  {
    row: "the Hangul fillers escape",
    cases: [
      ["a" + cp(0x115f) + "b", "a\\u115fb"],
      ["a" + cp(0x1160) + "b", "a\\u1160b"],
      ["a" + cp(0x3164) + "b", "a\\u3164b"],
      ["a" + cp(0xffa0) + "b", "a\\uffa0b"],
    ],
  },
  { row: "VS1 U+FE00 after a letter escapes", cases: [["a" + cp(0xfe00) + "b", "a\\ufe00b"]] },
  {
    row: "VS1 U+FE00 after a pictograph escapes",
    cases: [[HEART + cp(0xfe00) + "b", HEART + "\\ufe00b"]],
  },
  {
    row: "VS16 U+FE0F after a pictograph prints as itself",
    cases: [
      [HEART + cp(0xfe0f) + "b", HEART + cp(0xfe0f) + "b"],
      [HEART + cp(0xfe0e) + "b", HEART + cp(0xfe0e) + "b"],
      ["a" + cp(0xfe0f) + "b", "a\\ufe0fb"],
    ],
  },
  {
    row: "U+E0100 after a pictograph escapes",
    cases: [[HEART + cp(0xe0100) + "b", HEART + "\\u{e0100}b"]],
  },
  { row: "TAG A U+E0041 escapes", cases: [["a" + cp(0xe0041) + "b", "a\\u{e0041}b"]] },
  {
    row: "unassigned plane 14 escapes",
    cases: [
      ["a" + cp(0xe0000) + "b", "a\\u{e0000}b"],
      ["a" + cp(0xe01f0) + "b", "a\\u{e01f0}b"],
      ["a" + cp(0xe0200) + "b", "a\\u{e0200}b"],
    ],
  },
  {
    row: "NBSP, Cyrillic a and a literal backslash-n print as themselves",
    cases: [
      ["a" + cp(0x00a0) + "b", "a" + cp(0x00a0) + "b"],
      ["a" + cp(0x0430) + "b", "a" + cp(0x0430) + "b"],
      ["a\\nb", "a\\nb"],
    ],
  },
];

describe("escapeForDisplay, one probe row at a time", () => {
  for (const { row, cases } of PROBE_ROWS) {
    it(row, () => {
      for (const [input, render] of cases) {
        expect(escapeForDisplay(input)).toBe(render);
        expect(hasDisplayHazard(input)).toBe(input !== render);
      }
    });
  }
});

describe("hasDisplayHazard", () => {
  it("answers the same on every call", () => {
    const text = "a" + ESC + "b";
    expect(hasDisplayHazard(text)).toBe(true);
    expect(hasDisplayHazard(text)).toBe(true);
    escapeForDisplay(text);
    expect(hasDisplayHazard(text)).toBe(true);
    expect(hasDisplayHazard("plain.txt")).toBe(false);
  });
});

describe("escapePathForDisplay", () => {
  it("doubles a backslash only where it could be read as an escape", () => {
    expect(escapePathForDisplay("a\\b.txt", "/")).toBe("a\\b.txt");
    expect(escapePathForDisplay("dir\\nx", "/")).toBe("dir\\\\nx");
    expect(escapePathForDisplay("dir" + LF + "x", "/")).toBe("dir\\nx");
    expect(escapePathForDisplay("dir\\\\x", "/")).toBe("dir\\\\\\\\x");
    expect(escapePathForDisplay("dir\\", "/")).toBe("dir\\");
    expect(escapePathForDisplay("a\\" + ESC, "/")).toBe("a\\\\\\e");
  });

  it("prints a Windows separator as / and keeps a POSIX backslash", () => {
    expect(escapePathForDisplay("src\\new.ts", "\\")).toBe("src/new.ts");
    expect(escapePathForDisplay("n\\x.txt", "/")).toBe("n\\\\x.txt");
  });

  it("keeps the pictograph exemption on a bare name", () => {
    const name = HEART + cp(0xfe0f) + ".txt";
    expect(escapePathForDisplay(name, "/")).toBe(name);
    expect(escapePathForDisplay(HEART + "\\" + cp(0xfe0f), "/")).toBe(
      HEART + "\\\\\\ufe0f",
    );
  });
});

describe("quotePathForDisplay", () => {
  it("quotes an escaped name as one word", () => {
    expect(quotePathForDisplay(".a" + ESC + ": test directory", "/")).toBe(
      "$'.a\\e: test directory'",
    );
    expect(quotePathForDisplay("it's\\" + ESC, "/")).toBe("$'it\\'s\\\\\\e'");
    expect(quotePathForDisplay("dir\\x" + LF, "\\")).toBe("$'dir/x\\n'");
  });
});

describe("excerptLinesForDisplay", () => {
  it("splits on line breaks and escapes what is left on each line", () => {
    const excerpt = "one" + CR + LF + "two" + CR + ESC + "[1A" + LF + "three" + cp(0x2800);
    expect(excerptLinesForDisplay(excerpt)).toEqual([
      "one",
      "two\\r\\e[1A",
      "three\\u2800",
    ]);
  });
});

describe("escapeJsonDisplayHazards", () => {
  it("escapes the class inside a JSON document and keeps it parseable", () => {
    const value = {
      path: "a" + RLO + "b" + cp(0x2028) + cp(0x7f) + cp(0x2800) + cp(0xe0041) + LF,
    };
    const json = escapeJsonDisplayHazards(JSON.stringify(value, null, 2));
    expect(JSON.parse(json)).toEqual(value);
    expect(json).toContain("a\\u202eb\\u2028\\u007f\\u2800\\udb40\\udc41\\n");
    // The document's own indentation newlines are structure and stay.
    expect(json.split(LF)).toHaveLength(3);
    expect(hasDisplayHazard(json.split(LF).join(""))).toBe(false);
  });
});

describe("sanitizeForTerminal is still the prose sanitizer", () => {
  it("strips the escape sequence and keeps the line feed", () => {
    expect(sanitizeForTerminal(HOSTILE_NAME)).toBe(
      "report" + RLO + "gnp.elif" + ZWSP + "name" + LF + "x",
    );
  });
});

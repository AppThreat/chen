#!/usr/bin/env python3
"""Regenerate the identifier character classes of pythonGrammar.jj from CPython itself.

Usage (run with the newest CPython whose identifiers the grammar should accept):

    python3.15 scripts/gen_identifier_classes.py pythonGrammar.jj

CPython's tokenizer accepts an identifier when its first character is XID_Start or '_' and
every further character is XID_Continue (``_PyUnicode_ScanIdentifier``), using its own
``unicodedata`` (Unicode 17.0.0 in 3.15); the parser then NFKC-normalises it. ``str.isidentifier``
applies exactly that check, so it is the oracle used here. The grammar lexes UTF-16 code units:
Basic Multilingual Plane code points are emitted as character ranges, supplementary ones (e.g.
U+1D400 MATHEMATICAL BOLD CAPITAL A, CJK Extension B) as high-surrogate/low-surrogate sequences,
consecutive high surrogates that share their low-surrogate ranges folded into one alternative.

The script rewrites the block between the BEGIN/END GENERATED IDENTIFIER CLASSES markers in
place and leaves the rest of the grammar untouched.
"""
import sys
import unicodedata

BEGIN = "// BEGIN GENERATED IDENTIFIER CLASSES"
END = "// END GENERATED IDENTIFIER CLASSES"


def ranges(predicate, lo=0, hi=0x10000):
    out, start, prev = [], None, None
    for cp in range(lo, hi):
        if 0xD800 <= cp <= 0xDFFF or not predicate(cp):
            if start is not None:
                out.append((start, prev))
                start = None
            continue
        if start is None:
            start = cp
        prev = cp
    if start is not None:
        out.append((start, prev))
    return out


def describe(lo, hi, partial=False):
    """Categories and first..last names; `partial` spans also contain non-identifier gaps."""
    if partial:
        first = unicodedata.name(chr(lo), f"U+{lo:04X}")
        last = unicodedata.name(chr(hi), f"U+{hi:04X}")
        return f"U+{lo:04X}..U+{hi:04X} {first}..{last}" if lo != hi else f"U+{lo:04X} {first}"
    cats = sorted({unicodedata.category(chr(c)) for c in range(lo, hi + 1)})
    cat = "/".join(cats) if len(cats) <= 3 else "/".join(cats[:3]) + "/.."
    first = unicodedata.name(chr(lo), f"U+{lo:04X}")
    if lo == hi:
        return f"{cat:<8} {first}"
    last = unicodedata.name(chr(hi), f"U+{hi:04X}")
    return f"{cat:<8} [{hi - lo + 1}] {first}..{last}"


def u(cp):
    return f'"\\u{cp:04X}"'


def char_range(lo, hi):
    return u(lo) if lo == hi else f"{u(lo)} - {u(hi)}"


def surrogate_groups(rs):
    """Supplementary ranges as UTF-16 sequences: [(first_high, last_high, [(lo_low, hi_low)])],
    consecutive high surrogates with identical low-surrogate ranges folded together, plus the
    code point span each group covers (for the comment)."""
    by_high = {}
    for lo, hi in rs:
        for cp_lo, cp_hi in split_by_high(lo, hi):
            high = 0xD800 + ((cp_lo - 0x10000) >> 10)
            by_high.setdefault(high, []).append(
                (0xDC00 + ((cp_lo - 0x10000) & 0x3FF), 0xDC00 + ((cp_hi - 0x10000) & 0x3FF), cp_lo, cp_hi))
    groups = []
    for high in sorted(by_high):
        lows = [(a, b) for a, b, _, _ in by_high[high]]
        span = (by_high[high][0][2], by_high[high][-1][3])
        if groups and groups[-1][1] == high - 1 and groups[-1][2] == lows:
            first, _, _, (span_lo, _) = groups[-1]
            groups[-1] = (first, high, lows, (span_lo, span[1]))
        else:
            groups.append((high, high, lows, span))
    return groups


def split_by_high(lo, hi):
    """Split a supplementary range at 1024-code-point (one high surrogate) boundaries."""
    while lo <= hi:
        block_end = lo | 0x3FF
        yield lo, min(hi, block_end)
        lo = block_end + 1


def klass(name, rs, supplementary):
    """`| <#NAME: item // comment` followed by one `| item` line per further range."""
    head = f"| <#{name}: "
    pad = " " * (len(head) - 2)
    items = [(char_range(lo, hi) if lo == hi else f"[{char_range(lo, hi)}]", describe(lo, hi))
             for lo, hi in rs]
    for first, last, lows, (span_lo, span_hi) in surrogate_groups(supplementary):
        high = f"[{char_range(first, last)}]"
        low = "[" + ", ".join(char_range(a, b) for a, b in lows) + "]"
        items.append((f"{high} {low}", describe(span_lo, span_hi, partial=True)))
    lines = []
    for i, (item, comment) in enumerate(items):
        lead = head if i == 0 else pad + "| "
        lines.append(f"{lead}{item} // {comment}")
    lines.append(pad + ">")
    return lines


def main():
    path = sys.argv[1]
    is_start = lambda c: chr(c) == "_" or chr(c).isidentifier()
    is_continue = lambda c: ("a" + chr(c)).isidentifier()
    start = ranges(is_start)
    start_sup = ranges(is_start, 0x10000, 0x110000)
    # ID_CONTINUE is emitted as <ID_START> | <ID_CONTINUE_ONLY> to keep the table compact.
    cont_only_pred = lambda c: is_continue(c) and not is_start(c)
    cont_only = ranges(cont_only_pred)
    cont_only_sup = ranges(cont_only_pred, 0x10000, 0x110000)
    version = sys.version.split()[0]
    body = [
        BEGIN,
        f"// Generated by scripts/gen_identifier_classes.py with CPython {version}",
        f"// (unicodedata {unicodedata.unidata_version}): ID_START = XID_Start | '_',",
        "// ID_CONTINUE = XID_Continue; supplementary code points as UTF-16 surrogate pairs.",
        "// Do not edit by hand.",
        "TOKEN: {",
        "  <NAME: <ID_START> (<ID_CONTINUE>)*>",
        *klass("ID_START", start, start_sup),
        *klass("ID_CONTINUE_ONLY", cont_only, cont_only_sup),
        "| <#ID_CONTINUE: <ID_START> | <ID_CONTINUE_ONLY> >",
        "}",
        END,
    ]
    src = open(path, encoding="utf-8").read()
    if BEGIN not in src or END not in src:
        raise SystemExit(f"markers not found in {path}")
    head, rest = src.split(BEGIN, 1)
    _, tail = rest.split(END, 1)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(head + "\n".join(body) + tail)
    print(f"{path}: ID_START {len(start)}+{len(start_sup)} ranges, ID_CONTINUE_ONLY "
          f"{len(cont_only)}+{len(cont_only_sup)} ranges (BMP+supplementary; CPython {version}, "
          f"Unicode {unicodedata.unidata_version})")


if __name__ == "__main__":
    main()

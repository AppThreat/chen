# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# Python 3.15 (gh-145239): unary plus is accepted in match literal patterns, mirroring unary
# minus - in signed numbers, the real part of complex literals, and mapping-pattern keys.
# Oracle: CPython 3.15.0 - `case +1:` -> MatchValue(UnaryOp(UAdd, Constant(1))).


def classify(x):
    match x:
        case +1:
            return "plus one"
        case -1:
            return "minus one"
        case +1.5:
            return "plus float"
        case +0j:
            return "plus imaginary"
        case +1 + 2j:
            return "plus complex"
        case +1.5 - 2j:
            return "plus complex minus"
        case -1 - 2j:
            return "minus complex"
        case +1 | -1 | +2:
            return "or of signed"
        case [+1, -1, +2.5]:
            return "sequence of signed"
        case {+1: a, -2: b}:
            return ("mapping keys", a, b)
        case (+3):
            return "group"
        case int(real=+4):
            return "keyword pattern"
        case +5 as five:
            return five
        case _:
            return None

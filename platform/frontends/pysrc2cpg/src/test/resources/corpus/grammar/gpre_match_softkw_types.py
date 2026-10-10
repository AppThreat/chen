# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# Pattern-matching and soft-keyword edge cases. Found in CPython's Lib/test:
#   case [*x, 2]:       chen rejected ANY pattern after a star pattern (test_patma.py)
#   match: str | None   chen took an annotated variable named `match` for a match statement
#                       (test_regrtest.py)
#   type X[T: int] = .. chen's type-statement detector stopped at the bound's ':'
#                       (test_type_aliases.py, test_type_params.py)
# Oracle: CPython 3.15.0
import re


def patterns(subject):
    match subject:
        case [*head, 2]:
            return head
        case [1, *middle, 9]:
            return middle
        case (*init, last):
            return init, last
        case [*_, "end"]:
            return "ends"
        case [first, *_]:
            return first
        case {"k": [*items], **rest}:
            return items, rest
        case {**rest}:
            return rest
        case str() | bytes():
            return "text"
        case (1 | 2) as small:
            return small
        case -1j | 1 - 2j:
            return "complex"
        case re.I:
            return "value pattern"
        case _ if subject:
            return "guarded"


def open_sequence(pair):
    match pair:
        case *a, b:
            return a, b


def subjects(x, y, z):
    match x, y:
        case _:
            pass
    match *z, x:
        case _:
            pass
    match (x):
        case _:
            pass
    match [x, y]:
        case _:
            pass
    match -x:
        case _:
            pass
    match x if y else z:
        case _:
            pass
    match x := y:
        case _:
            pass


# Soft keywords as ordinary names in every position.
match: str | None = None
match = re.match(r"a", "a")
match.group(0)
match = lambda match: match
match, case = 1, 2
match.bit_length() if isinstance(match, int) else None
case: int = 3
case = {"match": match, "case": case}
type: type = type
_ = type(case)
print(match, case, type, _)


def match(match=None, *, case=None, type=None):
    return match, case, type


class case:
    match = 1
    type = 2
    _ = 3


# Type aliases whose type parameters carry bounds / constraints / defaults (PEP 695/696).
type Bounded[T: int] = list[T]
type Constrained[T: (int, str)] = set[T]
type WithDefault[T: (int, str) = int] = T
type Comprehended[T: ([T for T in (T, [1])[1]], T)] = [T for T in T.__name__]
type Lambdas[T: [lambda: T for T in (T, [1])[1]]] = [lambda: T for T in T.__name__]
type Spec[**P = [int, str]] = P

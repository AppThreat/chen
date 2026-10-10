# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# Named expressions in the positions the 3.10+ grammar allows them (subscripts, set displays)
# and f-string forms that chen mis-lexed. Found in CPython's Lib/test:
#   a[b:=0]                       test_named_expressions.py
#   f'\N{GREEK CAPITAL LETTER DELTA}'  test_fstring.py (\N{...} is an escape, not a field)
#   f'{x:=10}'                    test_fstring.py (`:=` at the top of a field is ':' + spec '=10')
# Oracle: CPython 3.15.0
import re

a = [10, 20, 30]
s = "abc"

e1 = a[b := 0]
e2 = a[b:=0]
e3 = {(c := 1), 2}
e4 = {c := 1, 2}
e5 = {d := 1}
e6 = [y := 1, y ** 2]
e7 = print(z := 1)
e8 = a[(i := 0):2]
if (m := re.match("a", s)) is not None:
    print(m)
while (n := len(a)) > 5:
    break
filtered = [y for x in a if (y := x)]


def with_default(v=(w := 1)):
    return v, w


delta = f'\N{GREEK CAPITAL LETTER DELTA}'
two_delta = f'{2}\N{GREEK CAPITAL LETTER DELTA}{3}'
braces = f'\N{LEFT CURLY BRACKET}1+1\N{RIGHT CURLY BRACKET}'
bullet = t'\N{BULLET} {s}'
raw_n = rf'\N{s}'  # raw: \N is literal text and {s} IS a replacement field
x = 10
spec_equals = f'{x:=10}'
spec_equals_conv = f'{x!r:=^10}'
walrus_in_parens = f'{(x := 20)}'
nested_quotes = f"{"a" + 'b'}"
nested_f = f"{f"{x}"}"
debug = f"{x=}"
debug_spec = f"{x=!r:>10}"
spec_nested = f"{x:{'>'}{10}}"
multiline = f"""{
    x
    + 1  # comment inside a replacement field (3.12+)
}"""
backslash = f"{'\n'.join(s)}"
starred_tuple = f"{*a,}"

# Tab indentation: a tab advances to the next multiple of 8 columns. chen computed
# `indent / 8 + 8`, so two and three tabs were both column 9 and the third level never
# produced an INDENT (found in pygoat's views.py/forms.py).
def tabs(v):
	if v:
		if v > 1:
			if v > 2:
				return 3
			return 2
		return 1
	return 0

# Form feed (^L) is whitespace; at the start of a line it resets the indentation count.


def after_form_feed():
    return 1
x =1  # a form feed between tokens is skipped

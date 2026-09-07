# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN  # Slice/Starred/yield lower to real operators now

import numpy as np
m = np.zeros((3,3)) @ np.ones((3,3))
sl = m[1:2, ::2, ..., None]
c = {k: v for k, v in zip("ab", [1,2]) if k != "z"}
s = {i for i in range(3)}
gen = (i*2 for i in range(3))
nested = [[y for y in row] for row in m]
a, (b, *rest) = 1, (2, 3, 4)
del a, b
assert m is not None, "msg"
global_var = ...
b1 = 0b1010_1010; h = 0xDEAD_BEEF; fl = 1_000.5e-3; im = 3j
bs = rb"raw\bytes"; u = u"unicode"
concat = "a" "b" f"c{m}"

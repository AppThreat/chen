# CHEN-EXPECT: no-parse-errors

from typing import Optional
def f(a, b, /, c, d, *, e, g=1, **kw): return a
if (n := len([1,2,3])) > 2: print(n)
async def agen():
    yield 1
x: Optional[int] = None
print(f"{x!r:>10}")

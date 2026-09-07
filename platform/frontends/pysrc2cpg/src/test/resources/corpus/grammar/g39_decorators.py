# CHEN-EXPECT: no-parse-errors

d = {"a":1} | {"b":2}
d |= {"c": 3}
button = lambda x: x
@button
def foo(): ...
class C:
    @property
    def p(self): return 1
    @p.setter
    def p(self, v): self._v = v

# CHEN-EXPECT: no-parse-errors

import re
def probe(obj, s):
    a = re.match(r"x", s)
    b = obj.match(return_rule=True)
    c = obj.type
    d = obj.type()
    match = 5
    type = "shadow"
    print(match, type)
    e = {"match": 1, "type": 2}
    return a, b, c, d, e
class C:
    def match(self, x): return x
    def type(self): return 1

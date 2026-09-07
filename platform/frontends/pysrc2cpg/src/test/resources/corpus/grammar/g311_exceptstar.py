# CHEN-EXPECT: no-parse-errors

from typing import Self, LiteralString
try:
    pass
except* ValueError as eg:
    print(eg.exceptions)
except* (TypeError, KeyError) as eg2:
    raise
class B:
    def clone(self) -> Self: return self
def tv[T](x: T) -> T: return x

# CHEN-EXPECT: no-parse-errors

type ListOrSet[T = int] = list[T] | set[T]
def fn[T = str](x: T = "a") -> T: return x
class K[T = int]: ...

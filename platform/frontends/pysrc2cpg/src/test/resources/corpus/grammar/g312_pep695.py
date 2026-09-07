# CHEN-EXPECT: no-parse-errors

type Alias[T] = list[T]
type Point = tuple[float, float]
def first[T](xs: list[T]) -> T: return xs[0]
class Container[T, *Ts, **P]:
    def get(self) -> T: ...
name = "w"
s = f"{f'{name}'} {'nested "quotes"'} {name!s:{'>'}{10}}"

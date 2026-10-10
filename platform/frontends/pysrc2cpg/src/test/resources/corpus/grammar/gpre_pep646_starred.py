# CHEN-EXPECT: no-parse-errors
# CHEN-EXPECT: node-absent UNKNOWN
# PEP 646 (3.11) / PEP 696 (3.13) starred forms. Found in CPython's own Lib/test (typing,
# genericalias, type_aliases, annotationlib) - every statement here was a chen parse error.
# Oracle: CPython 3.15.0
#   a[*b]            -> Subscript(a, Tuple([Starred(b)]))
#   def f(*a: *Ts)   -> arg(annotation=Starred(Ts))
#   class C[*Ts = *tuple[int]] -> TypeVarTuple(default_value=Starred(...))
from typing import Callable, Generic, TypeVarTuple, Unpack

Ts = TypeVarTuple("Ts")
a = {(): 0, (1,): 1, (1, 2): 2}
b = (1,)

x1 = a[*b]
x2 = a[*b, *b]
x3 = a[1, *b]
x4 = tuple[*Ts]
x5 = tuple[int, *Ts, str]
x6 = tuple[*tuple[int, ...]]
x7 = Callable[[*Ts], None]
x8 = dict[str, tuple[*Ts]]


class Array(Generic[*Ts]):
    def shape(self) -> tuple[*Ts]: ...


class Mixed[T, *Shape, **P]:
    pass


def star_annotation(*args: *Ts) -> None: ...


def star_annotation_tuple(*args: *tuple[int, ...]) -> None: ...


def unpack_kwargs(**kwargs: Unpack[dict]) -> None: ...


def generic[*Ts2](*args: *Ts2) -> tuple[*Ts2]:
    return args


class Defaults[*Ts3 = *tuple[int, str]]:
    pass


type Variadic[*Ts4] = tuple[*Ts4]
type VariadicDefault[*Ts5 = *tuple[int]] = tuple[*Ts5]
y: tuple[*Ts]
z: tuple[int, *tuple[str, ...]] = (1, "a")

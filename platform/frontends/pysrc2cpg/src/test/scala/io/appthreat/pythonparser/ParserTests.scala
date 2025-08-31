package io.appthreat.pythonparser
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers
class ParserTests extends AnyFreeSpec with Matchers {
    // code is parsed and the resulting AST is printed and compared against code.
    // expected is optional and if present the printed AST is compare against it
    // instead of code.
    def test(code: String, expected: String, indentStr: String): Unit = {
        val ast       = new PyParser().parse(code)
        val compareTo = if (expected != null) expected else code
        val astPrinter = new AstPrinter(indentStr)
        astPrinter.print(ast) shouldBe compareTo
    }
    def testS(code: String, expected: String = null): Unit = {
        test(code, expected, "  ")
    }
    def testT(code: String, expected: String = null): Unit = {
        test(code, expected, "\t")
    }
    "statements" - {
        "return statement tests" in {
            testT("return")
            testT("return x")
            testT("return x, y", "return (x,y)")
            testT("return *x")
            testT("return *x, *y", "return (*x,*y)")
        }
        "import statement tests" in {
            testT("import x")
            testT("import x, y")
            testT("import x.y")
            testT("import x.y, z.a")
            testT("import x as y")
            testT("import x as y, z as a")
            testT("import x.y as z")
            testT("from . import x")
            testT("from .. import x")
            testT("from ... import x")
            testT("from .... import x")
            testT("from x import y")
            testT("from . x import y")
            testT("from x import y, z")
            testT("from x import (y, z)", "from x import y, z")
            testT("from x import (y, z,)", "from x import y, z")
            testT("from x import y as z")
            testT("from x import (y as z, a as b)", "from x import y as z, a as b")
        }
        "raise statement tests" in {
            testT("raise")
            testT("raise x")
            testT("raise x from y")
            // Python2 style raise syntax.
            testT("raise x, y")
            testT("raise x, y, z")
        }
        "pass statement tests" in {
            testT("pass")
        }
        "del statement tests" in {
            testT("del x")
            testT("del x,", "del x")
            testT("del x, y")
            testT("del x, y,", "del x, y")
            testT("del x.y")
            testT("del x().y")
        }
        "yield statement tests" in {
            testT("yield")
            testT("yield x")
            testT("yield x, y", "yield (x,y)")
            testT("yield from x")
        }
        "assert statement tests" in {
            testT("assert x")
            testT("assert x, y")
        }
        "break statement tests" in {
            testT("break")
        }
        "continue statement tests" in {
            testT("continue")
        }
        "global statement tests" in {
            testT("global x")
            testT("global x, y")
        }
        "nonlocal statement tests" in {
            testT("nonlocal x")
            testT("nonlocal x, y")
        }
        "function def statement tests" in {
            testT("def func():\n\tpass")
            testT("def func(x):\n\tpass")
            testT("def func(x,):\n\tpass", s"def func(x):\n\tpass")
            testT("def func(x = 1):\n\tpass")
            testT("def func(x = 1,):\n\tpass", s"def func(x = 1):\n\tpass")
            testT("def func(x, y):\n\tpass")
            testT("def func(x, y = 2):\n\tpass")
            testT("def func(x = 1, y = 2):\n\tpass")
            testT("def func(x, y,):\n\tpass", s"def func(x, y):\n\tpass")
            testT("def func(x, /, y):\n\tpass")
            testT("def func(x, /):\n\tpass")
            testT("def func(x, /,):\n\tpass", s"def func(x, /):\n\tpass")
            testT("def func(x, *y):\n\tpass")
            testT("def func(x, *y, z):\n\tpass")
            testT("def func(x, *y, z, **a):\n\tpass")
            testT("def func(x, *y, **z):\n\tpass")
            testT("def func(x, **y):\n\tpass")
            testT("def func(*x):\n\tpass")
            testT("def func(*x,):\n\tpass", s"def func(*x):\n\tpass")
            testT("def func(*x, y):\n\tpass")
            testT("def func(*x, y, ):\n\tpass", s"def func(*x, y):\n\tpass")
            testT("def func(*x, y = 1):\n\tpass")
            testT("def func(*x, y, z):\n\tpass")
            testT("def func(*x, y = 1, z = 2):\n\tpass")
            testT("def func(*x, y = 1, z):\n\tpass")
            testT("def func(*x, y, z = 2):\n\tpass")
            testT("def func(*x, y, **z):\n\tpass")
            testT("def func(*x, **z):\n\tpass")
            testT("def func(*, x):\n\tpass")
            testT("def func(*, x, ):\n\tpass", s"def func(*, x):\n\tpass")
            testT("def func(*, x, **y):\n\tpass")
            testT("def func(**x):\n\tpass")
            testT("def func(**x, ):\n\tpass", s"def func(**x):\n\tpass")
            testT("def func(x: y):\n\tpass")
            testT("def func(x: y = z):\n\tpass")
            testT("def func() -> x:\n\tpass")
            testT("@x\ndef func():\n\tpass")
            testT("@x\n@y\ndef func():\n\tpass")
            testT("async def func():\n\tpass")
            testT("@x\nasync def func():\n\tpass")
        }
        "if statement tests" in {
            testT("if x: y;", s"if x:\n\ty")
            testT("if x:\n\ty")
            testT("if x:\n\ty\nelse:\n\tz")
            testT("if x:\n\ty\nelif z:\n\ta")
        }
        "class def statement tests" in {
            testT("class x:\n\tpass", s"class x():\n\tpass")
            testT("class x():\n\tpass")
            testT("class x(y):\n\tpass")
            testT("class x(y, z):\n\tpass")
            testT("class x(y = z):\n\tpass")
            testT("class x(y, z = a):\n\tpass")
            testT("@x\nclass y():\n\tpass")
            testT("@x\n@y\nclass z():\n\tpass")
        }
        "try statement tests" in {
            testS("""try:
                    |  x
                    |except:
                    |  y""".stripMargin)
            testS("""try:
                    |  x
                    |except e:
                    |  y""".stripMargin)
            testS("""try:
                    |  x
                    |except e as f:
                    |  y""".stripMargin)
            testS("""try:
                    |  x
                    |except e as f:
                    |  y
                    |except g as h:
                    |  z""".stripMargin)
            testS("""try:
                    |  x
                    |finally:
                    |  y""".stripMargin)
            testS("""try:
                    |  x
                    |except e as f:
                    |  y
                    |else:
                    |  z
                    |finally:
                    |  a""".stripMargin)
            // Python2 style COMMA syntax.
            testS(
                """try:
                  |  x
                  |except e, f:
                  |  y""".stripMargin,
                """try:
                  |  x
                  |except e as f:
                  |  y""".stripMargin
            )
        }
        "try* statement tests" in {
            testS("""try*:
                    |  x
                    |except*:
                    |  y""".stripMargin)
            testS("""try*:
                    |  x
                    |except* e:
                    |  y""".stripMargin)
            testS("""try*:
                    |  x
                    |except* e as f:
                    |  y""".stripMargin)
            testS("""try*:
                    |  x
                    |except* e as f:
                    |  y
                    |except* g as h:
                    |  z""".stripMargin)
            testS("""try*:
                    |  x
                    |finally:
                    |  y""".stripMargin)
            testS("""try*:
                    |  x
                    |except* e as f:
                    |  y
                    |else:
                    |  z
                    |finally:
                    |  a""".stripMargin)
        }
        "while statement tests" in {
            testT("while x: y;", s"while x:\n\ty")
            testT("while x:\n\ty")
            testT("while x:\n\twhile y:\n\t\tz")
            testT("while x:\n\ty\nelse:\n\tz")
        }
        "with statement tests" in {
            testT("with x:\n\tpass")
            testT("with x, :\n\tpass", s"with x:\n\tpass")
            testT("with x, y:\n\tpass")
            testT("with x, y, z:\n\tpass")
            testT("with (x):\n\tpass", s"with x:\n\tpass")
            testT("with (x,):\n\tpass", s"with x:\n\tpass")
            testT("with (x, y):\n\tpass", s"with x, y:\n\tpass")
            testT("with (x, y, z):\n\tpass", s"with x, y, z:\n\tpass")
            testT("with x + 1:\n\tpass")
            testT("with x + 1, y + 2:\n\tpass")
            testT("with (x + 1):\n\tpass", s"with x + 1:\n\tpass")
            testT("with (x + 1, y + 2):\n\tpass", s"with x + 1, y + 2:\n\tpass")
            testT("with x as y:\n\tpass")
            testT("with x as *y:\n\tpass")
            testT("with x as y, z:\n\tpass")
            testT("with x as y, z as a:\n\tpass")
            testT("with x as y, z as a,:\n\tpass", s"with x as y, z as a:\n\tpass")
        }
        "for statement tests" in {
            testT("for x in l:\n\tpass")
            testT("for x, in l:\n\tpass", s"for (x,) in l:\n\tpass")
            testT("for x, y in l:\n\tpass", s"for (x,y) in l:\n\tpass")
            testT("for x, y, in l:\n\tpass", s"for (x,y) in l:\n\tpass")
            testT("for *x in l:\n\tpass")
            testT("for x.y in l:\n\tpass")
            testT("for x in l,:\n\tpass", s"for x in (l,):\n\tpass")
            testT("for x in *l:\n\tpass")
            testT("for x in l.m:\n\tpass")
            testT("for x in l, m:\n\tpass", s"for x in (l,m):\n\tpass")
            testT("for x in l, m,:\n\tpass", s"for x in (l,m):\n\tpass")
            // TODO test with parenthesized target an iter
        }
        "assign statement tests" in {
            testT("x = 1")
            testT("x = y = 1")
            testT("x = y = z = 1")
            testT("x, = 1", "(x,) = 1")
            testT("x,y = 1", "(x,y) = 1")
            testT("*x = 1")
            testT("*x, *y = 1", "(*x,*y) = 1")
            testT("x = yield y")
            testT("x = y, z = 1", "x = (y,z) = 1")
        }
        "annotated assign statement tests" in {
            testT("x: y")
            testT("x: y = 1")
            testT("x: y = *z")
            testT("x: y = yield z")
            testT("x, y: z = 1", "(x,y): z = 1")
        }
        "augmented assign statement tests" in {
            testT("x += 1")
            testT("x += *y")
            testT("x += yield y")
            testT("x -= 1")
            testT("x *= 1")
            testT("x @= 1")
            testT("x /= 1")
            testT("x %= 1")
            testT("x &= 1")
            testT("x |= 1")
            testT("x ^= 1")
            testT("x <<= 1")
            testT("x >>= 1")
            testT("x **= 1")
            testT("x //= 1")
        }
    }
    "Python 3.10-3.12 Feature Tests" - {
        "Positional-only parameters with defaults" in {
            testT("def func(a, b=2, /, c=3):\n\tpass")
            testT("def func(a, b=2, /, c, d=4):\n\tpass")
        }

        "Parenthesized context managers" in {
            testT("with (x() as y):\n\tpass")
            testT("with (x() as y, z() as w):\n\tpass")
            testT("with (x() as y):\n\twith (z() as w):\n\t\tpass")
        }

        "Union types with | operator (PEP 604)" in {
            testT("def func(x: int | str):\n\tpass")
            testT("def func(x: int | str | float):\n\tpass")
            testT("x: int | str = 1")
        }

        "Lambda expressions with positional-only parameters" in {
            testT("lambda a, /: a")
            testT("lambda a, b, /, c: a + b + c")
            testT("lambda a, b=2, /, c=3: a + b + c")
        }

        "Match statement with class patterns" in {
            testS("""match point:
                    |  case Point(x=0, y=0):
                    |    print("Origin")
                    |  case Point(x=0):
                    |    print("On Y axis")
                    |  case Point(y=0):
                    |    print("On X axis")""".stripMargin)
        }

        "Match statement with mapping patterns" in {
            testS("""match value:
                    |  case {"key": x}:
                    |    print(x)
                    |  case {"key": x, **rest}:
                    |    print(x, rest)""".stripMargin)
        }

        "Match statement with OR patterns" in {
            testS("""match value:
                    |  case 1 | 2 | 3:
                    |    print("Small number")
                    |  case "a" | "b" | "c":
                    |    print("Small letter")""".stripMargin)
        }

        "Match statement with guards" in {
            testS("""match value:
                    |  case x if x > 0:
                    |    print("Positive")
                    |  case x if x < 0:
                    |    print("Negative")
                    |  case _:
                    |    print("Zero")""".stripMargin)
        }

        "Match statement with nested patterns" in {
            testS("""match value:
                    |  case [a, [b, c]]:
                    |    print(a, b, c)
                    |  case {"key": [d, e]}:
                    |    print(d, e)""".stripMargin)
        }

        "Exception groups and except* (PEP 654)" in {
            testS("""try*:
                    |  raise ExceptionGroup("group", [ValueError(1), TypeError(2)])
                    |except* ValueError as e:
                    |  print(f"Value errors: {e.exceptions}")
                    |except* TypeError as e:
                    |  print(f"Type errors: {e.exceptions}")""".stripMargin)
        }

        "ExceptionGroup builtin" in {
            testT("raise ExceptionGroup('errors', [ValueError(1), TypeError(2)])")
            testT("eg = ExceptionGroup('group', [ValueError(1), TypeError(2)])")
        }

        "TypeAlias statement (PEP 613)" in {
            testT("type Point = tuple[float, float]")
            testT("type Point = tuple[float, float]")
        }

        "Type parameter lists (PEP 695)" in {
            testT("def func[T](x: T) -> T: ...")
            testT("class Box[T]:\n  def __init__(self, value: T):\n    self.value = value")
            testT("type Alias[T] = list[T]")
        }

        "Generic type defaults (PEP 696)" in {
            testT("class Box[T = int]:\n  def __init__(self, value: T):\n    self.value = value")
            testT("def func[T: int = int](x: T) -> T: ...")
        }

        "f-string improvements" in {
            testT("f'{x=}'")
            testT("f'{x=!s}'")
            testT("f'{x=!r}'")
            testT("f'{x=!a}'")
            testT("f'{x=:10}'")
            testT("f'{x=!s:10}'")
            testT("f'{(x+y)=}'")
            testT("f'{(x+y)=!r}'")
        }

        "f-string self-documenting expressions" in {
            testT("f'{user=}'")
            testT("f'{count=}'")
            testT("f'{items=}'")
        }

        "f-string debug expressions" in {
            testT("f'{user=!r}'")
            testT("f'{count=!s}'")
            testT("f'{items=!a:10.2f}'")
        }

        "Parenthesized patterns in match statements" in {
            testS("""match value:
                    |  case (x, y):
                    |    print(x, y)
                    |  case (Point(x=0, y=0)):
                    |    print("Origin")""".stripMargin)
        }

        "Walrus operator in more contexts" in {
            testT("if (x := 5) > 3:\n\tprint(x)")
            testT("while (x := input()) != 'quit':\n\tprint(x)")
            testT("values = [y := 2 * x for x in range(5)]")
            testT("print(y)")
            testT("result = [x for x in range(10) if (y := x % 2) == 0]")
            testT("print(y)")
        }

        "Match statement with value constraints" in {
            testS("""match point:
                    |  case Point(x=x, y=y) if x == y:
                    |    print("On diagonal")
                    |  case Point(x=x, y=y) if x > y:
                    |    print("Above diagonal")
                    |  case Point(x=x, y=y) if x < y:
                    |    print("Below diagonal")""".stripMargin)
        }

        "Match statement with class pattern inheritance" in {
            testS("""match shape:
                    |  case Circle(radius=r):
                    |    print(f"Circle with radius {r}")
                    |  case Rectangle(width=w, height=h):
                    |    print(f"Rectangle with width {w} and height {h}")
                    |  case Square(side=s):
                    |    print(f"Square with side {s}")""".stripMargin)
        }

        "Match statement with sequence patterns" in {
            testS("""match value:
                    |  case [1, 2, *rest]:
                    |    print(f"Starts with 1, 2, rest: {rest}")
                    |  case [first, *middle, last]:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case []:
                    |    print("Empty list")""".stripMargin)
        }

        "Match statement with tuple patterns" in {
            testS("""match value:
                    |  case (1, 2):
                    |    print("Tuple (1, 2)")
                    |  case (x, y):
                    |    print(f"Tuple with values {x}, {y}")
                    |  case (x, y, z):
                    |    print(f"3-tuple with values {x}, {y}, {z}")""".stripMargin)
        }

        "Match statement with wildcard patterns" in {
            testS("""match value:
                    |  case {"key": _, "other": _}:
                    |    print("Has key and other")
                    |  case [_, _, _]:
                    |    print("List of length 3")
                    |  case _:
                    |    print("Anything else")""".stripMargin)
        }

        "Match statement with capture patterns" in {
            testS("""match value:
                    |  case {"key": x}:
                    |    print(f"Key value: {x}")
                    |  case [x, y, z]:
                    |    print(f"List values: {x}, {y}, {z}")
                    |  case x:
                    |    print(f"Single value: {x}")""".stripMargin)
        }

        "Match statement with as patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case x as val:
                    |    print(f"Value: {val}")""".stripMargin)
        }

        "Match statement with class patterns with positional args" in {
            testS("""match point:
                    |  case Point(0, 0):
                    |    print("Origin")
                    |  case Point(0, y):
                    |    print(f"On Y axis at {y}")
                    |  case Point(x, 0):
                    |    print(f"On X axis at {x}")
                    |  case Point(x, y):
                    |    print(f"At ({x}, {y})")""".stripMargin)
        }

        "Match statement with class patterns with mixed args" in {
            testS("""match point:
                    |  case Point(0, 0, color="red"):
                    |    print("Red origin")
                    |  case Point(x, y, color="blue"):
                    |    print(f"Blue point at ({x}, {y})")
                    |  case Point(x, y, color=c):
                    |    print(f"Point at ({x}, {y}) with color {c}")""".stripMargin)
        }

        "Match statement with sequence unpacking" in {
            testS("""match value:
                    |  case [1, *rest]:
                    |    print(f"Starts with 1, rest: {rest}")
                    |  case [first, *middle, last]:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case [*all_items]:
                    |    print(f"All items: {all_items}")""".stripMargin)
        }

        "Match statement with mapping unpacking" in {
            testS("""match value:
                    |  case {"key": val, **rest}:
                    |    print(f"Key: {val}, rest: {rest}")
                    |  case {"a": a, "b": b, **rest}:
                    |    print(f"a: {a}, b: {b}, rest: {rest}")
                    |  case {**all_items}:
                    |    print(f"All items: {all_items}")""".stripMargin)
        }

        "Match statement with nested patterns" in {
            testS("""match value:
                    |  case {"data": [x, y, {"key": z}]}:
                    |    print(f"x: {x}, y: {y}, z: {z}")
                    |  case [first, {"nested": [a, b]}]:
                    |    print(f"first: {first}, a: {a}, b: {b}")
                    |  case {"outer": {"inner": val}}:
                    |    print(f"Inner value: {val}")""".stripMargin)
        }

        "Match statement with complex guards" in {
            testS("""match value:
                    |  case x if isinstance(x, int) and x > 0:
                    |    print(f"Positive integer: {x}")
                    |  case x if isinstance(x, str) and len(x) > 5:
                    |    print(f"Long string: {x}")
                    |  case x if x in [1, 2, 3]:
                    |    print(f"Small number: {x}")""".stripMargin)
        }

        "Match statement with OR patterns and guards" in {
            testS("""match value:
                    |  case 1 | 2 | 3 if value > 0:
                    |    print("Small positive number")
                    |  case "a" | "b" | "c" if len(value) == 1:
                    |    print("Single letter")
                    |  case x if x in [1, 2, 3] or x in ["a", "b", "c"]:
                    |    print("Small value")""".stripMargin)
        }

        "Match statement with class patterns and inheritance" in {
            testS("""match shape:
                    |  case Circle(radius=r):
                    |    print(f"Circle with radius {r}")
                    |  case Rectangle(width=w, height=h):
                    |    print(f"Rectangle with width {w} and height {h}")
                    |  case Square(side=s):
                    |    print(f"Square with side {s}")
                    |  case Triangle(base=b, height=h):
                    |    print(f"Triangle with base {b} and height {h}")""".stripMargin)
        }

        "Match statement with sequence patterns and guards" in {
            testS("""match value:
                    |  case [x, y] if x == y:
                    |    print(f"Equal pair: {x}, {y}")
                    |  case [x, y] if x > y:
                    |    print(f"Descending pair: {x}, {y}")
                    |  case [x, y] if x < y:
                    |    print(f"Ascending pair: {x}, {y}")
                    |  case [x, y, z] if x + y == z:
                    |    print(f"Sum: {x} + {y} = {z}")""".stripMargin)
        }

        "Match statement with mapping patterns and guards" in {
            testS("""match value:
                    |  case {"x": x, "y": y} if x == y:
                    |    print(f"Equal coordinates: {x}, {y}")
                    |  case {"x": x, "y": y} if x > y:
                    |    print(f"X > Y: {x}, {y}")
                    |  case {"x": x, "y": y} if x < y:
                    |    print(f"X < Y: {x}, {y}")
                    |  case {"sum": s, "count": c} if s > 0 and c > 0:
                    |    print(f"Average: {s/c}")""".stripMargin)
        }

        "Match statement with nested OR patterns" in {
            testS("""match value:
                    |  case (1 | 2, 3 | 4):
                    |    print("Tuple with small numbers")
                    |  case {"key": 1 | 2 | 3}:
                    |    print("Dict with small key value")
                    |  case [1 | 2, 3 | 4, 5 | 6]:
                    |    print("List with small numbers")""".stripMargin)
        }

        "Match statement with nested AS patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst if len(lst) == 2:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct if "key" in dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case (x, y) as point if x > 0 and y > 0:
                    |    print(f"Point in first quadrant: {point}")""".stripMargin)
        }

        "Match statement with complex nested patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x}, {"value": y}], "meta": {"count": c}} if c > 0:
                    |    print(f"x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0:
                    |    print(f"first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None:
                    |    print(f"Deep value: {v}")""".stripMargin)
        }

        "Match statement with sequence patterns and star patterns" in {
            testS("""match value:
                    |  case [1, *rest, 10]:
                    |    print(f"Starts with 1, ends with 10, middle: {rest}")
                    |  case [first, *middle, last] if len(middle) > 0:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case [*, x, *] if x == 5:
                    |    print(f"Contains 5: {x}")
                    |  case [x, *] if x == 0:
                    |    print(f"Starts with 0: {x}")""".stripMargin)
        }

        "Match statement with mapping patterns and star patterns" in {
            testS("""match value:
                    |  case {"required": val, **rest} if len(rest) > 0:
                    |    print(f"Required: {val}, rest: {rest}")
                    |  case {"a": a, "b": b, **rest} if len(rest) == 0:
                    |    print(f"Only a and b: {a}, {b}")
                    |  case {**all} if "key" in all:
                    |    print(f"Contains key: {all}")
                    |  case {"key": val, **} if val > 0:
                    |    print(f"Positive key value: {val}")""".stripMargin)
        }

        "Match statement with class patterns and star patterns" in {
            testS("""match value:
                    |  case Point(0, 0, *args):
                    |    print(f"Origin with args: {args}")
                    |  case Point(x, y, *args) if len(args) > 0:
                    |    print(f"Point with args: {x}, {y}, {args}")
                    |  case Point(*args) if len(args) == 2:
                    |    print(f"2D point: {args}")
                    |  case Point(*args) if len(args) == 3:
                    |    print(f"3D point: {args}")""".stripMargin)
        }

        "Match statement with mixed pattern types" in {
            testS("""match value:
                    |  case {"data": [Point(x, y), {"info": z}], "meta": m} if m["valid"]:
                    |    print(f"Point: ({x}, {y}), info: {z}")
                    |  case [first, {"nested": Point(x, y)}, *rest] if x > 0 and y > 0:
                    |    print(f"First: {first}, point: ({x}, {y}), rest: {rest}")
                    |  case {"outer": [Point(x, y) as point, *rest]} if x == y:
                    |    print(f"Diagonal point: {point}, rest: {rest}")""".stripMargin)
        }

        "Match statement with complex OR patterns" in {
            testS("""match value:
                    |  case 1 | 2 | 3 | 4 | 5:
                    |    print("Small number")
                    |  case "a" | "b" | "c" | "d" | "e":
                    |    print("Small letter")
                    |  case True | False:
                    |    print("Boolean")
                    |  case None | []:
                    |    print("Empty value")
                    |  case Point(0, 0) | Point(1, 1):
                    |    print("Special point")""".stripMargin)
        }

        "Match statement with complex AS patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst if len(lst) == 2:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct if "key" in dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case (x, y) as point if x > 0 and y > 0:
                    |    print(f"Point in first quadrant: {point}")
                    |  case Point(x, y) as p if x == y:
                    |    print(f"Diagonal point: {p}")
                    |  case {"data": [x, y]} as d if x + y > 10:
                    |    print(f"Data dict with sum > 10: {d}")""".stripMargin)
        }

        "Match statement with complex guards" in {
            testS("""match value:
                    |  case x if isinstance(x, int) and x > 0 and x < 100:
                    |    print(f"Small positive integer: {x}")
                    |  case x if isinstance(x, str) and len(x) > 5 and x.startswith("a"):
                    |    print(f"Long string starting with 'a': {x}")
                    |  case x if x in [1, 2, 3] or x in ["a", "b", "c"]:
                    |    print(f"Small value: {x}")
                    |  case x if hasattr(x, "value") and x.value > 0:
                    |    print(f"Object with positive value: {x.value}")
                    |  case x if callable(x):
                    |    print(f"Callable: {x}")""".stripMargin)
        }

        "Match statement with nested patterns and guards" in {
            testS("""match value:
                    |  case {"data": [{"key": x}, {"value": y}], "meta": {"count": c}} if c > 0 and x + y > 10:
                    |    print(f"x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0 and a + b == d:
                    |    print(f"first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None and v > 0:
                    |    print(f"Deep positive value: {v}")
                    |  case [Point(x, y), Point(z, w)] if x == z and y == w:
                    |    print(f"Equal points: ({x}, {y}) and ({z}, {w})")""".stripMargin)
        }

        "Match statement with complex mixed patterns" in {
            testS("""match value:
                    |  case {"data": [Point(x, y), {"info": z}], "meta": m} if m["valid"] and x > 0 and y > 0:
                    |    print(f"Point: ({x}, {y}), info: {z}")
                    |  case [first, {"nested": Point(x, y)}, *rest] if x > 0 and y > 0 and len(rest) > 0:
                    |    print(f"First: {first}, point: ({x}, {y}), rest: {rest}")
                    |  case {"outer": [Point(x, y) as point, *rest]} if x == y and len(rest) > 0:
                    |    print(f"Diagonal point: {point}, rest: {rest}")
                    |  case {"data": [{"key": k, "value": v} for k, v in zip(["a", "b"], [1, 2])], "meta": m} if m["valid"]:
                    |    print(f"Complex data structure")""".stripMargin)
        }

        "Match statement with very complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x, "value": y} for x, y in zip(range(3), range(3, 6))], "meta": {"count": c}} if c > 0 and sum(range(3, 6)) > 10:
                    |    print(f"Complex data structure with x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0 and a + b == d and len(rest) > 0:
                    |    print(f"Nested structure with first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None and v > 0 and isinstance(v, int):
                    |    print(f"Deep nested positive integer: {v}")
                    |  case [Point(x, y) as p1, Point(z, w) as p2, *rest] if x == z and y == w and len(rest) > 0:
                    |    print(f"Equal points: {p1}, {p2}, rest: {rest}")""".stripMargin)
        }

        "Match statement with exception handling" in {
            testS("""match result:
                    |  case {"status": "success", "data": data}:
                    |    print(f"Success: {data}")
                    |  case {"status": "error", "error": {"code": 404}}:
                    |    print("Not found")
                    |  case {"status": "error", "error": {"code": 500}}:
                    |    print("Server error")
                    |  case {"status": "error", "error": e}:
                    |    print(f"Other error: {e}")
                    |  case _:
                    |    print("Unknown result")""".stripMargin)
        }

        "Match statement with type patterns" in {
            testS("""match value:
                    |  case int():
                    |    print("Integer")
                    |  case str():
                    |    print("String")
                    |  case list():
                    |    print("List")
                    |  case dict():
                    |    print("Dictionary")
                    |  case _:
                    |    print("Other type")""".stripMargin)
        }

        "Match statement with value patterns" in {
            testS("""match value:
                    |  case 0:
                    |    print("Zero")
                    |  case 1:
                    |    print("One")
                    |  case "":
                    |    print("Empty string")
                    |  case []:
                    |    print("Empty list")
                    |  case {}:
                    |    print("Empty dict")
                    |  case None:
                    |    print("None")
                    |  case True:
                    |    print("True")
                    |  case False:
                    |    print("False")""".stripMargin)
        }

        "Match statement with sequence patterns" in {
            testS("""match value:
                    |  case []:
                    |    print("Empty list")
                    |  case [x]:
                    |    print(f"Single element: {x}")
                    |  case [x, y]:
                    |    print(f"Two elements: {x}, {y}")
                    |  case [x, y, z]:
                    |    print(f"Three elements: {x}, {y}, {z}")
                    |  case [x, y, *rest]:
                    |    print(f"At least two elements: {x}, {y}, rest: {rest}")
                    |  case [*all]:
                    |    print(f"All elements: {all}")""".stripMargin)
        }

        "Match statement with mapping patterns" in {
            testS("""match value:
                    |  case {}:
                    |    print("Empty dict")
                    |  case {"key": x}:
                    |    print(f"Single key: {x}")
                    |  case {"key1": x, "key2": y}:
                    |    print(f"Two keys: {x}, {y}")
                    |  case {"key": x, **rest}:
                    |    print(f"Key and rest: {x}, {rest}")
                    |  case {**all}:
                    |    print(f"All keys: {all}")""".stripMargin)
        }

        "Match statement with class patterns" in {
            testS("""match value:
                    |  case Point():
                    |    print("Any point")
                    |  case Point(x=0, y=0):
                    |    print("Origin")
                    |  case Point(x=0):
                    |    print("On Y axis")
                    |  case Point(y=0):
                    |    print("On X axis")
                    |  case Point(x=x, y=y):
                    |    print(f"Point at ({x}, {y})")""".stripMargin)
        }

        "Match statement with OR patterns" in {
            testS("""match value:
                    |  case 1 | 2 | 3:
                    |    print("Small number")
                    |  case "a" | "b" | "c":
                    |    print("Small letter")
                    |  case True | False:
                    |    print("Boolean")
                    |  case None | []:
                    |    print("Empty value")
                    |  case Point(0, 0) | Point(1, 1):
                    |    print("Special point")""".stripMargin)
        }

        "Match statement with AS patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case (x, y) as point:
                    |    print(f"Point: {point}")
                    |  case Point(x, y) as p:
                    |    print(f"Point object: {p}")
                    |  case x as val:
                    |    print(f"Value: {val}")""".stripMargin)
        }

        "Match statement with guards" in {
            testS("""match value:
                    |  case x if x > 0:
                    |    print(f"Positive: {x}")
                    |  case x if x < 0:
                    |    print(f"Negative: {x}")
                    |  case x if x == 0:
                    |    print("Zero")
                    |  case x if isinstance(x, str):
                    |    print(f"String: {x}")
                    |  case x if isinstance(x, int):
                    |    print(f"Integer: {x}")""".stripMargin)
        }

        "Match statement with nested patterns" in {
            testS("""match value:
                    |  case {"data": [x, y]}:
                    |    print(f"Data: {x}, {y}")
                    |  case [first, {"nested": [a, b]}]:
                    |    print(f"First: {first}, nested: {a}, {b}")
                    |  case {"outer": {"inner": val}}:
                    |    print(f"Inner value: {val}")
                    |  case [Point(x, y), Point(z, w)]:
                    |    print(f"Points: ({x}, {y}), ({z}, {w})")""".stripMargin)
        }

        "Match statement with star patterns" in {
            testS("""match value:
                    |  case [1, *rest, 10]:
                    |    print(f"Starts with 1, ends with 10, middle: {rest}")
                    |  case [first, *middle, last]:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case {"key": val, **rest}:
                    |    print(f"Key: {val}, rest: {rest}")
                    |  case Point(0, 0, *args):
                    |    print(f"Origin with args: {args}")
                    |  case Point(*args):
                    |    print(f"Point with args: {args}")""".stripMargin)
        }

        "Match statement with complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x}, {"value": y}], "meta": {"count": c}} if c > 0:
                    |    print(f"x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0:
                    |    print(f"first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None:
                    |    print(f"Deep value: {v}")
                    |  case [Point(x, y), Point(z, w)] if x == z and y == w:
                    |    print(f"Equal points: ({x}, {y}) and ({z}, {w})")""".stripMargin)
        }

        "Match statement with very complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x, "value": y} for x, y in zip(range(3), range(3, 6))], "meta": {"count": c}} if c > 0:
                    |    print(f"Complex data structure with x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0 and a + b == d:
                    |    print(f"Nested structure with first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None and v > 0:
                    |    print(f"Deep nested positive value: {v}")
                    |  case [Point(x, y) as p1, Point(z, w) as p2, *rest] if x == z and y == w:
                    |    print(f"Equal points: {p1}, {p2}, rest: {rest}")""".stripMargin)
        }

        "Match statement with exception handling patterns" in {
            testS("""match result:
                    |  case {"status": "success", "data": data}:
                    |    print(f"Success: {data}")
                    |  case {"status": "error", "error": {"code": 404}}:
                    |    print("Not found")
                    |  case {"status": "error", "error": {"code": 500}}:
                    |    print("Server error")
                    |  case {"status": "error", "error": e}:
                    |    print(f"Other error: {e}")
                    |  case _:
                    |    print("Unknown result")""".stripMargin)
        }

        "Match statement with type patterns" in {
            testS("""match value:
                    |  case int():
                    |    print("Integer")
                    |  case str():
                    |    print("String")
                    |  case list():
                    |    print("List")
                    |  case dict():
                    |    print("Dictionary")
                    |  case _:
                    |    print("Other type")""".stripMargin)
        }

        "Match statement with value patterns" in {
            testS("""match value:
                    |  case 0:
                    |    print("Zero")
                    |  case 1:
                    |    print("One")
                    |  case "":
                    |    print("Empty string")
                    |  case []:
                    |    print("Empty list")
                    |  case {}:
                    |    print("Empty dict")
                    |  case None:
                    |    print("None")
                    |  case True:
                    |    print("True")
                    |  case False:
                    |    print("False")""".stripMargin)
        }

        "Match statement with sequence patterns" in {
            testS("""match value:
                    |  case []:
                    |    print("Empty list")
                    |  case [x]:
                    |    print(f"Single element: {x}")
                    |  case [x, y]:
                    |    print(f"Two elements: {x}, {y}")
                    |  case [x, y, z]:
                    |    print(f"Three elements: {x}, {y}, {z}")
                    |  case [x, y, *rest]:
                    |    print(f"At least two elements: {x}, {y}, rest: {rest}")
                    |  case [*all]:
                    |    print(f"All elements: {all}")""".stripMargin)
        }

        "Match statement with mapping patterns" in {
            testS("""match value:
                    |  case {}:
                    |    print("Empty dict")
                    |  case {"key": x}:
                    |    print(f"Single key: {x}")
                    |  case {"key1": x, "key2": y}:
                    |    print(f"Two keys: {x}, {y}")
                    |  case {"key": x, **rest}:
                    |    print(f"Key and rest: {x}, {rest}")
                    |  case {**all}:
                    |    print(f"All keys: {all}")""".stripMargin)
        }

        "Match statement with class patterns" in {
            testS("""match value:
                    |  case Point():
                    |    print("Any point")
                    |  case Point(x=0, y=0):
                    |    print("Origin")
                    |  case Point(x=0):
                    |    print("On Y axis")
                    |  case Point(y=0):
                    |    print("On X axis")
                    |  case Point(x=x, y=y):
                    |    print(f"Point at ({x}, {y})")""".stripMargin)
        }

        "Match statement with OR patterns" in {
            testS("""match value:
                    |  case 1 | 2 | 3:
                    |    print("Small number")
                    |  case "a" | "b" | "c":
                    |    print("Small letter")
                    |  case True | False:
                    |    print("Boolean")
                    |  case None | []:
                    |    print("Empty value")
                    |  case Point(0, 0) | Point(1, 1):
                    |    print("Special point")""".stripMargin)
        }

        "Match statement with AS patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case (x, y) as point:
                    |    print(f"Point: {point}")
                    |  case Point(x, y) as p:
                    |    print(f"Point object: {p}")
                    |  case x as val:
                    |    print(f"Value: {val}")""".stripMargin)
        }

        "Match statement with guards" in {
            testS("""match value:
                    |  case x if x > 0:
                    |    print(f"Positive: {x}")
                    |  case x if x < 0:
                    |    print(f"Negative: {x}")
                    |  case x if x == 0:
                    |    print("Zero")
                    |  case x if isinstance(x, str):
                    |    print(f"String: {x}")
                    |  case x if isinstance(x, int):
                    |    print(f"Integer: {x}")""".stripMargin)
        }

        "Match statement with nested patterns" in {
            testS("""match value:
                    |  case {"data": [x, y]}:
                    |    print(f"Data: {x}, {y}")
                    |  case [first, {"nested": [a, b]}]:
                    |    print(f"First: {first}, nested: {a}, {b}")
                    |  case {"outer": {"inner": val}}:
                    |    print(f"Inner value: {val}")
                    |  case [Point(x, y), Point(z, w)]:
                    |    print(f"Points: ({x}, {y}), ({z}, {w})")""".stripMargin)
        }

        "Match statement with star patterns" in {
            testS("""match value:
                    |  case [1, *rest, 10]:
                    |    print(f"Starts with 1, ends with 10, middle: {rest}")
                    |  case [first, *middle, last]:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case {"key": val, **rest}:
                    |    print(f"Key: {val}, rest: {rest}")
                    |  case Point(0, 0, *args):
                    |    print(f"Origin with args: {args}")
                    |  case Point(*args):
                    |    print(f"Point with args: {args}")""".stripMargin)
        }

        "Match statement with complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x}, {"value": y}], "meta": {"count": c}} if c > 0:
                    |    print(f"x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0:
                    |    print(f"first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None:
                    |    print(f"Deep value: {v}")
                    |  case [Point(x, y), Point(z, w)] if x == z and y == w:
                    |    print(f"Equal points: ({x}, {y}) and ({z}, {w})")""".stripMargin)
        }

        "Match statement with very complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x, "value": y} for x, y in zip(range(3), range(3, 6))], "meta": {"count": c}} if c > 0:
                    |    print(f"Complex data structure with x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0 and a + b == d:
                    |    print(f"Nested structure with first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None and v > 0:
                    |    print(f"Deep nested positive value: {v}")
                    |  case [Point(x, y) as p1, Point(z, w) as p2, *rest] if x == z and y == w:
                    |    print(f"Equal points: {p1}, {p2}, rest: {rest}")""".stripMargin)
        }

        "Match statement with exception handling patterns" in {
            testS("""match result:
                    |  case {"status": "success", "data": data}:
                    |    print(f"Success: {data}")
                    |  case {"status": "error", "error": {"code": 404}}:
                    |    print("Not found")
                    |  case {"status": "error", "error": {"code": 500}}:
                    |    print("Server error")
                    |  case {"status": "error", "error": e}:
                    |    print(f"Other error: {e}")
                    |  case _:
                    |    print("Unknown result")""".stripMargin)
        }

        "Match statement with type patterns" in {
            testS("""match value:
                    |  case int():
                    |    print("Integer")
                    |  case str():
                    |    print("String")
                    |  case list():
                    |    print("List")
                    |  case dict():
                    |    print("Dictionary")
                    |  case _:
                    |    print("Other type")""".stripMargin)
        }

        "Match statement with value patterns" in {
            testS("""match value:
                    |  case 0:
                    |    print("Zero")
                    |  case 1:
                    |    print("One")
                    |  case "":
                    |    print("Empty string")
                    |  case []:
                    |    print("Empty list")
                    |  case {}:
                    |    print("Empty dict")
                    |  case None:
                    |    print("None")
                    |  case True:
                    |    print("True")
                    |  case False:
                    |    print("False")""".stripMargin)
        }

        "Match statement with sequence patterns" in {
            testS("""match value:
                    |  case []:
                    |    print("Empty list")
                    |  case [x]:
                    |    print(f"Single element: {x}")
                    |  case [x, y]:
                    |    print(f"Two elements: {x}, {y}")
                    |  case [x, y, z]:
                    |    print(f"Three elements: {x}, {y}, {z}")
                    |  case [x, y, *rest]:
                    |    print(f"At least two elements: {x}, {y}, rest: {rest}")
                    |  case [*all]:
                    |    print(f"All elements: {all}")""".stripMargin)
        }

        "Match statement with mapping patterns" in {
            testS("""match value:
                    |  case {}:
                    |    print("Empty dict")
                    |  case {"key": x}:
                    |    print(f"Single key: {x}")
                    |  case {"key1": x, "key2": y}:
                    |    print(f"Two keys: {x}, {y}")
                    |  case {"key": x, **rest}:
                    |    print(f"Key and rest: {x}, {rest}")
                    |  case {**all}:
                    |    print(f"All keys: {all}")""".stripMargin)
        }

        "Match statement with class patterns" in {
            testS("""match value:
                    |  case Point():
                    |    print("Any point")
                    |  case Point(x=0, y=0):
                    |    print("Origin")
                    |  case Point(x=0):
                    |    print("On Y axis")
                    |  case Point(y=0):
                    |    print("On X axis")
                    |  case Point(x=x, y=y):
                    |    print(f"Point at ({x}, {y})")""".stripMargin)
        }

        "Match statement with OR patterns" in {
            testS("""match value:
                    |  case 1 | 2 | 3:
                    |    print("Small number")
                    |  case "a" | "b" | "c":
                    |    print("Small letter")
                    |  case True | False:
                    |    print("Boolean")
                    |  case None | []:
                    |    print("Empty value")
                    |  case Point(0, 0) | Point(1, 1):
                    |    print("Special point")""".stripMargin)
        }

        "Match statement with AS patterns" in {
            testS("""match value:
                    |  case [1, 2] as lst:
                    |    print(f"List: {lst}")
                    |  case {"key": val} as dct:
                    |    print(f"Dict: {dct} with value: {val}")
                    |  case (x, y) as point:
                    |    print(f"Point: {point}")
                    |  case Point(x, y) as p:
                    |    print(f"Point object: {p}")
                    |  case x as val:
                    |    print(f"Value: {val}")""".stripMargin)
        }

        "Match statement with guards" in {
            testS("""match value:
                    |  case x if x > 0:
                    |    print(f"Positive: {x}")
                    |  case x if x < 0:
                    |    print(f"Negative: {x}")
                    |  case x if x == 0:
                    |    print("Zero")
                    |  case x if isinstance(x, str):
                    |    print(f"String: {x}")
                    |  case x if isinstance(x, int):
                    |    print(f"Integer: {x}")""".stripMargin)
        }

        "Match statement with nested patterns" in {
            testS("""match value:
                    |  case {"data": [x, y]}:
                    |    print(f"Data: {x}, {y}")
                    |  case [first, {"nested": [a, b]}]:
                    |    print(f"First: {first}, nested: {a}, {b}")
                    |  case {"outer": {"inner": val}}:
                    |    print(f"Inner value: {val}")
                    |  case [Point(x, y), Point(z, w)]:
                    |    print(f"Points: ({x}, {y}), ({z}, {w})")""".stripMargin)
        }

        "Match statement with star patterns" in {
            testS("""match value:
                    |  case [1, *rest, 10]:
                    |    print(f"Starts with 1, ends with 10, middle: {rest}")
                    |  case [first, *middle, last]:
                    |    print(f"First: {first}, middle: {middle}, last: {last}")
                    |  case {"key": val, **rest}:
                    |    print(f"Key: {val}, rest: {rest}")
                    |  case Point(0, 0, *args):
                    |    print(f"Origin with args: {args}")
                    |  case Point(*args):
                    |    print(f"Point with args: {args}")""".stripMargin)
        }

        "Match statement with complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x}, {"value": y}], "meta": {"count": c}} if c > 0:
                    |    print(f"x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0:
                    |    print(f"first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None:
                    |    print(f"Deep value: {v}")
                    |  case [Point(x, y), Point(z, w)] if x == z and y == w:
                    |    print(f"Equal points: ({x}, {y}) and ({z}, {w})")""".stripMargin)
        }

        "Match statement with very complex patterns" in {
            testS("""match value:
                    |  case {"data": [{"key": x, "value": y} for x, y in zip(range(3), range(3, 6))], "meta": {"count": c}} if c > 0:
                    |    print(f"Complex data structure with x: {x}, y: {y}, count: {c}")
                    |  case [first, {"nested": [a, b, {"deep": d}]}, *rest] if d > 0 and a + b == d:
                    |    print(f"Nested structure with first: {first}, a: {a}, b: {b}, d: {d}, rest: {rest}")
                    |  case {"outer": {"inner": {"deep": {"value": v}}}} if v is not None and v > 0:
                    |    print(f"Deep nested positive value: {v}")
                    |  case [Point(x, y) as p1, Point(z, w) as p2, *rest] if x == z and y == w:
                    |    print(f"Equal points: {p1}, {p2}, rest: {rest}")""".stripMargin)
        }

        "Match statement with exception handling patterns" in {
            testS("""match result:
                    |  case {"status": "success", "data": data}:
                    |    print(f"Success: {data}")
                    |  case {"status": "error", "error": {"code": 404}}:
                    |    print("Not found")
                    |  case {"status": "error", "error": {"code": 500}}:
                    |    print("Server error")
                    |  case {"status": "error", "error": e}:
                    |    print(f"Other error: {e}")
                    |  case _:
                    |    print("Unknown result")""".stripMargin)
        }
    }
    "error recovery tests" in {
        testT("<someErr>", "<error>")
        testT("x;<someErr>", s"x\n<error>")
        testT("x;<someErr>;", s"x\n<error>")
        testT("<someErr>;x", s"<error>\nx")
        testT("<someErr>;x;", s"<error>\nx")
        testT("x;<someErr>;y", s"x\n<error>\ny")
        testT("x;<someErr>;y;<someErr>", s"x\n<error>\ny\n<error>")
        testT("x\n<someErr>", s"x\n<error>")
        testT("<someErr>\nx", s"<error>\nx")
        testT("x\n<someErr>\ny", s"x\n<error>\ny")
        testT("x\n<someErr>\ny\n<someErr>", s"x\n<error>\ny\n<error>")
        testT("print x = y", "<error>")
    }
    "parser tests" in {
        testT("x,y = z", "(x,y) = z")
        testT("x if y else z")
        testT("x or y")
        testT("x and y")
        testT("x and y or z")
    }
    "comment tests" in {
        testT("#comment", "")
        testT("x#comment", "x")
        testT("x#comment\ny", s"x\ny")
        testT("x#comment\ny#comment\nz", s"x\ny\nz")
        testT("x\n#comment", "x")
        testT("x\n  #comment", "x")
        testT("x\n  #comment\ny", s"x\ny")
        testT("#\u2265", "")
    }
    "indentation tests" in {
        testS("""if True:
                |  x
                |  if True:
                |    y
                |z""".stripMargin)
        testT("if True:\n\t x\n \t y", s"if True:\n\tx\n\ty")
        testS(
            """if True:
              |  z = (x
              |,y)
              |a""".stripMargin,
            """if True:
              |  z = (x,y)
              |a""".stripMargin
        )
    }
    "explicit line joining tests" in {
        testS(
            """if True:
              |  z = x + \
              |y
              |  a""".stripMargin,
            """if True:
              |  z = x + y
              |  a""".stripMargin
        )
    }
    "implicit line joining tests" in {
        testS(
            """if True:
              |  z = (x
              |,y)
              |  a""".stripMargin,
            """if True:
              |  z = (x,y)
              |  a""".stripMargin
        )
        testS(
            """if True:
              |  z = {x
              |,y}
              |  a""".stripMargin,
            """if True:
              |  z = {x, y}
              |  a""".stripMargin
        )
        testS(
            """if True:
              |  z = [x
              |,y]
              |  a""".stripMargin,
            """if True:
              |  z = [x, y]
              |  a""".stripMargin
        )
        testS(
            """if True:
              |  z = [(x
              |,y)
              |   ]
              |  a""".stripMargin,
            """if True:
              |  z = [(x,y)]
              |  a""".stripMargin
        )
    }
    "blank line tests" in {
        testS(
            """if True:
              |  z = x + y
              |
              |  a""".stripMargin,
            """if True:
              |  z = x + y
              |  a""".stripMargin
        )
    }
    "multi character new line tests" in {
        testT("if True:\n\r\tx", s"if True:\n\tx")
        testT("if True:\r\n\tx", s"if True:\n\tx")
        testT("if True:\n\n\r\tx", s"if True:\n\tx")
        testT("if True:\n\r\n\tx", s"if True:\n\tx")
        testT("if True:\n\t(x,\n\ry)", s"if True:\n\t(x,y)")
        testT("if True:\n\t(x,\r\ny)", s"if True:\n\t(x,y)")
    }
    "inversion rule tests" in {
        testT("not x")
        testT("not not x")
    }
    "comparison rule tests" in {
        testT("x == y")
        testT("x != y")
        testT("x < y")
        testT("x <= y")
        testT("x > y")
        testT("x >= y")
        testT("x is y")
        testT("x is not y")
        testT("x in y")
        testT("x not in y")
    }
    "bitwiseOr rule tests" in {
        testT("x | y")
        testT("x | y | z")
    }
    "bitwiseXor rule tests" in {
        testT("x ^ y")
        testT("x ^ y ^ z")
    }
    "bitwiseAnd rule tests" in {
        testT("x & y")
        testT("x & y & z")
    }
    "shiftExpr rule tests" in {
        testT("x << y")
        testT("x >> y")
        testT("x << y << z")
        testT("x >> y >> z")
    }
    "sum rule tests" in {
        testT("x + y")
        testT("x - y")
        testT("x + y + z")
        testT("x - y - z")
    }
    "term rule tests" in {
        testT("x * y")
        testT("x / y")
        testT("x // y")
        testT("x % y")
        testT("x @ y")
        testT("x * y / z")
    }
    "factor rule tests" in {
        testT("+x")
        testT("-x")
        testT("~x")
        testT("+-x")
    }
    "power rule tests" in {
        testT("x ** y")
        testT("x ** -y")
    }
    "await primary rule tests" in {
        testT("await x")
    }
    "primary rule tests" in {
        testT("x.y")
        testT("x.y.z")
        testT("func(x)")
        testT("func(x, y)")
        testT("func(*x)")
        testT("func(*x, *y)")
        testT("func(x, *y)")
        testT("func(*x, y)")
        testT("func(x := y)")
        testT("func(x := y, z)")
        testT("func(x, y := z)")
        testT("func(x,)", "func(x)")
        testT("func(x = y)")
        testT("func(x = y, z = a)")
        testT("func(**x)")
        testT("func(**x, **y)")
        testT("func(x, y = z, **a)")
        testT("func(x for x in y)")
        testT("obj[x]")
        testT("obj[x, y]", "obj[(x,y)]")
        testT("obj[:]")
        testT("obj[::]", "obj[:]")
        testT("obj[x::]", "obj[x:]")
        testT("obj[:y:]", "obj[:y]")
        testT("obj[::z]")
        testT("obj[x:y:]", "obj[x:y]")
        testT("obj[:y:z]")
        testT("obj[x:y:z]")
        testT("obj[x,y]", "obj[(x,y)]")
        testT("obj[x,]", "obj[(x,)]")
    }
    "atom rule tests" in {
        testT("x")
        testT("True")
        testT("False")
        testT("None")
        testT("123")
        testT("...")
    }
    "lambda rule tests" in {
        testT("lambda: e")
        testT("lambda x: e")
        testT("lambda x,: e", "lambda x: e")
        testT("lambda x = 1: e")
        testT("lambda x = 1,: e", "lambda x = 1: e")
        testT("lambda x, y: e")
        testT("lambda x, y = 2: e")
        testT("lambda x = 1, y = 2: e")
        testT("lambda x, y,: e", "lambda x, y: e")
        testT("lambda x, /, y: e")
        testT("lambda x, /: e")
        testT("lambda x, /,: e", "lambda x, /: e")
        testT("lambda x, *y: e")
        testT("lambda x, *y, z: e")
        testT("lambda x, *y, z, **a: e")
        testT("lambda x, *y, **z: e")
        testT("lambda x, **y: e")
        testT("lambda *x: e")
        testT("lambda *x,: e", "lambda *x: e")
        testT("lambda *x, y: e")
        testT("lambda *x, y, : e", "lambda *x, y: e")
        testT("lambda *x, y = 1: e")
        testT("lambda *x, y, z: e")
        testT("lambda *x, y = 1, z = 2: e")
        testT("lambda *x, y = 1, z: e")
        testT("lambda *x, y, z = 2: e")
        testT("lambda *x, y, **z: e")
        testT("lambda *x, **z: e")
        testT("lambda *, x: e")
        testT("lambda *, x, : e", "lambda *, x: e")
        testT("lambda *, x, **y: e")
        testT("lambda **x: e")
        testT("lambda **x, : e", "lambda **x: e")
    }
    "listOrListComprehension rule tests" in {
        testT("[]")
        testT("[x]")
        testT("[x, y]")
        testT("[x, y, z]")
        testT("[x for x in y]")
        testT("[x for x in y if z]")
        testT("[x for x in y if z if a]")
        testT("[x for x in y if z if a if b]")
        testT("[x for x in y if z if a if b]")
        testT("[x for x in y for y in z]")
        testT("[x for x in y if z for y in a]")
    }
    "tupleOrGeneratorExpOrGroup rule tests" in {
        testT("()")
        testT("(x,)")
        testT("(x,y)")
        testT("(x,y,)", "(x,y)")
        testT("(x :=y )", "x := y")
        testT("(*x)", "*x")
        testT("(yield x)", "yield x")
        testT("(x for x in y)")
        testT("(x for x in y if z)")
        testT("(x for x in y for y in z)")
    }
    "setOrDictOrSetCompOrDictComp rule tests" in {
        testT("{}")
        testT("{x}")
        testT("{x,}", "{x}")
        testT("{x, y}")
        testT("{x, y,}", "{x, y}")
        testT("{x, y, z}")
        testT("{x for x in y}")
        testT("{x for x in y if z}")
        testT("{x for x in y for y in z}")
        testT("{x:1}")
        testT("{x:1,}", "{x:1}")
        testT("{x:1, y:2}")
        testT("{x:1, y:2,}", "{x:1, y:2}")
        testT("{**x}")
        testT("{**x, **y}")
        testT("{**x, y:1}")
        testT("{**x, y:1, **z}")
        testT("{**x, y:1, **z, a:2}")
        testT("{x:1, **y, z:2, **a}")
        testT("{x:1, **y}")
        testT("{x:1, **y, z:2}")
        testT("{x:1, **y, z:2, **a}")
        testT("{x:1, **y, z:2, **a}")
        testT("{x:y for (x,y) in z}")
        testT("{x:y for x,y in z}", "{x:y for (x,y) in z}")
    }
    "string literal tests" in {
        testT("\"abc\"")
        testT("r\"abc\"")
        testT("u\"abc\"")
        testT("b\"abc\"")
        testT("rb\"abc\"")
        testT("'abc'")
        testT("r'abc'")
        testT("u'abc'")
        testT("b'abc'")
        testT("rb'abc'")
        testT("\"\"\"abc\"\"\"")
        testT("r\"\"\"abc\"\"\"")
        testT("u\"\"\"abc\"\"\"")
        testT("b\"\"\"abc\"\"\"")
        testT("rb\"\"\"abc\"\"\"")
        testT("'''abc'''")
        testT("r'''abc'''")
        testT("u'''abc'''")
        testT("b'''abc'''")
        testT("rb'''abc'''")
        testT("'abc' 'def' \"ghi\"")
    }
    "format string tests" in {
        testT("f\"{x}\"")
        testT("f\"{x,}\"", "f\"{(x,)}\"")
        testT("f\"{*x}\"")
        testT("f\"{yield x}\"")
        testT("f\"{x}{y}\"")
        testT("f\"pre{x}post\"")
        testT("f\"pre{x}mid{y}post\"")
        testT("f\"{{x}}\"")
        testT("f\"\\{x}\"")
        testT("f\"{x=}\"")
        testT("f\"{x!s}\"")
        testT("f\"{x!r}\"")
        testT("f\"{x!a}\"")
        testT("f\"{x=!s}\"")
        testT("f\"{x:1}\"")
        testT("f\"{x:{y}}\"")
        testT("f\"{x:{y}{z}}\"")
        testT("f\"{x=:1}\"")
        testT("f\"{x=!s:1}\"")
        testT("rf\"{x=!s:1}\"")
        testT("f\"a\"")
        testT("f'{a}'")
        testT("f'a'")
        testT("f\"\"\"{a}\"\"\"")
        testT("f\"\"\"a\"\"\"")
        testT("f'''{a}'''")
        testT("f'''a'''")
    }
    "format string tests with context" in {
        testS("""func(f"x: {y}")""".stripMargin)
    }
    // Check that an escaped string terminal character does not break
    // tokenization.
    "string literal terminal escape tests" in {
        testT("\"\\\"\"")
        testT("'\\''")
        testT("\"\"\"\\\"\"\"\"")
        testT("'''\\''''")
    }
    "string literal escape tests" in {
        testT("\"\\\\\"")
        testT("'\\\\'")
        testT("\"\"\"\\\\\"\"\"")
        testT("'''\\\\'''")
        testT("'\\ufoo'")
    }
    "integer literal tests" in {
        testT("000")
        testT("01")
        testT("1")
        testT("0b1")
        testT("0B1")
        testT("0b1_1")
        testT("0o1")
        testT("0O1")
        testT("0o1_1")
        testT("0x1")
        testT("0X1")
        testT("0x1_1")
    }
    "float literal tests" in {
        testT("1.")
        testT("1.1")
        testT("1.1e1")
        testT(".1")
        testT(".1e1")
        testT("1e1")
        testT("1e+1")
        testT("1e-1")
    }
    "imaginary literal tests" in {
        testT("1j")
        testT("1_1j")
        testT("1.j")
        testT("1.1j")
        testT("1.1e1j")
        testT(".1j")
        testT(".1e1j")
        testT("1e1j")
        testT("1e+1j")
        testT("1e-1j")
    }
    "empty input test" in {
        testT("")
    }
    "python2 print statement tests" in {
        testT("print x", "print(x)")
        testT("print x; print y", s"print(x)\nprint(y)")
        testT("print x\nprint y", s"print(x)\nprint(y)")
        testT("valid1;print x;valid2", s"valid1\nprint(x)\nvalid2")
        testT("valid1\nprint x;valid2", s"valid1\nprint(x)\nvalid2")
        testT("valid1\nprint x\nvalid2", s"valid1\nprint(x)\nvalid2")
        testT("valid1;print x\nvalid2", s"valid1\nprint(x)\nvalid2")
    }
    // These print statements are valid in python2 and python3
    // but have different semantics in the respective versions.
    // We favor the python2 interpretation.
    "ambigious print statement tests" in {
        testT("print (x), y", "print(x, y)")
        testT("print (x, y), z", "print(x, y, z)")
        testT("print (x, y), z, a", "print(x, y, z, a)")
    }
    "python2 exec statement tests" in {
        testT("exec x", "exec(x)")
        testT("exec x in y", "exec(x, y)")
        testT("exec x in y, z", "exec(x, y, z)")
        testT("exec x; pass", s"exec(x)\npass")
        testT("exec x;\npass", s"exec(x)\npass")
    }
    "pattern matching subject tests" in {
        testS("""match x:
                |  case _:
                |    pass""".stripMargin)
        testS(
            """match x,:
              |  case _:
              |    pass""".stripMargin,
            """match (x,):
              |  case _:
              |    pass""".stripMargin
        )
        testS(
            """match x,y,z:
              |  case _:
              |    pass""".stripMargin,
            """match (x,y,z):
              |  case _:
              |    pass""".stripMargin
        )
        testS(
            """match x,y,z,:
              |  case _:
              |    pass""".stripMargin,
            """match (x,y,z):
              |  case _:
              |    pass""".stripMargin
        )
        testS(
            """match *x,:
              |  case _:
              |    pass""".stripMargin,
            """match (*x,):
              |  case _:
              |    pass""".stripMargin
        )
        testS(
            """match *x,y:
              |  case _:
              |    pass""".stripMargin,
            """match (*x,y):
              |  case _:
              |    pass""".stripMargin
        )
        testS(
            """match x,*y:
              |  case _:
              |    pass""".stripMargin,
            """match (x,*y):
              |  case _:
              |    pass""".stripMargin
        )
        testS("""match a := b:
                |  case _:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - literal" in {
        testS("""match x:
                |  case 1:
                |    pass""".stripMargin)
        testS("""match x:
                |  case -1:
                |    pass""".stripMargin)
        testS("""match x:
                |  case 1.0 + 1j:
                |    pass""".stripMargin)
        testS("""match x:
                |  case 1.0 - 1j:
                |    pass""".stripMargin)
        testS("""match x:
                |  case 'abc':
                |    pass""".stripMargin)
        testS("""match x:
                |  case 'abc' 'def':
                |    pass""".stripMargin)
        testS("""match x:
                |  case None:
                |    pass""".stripMargin)
        testS("""match x:
                |  case True:
                |    pass""".stripMargin)
        testS("""match x:
                |  case False:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - capture" in {
        testS("""match x:
                |  case y:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - wildcard" in {
        testS("""match x:
                |  case _:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - value" in {
        testS("""match x:
                |  case a.b:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - group" in {
        testS(
            """match x:
              |  case (a):
              |    pass""".stripMargin,
            """match x:
              |  case a:
              |    pass""".stripMargin
        )
    }
    "pattern matching case tests - sequence" in {
        testS(
            """match x:
              |  case a,:
              |    pass""".stripMargin,
            """match x:
              |  case [a]:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case a, b:
              |    pass""".stripMargin,
            """match x:
              |  case [a, b]:
              |    pass""".stripMargin
        )
        testS("""match x:
                |  case []:
                |    pass""".stripMargin)
        testS("""match x:
                |  case [a]:
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case [a,]:
              |    pass""".stripMargin,
            """match x:
              |  case [a]:
              |    pass""".stripMargin
        )
        testS("""match x:
                |  case [a, b, c]:
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case [a, b, c,]:
              |    pass""".stripMargin,
            """match x:
              |  case [a, b, c]:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case ():
              |    pass""".stripMargin,
            """match x:
              |  case []:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case (a,):
              |    pass""".stripMargin,
            """match x:
              |  case [a]:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case (a, b, c):
              |    pass""".stripMargin,
            """match x:
              |  case [a, b, c]:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case (a, b, c,):
              |    pass""".stripMargin,
            """match x:
              |  case [a, b, c]:
              |    pass""".stripMargin
        )
    }
    "pattern matching case tests - mapping" in {
        testS("""match x:
                |  case {}:
                |    pass""".stripMargin)
        testS("""match x:
                |  case {**y}:
                |    pass""".stripMargin)
        testS("""match x:
                |  case {1: a}:
                |    pass""".stripMargin)
        testS("""match x:
                |  case {n.m: a}:
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case {1: a, 2: b, **r,}:
              |    pass""".stripMargin,
            """match x:
              |  case {1: a, 2: b, **r}:
              |    pass""".stripMargin
        )
        testS(
            """match x:
              |  case {1: a, **r, 2: b}:
              |    pass""".stripMargin,
            """match x:
              |  case {1: a, 2: b, **r}:
              |    pass""".stripMargin
        )
    }
    "pattern matching case tests - class" in {
        testS("""match x:
                |  case Foo():
                |    pass""".stripMargin)
        testS("""match x:
                |  case lib.Foo():
                |    pass""".stripMargin)
        testS("""match x:
                |  case Foo(1, 2):
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case Foo(1, 2,):
              |    pass""".stripMargin,
            """match x:
              |  case Foo(1, 2):
              |    pass""".stripMargin
        )
        testS("""match x:
                |  case Foo(a = 1, b = 2):
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case Foo(a = 1, b = 2,):
              |    pass""".stripMargin,
            """match x:
              |  case Foo(a = 1, b = 2):
              |    pass""".stripMargin
        )
        testS("""match x:
                |  case Foo(1, 2, a = 3, b = 4):
                |    pass""".stripMargin)
    }
    "pattern matching case tests - guard" in {
        testS("""match x:
                |  case y if y == x:
                |    pass""".stripMargin)
        testS("""match x:
                |  case y if a := 1:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - as" in {
        testS("""match x:
                |  case _ as z:
                |    pass""".stripMargin)
    }
    "pattern matching case tests - general" in {
        testS("""match x:
                |  case 1 | 2 | 3:
                |    pass""".stripMargin)
        testS(
            """match x:
              |  case (1 | 2 | 3) as x:
              |    pass""".stripMargin,
            """match x:
              |  case 1 | 2 | 3 as x:
              |    pass""".stripMargin
        )
        testS("""match x:
                |  case 1 | 2 | 3 as x:
                |    pass""".stripMargin)
        testS("""match x:
                |  case [a, b, Foo(1, n = 2)] as x:
                |    pass""".stripMargin)
        testS("""match x:
                |  case 1:
                |    pass
                |  case 2:
                |    print()""".stripMargin)
        testS("""match x:
                |  case 1:
                |    while y != 2:
                |      pas
                |  case 2:
                |    print()""".stripMargin)
        testS("""match x:
                |  case 1:
                |    match y:
                |      case 1:
                |        pass""".stripMargin)
        testS("""match x:
                |  case 1:
                |    pass
                |pass""".stripMargin)
    }
    "test non keyword 'match' usages" in {
        testT("match[1] = 0")
        testT("match * 2")
    }
    "non-latin identifier name tests" in {
        testT("print(Σ_1)")
        testT("print(ø2)")
        testT("print(_x)")
        testT("print(Ǝ1)")
        testT("print(ƹ0)")
        testT("print(ש0)")
        testT("print(ߕ)")
    }
    "try* and try mixed usage tests" in {
        testS("""try*:
                |  x
                |except* e:
                |  y
                |try:
                |  z
                |except f:
                |  w""".stripMargin)
        testS("""try:
                |  x
                |except e:
                |  y
                |try*:
                |  z
                |except* f:
                |  w""".stripMargin)
        testS("""def func():
                |  try*:
                |    x
                |  except* e:
                |    y
                |  try:
                |    z
                |  except f:
                |    w""".stripMargin)
    }
}
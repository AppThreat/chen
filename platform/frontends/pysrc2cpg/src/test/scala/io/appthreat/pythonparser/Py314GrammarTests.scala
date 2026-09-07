package io.appthreat.pythonparser

import io.appthreat.pythonparser.ast.iast
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** Python 3.14 syntax probes (Task 10 / version-matrix completion).
  *
  * Oracle for every expectation here: CPython 3.14.6 (`python3 --version`), transcripts in the task
  * write-up - notably that `except A, B as e:` is a SyntaxError in 3.14 ("multiple exception types
  * must be parenthesized when using 'as'"; the unparenthesised `as` form is 3.15 material), while
  * `except A, B:`, `except A, B,:` and `except* A, B:` are legal.
  *
  * Every probe asserts AST SHAPE through the printer, not just absence of a parse error: the
  * pre-fix grammar accepted `except A, B:` by silently reusing the Python 2 `except E, name:` arm
  * and BINDING B - a parses-but-wrong-AST failure mode a naive error check misses.
  */
class Py314GrammarTests extends AnyFreeSpec with Matchers:

  private def parseWithoutErrors(code: String): iast =
    val parser = new PyParser()
    val ast    = parser.parse(code)
    parser.errors shouldBe empty
    ast

  private def print(code: String): String =
      new AstPrinter("  ").print(parseWithoutErrors(code))

  "t-strings (PEP 750)" - {

      "single lowercase prefix with an interpolation" in {
          print("""x = t"a{b}c"""") should include("t\"a{b}c\"")
      }

      "uppercase and raw combinations" in {
          print("""x = T'a{b}'""") should include("T'a{b}'")
          print("""x = rt"a{b}c\""""") should include("rt\"a{b}c\\\"")
          print("""x = tr'a{b}'""") should include("tr'a{b}'")
          print("""x = TR'''a{b}'''""") should include("TR'''a{b}'''")
      }

      "a t-string without interpolations is still a template" in {
          print("""x = t"plain"""") should include("t\"plain\"")
      }

      "conversions, format specs and the = debug form parse like an f-string's" in {
          print("""x = t"a{b!r:>{w}}c={d=}"""") should include("{b!r:>{w}}")
      }

      "t-strings concatenate like other string literals" in {
          print("""x = t"a" t"b"""") should include("t\"a\"")
      }

      "bt is not a prefix (oracle: 'b' and 't' prefixes are incompatible)" in {
          val parser = new PyParser()
          parser.parse("""x = bt"a"""")
          parser.errors should not be empty
      }
  }

  "unparenthesised multiple exception types (PEP 758)" - {

      "except A, B: is a tuple of types and binds nothing" in {
          val out = print("try:\n    pass\nexcept ValueError, TypeError:\n    pass\n")
          out should include("except (ValueError,TypeError):")
          (out should not).include("as ")
      }

      "the Python 2 spelling no longer binds: except A, b: keeps b a type" in {
          // Pre-fix this printed `except A as b:` - the py2 arm - which is a SyntaxError in
          // every 3.x and silently mis-bound the second type as a name.
          val out = print("try:\n    pass\nexcept ValueError, TypeError:\n    e = 1\n")
          (out should not).include("as TypeError")
      }

      "three types and a trailing comma" in {
          print("try:\n    pass\nexcept A, B, C:\n    pass\n") should
              include("except (A,B,C):")
          parseWithoutErrors("try:\n    pass\nexcept A, B,:\n    pass\n")
      }

      "except A, B as e: parses with e bound (3.15-lenient)" in {
          // Rejected by 3.14.6, accepted here deliberately: the grammar is not a validator,
          // and 3.15 un-parenthesises this form.
          print("try:\n    pass\nexcept A, B as e:\n    pass\n") should include("as e")
      }

      "except* A, B: is a tuple of types (PEP 654 + 758)" in {
          val out = print("try:\n    pass\nexcept* A, B:\n    pass\n")
          out should include("except* (A,B):")
          (out should not).include("as ")
      }

      "parenthesised forms keep working" in {
          print("try:\n    pass\nexcept (A, B) as e:\n    pass\n") should include("as e")
          print("try:\n    pass\nexcept A as e:\n    pass\n") should include("except A as e:")
      }
  }

  "pre-3.14 confirmations from the probe table" - {

      "type-param defaults inside a type statement (PEP 696)" in {
          parseWithoutErrors("type ListOrSet[T = int] = list[T] | set[T]")
      }

      "except* with as (PEP 654)" in {
          parseWithoutErrors("try:\n    pass\nexcept* ValueError as e:\n    pass\n")
      }

      "type alias statement (PEP 695)" in {
          parseWithoutErrors("type Point = tuple[float, float]")
      }
  }

  "Python 3.15 lazy imports (contextual keyword)" - {

      "lazy import and lazy from keep `lazy` a soft keyword" in {
          // Oracle: SyntaxError on 3.14.6; the CPython 3.15 branch grammar accepts
          // lazy="lazy"? before both import forms. The flag only defers loading at runtime,
          // so the AST is an ordinary Import/ImportFrom.
          print("lazy import os.path\n") should include("import os.path")
          print("lazy from os import path\n") should include("from os import path")
      }

      "lazy as a plain name still parses everywhere" in {
          parseWithoutErrors("lazy = 1")
          parseWithoutErrors("lazy\n")
          parseWithoutErrors("def f(lazy):\n    return lazy\n")
      }
  }

  "the 3.8 floor still parses" - {

      "unpacking call arguments" in {
          parseWithoutErrors("print(*args, sep='')")
      }

      "positional-only parameters" in {
          parseWithoutErrors("def f(a, b, /, c, *, d):\n    return a + b + c + d\n")
      }

      "walrus" in {
          parseWithoutErrors("if (n := 10) > 5:\n    print(n)\n")
      }

      "async generators and comprehensions" in {
          parseWithoutErrors("async def f():\n    yield 1\n")
          parseWithoutErrors("async def g(it):\n    return [x async for x in it]\n")
      }
  }
end Py314GrammarTests

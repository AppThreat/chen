package io.appthreat.pythonparser

import io.appthreat.pythonparser.ast.iast
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** match/case/type are SOFT keywords in Python: reserved only in the statement and pattern
  * positions (guarded by isMatchStatement()/isTypeStatement()), and ordinary identifiers everywhere
  * else. Before the softName() fix the grammar treated them as hard tokens, so real-world code like
  * `re.match(...)` or `obj.type` failed to parse
  *   - and a failure inside a parameter list desynchronised the INDENT/DEDENT stream, dropping the
  *     whole enclosing function.
  */
class SoftKeywordParserTests extends AnyFreeSpec with Matchers:

  private def parseWithoutErrors(code: String): iast =
    val parser = new PyParser()
    val ast    = parser.parse(code)
    parser.errors shouldBe empty
    ast

  "soft keywords in identifier positions" - {
      "attribute access" in {
          parseWithoutErrors("a = re.match(r\"x\", s)")
          parseWithoutErrors("b = obj.match(return_rule=True)")
          parseWithoutErrors("c = obj.type")
          parseWithoutErrors("d = obj.type()")
      }

      "def/class names and parameter names" in {
          parseWithoutErrors("def match(self, x): return x")
          parseWithoutErrors("def type(self): return 1")
          parseWithoutErrors("def f(case, type, _): return case")
          parseWithoutErrors("class match: pass")
          parseWithoutErrors("class type: pass")
          parseWithoutErrors("lambda case: case")
      }

      "import names" in {
          parseWithoutErrors("from x import match as type")
          parseWithoutErrors("import a.match")
          parseWithoutErrors("from x import case, type")
      }

      "global/nonlocal and except-as bindings" in {
          parseWithoutErrors("def f():\n  global case, type\n  case = 1")
          parseWithoutErrors("def f():\n  nonlocal match\n  match += 1")
          parseWithoutErrors("try:\n  pass\nexcept ValueError as type:\n  pass")
          parseWithoutErrors("try:\n  pass\nexcept* ValueError as case:\n  pass")
      }

      "assignment to a soft keyword name" in {
          parseWithoutErrors("match = 5")
          parseWithoutErrors("type = \"shadow\"")
          parseWithoutErrors("case, type = 1, 2")
      }

      "the statement forms keep working alongside the identifier forms" in {
          parseWithoutErrors(
            """def m(cmd, point):
          |    match cmd.split():
          |        case ["go", ("north"|"south") as dir]:
          |            return dir
          |        case [Point(x=x1), *objs] if x1 == 0:
          |            return objs
          |        case _:
          |            return None
          |type Alias = int
          |match = probe(match)
          |""".stripMargin
          )
      }

      "the gettext alias _ keeps working as a name and as the match wildcard" in {
          parseWithoutErrors("_(\"hello\")")
          parseWithoutErrors("def f(x):\n    match x:\n        case _:\n            return _\n")
      }
  }
end SoftKeywordParserTests

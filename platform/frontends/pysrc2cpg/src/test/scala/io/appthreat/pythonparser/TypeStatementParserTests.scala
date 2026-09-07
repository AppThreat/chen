package io.appthreat.pythonparser

import io.appthreat.pythonparser.ast.iast
import org.scalatest.freespec.AnyFreeSpec
import org.scalatest.matchers.should.Matchers

/** PEP 695 `type` alias statements (3.12) and PEP 696 type-parameter defaults (3.13). Root cause
  * when this failed: `type_stmt()` was only reachable from `compoundStatement()`, which never
  * consumes the statement terminator, so a successful alias parse left the NEWLINE unconsumed and
  * the error recovery swallowed the statement. A `type` alias is a simple statement; it is routed
  * through smallStatement() now.
  */
class TypeStatementParserTests extends AnyFreeSpec with Matchers:

  private def parseWithoutErrors(code: String): iast =
    val parser = new PyParser()
    val ast    = parser.parse(code)
    parser.errors shouldBe empty
    ast

  "type alias statements" - {
      "simple alias" in {
          parseWithoutErrors("type Point = tuple[float, float]")
      }

      "alias with type parameters" in {
          parseWithoutErrors("type Alias[T] = list[T]")
      }

      "alias with a type-parameter default (PEP 696)" in {
          parseWithoutErrors("type ListOrSet[T = int] = list[T] | set[T]")
      }

      "statements following a type alias still parse" in {
          parseWithoutErrors(
            """type Alias[T] = list[T]
          |type Point = tuple[float, float]
          |x = 1
          |y = 2
          |""".stripMargin
          )
      }

      "type inside a nested block" in {
          parseWithoutErrors(
            """def f():
          |    type Inner = int
          |    return Inner
          |""".stripMargin
          )
      }

      "`type` as a plain name keeps working" in {
          parseWithoutErrors("type = 3")
          parseWithoutErrors("x = type(5)")
          parseWithoutErrors("class C:\n    type = 1")
      }
  }
end TypeStatementParserTests

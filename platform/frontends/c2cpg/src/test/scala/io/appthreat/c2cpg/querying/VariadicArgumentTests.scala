package io.appthreat.c2cpg.querying

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}

/** The arguments a C variadic function takes after its last named parameter reach its `va_list`,
  * not that parameter, which c2cpg marks variadic (`const char *fmt...`).
  */
class VariadicArgumentTests extends CCodeToCpgSuite:

  private given ICallResolver = NoResolve

  "the arguments of a variadic function" should {
      val cpg = code("""
          |void log_msg(int level, const char *fmt, ...) {}
          |void handle(char *source) { log_msg(1, "%s", source); }
          |""".stripMargin)

      "bind the named parameters by index and the extra ones none" in {
          cpg.parameter.nameExact("fmt").isVariadic.l shouldBe List(true)
          cpg.call.nameExact("log_msg").argument.l.map(_.parameter.name.l) shouldBe List(
            List("level"),
            List("fmt"),
            List()
          )
      }
  }
end VariadicArgumentTests

package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}

/** A varargs parameter is variadic; its extra arguments are packed into one array, unless the call
  * passes that array itself.
  */
class VarargsTests extends JavaSrcCode2CpgFixture:

  private given ICallResolver = NoResolve

  private val cpg = code("""
      |class Runner {
      |  static void run(String cmd, String... args) {}
      |  static void handle(String source, String[] all) {
      |    run("ls", "-l", source);
      |    run("ls", all);
      |    run("ls");
      |  }
      |}
      |""".stripMargin)

  "a varargs parameter" should {
      "be variadic, typed as its array" in {
          val args = cpg.method.nameExact("run").parameter.nameExact("args").l
          args.isVariadic.l shouldBe List(true)
          args.typeFullName.l shouldBe List("java.lang.String[]")
      }
  }

  "a call to a varargs method" should {
      "pack the extra arguments into one array" in {
          val call = cpg.call.nameExact("run").codeExact("run(\"ls\", \"-l\", source)").head
          call.argument.l.map(a => a.argumentIndex -> a.code) shouldBe List(
            1 -> "\"ls\"",
            2 -> Operators.arrayInitializer
          )
          call.argument(2).parameter.name.l shouldBe List("args")
      }

      "pass an array argument as it is" in {
          val call = cpg.call.nameExact("run").codeExact("run(\"ls\", all)").head
          call.argument.l.map(a => a.argumentIndex -> a.code) shouldBe List(
            1 -> "\"ls\"",
            2 -> "all"
          )
          call.argument(2).parameter.name.l shouldBe List("args")
      }
  }
end VarargsTests

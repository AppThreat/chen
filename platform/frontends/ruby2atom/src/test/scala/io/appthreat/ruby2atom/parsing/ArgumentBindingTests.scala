package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.ArgumentBinding

/** Which parameters Ruby's arguments bind (`resources/ruby/argument_binding.rb`): keywords bind
  * keyword parameters and never positional ones, the keywords of a call to a method that takes none
  * arrive as its trailing Hash, `*xs` and `**h` unpack into the positionals and the keywords, and
  * `def f(...)` takes - and `g(...)` passes on - everything.
  */
class ArgumentBindingTests extends RubyCode2CpgFixture:

  private lazy val cpg = fixture("argument_binding")

  /** The parameters of the callee RubyCallLinker named that each argument of the call binds. */
  private def boundBy(callCode: String): List[(String, List[String])] =
    val call   = cpg.call.codeExact(callCode).head
    val params = cpg.method.fullNameExact(call.methodFullName).parameter.l
    call.argument.argumentIndexGt(0).l.map(arg =>
        arg.code -> ArgumentBinding.parametersBound(arg, params).map(_.name).toList
    )

  "calls to the project's methods" should {
      "be named after their callee" in {
          cpg.call.nameExact("run", "configure", "collect", "forward").methodFullName.toSet shouldBe
              Set(
                "argument_binding.rb:<main>.run",
                "argument_binding.rb:<main>.configure",
                "argument_binding.rb:<main>.collect",
                "argument_binding.rb:<main>.forward"
              )
      }
  }

  "keyword arguments" should {
      "bind the keyword parameter of their name" in {
          boundBy("run(source, shell: true)") shouldBe List(
            "source" -> List("cmd"),
            "true"   -> List("shell")
          )
      }

      "arrive as the trailing Hash of a method that takes no keywords" in {
          boundBy("configure(name: source)") shouldBe List("source" -> List("opts"))
      }
  }

  "splats" should {
      "unpack an array into the positionals" in {
          boundBy("collect(1, *source)") shouldBe List(
            "1"       -> List("first"),
            "*source" -> List("rest")
          )
      }

      "unpack a hash into the keywords" in {
          cpg.call.codeExact("**source").argumentName.l shouldBe List("**")
          boundBy("collect(1, **source)") shouldBe List(
            "1"        -> List("first"),
            "**source" -> List("kw")
          )
      }
  }

  "argument forwarding" should {
      "take every argument" in {
          cpg.parameter.nameExact("...").isVariadic.l shouldBe List(true)
          boundBy("forward(source)") shouldBe List("source" -> List("..."))
      }

      "pass every argument on" in {
          boundBy("run(...)") shouldBe List("..." -> List("cmd", "shell"))
      }
  }
end ArgumentBindingTests

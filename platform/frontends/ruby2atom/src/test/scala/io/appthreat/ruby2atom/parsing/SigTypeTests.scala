package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.datastructures.RubyProgramSummaryBuilder
import io.appthreat.ruby2atom.parser.{RubyJsonParser, RubyJsonToNodeCreator}
import io.appthreat.ruby2atom.passes.Defines
import io.appthreat.ruby2atom.testfixtures.Ruby2AtomFixture
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

/** Sorbet `sig` blocks flow into the program summary: the generator (ruby_ast_gen 2.x) marks the
  * def with `has_sig`, the JSON creator attaches the preceding block's types, and
  * `RubyProgramSummaryBuilder` fills `parameterTypes`/`returnType` instead of `Any`. Fixture:
  * `sorbet_types.rb(.json)`.
  */
class SigTypeTests extends AnyWordSpec with Matchers:

  private def orderType =
    val summary = RubyProgramSummaryBuilder.build(Ruby2AtomFixture.parse("sorbet_types"))
    summary.matchingTypes("Order").find(_.name == "Order").get

  "the summary fills return types from the sig block" in {
      orderType.methods.find(_.name == "format").get.returnType shouldBe "String"
      // T.nilable(X) collapses to X.
      orderType.methods.find(_.name == "find").get.returnType shouldBe "String"
  }

  "T.untyped and T.any map to the summary's unknown" in {
      val merge = orderType.methods.find(_.name == "merge").get
      merge.returnType shouldBe Defines.Any
      merge.parameterTypes should contain("other" -> Defines.Any)
  }

  "void sigs report void instead of the unknown type" in {
      orderType.methods.find(_.name == "validate").get.returnType shouldBe Defines.Void
  }

  "parameter types come from params()" in {
      orderType.methods.find(_.name == "format").get.parameterTypes should contain(
        "amount" -> "Integer"
      )
      orderType.methods.find(_.name == "format").get.parameterTypes should contain(
        "currency" -> "String"
      )
  }

  "singleton methods pick up their sig too" in {
      val log = orderType.methods.find(_.name == "log!").get
      log.returnType shouldBe Defines.Void
      log.parameterTypes should contain("label" -> "String")
  }

  "the sig forms Sorbet allows around the block are all recognised" in {
      // `sig { ... }.checked(:never)` puts the block behind a send chain and
      // T::Sig::WithoutRuntime.sig gives it a constant receiver. Matching the block structurally
      // rather than on the statement's text is what makes both work.
      orderType.methods.find(_.name == "checked_form").get.returnType shouldBe "String"
      orderType.methods.find(_.name == "checked_form").get.parameterTypes should contain(
        "count" -> "Integer"
      )
      orderType.methods.find(_.name == "without_runtime").get.returnType shouldBe "Integer"
  }

  "a method without a sig stays untyped" in {
      // The fact key is emitted only when it holds, so the negative case must not grow types.
      val untyped = orderType.methods.find(_.name == "untyped_method").get
      untyped.returnType shouldBe Defines.Any
      untyped.parameterTypes shouldBe empty
  }

  "pre-2.1 JSON without the fact key keeps methods untyped even when a sig block precedes" in {
      // The generator's `has_sig` is what authorizes the attachment. JSON from an older generator
      // has no fact, and reading it with an adjacency heuristic would silently type those defs -
      // the exact getOrElse(<heuristic>) defect plan 04 §5 records.
      val tmpDir = Files.createTempDirectory("ruby2atomLegacySig")
      val source = tmpDir.resolve("sorbet_types.rb")
      Files.copy(getClass.getResourceAsStream("/ruby/sorbet_types.rb"), source)
      val json = ujson.read(
        new String(
          getClass.getResourceAsStream("/ruby/sorbet_types.rb.json").readAllBytes(),
          "UTF-8"
        )
      )
      json("generator_version") = "1.3.0"
      def stripFact(value: ujson.Value): Unit = value match
        case obj: ujson.Obj =>
            obj.obj.remove("has_sig")
            obj("file_path") = source.toAbsolutePath.toString
            obj.value.values.foreach(stripFact)
        case arr: ujson.Arr => arr.value.foreach(stripFact)
        case _              =>
      stripFact(json)
      val target = tmpDir.resolve("sorbet_types.rb.json")
      Files.writeString(target, ujson.write(json))

      val parserResult = RubyJsonParser.readFile(target)
      val program = new RubyJsonToNodeCreator(fileName = parserResult.fullPath)
          .visitProgram(parserResult.json)
      val summary = RubyProgramSummaryBuilder.build(List(parserResult.filename -> program))

      val order = summary.matchingTypes("Order").find(_.name == "Order").get
      order.methods.find(_.name == "format").get.returnType shouldBe Defines.Any
      order.methods.find(_.name == "log!").get.parameterTypes shouldBe empty
  }
end SigTypeTests

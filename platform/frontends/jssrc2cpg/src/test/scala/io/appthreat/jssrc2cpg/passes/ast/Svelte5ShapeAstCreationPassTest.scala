package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Shape-contract coverage for the Svelte AST JSON that astgen emits.
  *
  * The committed fixture under src/test/resources/svelte5 (source + .json + .typemap, see its
  * README for the regeneration command) is consumed via `AstJsonFixture`, so no astgen invocation
  * is needed: this test pins the emitted node shape itself. If atom-parsetools changes the Svelte
  * output shape, this test fails here first and forces a deliberate re-baseline of the committed
  * fixture.
  */
class Svelte5ShapeAstCreationPassTest extends AbstractPassTest:

  "AST generation from a committed Svelte astgen JSON fixture" should {

      "build the expected CPG for Counter.svelte" in AstJsonFixture("svelte5") { cpg =>
        cpg.file.name.l shouldBe List("Counter.svelte")

        // script statements: imports, runes, function
        cpg.imports.importedEntity.l should contain("svelte:onMount")
        cpg.method.name("increment").size shouldBe 1
        cpg.local.name.l should contain allElementsOf List("count", "doubled", "initial")

        // template synthesized as JSX DOM structure with real source text
        cpg.templateDom.nameExact("JSXAttribute").code.l shouldBe List(
          "on:click={increment}",
          "disabled={count > 10}",
          """class="big"""",
          """class="note""""
        )
        cpg.templateDom.nameExact("JSXText").code.l should contain("Keep going.")

        // {#each [count, doubled] as value, index (index)} -> .map() closure
        // whose arrow function is a real method with the context/index params
        cpg.call.name("map").size shouldBe 1
        val List(arrow) = cpg.method.parameter.name("value").method.l
        arrow.parameter.name.l shouldBe List("this", "value", "index")

        // {#if count > 10} ... {:else} -> conditional with both branches
        // (the second conditional in the fixture is chen's own desugaring of
        // the `initial = 0` default in the $props() destructuring)
        val List(conditional) = cpg.call
            .name(Operators.conditional)
            .code("count > 10 .*")
            .l
        conditional.code should include("That is plenty.")

        // {@html ...} keeps its expression reachable
        cpg.templateDom.nameExact("SvelteHtmlTag").code.l should contain(
          "{@html `<em>${doubled}</em>`}"
        )
      }
  }
end Svelte5ShapeAstCreationPassTest

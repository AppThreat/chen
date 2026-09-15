package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractDomPassTest
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** DOM/AST creation coverage for `.svelte` single-file components.
  *
  * astgen (>= 4.2.0, @appthreat/atom-parsetools >= 1.6.0) parses Svelte files by segmenting them
  * with svelte/compiler and emitting stock Babel JSX nodes whose offsets are absolute byte
  * positions into the `.svelte` source. This suite consumes that output through the normal astgen
  * invocation, so it requires a locally installed astgen with Svelte support on the PATH. If these
  * tests fail with empty `templateDom` results, the astgen on PATH is too old.
  */
class SvelteDomAstCreationPassTest extends AbstractDomPassTest:

  "AST generation for Svelte templates" should {

      "create template DOM nodes with exact source offsets for directives" in AstFixture(
        """
        |<script lang="ts">
        |let { q = '' }: { q?: string } = $props();
        |function increment(): void {
        |  q = q + 'x';
        |}
        |</script>
        |
        |<input bind:value={q} on:input={increment} placeholder="type here" />
        |<button on:click={increment}>Go</button>
        |""".stripMargin,
        "foo.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("foo.svelte")

        // The decisive offset assertion: the JSXAttribute code fields must be
        // the exact directive source text. `astForJsxAttribute` re-adds a ":"
        // when the character before the attribute is a colon; with absolute
        // offsets the preceding character is whitespace, so nothing is added
        // and the directive reads exactly as written.
        cpg.templateDom.nameExact("JSXAttribute").code.l shouldBe List(
          "bind:value={q}",
          "on:input={increment}",
          """placeholder="type here"""",
          "on:click={increment}"
        )

        templateDomName(cpg) shouldBe Set(
          "JSXFragment",
          "JSXElement",
          "JSXOpeningElement",
          "JSXClosingElement",
          "JSXAttribute",
          "JSXText",
          "JSXExpressionContainer"
        )

        // script statements share the same file and method scope
        cpg.method.name("increment").size shouldBe 1
        cpg.local.name.l should contain("q")
      }

      "model {#each} blocks as .map() calls with arrow closures" in AstFixture(
        """
        |<script lang="ts">
        |let { items }: { items: Array<string> } = $props();
        |</script>
        |
        |<ul>
        |  {#each items as item, i (item)}
        |    <li>{i}: {item}</li>
        |  {/each}
        |</ul>
        |""".stripMargin,
        "each.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("each.svelte")

        // {#each} becomes `<expr>.map(...)`; the synthesized arrow function is
        // a real method so the loop body is traversable.
        cpg.call.name("map").size shouldBe 1
        val List(arrow) = cpg.method.parameter.name("item").method.l
        arrow.parameter.name.l shouldBe List("this", "item", "i")

        // template identifiers are attached under the loop closure
        arrow.ast.isIdentifier.name.l should contain allElementsOf List("item", "i")
        cpg.identifier.name("items").size should be >= 1
      }

      "model {#if}/{:else if}/{:else} as a conditional chain" in AstFixture(
        """
        |<script lang="ts">
        |let count = $state(0);
        |</script>
        |
        |{#if count > 10}
        |  <p>big</p>
        |{:else if count > 5}
        |  <p>mid</p>
        |{:else}
        |  <p>small</p>
        |{/if}
        |""".stripMargin,
        "if.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("if.svelte")
        // {:else if} splices the nested conditional in as the alternate, so
        // the two {#if}/{:else if} tests surface as two chained conditionals
        val conditionals = cpg.call.name(Operators.conditional).l
        conditionals.size shouldBe 2
        // both tests are `>` comparisons; the branch markup survives as
        // JSXText template DOM nodes
        cpg.call.name(Operators.greaterThan).size shouldBe 2
        cpg.templateDom.nameExact("JSXText").code.l should contain allElementsOf
            List("big", "mid", "small")
      }

      "model {#snippet}/{@render} as an assignment and a call" in AstFixture(
        """
        |<script lang="ts">
        |let { name }: { name: string } = $props();
        |</script>
        |
        |{#snippet greet(who: string)}
        |  <b>{who}</b>
        |{/snippet}
        |
        |<p>{@render greet(name)}</p>
        |""".stripMargin,
        "snippet.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("snippet.svelte")

        // the snippet becomes `greet = (who) => ...`, the render a call to greet
        val List(assignment) = cpg.assignment.code("greet.*").l
        assignment.target.code shouldBe "greet"
        cpg.call.name("greet").size shouldBe 1
      }

      "keep {@html} expressions reachable as template DOM children" in AstFixture(
        """
        |<script lang="ts">
        |let { bio }: { bio: string } = $props();
        |</script>
        |
        |<div class="bio">{@html bio}</div>
        |""".stripMargin,
        "html.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("html.svelte")
        // Svelte blocks and tags all map onto JSXExpressionContainer, so the DOM node is named
        // after the construct instead - see AstForTemplateDomCreator.templateDomNodeName.
        val List(container) = cpg.templateDom.nameExact("SvelteHtmlTag").l
        container.code shouldBe "{@html bio}"
        val bioIdentifier = container.ast.isIdentifier.name("bio").l.head
        parentTemplateDom(bioIdentifier).name shouldBe "SvelteHtmlTag"
        parentTemplateDom(parentTemplateDom(bioIdentifier)).name shouldBe "JSXElement"
        // the template identifier binds to the script local from $props()
        cpg.identifier.name("bio").size should be >= 2
      }

      "handle Svelte 4 legacy syntax (export let, $:, on:click)" in AstFixture(
        """
        |<script lang="ts">
        |export let visible = true;
        |$: label = visible ? 'shown' : 'hidden';
        |function toggle(): void {
        |  visible = !visible;
        |}
        |</script>
        |
        |<button on:click={toggle}>{label}</button>
        |""".stripMargin,
        "legacy.svelte"
      ) { cpg =>
        cpg.file.name.l shouldBe List("legacy.svelte")
        cpg.templateDom.nameExact("JSXAttribute").code.l shouldBe List("on:click={toggle}")
        cpg.local.name.l should contain allElementsOf List("visible", "label")
        // $: reactive statements are LabeledStatements in the script block
        cpg.identifier.name("label").size should be >= 2
      }

  }
end SvelteDomAstCreationPassTest

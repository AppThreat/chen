package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** `framework-output` tagging of raw-HTML template interpolations.
  *
  * `EasyTagsPass` tags two things per sink: the TEMPLATE_DOM node (so the tag is an inventory of
  * render sites with their exact source text) and the script-side *definition* of the rendered
  * value (so `reachables` can find a source -> sink path, which a template node alone cannot
  * support - see the comment on `tagRawHtmlTemplateSinks`).
  *
  * The Svelte cases need a locally installed astgen >= 4.2.0 (`@appthreat/atom-parsetools` >=
  * 1.6.0). If they fail with no tagged sink at all, the astgen on PATH is too old.
  */
class RawHtmlTemplateSinkTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    cpg

  private def sinkCodes(cpg: Cpg): List[String] =
      cpg.templateDom.where(_.tag.name("framework-output")).code.l

  "raw-HTML template sink tagging" should {

      "tag a Svelte {@html} site with its exact source text" in {
          val cpg = tagged(code(
            """
          |<script lang="ts">
          |let { bio }: { bio: string } = $props();
          |</script>
          |
          |<div class="bio">{@html bio}</div>
          |""".stripMargin,
            "bio.svelte"
          ))

          sinkCodes(cpg) shouldBe List("{@html bio}")
      }

      "not tag the enclosing fragment, which spans the whole component" in {
          val cpg = tagged(code(
            """
          |<script lang="ts">
          |let { bio }: { bio: string } = $props();
          |</script>
          |
          |<div>{@html bio}</div>
          |""".stripMargin,
            "frag.svelte"
          ))

          // The JSXFragment's code is the entire template; an unanchored `.*@html.*`
          // would tag it and make the whole component a sink.
          cpg.templateDom.where(_.tag.name("framework-output")).name.toSetImmutable shouldBe
              Set("SvelteHtmlTag")
      }

      "tag a Vue v-html attribute" in {
          val cpg = tagged(code(
            """
          |<template><div v-html="bio"></div></template>
          |""".stripMargin,
            "bio.vue"
          ))

          sinkCodes(cpg) shouldBe List("""v-html="bio"""")
      }

      "tag a React dangerouslySetInnerHTML attribute" in {
          val cpg = tagged(code(
            """
          |function C(p) { return <div dangerouslySetInnerHTML={{__html: p.bio}} />; }
          |""".stripMargin,
            "c.jsx"
          ))

          sinkCodes(cpg).size shouldBe 1
          sinkCodes(cpg).head should startWith("dangerouslySetInnerHTML")
      }

      "leave a component with no raw-HTML render untagged" in {
          val cpg = tagged(code(
            """
          |<script lang="ts">
          |let { bio }: { bio: string } = $props();
          |</script>
          |
          |<div>{bio}</div>
          |""".stripMargin,
            "safe.svelte"
          ))

          sinkCodes(cpg) shouldBe empty
      }

      "tag the interpolation at the markup line, not the script line" in {
          val cpg = tagged(code(
            """
          |<script lang="ts">
          |let { bio }: { bio: string } = $props();
          |const rendered = bio + "<br>";
          |function log(): void { console.log(rendered); }
          |</script>
          |
          |<div>{@html rendered}</div>
          |""".stripMargin,
            "def.svelte"
          ))

          // The interpolation call sits on the markup line (8), so a flow terminates at the
          // markup that renders the value rather than at the script line that computed it.
          val taggedCalls =
              cpg.tag.name("framework-output").call.nameExact("<operator>.interpolation").l
          taggedCalls.map(_.lineNumber.map(_.intValue).getOrElse(-1)) shouldBe List(8)
          taggedCalls.map(_.code) shouldBe List("{@html rendered}")
      }
  }

  "reachability through a raw-HTML sink" should {

      "find a path from a tainted source to the rendered value" in {
          val cpg = tagged(code(
            """
          |<script lang="ts">
          |const bio = taint();
          |const rendered = bio + "<br>";
          |</script>
          |
          |<div>{@html rendered}</div>
          |""".stripMargin,
            "flow.svelte"
          ))

          val source = cpg.call.nameExact("taint").l
          val sinks  = cpg.tag.name("framework-output").call.l
          sinks should not be empty
          sinks.iterator.reachableByFlows(source.iterator).size should be > 0

          // and the terminus is the markup, not the script-side definition
          val interpolation =
              cpg.tag.name("framework-output").call.nameExact("<operator>.interpolation").l
          interpolation.iterator.reachableByFlows(source.iterator).size should be > 0
      }
  }
end RawHtmlTemplateSinkTagsTest

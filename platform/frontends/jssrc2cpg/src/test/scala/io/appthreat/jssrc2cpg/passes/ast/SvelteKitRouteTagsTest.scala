package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** SvelteKit route semantics: server entrypoints recognised by file convention, and the component
  * props boundary.
  *
  * SvelteKit has no route-registration call for `JS_ROUTES_CALL_REGEX` to match - a `load` exported
  * from `+page.server.ts` *is* the handler - so `ChennaiTagsPass` keys off the file name instead.
  */
class SvelteKitRouteTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def routes(cpg: Cpg): List[String] =
      cpg.method.where(_.tag.name("framework-route")).name.sorted.l

  private def inputParams(cpg: Cpg): List[String] =
      cpg.tag.name("framework-input").parameter.name.sorted.l

  "SvelteKit server entrypoints" should {

      "tag load in +page.server.js as a route and its request parameter as input" in {
          val cpg = tagged(code(
            """
          |export async function load({ params, url }) {
          |  return { slug: params.slug };
          |}
          |function helper(config) { return config; }
          |""".stripMargin,
            "+page.server.js"
          ))

          routes(cpg) shouldBe List("load")
          // the destructured request object, and NOT the helper's parameter
          inputParams(cpg).size shouldBe 1
      }

      "tag an actions handler, which compiles to an anonymous method" in {
          val cpg = tagged(code(
            """
          |export const actions = {
          |  default: async ({ request }) => {
          |    const form = await request.formData();
          |    return { ok: form.get('x') };
          |  }
          |};
          |""".stripMargin,
            "+page.server.ts"
          ))

          routes(cpg) should contain("anonymous")
          inputParams(cpg) should not be empty
      }

      "tag every handler of a multi-action file, which numbers the anonymous methods" in {
          val cpg = tagged(code(
            """
          |export const actions = {
          |  login: async ({ request }) => { return { a: (await request.formData()).get('u') }; },
          |  logout: async ({ cookies }) => { cookies.delete('session'); return { ok: true }; },
          |  update: async ({ request }) => { return { b: (await request.formData()).get('v') }; }
          |};
          |""".stripMargin,
            "+page.server.js"
          ))

          // anonymous, anonymous1, anonymous2 - a `m.name == "anonymous"` filter would
          // catch only the first, leaving the other two handlers untagged.
          routes(cpg).size shouldBe 3
          routes(cpg).foreach(_ should startWith("anonymous"))
          inputParams(cpg).size shouldBe 3
      }

      "tag every HTTP verb exported from +server.ts" in {
          val cpg = tagged(code(
            """
          |export function GET({ url }) { return new Response(url.searchParams.get('q')); }
          |export async function POST({ request }) { return new Response(await request.text()); }
          |export async function DELETE({ params }) { return new Response(params.id); }
          |""".stripMargin,
            "+server.ts"
          ))

          routes(cpg) shouldBe List("DELETE", "GET", "POST")
      }

      "tag hooks.server.ts handlers" in {
          val cpg = tagged(code(
            """
          |export async function handle({ event, resolve }) { return resolve(event); }
          |export async function handleError({ error }) { return { message: 'oops' }; }
          |""".stripMargin,
            "hooks.server.ts"
          ))

          routes(cpg) shouldBe List("handle", "handleError")
      }

      "not treat a plain module as a route" in {
          val cpg = tagged(code(
            """
          |export function load(config) { return config; }
          |""".stripMargin,
            "helpers.ts"
          ))

          routes(cpg) shouldBe empty
      }

      "not confuse +page.server.js with +server.js" in {
          val cpg = tagged(code(
            """
          |export function GET({ url }) { return new Response(url.href); }
          |""".stripMargin,
            "+page.server.js"
          ))

          // GET is a +server.ts entrypoint, not a +page.server.ts one
          routes(cpg) shouldBe empty
      }
  }

  "the component props boundary" should {

      "tag $props() in a .svelte file as framework-input" in {
          val cpg = tagged(code(
            """
          |<script>
          |	const { data } = $props();
          |</script>
          |<p>{data.title}</p>
          |""".stripMargin,
            "+page.svelte"
          ))

          cpg.tag.name("framework-input").call.code.l shouldBe List("$props()")
      }
  }

  "Svelte 4 components" should {

      "tag reads of an `export let` prop as framework-input" in {
          val cpg = tagged(code(
            """
          |<script>
          |	export let data;
          |	const html = data.body + '!';
          |</script>
          |<div>{@html html}</div>
          |""".stripMargin,
            "legacy.svelte"
          ))

          // `export let data` lowers to `exports.data = data`; the prop's reads are the source
          cpg.tag.name("framework-input").identifier.nameExact("data").l should not be empty
      }

      "close a Svelte 4 prop to raw-HTML path" in {
          val cpg = code(
            """
          |<script>
          |	export let data;
          |	const html = data.body + '!';
          |</script>
          |<div>{@html html}</div>
          |""".stripMargin,
            "legacy2.svelte"
          )
          new ChennaiTagsPass(cpg).createAndApply()
          new EasyTagsPass(cpg).createAndApply()

          val sources = cpg.tag.name("framework-input").identifier.l
          val sinks = cpg.tag.name("framework-output").call
              .nameExact("<operator>.interpolation").l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }
  }

  "route to template" should {

      "close a path from the props boundary to a raw-HTML render" in {
          val cpg = code(
            """
          |<script>
          |	const { data } = $props();
          |</script>
          |<div>{@html data.article.body}</div>
          |""".stripMargin,
            "+page.svelte"
          )
          new ChennaiTagsPass(cpg).createAndApply()
          new EasyTagsPass(cpg).createAndApply()

          val sources = cpg.tag.name("framework-input").call.l
          // `data.article.body` is already a call (a field access), so it carries its own uses
          // and no `<operator>.interpolation` wrapper is added - the field access is the sink.
          val sinks = cpg.tag.name("framework-output").call.l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }
  }
end SvelteKitRouteTagsTest

package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** `$lib` import resolution.
  *
  * SvelteKit rewrites `$lib` to `src/lib`. The mapping lives in `.svelte-kit/tsconfig.json`, which
  * only exists after a build, so a scanner has to know the convention. Without it `$lib/...` is not
  * a relative specifier, `ImportResolverPass` treats it as external, and most of a SvelteKit
  * project's internal imports resolve to nothing.
  */
class SvelteKitAliasImportTests extends DataFlowCodeToCpgSuite:

  "a $lib import" should {

      "resolve to the file under src/lib" in {
          val cpg = code(
            """
          |export function getArticle(slug) { return { slug }; }
          |""".stripMargin,
            "src/lib/api.js"
          ).moreCode(
            """
          |import { getArticle } from '$lib/api';
          |export async function load({ params }) { return getArticle(params.slug); }
          |""".stripMargin,
            "src/routes/+page.server.js"
          )

          // the call resolves to the internal method rather than <unknownFullName>
          val List(call) = cpg.call.nameExact("getArticle").l
          call.methodFullName should include("src/lib/api.js")
      }

      "resolve a nested $lib path" in {
          val cpg = code(
            """
          |export function esc(s) { return s; }
          |""".stripMargin,
            "src/lib/util/html.js"
          ).moreCode(
            """
          |import { esc } from '$lib/util/html';
          |export function load() { return esc('x'); }
          |""".stripMargin,
            "src/routes/+page.js"
          )

          val List(call) = cpg.call.nameExact("esc").l
          call.methodFullName should include("src/lib/util/html.js")
      }

      "leave the framework-provided $app namespace unresolved" in {
          val cpg = code(
            """
          |import { goto } from '$app/navigation';
          |export function load() { return goto('/'); }
          |""".stripMargin,
            "src/routes/+page.js"
          )

          // no file backs $app/navigation, so nothing internal should be invented for it
          cpg.call.nameExact("goto").methodFullName.l.foreach(_ should not include "src/lib")
      }
  }
end SvelteKitAliasImportTests

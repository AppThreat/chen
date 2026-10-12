package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*

/** What carries a JavaScript value where no call does: class fields read by another method,
  * reactive derivations, closures over a component's top-level variables, and member chains - the
  * last two in the def-use edges themselves.
  */
class JsTaintBridgesTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def show(paths: Iterator[Path]): List[String] =
      paths.map(_.elements.map(_.code).mkString(" -> ")).l

  "Def-use edges" should {
      "carry a value through a read of a read" in {
          val cpg = code(
            """
          |function a(e, route) {
          |  const el = document.getElementById('out');
          |  el.innerHTML = e.data.html;
          |  el.outerHTML = route.query.next;
          |}
          |""".stripMargin,
            "nested.js"
          )
          val sinks = cpg.call.nameExact(Operators.assignment).code("el\\.(inner|outer)HTML = .*")
          show(sinks.reachableByFlows(cpg.parameter.nameExact("e"))) should not be empty
          show(cpg.call.nameExact(Operators.assignment).code("el\\.outerHTML.*")
              .reachableByFlows(cpg.parameter.nameExact("route"))) should not be empty
      }

      "carry a value into an optional call on it" in {
          val cpg = code(
            """
          |async function post(request) {
          |  const form = await request.formData();
          |  const next = form.get('next')?.toString() ?? '/';
          |  location.assign(next);
          |}
          |""".stripMargin,
            "optional.js"
          )
          // a member call through `?.` is a call on its object, named after the member
          cpg.call.nameExact("toString").receiver.code.l shouldBe List(
            "(_tmp_0 = form.get('next')).toString"
          )
          show(
            cpg.call.nameExact("assign").reachableByFlows(cpg.parameter.nameExact("request"))
          ) should not be empty
      }

      "carry a captured variable to every read in the closure, not only the first" in {
          val cpg = code(
            """
          |export default function Go(params) {
          |  const next = params.get('next');
          |  function handle() {
          |    if (next) {
          |      window.location.href = next;
          |    }
          |  }
          |  return handle;
          |}
          |""".stripMargin,
            "go.js"
          )
          val sink =
              cpg.call.nameExact(Operators.assignment).code("window\\.location\\.href = next")
          show(sink.reachableByFlows(cpg.call.nameExact("get"))) should not be empty
      }
  }

  "The member bridge" should {
      "make a field assigned from a source a source where another method reads it" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |@Component({ selector: 'app-o', template: '' })
          |export class OComponent {
          |  private route = inject(ActivatedRoute);
          |  orderId: string;
          |  label = 'x';
          |  ngOnInit() {
          |    this.route.paramMap.subscribe(pm => { this.orderId = pm.get('id'); });
          |  }
          |  open() { window.open('/ftp/order_' + this.orderId + '.pdf'); window.open(this.label); }
          |}
          |""".stripMargin,
            "o.component.ts"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("this.orderId")
          cpg.tag.name("framework-input").call.code.l should not contain "this.label"
      }
  }

  "The reactive bridge" should {
      "make a derived value a source, and a sanitising derivation a sanitiser" in {
          val cpg = tagged(code(
            """
          |import { computed } from 'vue';
          |import { useRoute } from 'vue-router';
          |import DOMPurify from 'dompurify';
          |const route = useRoute();
          |const id = computed(() => route.params.id);
          |const clean = computed(() => DOMPurify.sanitize(String(route.query.q)));
          |export function render(el) { el.innerHTML = id.value; el.outerHTML = clean.value; }
          |""".stripMargin,
            "view.js"
          ))
          cpg.tag.name("framework-input").identifier.name.l should contain("id")
          cpg.tag.name("sanitizer-xss").call.code.l.filter(
            _.startsWith("computed")
          ) should not be empty
      }

      "stop at a sanitiser when looking for a source" in {
          val cpg = tagged(code(
            """
          |import { useParams } from 'react-router-dom';
          |export default function Order() {
          |  const { id } = useParams();
          |  const n = Number(id);
          |  function show(el) { el.innerHTML = '<b>' + n + '</b>'; }
          |  return <div onClick={show} />;
          |}
          |""".stripMargin,
            "order.jsx"
          ))
          cpg.tag.name("framework-input").identifier.name.l should not contain "n"
      }
  }

  "A component element" should {
      "carry any of its attributes into the component's props" in {
          val cpg = code(
            """
          |import RichText from './RichText';
          |export function Page(q) {
          |  return <RichText title="About" label={'x'} html={q} />;
          |}
          |""".stripMargin,
            "page.jsx"
          ).moreCode(
            """
          |export default function RichText({ html }) {
          |  document.getElementById('out').innerHTML = html;
          |  return null;
          |}
          |""".stripMargin,
            "RichText.jsx"
          )
          tagged(cpg)
          val element = cpg.call.nameExact("RichText").l
          element.argument.code.l shouldBe List("{q}")
          element.callee(using NoResolve).fullName.l should contain(
            "RichText.jsx::program:RichText"
          )
          val sink = cpg.call.nameExact(Operators.assignment).code(".*innerHTML = html")
          show(sink.reachableByFlows(cpg.parameter.nameExact("q"))) should not be empty
      }
  }

  "A single-file component" should {
      "take a source an element passes into its props, with where it came from" in {
          val cpg = tagged(code(
            """<script setup lang="ts">
          |const route = useRoute()
          |const slug = computed(() => String(route.params.slug))
          |const { data: article } = await useFetch(() => `/api/articles/${encodeURIComponent(slug.value)}`)
          |</script>
          |
          |<template>
          |  <article v-if="article">
          |    <h1>{{ article.title }}</h1>
          |    <ArticleBody :html="article.body" />
          |  </article>
          |</template>
          |""".stripMargin,
            "app/pages/article/[slug].vue"
          ).moreCode(
            """<script setup lang="ts">
          |defineProps<{ html: string }>()
          |</script>
          |
          |<template>
          |  <div v-html="html"></div>
          |</template>
          |""".stripMargin,
            "app/components/ArticleBody.vue"
          ).moreCode("""{ "dependencies": { "nuxt": "^4.0.0" } }""", "package.json"))
          val element = cpg.call.nameExact("ArticleBody").l
          element.argument.isCall.nameExact("<operator>.jsxProps").argument.code.l shouldBe List(
            "article.body"
          )
          val read =
              cpg.identifier.nameExact("html").filter(_.method.filename.contains("ArticleBody")).l
          read.tag.name.l should contain("service-ingress")
          read.tag.name.l should contain("via:app/pages/article/[slug].vue#4")
      }
  }

  "Provenance" should {
      "name where a bridged source came from: Astro locals written by middleware" in {
          val cpg = tagged(code(
            """
          |import { defineMiddleware } from 'astro:middleware';
          |export const onRequest = defineMiddleware((context, next) => {
          |  context.locals.banner = context.url.searchParams.get('banner');
          |  context.locals.theme = 'dark';
          |  return next();
          |});
          |""".stripMargin,
            "src/middleware.ts"
          ).moreCode(
            """
          |const banner = Astro.locals.banner;
          |const theme = Astro.locals.theme;
          |""".stripMargin,
            "src/layouts/Base.ts"
          ).moreCode("""{ "dependencies": { "astro": "^5.0.0" } }""", "package.json"))
          val bridged = cpg.call.code("Astro\\.locals\\.banner").l
          bridged.tag.name.l should contain("framework-input")
          bridged.tag.name.l should contain("via:src/middleware.ts#4")
          // a field middleware set to a constant is no source
          cpg.call.code("Astro\\.locals\\.theme").tag.name.l should not contain "framework-input"
      }
  }
end JsTaintBridgesTest

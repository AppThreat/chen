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
      "not make an instance read of a field a source because a static field of its name is one" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |@Component({ selector: 'app-s', template: '' })
          |export class SComponent {
          |  static orderId = inject(ActivatedRoute).snapshot.paramMap.get('id');
          |  orderId = 'x';
          |  route = inject(ActivatedRoute);
          |  id = this.route.snapshot.paramMap.get('id');
          |  open() { window.open('/ftp/' + this.orderId); window.open('/ftp/' + this.id); }
          |}
          |""".stripMargin,
            "s.component.ts"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("this.id")
          cpg.tag.name("framework-input").call.code.l should not contain "this.orderId"
      }

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

  "Framework links" should {
      "carry a Svelte action's bound value into the action, only where a source reaches it" in {
          val cpg = tagged(code(
            """<script>
          |import { page } from '$app/state';
          |import { tooltip } from './tooltip';
          |</script>
          |<span use:tooltip={page.url.searchParams.get('tip')}>?</span>
          |<span use:tooltip={'Fixed help'}>?</span>
          |""".stripMargin,
            "src/routes/+page.svelte"
          ).moreCode(
            """
          |export function tooltip(node, markup) { node.innerHTML = markup; }
          |""".stripMargin,
            "src/routes/tooltip.ts"
          ).moreCode("""{ "dependencies": { "@sveltejs/kit": "^2.0.0" } }""", "package.json"))
          cpg.method.nameExact("tooltip").parameter.nameExact("markup").tag.name.l should contain(
            "via:src/routes/+page.svelte#5"
          )
      }

      "resolve calls of a SolidStart query to the wrapped function" in {
          val cpg = code(
            """
          |import { query } from '@solidjs/router';
          |export const getUser = query(async (id) => {
          |  const res = await fetch(`https://users.internal/v1/users/${id}`);
          |  return res.json();
          |}, 'user');
          |""".stripMargin,
            "src/lib/api.ts"
          ).moreCode(
            """
          |import { useParams, createAsync } from '@solidjs/router';
          |import { getUser } from '../lib/api';
          |export default function Profile() {
          |  const params = useParams();
          |  const user = createAsync(() => getUser(params.id));
          |  return <p>{user()?.name}</p>;
          |}
          |""".stripMargin,
            "src/routes/profile.tsx"
          )
          tagged(cpg)
          cpg.call.nameExact("getUser").callee(using NoResolve).isMethod.filename.l should contain(
            "src/lib/api.ts"
          )
      }

      "follow an Alpine component's properties, not a sanitising getter's siblings" in {
          val cpg = tagged(code(
            """
          |import Alpine from 'alpinejs';
          |import DOMPurify from 'dompurify';
          |Alpine.data('search', () => ({
          |  q: new URLSearchParams(window.location.search).get('q') ?? '',
          |  get highlighted() { return `<mark>${this.q}</mark>`; },
          |  get clean() { return DOMPurify.sanitize(this.q); },
          |}));
          |""".stripMargin,
            "app.js"
          ).moreCode(
            """<section x-data="search">
          |  <p x-html="highlighted"></p>
          |  <p x-html="clean"></p>
          |</section>
          |""".stripMargin,
            "index.html"
          ).moreCode("""{ "dependencies": { "alpinejs": "^3.14.0" } }""", "package.json"))
          val reads = cpg.call.code("search_data\\.(highlighted|clean)").l
          reads.filter(_.code.endsWith("highlighted")).tag.name.l should contain("framework-input")
          reads.filter(_.code.endsWith("clean")).tag.name.l should not contain "framework-input"
      }

      "take getServerSideProps' props, even through satisfies, into the page" in {
          val cpg = tagged(code(
            """
          |import type { GetServerSideProps } from 'next';
          |export const getServerSideProps = (async (context) => {
          |  const notice = String(context.query.notice ?? '');
          |  return { props: { notice } };
          |}) satisfies GetServerSideProps;
          |export default function Page({ notice }) {
          |  return <div dangerouslySetInnerHTML={{ __html: notice }} />;
          |}
          |""".stripMargin,
            "pages/legacy.tsx"
          ).moreCode("""{ "dependencies": { "next": "^15.0.0" } }""", "package.json"))
          cpg.method.nameExact("getServerSideProps").parameter.nameExact("context").tag.name.l should
              contain("framework-input")
          cpg.method.nameExact("Page").parameter.indexFrom(1).tag.name.l should contain(
            "via:pages/legacy.tsx#4"
          )
      }

      "carry an Options API computed property into the template" in {
          val cpg = tagged(code(
            """<template>
          |  <div v-html="notice"></div>
          |  <div v-html="fixed"></div>
          |</template>
          |<script lang="ts">
          |import { defineComponent } from 'vue'
          |export default defineComponent({
          |  computed: {
          |    notice(): string { return `<p>${this.$route.query.msg ?? ''}</p>` },
          |    fixed(): string { return '<p>hello</p>' },
          |  },
          |})
          |</script>
          |""".stripMargin,
            "src/views/Legacy.vue"
          ).moreCode(
            """{ "dependencies": { "vue": "^3.5.0", "vue-router": "^4.6.0" } }""",
            "package.json"
          ))
          val reads =
              cpg.identifier.nameExact("notice", "fixed").filter(_.lineNumber.exists(_ <= 3)).l
          reads.filter(_.name == "notice").tag.name.l should contain("framework-input")
          reads.filter(_.name == "fixed").tag.name.l should not contain "framework-input"
      }

      "resolve a handler looked up in a Map to the functions registered in it" in {
          val cpg = code(
            """
          |const routes = new Map();
          |export function route(name, handler) { routes.set(name, handler); }
          |export function start(outlet) {
          |  const current = { param: location.hash.slice(1) };
          |  const handler = routes.get('home');
          |  handler(outlet, current);
          |}
          |""".stripMargin,
            "router.js"
          ).moreCode(
            """
          |export function home(outlet, { param }) { outlet.innerHTML = param; }
          |""".stripMargin,
            "views.js"
          ).moreCode(
            """
          |import { route } from './router.js';
          |import * as views from './views.js';
          |route('home', views.home);
          |""".stripMargin,
            "main.js"
          )
          tagged(cpg)
          cpg.call.nameExact("handler").callee(using NoResolve).isMethod.name.l should contain(
            "home"
          )
          val sink = cpg.call.nameExact(Operators.assignment).code("outlet\\.innerHTML = param")
          show(sink.reachableByFlows(cpg.call.code("location\\.hash"))) should not be empty
      }
  }

  "Ember templates" should {
      def emberApp =
          code(
            """
          |import Route from '@ember/routing/route';
          |export default class PostRoute extends Route {
          |  async model(params) {
          |    const slug = params.post_id;
          |    return { slug, title: 'Hello' };
          |  }
          |}
          |""".stripMargin,
            "app/routes/post.js"
          ).moreCode(
            """
          |import PostHeader from 'docs-app/components/post-header';
          |<template>
          |  <PostHeader @slug={{@model.slug}} @title={{@model.title}} />
          |</template>
          |""".stripMargin,
            "app/templates/post.gjs"
          ).moreCode(
            """
          |import Component from '@glimmer/component';
          |import { htmlSafe } from '@ember/template';
          |export default class PostHeader extends Component {
          |  get crumb() { return `<b>${this.args.slug}</b>`; }
          |  get heading() { return htmlSafe(this.crumb); }
          |  get title() { return htmlSafe(this.args.title); }
          |  <template><h1>{{this.heading}}</h1></template>
          |}
          |""".stripMargin,
            "app/components/post-header.gjs"
          ).moreCode(
            """
          |import Controller from '@ember/controller';
          |export default class SearchController extends Controller {
          |  queryParams = ['q'];
          |  q = '';
          |}
          |""".stripMargin,
            "app/controllers/search.js"
          ).moreCode(
            """<p>{{this.q}}</p>
          |<p>{{{this.q}}}</p>
          |""".stripMargin,
            "app/templates/search.hbs"
          ).moreCode(
            """
          |import { modifier } from 'ember-modifier';
          |export default modifier((element, [markup]) => {
          |  element.innerHTML = markup;
          |});
          |""".stripMargin,
            "app/modifiers/inner-html.js"
          ).moreCode(
            """
          |import Component from '@glimmer/component';
          |import { service } from '@ember/service';
          |import innerHtml from 'docs-app/modifiers/inner-html';
          |export default class Snippet extends Component {
          |  @service router;
          |  get snippet() { return this.router.currentRoute.queryParams.s; }
          |  <template><div {{innerHtml this.snippet}}></div></template>
          |}
          |""".stripMargin,
            "app/components/snippet.gjs"
          ).moreCode(
            """{ "name": "docs-app", "exports": { "./*": "./app/*" }, "dependencies": { "ember-source": "~6.12.0" } }""",
            "package.json"
          )

      "carry a route's model through its template and a component's arguments to a getter" in {
          val cpg = tagged(emberApp)
          // `@model.slug` is the route's `params.post_id`; `@model.title` a constant
          val args = cpg.tag.name("framework-input").call
              .filter(_.file.name.headOption.contains("app/components/post-header.gjs")).code.l
          args should contain("this.args.slug")
          args should not contain "this.args.title"
          // a getter read is what the getter returns, and says where that came from
          val crumb = cpg.call.code("this\\.crumb").filter(_.inCall.name.contains("htmlSafe")).l
          crumb.tag.name.l should contain("framework-input")
          crumb.tag.name.filter(_.startsWith("via:app/routes/post.js")).l should not be empty
          val sink = cpg.call.nameExact("htmlSafe").code("htmlSafe\\(this\\.crumb\\)")
          show(sink.reachableByFlows(crumb.iterator)) should not be empty
      }

      "make a controller's query parameter the route template's this, and {{{x}}} the sink" in {
          val cpg = tagged(emberApp)
          val raw = cpg.tag.name("xss").call.filter(
            _.file.name.headOption.contains("app/templates/search.hbs")
          ).l
          raw.map(_.code) shouldBe List("{this.q}")
          raw.flatMap(_.lineNumber).map(_.intValue) shouldBe List(2)
          // the read says it is the controller's `queryParams` entry
          val q = cpg.call.code("this\\.q").filter(
            _.file.name.headOption.contains("app/templates/search.hbs")
          ).l
          q.tag.name.l should contain("framework-input")
          q.tag.name.filter(_.startsWith("via:app/controllers/search.js")).l should not be empty
      }

      "hand a modifier the values a template invokes it with" in {
          val cpg = tagged(emberApp)
          cpg.method.filename("app/modifiers/inner-html.js").parameter.tag.name("framework-input")
              .l should not be empty
          val sink = cpg.call.code("element\\.innerHTML = markup")
          show(sink.reachableByFlows(cpg.tag.name("framework-input").parameter)) should not be empty
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

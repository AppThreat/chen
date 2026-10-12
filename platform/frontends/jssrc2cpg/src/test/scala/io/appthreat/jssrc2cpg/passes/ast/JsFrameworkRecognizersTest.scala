package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** The framework recognizers of `taggers/js`: Angular, React and its kin, Vue/Nuxt and Nitro,
  * Svelte, Lit, jQuery, Ember and Node.js on the server side.
  */
class JsFrameworkRecognizersTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def flows(cpg: Cpg, sinkTag: String, sourceTag: String = "framework-input"): Int =
    val sinks = cpg.tag.name(sinkTag).call.l ++ cpg.tag.name(sinkTag).identifier.l
    val sources =
        cpg.tag.name(sourceTag).call.l ++ cpg.tag.name(sourceTag).parameter.l ++
            cpg.tag.name(sourceTag).identifier.l
    sinks.iterator.reachableByFlows(sources.iterator).size

  "Angular" should {
      "type injected route, location and HTTP members, whatever they are called" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute, Router } from '@angular/router';
          |import { Location } from '@angular/common';
          |@Component({ selector: 'app-x', template: '' })
          |export class XComponent {
          |  private readonly ar = inject(ActivatedRoute);
          |  private readonly loc = inject(Location);
          |  constructor(private nav: Router) {}
          |  ngOnInit() {
          |    const q = this.ar.snapshot.queryParams.q;
          |    this.ar.paramMap.subscribe(pm => console.log(pm.get('id')));
          |    const path = this.loc.path();
          |    const url = this.nav.url;
          |  }
          |}
          |""".stripMargin,
            "x.component.ts"
          ))
          val inputs = cpg.tag.name("framework-input").call.code.l
          (inputs should contain).allOf(
            "this.ar.snapshot.queryParams",
            "this.ar.snapshot.queryParams.q",
            "this.loc.path()",
            "this.nav.url"
          )
          cpg.tag.name("framework-input").parameter.name.l shouldBe List("pm")
      }

      "carry HttpClient responses through a service method to the subscriber, not tag the request" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { DomSanitizer } from '@angular/platform-browser';
          |import { FeedService } from './feed.service';
          |@Component({ selector: 'app-feed', template: '' })
          |export class FeedComponent {
          |  private feeds = inject(FeedService);
          |  constructor(private sanitizer: DomSanitizer) {}
          |  load() {
          |    this.feeds.latest().subscribe({ next: (item) => {
          |      this.html = this.sanitizer.bypassSecurityTrustHtml(item.body);
          |    }});
          |  }
          |}
          |""".stripMargin,
            "feed.component.ts"
          ).moreCode(
            """
          |import { Injectable } from '@angular/core';
          |import { HttpClient } from '@angular/common/http';
          |@Injectable({ providedIn: 'root' })
          |export class FeedService {
          |  constructor(private http: HttpClient) {}
          |  latest() { return this.http.get('/api/feed').pipe(map((r) => r.items)); }
          |}
          |""".stripMargin,
            "feed.service.ts"
          ))
          cpg.tag.name("service-ingress").parameter.name.l.sorted shouldBe List("item", "r")
          cpg.tag.name("service-ingress").call.code.l shouldBe empty
          flows(cpg, "framework-output", "service-ingress") should be > 0
      }

      "carry service responses combined by forkJoin to the subscriber" in {
          val cpg = tagged(code(
            """
          |import { Component } from '@angular/core';
          |import { forkJoin } from 'rxjs';
          |import { ProductService } from './product.service';
          |@Component({ selector: 'app-s', template: '' })
          |export class SComponent {
          |  constructor (private readonly productService: ProductService) {}
          |  load () {
          |    const products = this.productService.search('')
          |    const counts = this.productService.counts()
          |    forkJoin([counts, products]).subscribe({
          |      next: ([counts, products]) => { this.render(products) }
          |    })
          |  }
          |  render (p) {}
          |}
          |""".stripMargin,
            "s.component.ts"
          ).moreCode(
            """
          |import { Injectable } from '@angular/core';
          |import { HttpClient } from '@angular/common/http';
          |@Injectable({ providedIn: 'root' })
          |export class ProductService {
          |  constructor (private readonly http: HttpClient) {}
          |  search (q: string) { return this.http.get(`/rest/products/search?q=${q}`) }
          |  counts () { return this.http.get('/api/counts') }
          |}
          |""".stripMargin,
            "product.service.ts"
          ))
          // the callback that destructures the combined values reuses the outer names; the outer
          // `products` is still the service call's result
          cpg.tag.name("service-ingress").parameter.method.filename.l should contain(
            "s.component.ts"
          )
      }

      "tag Renderer2 and @HostListener('window:message') boundaries, and sanitize() as a sanitiser" in {
          val cpg = tagged(code(
            """
          |import { Component, HostListener, Renderer2, ElementRef, SecurityContext } from '@angular/core';
          |import { DomSanitizer } from '@angular/platform-browser';
          |@Component({ selector: 'app-m', template: '' })
          |export class MComponent {
          |  constructor(private r: Renderer2, private el: ElementRef, private s: DomSanitizer) {}
          |  @HostListener('window:message', ['$event'])
          |  onMessage(event: MessageEvent) {
          |    this.r.setProperty(this.el.nativeElement, 'innerHTML', event.data);
          |    const clean = this.s.sanitize(SecurityContext.HTML, event.data);
          |  }
          |}
          |""".stripMargin,
            "m.component.ts"
          ))
          cpg.tag.name("framework-input").parameter.name.l shouldBe List("event")
          cpg.tag.name("xss").call.name.l shouldBe List("setProperty")
          cpg.tag.name("sanitizer-xss").call.name.l shouldBe List("sanitize")
          flows(cpg, "framework-output") should be > 0
      }

      "tag model() signal inputs like input()" in {
          val cpg = tagged(code(
            """
          |import { Component, model } from '@angular/core';
          |@Component({ selector: 'app-n', template: '' })
          |export class NComponent {
          |  notes = model('');
          |  read() { return this.notes(); }
          |}
          |""".stripMargin,
            "n.component.ts"
          ))
          cpg.tag.name("framework-input").member.name.l shouldBe List("notes")
          cpg.tag.name("framework-input").call.code.l shouldBe List("this.notes")
      }

      "resolve a call into the project's own injected service to the service's method" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |import { ProductService } from './product.service';
          |@Component({ selector: 'app-p', template: '' })
          |export class PComponent {
          |  private route = inject(ActivatedRoute);
          |  constructor(private products: ProductService) {}
          |  ngOnInit() { this.products.feed(this.route.snapshot.queryParams.src); }
          |}
          |""".stripMargin,
            "p.component.ts"
          ).moreCode(
            """
          |import { Injectable, inject } from '@angular/core';
          |import { HttpClient } from '@angular/common/http';
          |@Injectable({ providedIn: 'root' })
          |export class ProductService {
          |  private http = inject(HttpClient);
          |  feed(src: string) { return this.http.get(src); }
          |}
          |""".stripMargin,
            "product.service.ts"
          ))
          val feed = cpg.call.nameExact("feed").l
          feed.callee(using NoResolve).fullName.l.exists(_.contains("ProductService")) shouldBe true
          flows(cpg, "http-client") should be > 0
      }

      "tag resource URLs, form changes, host metadata handlers and navigateByUrl" in {
          val cpg = tagged(code(
            """
          |import { Component, inject, input } from '@angular/core';
          |import { httpResource } from '@angular/common/http';
          |import { FormControl } from '@angular/forms';
          |import { Router } from '@angular/router';
          |@Component({
          |  selector: 'app-r',
          |  template: '',
          |  host: { '(window:message)': 'onMessage($event)' }
          |})
          |export class RComponent {
          |  private router = inject(Router);
          |  cdn = input('');
          |  id = input('');
          |  item = httpResource(() => this.cdn() + '/items.json');
          |  query = httpResource(() => '/api/items?id=' + this.id());
          |  q = new FormControl('');
          |  ngOnInit() { this.q.valueChanges.subscribe(v => this.router.navigateByUrl(v)); }
          |  onMessage(e: MessageEvent) { this.router.navigateByUrl('/home'); }
          |}
          |""".stripMargin,
            "r.component.ts"
          ))
          // a host the component is configured with decides the target, a value in the query not
          cpg.tag.name("http-client").call.code.l shouldBe List("this.cdn()")
          (cpg.tag.name("framework-input").parameter.name.l should contain).allOf("v", "e")
          cpg.tag.name("redirect").call.code.l shouldBe List("this.router.navigateByUrl(v)")
      }
  }

  "Angular templates" should {
      "treat bindings as sanitised, reach a bypassing pipe, and tag links and ngModel fields" in {
          val cpg = tagged(code(
            """
          |import { Component, input, inject, Pipe } from '@angular/core';
          |import { DomSanitizer } from '@angular/platform-browser';
          |@Pipe({ name: 'safeHtml' })
          |export class SafeHtmlPipe {
          |  private sanitizer = inject(DomSanitizer);
          |  transform(value: string) { return this.sanitizer.bypassSecurityTrustHtml(value); }
          |}
          |@Component({ selector: 'app-e', templateUrl: './e.component.html', imports: [SafeHtmlPipe] })
          |export class EComponent {
          |  readonly caption = input('');
          |  readonly note = input('');
          |  readonly partner = input('');
          |  term = '';
          |  preview() { document.getElementById('p')!.innerHTML = this.term; }
          |}
          |""".stripMargin,
            "src/app/e.component.ts"
          ).moreCode(
            """<figure>
          |  <figcaption [innerHTML]="caption() | safeHtml"></figcaption>
          |  <p [innerHTML]="note()"></p>
          |  <a [href]="partner()">Partner</a>
          |  <svg><image [attr.href]="partner()" /></svg>
          |  <input [(ngModel)]="term" />
          |</figure>
          |""".stripMargin,
            "src/app/e.component.html"
          ))
          // the pipe is its class's transform; a plain [innerHTML] binding is no sink
          cpg.call.nameExact("safeHtml").callee(using NoResolve).name.l should contain("transform")
          flows(cpg, "xss") should be > 0
          cpg.tag.name("xss").call.code.l.filter(_.contains("note")) shouldBe empty
          // a link the user clicks to another site is no redirect, nor an SVG image's href
          cpg.tag.name("redirect").call.l shouldBe empty
          // ngModel writes the field with what the user typed
          cpg.tag.name("framework-input").call.code.l should contain("this.term")
      }
  }

  "Vue stores and composables" should {
      "carry a value through a Pinia setup store and a composable's derivation" in {
          val cpg = tagged(code(
            """
          |import { defineStore } from 'pinia';
          |import { ref, computed } from 'vue';
          |export const useSearchStore = defineStore('search', () => {
          |  const term = ref('');
          |  const highlighted = computed(() => `<mark>${term.value}</mark>`);
          |  function setTerm(v) { term.value = v; }
          |  return { term, highlighted, setTerm };
          |});
          |""".stripMargin,
            "src/stores/search.ts"
          ).moreCode(
            """
          |import { computed } from 'vue';
          |import { useRoute } from 'vue-router';
          |export function useQueryParam(name) {
          |  const route = useRoute();
          |  return computed(() => route.query[name]);
          |}
          |""".stripMargin,
            "src/composables/query.ts"
          ).moreCode(
            """
          |import { useRoute } from 'vue-router';
          |import { useSearchStore } from '../stores/search';
          |import { useQueryParam } from '../composables/query';
          |const route = useRoute();
          |const store = useSearchStore();
          |store.setTerm(route.query.q);
          |const tab = useQueryParam('tab');
          |export function render(el) { el.innerHTML = store.highlighted; el.outerHTML = tab.value; }
          |""".stripMargin,
            "src/views/search.ts"
          ))
          cpg.call.nameExact("useSearchStore").callee(using NoResolve).isMethod.l should not be empty
          cpg.call.nameExact("setTerm").callee(using NoResolve).isMethod.fullName.l
              .exists(_.contains("stores/search.ts")) shouldBe true
          cpg.call.nameExact("useQueryParam").callee(using NoResolve).fullName.l
              .exists(_.contains("composables/query.ts")) shouldBe true
          // the store's derived state is a source because setTerm is called with the route query
          cpg.tag.name("framework-input").call.code.l.exists(
            _.startsWith("computed(() => `<mark>")
          ) shouldBe true
      }
  }

  "React and Next.js" should {
      "tag server functions, form actions and request readers" in {
          val cpg = tagged(code(
            """
          |'use server';
          |import { cookies, headers } from 'next/headers';
          |import { redirect } from 'next/navigation';
          |export async function save(formData) {
          |  const next = formData.get('next');
          |  const theme = (await cookies()).get('theme');
          |  redirect(next);
          |}
          |""".stripMargin,
            "app/actions.ts"
          ))
          cpg.tag.name("framework-input").parameter.name.l shouldBe List("formData")
          cpg.tag.name("framework-input").call.name.l shouldBe List("cookies")
          cpg.tag.name("redirect").call.code.l shouldBe List("redirect(next)")
          flows(cpg, "redirect") should be > 0
      }

      "tag a navigation through a hook result called in a nested handler" in {
          val cpg = tagged(code(
            """
          |import { useNavigate, useSearchParams } from 'react-router-dom';
          |export default function Go() {
          |  const [params] = useSearchParams();
          |  const navigate = useNavigate();
          |  const to = params.get('to');
          |  function go() { navigate(to); }
          |  function home() { navigate('/home'); }
          |  return <button onClick={go}>go</button>;
          |}
          |""".stripMargin,
            "go.jsx"
          ))
          cpg.tag.name("redirect").call.code.l shouldBe List("navigate(to)")
          flows(cpg, "redirect") should be > 0
      }

      "make useActionState's state the action's return value" in {
          val cpg = tagged(code(
            """
          |import { useActionState } from 'react';
          |async function save(prev, formData) { return String(formData.get('sig')); }
          |export default function Profile() {
          |  const [sig, action] = useActionState(save, '');
          |  return <div dangerouslySetInnerHTML={{ __html: sig }} />;
          |}
          |""".stripMargin,
            "profile.jsx"
          ))
          cpg.tag.name("framework-input").parameter.name.l should contain("formData")
          cpg.tag.name("framework-input").identifier.name.l should contain("sig")
      }

      "resolve useLoaderData to the loader its type argument names" in {
          val cpg = tagged(code(
            """
          |import { useLoaderData } from 'react-router';
          |export async function previewLoader({ request }) {
          |  const url = new URL(request.url);
          |  return { draft: url.searchParams.get('draft') ?? '' };
          |}
          |export function Preview() {
          |  const { draft } = useLoaderData<typeof previewLoader>();
          |  return <div dangerouslySetInnerHTML={{ __html: draft }} />;
          |}
          |""".stripMargin,
            "preview.tsx"
          ).moreCode(
            """
          |import { createBrowserRouter } from 'react-router';
          |import { Preview, previewLoader } from './preview';
          |export const router = createBrowserRouter([
          |  { path: '/preview', loader: previewLoader, Component: Preview }
          |]);
          |""".stripMargin,
            "router.tsx"
          ))
          // the hook is resolved to the loader: the engine carries the loader's return value out
          val hook = cpg.call.nameExact("useLoaderData").l.head
          hook.methodFullName shouldBe "preview.tsx::program:previewLoader"
          flows(cpg, "framework-output") should be > 0
      }

      "tag history state read off useLocation" in {
          val cpg = tagged(code(
            """
          |import { useLocation } from 'react-router';
          |export function Go() {
          |  const location = useLocation();
          |  const state = location.state;
          |  return <button onClick={() => window.open(state.returnTo)}>go</button>;
          |}
          |""".stripMargin,
            "go.jsx"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("location.state")
      }

      "neutralise members a zod validateSearch schema types as a number" in {
          val cpg = tagged(code(
            """
          |import { createFileRoute } from '@tanstack/react-router';
          |import { z } from 'zod';
          |const searchSchema = z.object({
          |  q: z.string().catch(''),
          |  page: z.number().int().positive().catch(1),
          |});
          |export const Route = createFileRoute('/search')({
          |  validateSearch: searchSchema,
          |});
          |function SearchComponent() {
          |  const search = Route.useSearch();
          |  const page = search.page;
          |  const q = search.q;
          |  return <div>{q}</div>;
          |}
          |""".stripMargin,
            "search.tsx"
          ))
          // a number carries nothing to inject; a string schema neutralises nothing
          cpg.tag.name("predicate").call.code.l shouldBe List("search.page")
      }
  }

  "Vue, Nuxt and Nitro" should {
      "tag the Options API route and props, guards and external navigation" in {
          val cpg = tagged(code(
            """
          |import { defineComponent } from 'vue';
          |import { createRouter } from 'vue-router';
          |export default defineComponent({
          |  props: ['title'],
          |  methods: {
          |    show() { return this.$route.query.msg + this.title; }
          |  }
          |});
          |const router = createRouter({ routes: [] });
          |router.beforeEach((to, from) => { window.location.href = to.query.next; });
          |""".stripMargin,
            "legacy.js"
          ))
          val inputs = cpg.tag.name("framework-input").call.code.l
          (inputs should contain).allOf(
            "this.$route",
            "this.$route.query",
            "this.$route.query.msg",
            "this.title"
          )
          cpg.tag.name("framework-input").parameter.name.l should contain("to")
          flows(cpg, "redirect") should be > 0
      }

      "tag h3 readers and sinks in a Nitro handler" in {
          val cpg = tagged(code(
            """
          |export default defineEventHandler(async (event) => {
          |  const { url, next } = getQuery(event);
          |  const data = await $fetch(url);
          |  const item = await useStorage().getItem(next);
          |  if (!data) return sendRedirect(event, next);
          |  return `<p>${data}</p>`;
          |});
          |""".stripMargin,
            "server/api/proxy.get.ts"
          ))
          cpg.tag.name("framework-input").call.name.l should contain("getQuery")
          cpg.tag.name("ssrf").identifier.map(i => s"${i.name} ${i.inCall.code.head}").l shouldBe
              List("url $fetch(url)")
          cpg.tag.name("file-io").call.name.l shouldBe List("getItem")
          cpg.tag.name("redirect").call.name.l shouldBe List("sendRedirect")
          cpg.ret.where(_.tag.name("xss")).code.l shouldBe List("return `<p>${data}</p>`")
      }

      "resolve inject to the callback behind provide's computed value" in {
          val cpg = tagged(code(
            """
          |import { computed, provide, useRoute } from 'vue-router';
          |import { AnnouncementKey } from './keys';
          |export default {
          |  setup() {
          |    const route = useRoute();
          |    const announcement = computed(() => String(route.query.announce ?? ''));
          |    provide(AnnouncementKey, announcement);
          |  }
          |}
          |""".stripMargin,
            "app.vue"
          ).moreCode(
            """
          |import { inject } from 'vue';
          |import { AnnouncementKey } from './keys';
          |export default {
          |  setup() {
          |    const announcement = inject(AnnouncementKey, '');
          |    return { announcement };
          |  }
          |}
          |""".stripMargin,
            "bar.vue"
          ))
          val injectCall = cpg.call.nameExact("inject").l.head
          injectCall.methodFullName should endWith("setup:anonymous")
      }

      "resolve a Nitro runTask call to the task file's run method" in {
          val cpg = tagged(code(
            """
          |export default defineEventHandler(async (event) => {
          |  const body = await readBody(event);
          |  const { result } = await runTask('db:reindex', { payload: { index: body.index } });
          |  return { result };
          |});
          |""".stripMargin,
            "server/api/admin/reindex.post.ts"
          ).moreCode(
            """
          |import { execSync } from 'node:child_process';
          |export default defineTask({
          |  meta: { name: 'db:reindex' },
          |  run({ payload }) {
          |    const output = execSync(`./bin/reindex --index ${payload.index}`).toString();
          |    return { result: output };
          |  }
          |});
          |""".stripMargin,
            "server/tasks/db/reindex.ts"
          ))
          val runTaskCall = cpg.call.nameExact("runTask").l.head
          runTaskCall.methodFullName shouldBe "server/tasks/db/reindex.ts::program:run"
          flows(cpg, "shell-exec") should be > 0
      }
  }

  "Data functions" should {
      "keep a loader a route whose return value is no response" in {
          val cpg = tagged(code(
            """
          |import { useLoaderData } from 'react-router';
          |export async function loader({ params }) { return { id: params.id }; }
          |export default function Item() { const data = useLoaderData(); return <p>{data.id}</p>; }
          |""".stripMargin,
            "app/routes/item.tsx"
          ).moreCode(
            """
          |export async function loader({ params }) { return new Response(params.id); }
          |""".stripMargin,
            "app/routes/raw.tsx"
          ))
          cpg.tag.name("framework-route").method.filename.l.sorted shouldBe
              List("app/routes/item.tsx", "app/routes/raw.tsx")
          // a resource route (no component) answers the request with its return value
          cpg.tag.name("framework-data").method.filename.l shouldBe List("app/routes/item.tsx")
      }

      "carry h3 event.context fields a middleware set from the request" in {
          val cpg = tagged(code(
            """
          |export default defineEventHandler((event) => {
          |  event.context.tenant = getRequestHeader(event, 'x-tenant');
          |  event.context.region = 'eu';
          |});
          |""".stripMargin,
            "server/middleware/tenant.ts"
          ).moreCode(
            """
          |export default defineEventHandler(async (event) => {
          |  const tenant = event.context.tenant;
          |  const region = event.context.region;
          |  return $fetch(`https://${tenant}.internal/config`);
          |});
          |""".stripMargin,
            "server/api/config.get.ts"
          ).moreCode("""{ "dependencies": { "nuxt": "^4.0.0" } }""", "package.json"))
          val reads = cpg.call.code("event\\.context\\.(tenant|region)").filter(
            _.method.filename.contains("api")
          ).l
          reads.filter(_.code.endsWith("tenant")).tag.name.l should contain(
            "via:server/middleware/tenant.ts#3"
          )
          reads.filter(_.code.endsWith("region")).tag.name.l should not contain "framework-input"
      }
  }

  "Node.js on the server" should {
      "tag commands, files and SQL by binding, and leave bound parameters and basename alone" in {
          val cpg = tagged(code(
            """
          |import { exec } from 'node:child_process';
          |import { promisify } from 'node:util';
          |import { readFile } from 'node:fs/promises';
          |import { basename, join } from 'node:path';
          |import pg from 'pg';
          |const run = promisify(exec);
          |const pool = new pg.Pool();
          |export async function handler(req) {
          |  await run(`ping ${req.host}`);
          |  await readFile(join('/srv', basename(req.file)));
          |  await pool.query(`select * from t where a = '${req.a}'`);
          |  await pool.query('select * from t where a = $1', [req.a]);
          |}
          |""".stripMargin,
            "lib/server.ts"
          ))
          cpg.tag.name("shell-exec").call.code.l shouldBe List("run(`ping ${req.host}`)")
          cpg.tag.name("file-io").call.name.l shouldBe List("readFile")
          cpg.tag.name("sanitizer-file-io").call.name.l shouldBe List("basename")
          cpg.tag.name("sql").call.code.l shouldBe List(
            "pool.query(`select * from t where a = '${req.a}'`)"
          )
      }
  }

  "The controller file heuristic" should {
      "leave an API client alone in a frontend repo that carries a mock server" in {
          val cpg = tagged(code(
            """
          |import express from 'express';
          |express().listen(3000);
          |""".stripMargin,
            "mock-server.ts"
          ).moreCode(
            """
          |import { useState } from 'react';
          |export const x = useState;
          |""".stripMargin,
            "app.tsx"
          ).moreCode(
            """
          |export function get(url) { return fetch('/api' + url); }
          |""".stripMargin,
            "lib/api-client.ts"
          ).moreCode(
            """
          |export function list(req, res) { res.send(req.query.q); }
          |""".stripMargin,
            "server/controllers/items-controller.ts"
          ))
          val inputs =
              cpg.tag.name("framework-input").parameter.map(p => s"${p.method.name}.${p.name}").l
          inputs should contain("list.req")
          inputs should not contain "get.url"
      }
  }

  "Package attribution" should {
      "name the npm package behind a sink from the project's manifests, without an SBOM" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |import { DomSanitizer } from '@angular/platform-browser';
          |import axios from 'axios';
          |import { exec } from 'node:child_process';
          |@Component({ selector: 'app-p', template: '' })
          |export class PComponent {
          |  private route = inject(ActivatedRoute);
          |  private sanitizer = inject(DomSanitizer);
          |  load() {
          |    const q = this.route.snapshot.queryParams.q;
          |    this.html = this.sanitizer.bypassSecurityTrustHtml(q);
          |    axios.get(q);
          |    exec(q);
          |  }
          |}
          |""".stripMargin,
            "p.component.ts"
          ).moreCode(
            """{ "name": "p", "dependencies": { "@angular/core": "^20.3.0", "@angular/platform-browser": "^20.3.0", "axios": "~1.7.2" } }""",
            "package.json"
          ).moreCode(
            """{ "lockfileVersion": 3, "packages": { "": {}, "node_modules/axios": { "version": "1.7.9" } } }""",
            "package-lock.json"
          ))
          cpg.tag.name("pkg:npm/.*").call.map(c =>
              s"${c.name} ${c.tag.name("pkg:npm/.*").name.head}"
          ).l shouldBe
              List("bypassSecurityTrustHtml pkg:npm/%40angular/platform-browser@20.3.0")
          // a request is attributed on its URL, the sink
          cpg.tag.name("pkg:npm/.*").identifier.map(i =>
              s"${i.inCall.code.head} ${i.tag.name("pkg:npm/.*").name.head}"
          ).l shouldBe
              List("axios.get(q) pkg:npm/axios@1.7.9")
          // a Node.js built-in is no package, and sources get no purl (it would make them sinks)
          cpg.tag.name("pkg:npm/.*").call.name.l should not contain "exec"
      }
  }

  "Svelte, Lit, jQuery and Ember" should {
      "tag SvelteKit's page state and redirect" in {
          val cpg = tagged(code(
            """
          |import { page } from '$app/state';
          |import { redirect } from '@sveltejs/kit';
          |export function go() {
          |  const next = page.url.searchParams.get('next');
          |  redirect(303, next);
          |}
          |""".stripMargin,
            "src/lib/go.ts"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("page.url.searchParams")
          cpg.tag.name("redirect").call.code.l shouldBe List("redirect(303, next)")
      }

      "resolve a route component's $props to the sibling load" in {
          val cpg = tagged(code(
            """
          |export const load = async ({ params, cookies }) => {
          |  const slug = params.slug;
          |  const motd = cookies.get('motd') ?? '';
          |  return { heading: `Post ${slug}`, motd };
          |};
          |""".stripMargin,
            "src/routes/posts/+page.server.ts"
          ).moreCode(
            """
          |<script>
          |let { data } = $props();
          |</script>
          |<p>{data.heading}</p>
          |<div>{@html data.motd}</div>
          |""".stripMargin,
            "src/routes/posts/+page.svelte"
          ))
          // the page's props are what `load` returned, member by member: `data.motd` holds the
          // cookie, `data.heading` the route parameter - each read says where it came from
          cpg.call.nameExact("$props").tag.name("framework-input").l shouldBe empty
          val reads = cpg.tag.name("framework-input").call
              .filter(_.method.filename.endsWith("+page.svelte")).l
          reads.map(_.code) should contain("data.motd")
          // from the request's cookies (line 2), returned as `motd` (line 5)
          (reads.find(_.code == "data.motd").get.tag.name.l should contain).allOf(
            "via:src/routes/posts/+page.server.ts#2",
            "via:src/routes/posts/+page.server.ts#5"
          )
          // the request's members are the sources in the handler, not the event as a whole
          (cpg.tag.name("framework-input").call.code.l should contain).allOf(
            "param1_0.params",
            "param1_0.cookies"
          )
      }

      "make a transformPageChunk callback's return value an HTML sink" in {
          val cpg = tagged(code(
            """
          |export const handle = async ({ event, resolve }) => {
          |  const lang = event.url.searchParams.get('lang') ?? 'en';
          |  return resolve(event, {
          |    transformPageChunk: ({ html }) => html.replace('%lang%', lang)
          |  });
          |};
          |""".stripMargin,
            "src/hooks.server.ts"
          ))
          cpg.tag.name("xss").call.code.l shouldBe List("html.replace('%lang%', lang)")
      }

      "tag Lit properties, unsafe directives and markup bindings" in {
          val cpg = tagged(code(
            """
          |import { LitElement, html } from 'lit';
          |import { property } from 'lit/decorators.js';
          |import { unsafeHTML } from 'lit/directives/unsafe-html.js';
          |export class Card extends LitElement {
          |  @property() content = '';
          |  render() { return html`<div>${unsafeHTML(this.content)}</div><p .innerHTML=${this.content}></p>`; }
          |}
          |""".stripMargin,
            "card.ts"
          ))
          cpg.tag.name("framework-input").call.code.l should contain("this.content")
          cpg.tag.name("xss").call.name.l should contain("unsafeHTML")
      }

      "tag jQuery markup sinks and ajax responses" in {
          val cpg = tagged(code(
            """
          |function init() {
          |  const hash = location.hash;
          |  $(hash);
          |  $('#title').html(hash);
          |  $.globalEval(hash);
          |  $.ajax({ url: '/api/c', success: function (comments) { $('#c').html(comments); } });
          |  $(function () { console.log('ready'); });
          |}
          |""".stripMargin,
            "app.js"
          ))
          cpg.tag.name("xss").call.code.l.sorted shouldBe List(
            "$('#c').html(comments)",
            "$('#title').html(hash)",
            "$(hash)"
          )
          cpg.tag.name("code-execution").call.code.l shouldBe List("$.globalEval(hash)")
          cpg.tag.name("service-ingress").parameter.name.l shouldBe List("comments")
      }

      "tag Ember's htmlSafe and route model params" in {
          val cpg = tagged(code(
            """
          |import Route from '@ember/routing/route';
          |import { htmlSafe } from '@ember/template';
          |export default class PostRoute extends Route {
          |  model(params) { return htmlSafe(params.slug); }
          |}
          |""".stripMargin,
            "routes/post.js"
          ))
          cpg.tag.name("framework-input").parameter.name.l shouldBe List("params")
          cpg.tag.name("xss").call.name.l shouldBe List("htmlSafe")
      }
  }
end JsFrameworkRecognizersTest

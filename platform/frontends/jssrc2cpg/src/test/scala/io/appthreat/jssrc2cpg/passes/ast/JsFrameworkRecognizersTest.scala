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
    val sinks = cpg.tag.name(sinkTag).call.l
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
          inputs should contain allOf (
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
          inputs should contain allOf ("this.$route", "this.$route.query", "this.$route.query.msg", "this.title")
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
          cpg.tag.name("ssrf").call.code.l shouldBe List("$fetch(url)")
          cpg.tag.name("file-io").call.name.l shouldBe List("getItem")
          cpg.tag.name("redirect").call.name.l shouldBe List("sendRedirect")
          cpg.ret.where(_.tag.name("xss")).code.l shouldBe List("return `<p>${data}</p>`")
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
          cpg.tag.name("sql").call.code.l shouldBe List("pool.query(`select * from t where a = '${req.a}'`)")
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
          cpg.tag.name("pkg:npm/.*").call.map(c => s"${c.name} ${c.tag.name("pkg:npm/.*").name.head}").l.sorted shouldBe
              List(
                "bypassSecurityTrustHtml pkg:npm/%40angular/platform-browser@20.3.0",
                "get pkg:npm/axios@1.7.9"
              )
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
          cpg.tag.name("xss").call.code.l.sorted shouldBe List("$('#c').html(comments)", "$('#title').html(hash)", "$(hash)")
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

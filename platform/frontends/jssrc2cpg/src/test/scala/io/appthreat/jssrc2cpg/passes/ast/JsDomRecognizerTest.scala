package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.{Cpg, Operators}
import io.shiftleft.semanticcpg.language.*

/** The browser platform recognizer (`taggers/js/DomRecognizer`): DOM XSS sources and sinks,
  * navigation, string evaluation, requests and the calls that neutralise a value - plus the
  * precision of EasyTagsPass's Node.js patterns, which frontend code used to trip.
  */
class JsDomRecognizerTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def tagsOf(cpg: Cpg, tag: String): List[String] =
      cpg.tag.name(tag).call.code.l.sorted

  "DOM sources" should {
      "tag location, document and storage reads, and continue them through member chains" in {
          val cpg = tagged(code(
            """
          |function render(el) {
          |  el.innerHTML = location.hash.substring(1);
          |  const q = window.location.search;
          |  const r = document.referrer;
          |  const p = new URLSearchParams(window.location.search).get('p');
          |  const t = localStorage.getItem('t');
          |  const deep = window.location.href.length;
          |}
          |""".stripMargin,
            "dom.js"
          ))
          val inputs = tagsOf(cpg, "framework-input")
          inputs should contain allOf (
            "location.hash",
            "window.location.search",
            "document.referrer",
            "localStorage.getItem('t')",
            "window.location.href",
            "window.location.href.length"
          )
          // a write to location.href is a sink, not a read
          inputs should not contain "el.innerHTML"
      }

      "tag a message event, but not one whose handler checks the origin by equality" in {
          val cpg = tagged(code(
            """
          |window.addEventListener('message', (e) => { document.body.innerHTML = e.data; });
          |window.addEventListener('message', (ev) => {
          |  if (ev.origin !== 'https://app.example') return;
          |  document.body.innerHTML = ev.data;
          |});
          |""".stripMargin,
            "messages.js"
          ))
          cpg.tag.name("framework-input").parameter.name.l shouldBe List("e")
      }

      "reach an innerHTML write from location.hash" in {
          val cpg = tagged(code(
            """
          |function show() {
          |  const h = location.hash.slice(1);
          |  document.getElementById('out').innerHTML = '<b>' + h + '</b>';
          |}
          |""".stripMargin,
            "show.js"
          ))
          val sinks   = cpg.tag.name("framework-output").call.l
          val sources = cpg.tag.name("framework-input").call.l
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
          cpg.tag.name("xss").call.code.l shouldBe List("document.getElementById('out').innerHTML = '<b>' + h + '</b>'")
      }
  }

  "DOM sinks" should {
      "tag markup, navigation and evaluation sinks with their categories" in {
          val cpg = tagged(code(
            """
          |function sinks(el, v, cb) {
          |  el.outerHTML = v;
          |  el.insertAdjacentHTML('beforeend', v);
          |  document.write(v);
          |  el.setAttribute('href', v);
          |  location.href = v;
          |  location.assign(v);
          |  window.open(v);
          |  eval(v);
          |  setTimeout('run(' + v + ')', 1);
          |  setTimeout(cb, 1);
          |  new Function(v);
          |  parent.postMessage(v, '*');
          |  document.cookie = 'c=' + v;
          |}
          |""".stripMargin,
            "sinks.js"
          ))
          tagsOf(cpg, "xss") shouldBe List(
            "document.write(v)",
            "el.insertAdjacentHTML('beforeend', v)",
            "el.outerHTML = v",
            "el.setAttribute('href', v)"
          )
          tagsOf(cpg, "redirect") shouldBe List("location.assign(v)", "location.href = v", "window.open(v)")
          tagsOf(cpg, "code-execution") should contain allOf ("eval(v)", "setTimeout('run(' + v + ')', 1)")
          // a callback is not evaluated
          tagsOf(cpg, "code-execution") should not contain "setTimeout(cb, 1)"
          tagsOf(cpg, "framework-output") should contain allOf (
            "parent.postMessage(v, '*')",
            "document.cookie = 'c=' + v"
          )
      }

      "not tag constants, text writes, object-literal keys or anchored navigation" in {
          val cpg = tagged(code(
            """
          |function safe(el, q) {
          |  el.innerHTML = '<p>static</p>';
          |  el.textContent = q;
          |  const opts = { innerHTML: q, href: q };
          |  location.href = '/search?q=' + q;
          |}
          |""".stripMargin,
            "safe.js"
          ))
          cpg.tag.name("framework-output").call.code.l shouldBe empty
      }

      "tag a request by where its URL can point" in {
          val cpg = tagged(code(
            """
          |async function load(id, url, q, base) {
          |  await fetch(url);
          |  await fetch('/api/search?q=' + q);
          |  await fetch(`/api/items/${id}`);
          |  await fetch(`${base}/items?q=${q}`);
          |  await fetch(`wss://${q}/live`);
          |}
          |""".stripMargin,
            "requests.js"
          ))
          // the whole URL, a path segment (client-side path traversal), a host after a bare scheme;
          // for a variable base only the base is the sink; a value in the query is none
          cpg.tag.name("http-client").call.code.l.sorted shouldBe List(
            "fetch(`/api/items/${id}`)",
            "fetch(`wss://${q}/live`)",
            "fetch(url)"
          )
          cpg.tag.name("http-client").identifier.name.l shouldBe List("base")
      }

      "tag URL bindings in templates unless the code anchors them" in {
          val cpg = tagged(code(
            """
          |export function Link({ url, name }) {
          |  return <div>
          |    <a href={url}>go</a>
          |    <a href={`/profile/${name}`}>me</a>
          |    <iframe src={url} />
          |    <img src={url} />
          |  </div>;
          |}
          |""".stripMargin,
            "link.jsx"
          ))
          cpg.tag.name("xss").call.code.l.size shouldBe 2
      }
  }

  "Sanitisers" should {
      "tag HTML sanitisers, URL encoding, numeric conversions and predicates" in {
          val cpg = tagged(code(
            """
          |import DOMPurify from 'dompurify';
          |function clean(el, v, ALLOWED) {
          |  el.innerHTML = DOMPurify.sanitize(v);
          |  location.href = encodeURIComponent(v);
          |  el.innerHTML = Number(v);
          |  if (Object.hasOwn(ALLOWED, v)) location.href = ALLOWED[v];
          |}
          |""".stripMargin,
            "clean.js"
          ))
          cpg.tag.name("sanitizer-xss").call.code.l.sorted shouldBe List(
            "DOMPurify.sanitize(v)",
            "encodeURIComponent(v)"
          )
          cpg.tag.name("sanitizer").call.code.l should contain("Number(v)")
          cpg.tag.name("predicate").call.code.l shouldBe List("Object.hasOwn(ALLOWED, v)")
      }

      "tag a URL whose origin is compared before use" in {
          val cpg = tagged(code(
            """
          |function go(raw) {
          |  const target = new URL(raw, window.location.origin);
          |  if (target.origin === window.location.origin) window.location.assign(target.href);
          |}
          |""".stripMargin,
            "go.js"
          ))
          cpg.tag.name("sanitizer-redirect").call.code.l shouldBe List(
            "new URL(raw, window.location.origin)"
          )
      }
  }

  "EasyTagsPass Node.js patterns" should {
      "tag a handler's request reads and response calls, and nothing that merely contains the words" in {
          val cpg = tagged(code(
            """
          |const express = require('express');
          |const app = express();
          |app.get('/x', (req, res) => {
          |  const name = req.query.name;
          |  res.send(name);
          |});
          |function frontend(feedbackService, expires, res, db) {
          |  feedbackService.find();
          |  expires.setFullYear(2030);
          |  return res.json();
          |}
          |async function query(db, slug) {
          |  await db.query('select ' + slug);
          |  await db.sql`select ${slug}`;
          |}
          |""".stripMargin,
            "app.js"
          ))
          val outputs = cpg.tag.name("framework-output").call.code.l
          outputs should contain("res.send(name)")
          outputs should contain("db.query('select ' + slug)")
          outputs.filter(_.contains("feedbackService")) shouldBe empty
          outputs.filter(_.contains("setFullYear")) shouldBe empty
          outputs should not contain "res.json()"
          outputs.filter(_.contains("db.sql")) shouldBe empty
          // the registration call is neither a source nor a sink
          (outputs ++ cpg.tag.name("framework-input").call.code.l).filter(_.startsWith("app.get")) shouldBe empty
          cpg.tag.name("framework-input").call.code.l should contain("req.query.name")
      }
  }
end JsDomRecognizerTest

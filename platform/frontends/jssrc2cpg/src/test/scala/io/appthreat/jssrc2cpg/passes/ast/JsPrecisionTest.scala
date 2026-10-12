package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** Where a value is NOT the attacker's: checked by a guard before use, a constant a parent passes
  * to a child, one member of an object whose other member is tainted, a parameter bound to a
  * prepared statement - and where a value IS, though no call carries it: a state setter, a member
  * of what a data function returns.
  */
class JsPrecisionTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def sanitised(cpg: Cpg): List[String] =
      cpg.tag.name("sanitizer").identifier.code.l ++ cpg.tag.name("sanitizer").call.code.l

  "Guards" should {
      "make a ternary over an allow-list check the sanitiser" in {
          val cpg = tagged(code(
            """
          |const DESTINATIONS = ["/", "/login"];
          |export async function action({ request }) {
          |  const next = String((await request.formData()).get("next") ?? "/");
          |  const destination = DESTINATIONS.includes(next) ? next : "/";
          |  return redirect(destination);
          |}
          |""".stripMargin,
            "app/routes/logout.tsx"
          ))
          sanitised(cpg) should contain("""DESTINATIONS.includes(next) ? next : "/"""")
      }

      "validate the reads after an anchored regex check that returns early" in {
          val cpg = tagged(code(
            """
          |const ARITHMETIC = /^[\d\s+*\/().-]+$/;
          |export function evaluate(expression) {
          |  if (!ARITHMETIC.test(expression)) {
          |    return NaN;
          |  }
          |  return new Function(`return (${expression});`)();
          |}
          |""".stripMargin,
            "formula.js"
          ))
          cpg.tag.name("sanitizer").identifier.lineNumber.l.map(_.intValue) shouldBe List(7)
      }

      "follow a type predicate of the project to its allow-list" in {
          val cpg = tagged(code(
            """
          |export const TOPICS = ["billing", "shipping"] as const;
          |export function isTopic(value: string): value is (typeof TOPICS)[number] {
          |  return (TOPICS as readonly string[]).includes(value);
          |}
          |export async function load({ params }) {
          |  const topic = params.topic;
          |  if (!isTopic(topic)) throw new Error("unknown");
          |  return readFile(`help/${topic}.md`);
          |}
          |""".stripMargin,
            "help.ts"
          ))
          cpg.tag.name("sanitizer").identifier.nameExact("topic").lineNumber.l
              .map(_.intValue) shouldBe List(9)
      }

      "not take a prefix check for one" in {
          val cpg = tagged(code(
            """
          |export function go(url) {
          |  if (!url.startsWith("/")) return;
          |  location.href = url;
          |}
          |""".stripMargin,
            "go.js"
          ))
          cpg.tag.name("sanitizer").identifier.l shouldBe empty
      }
  }

  "Component props" should {
      "be what the parents pass, for a component an element renders" in {
          val cpg = tagged(code(
            """
          |export function Promo({ html }) {
          |  return <section dangerouslySetInnerHTML={{ __html: html }} />;
          |}
          |export default function Home() {
          |  const ref = new URLSearchParams(location.search).get("ref");
          |  return <main><p>{ref}</p><Promo html="<b>Free shipping</b>" /></main>;
          |}
          |""".stripMargin,
            "app/home.tsx"
          ))
          cpg.method.nameExact("Promo").parameter.tag.name("framework-input").l shouldBe empty
          // a page no element renders gets its props from outside the code
          cpg.method.nameExact("Home").parameter.l.filter(_.name != "this")
              .flatMap(_.tag.name.l) shouldBe empty
      }

      "name each value an element passes by its prop" in {
          val cpg = code(
            """
          |export function View({ a, b }) { return <i>{a}{b}</i>; }
          |export function Page(x, y) { return <View a={x} b={y} {...rest} />; }
          |""".stripMargin,
            "names.tsx"
          )
          cpg.call.nameExact("<operator>.jsxProps").argument.l
              .map(a => a.code -> a.argumentName) shouldBe List(
            "x"    -> Some("a"),
            "y"    -> Some("b"),
            "rest" -> None
          )
      }
  }

  "Data links" should {
      "carry a route module's loader data to its component member by member" in {
          val cpg = tagged(code(
            """
          |import { Link } from "react-router";
          |export async function loader({ request }) {
          |  const url = new URL(request.url);
          |  return { teaser: DOMPurify.sanitize(url.searchParams.get("t") ?? ""), q: url.searchParams.get("q") };
          |}
          |export default function Article({ loaderData }) {
          |  return <div><p dangerouslySetInnerHTML={{ __html: loaderData.teaser }} />{loaderData.q}</div>;
          |}
          |""".stripMargin,
            "app/routes/article.tsx"
          ))
          val reads = cpg.tag.name("framework-input").call
              .filter(_.method.name == "Article").code.l
          reads should contain("loaderData.q")
          reads should not contain "loaderData.teaser"
      }

      "carry one member of a Pinia store, not its neighbours" in {
          val cpg = tagged(code(
            """
          |import { defineStore } from 'pinia';
          |import { computed } from 'vue';
          |import { useRoute } from 'vue-router';
          |export const useSessionStore = defineStore('session', () => {
          |  const route = useRoute();
          |  const returnUrl = computed(() => String(route.query.returnUrl ?? '/'));
          |  const greeting = computed(() => 'Welcome back');
          |  return { returnUrl, greeting };
          |});
          |""".stripMargin,
            "src/stores/session.ts"
          ).moreCode(
            """
          |import { useSessionStore } from '@/stores/session';
          |export function finish() {
          |  const session = useSessionStore();
          |  document.title = session.greeting;
          |  window.location.assign(session.returnUrl);
          |}
          |""".stripMargin,
            "src/finish.ts"
          ))
          val reads = cpg.tag.name("framework-input").call.filter(_.method.name == "finish").code.l
          reads should contain("session.returnUrl")
          reads should not contain "session.greeting"
      }

      "carry what a state setter is called with to the state's reads" in {
          val cpg = tagged(code(
            """
          |import { useEffect, useState } from "react";
          |export default function Embed() {
          |  const [html, setHtml] = useState("");
          |  useEffect(() => {
          |    window.addEventListener("message", (event) => setHtml(String(event.data.html)));
          |  }, []);
          |  return <iframe srcDoc={html} />;
          |}
          |""".stripMargin,
            "embed.tsx"
          ))
          cpg.tag.name("framework-input").identifier.nameExact("html").l should not be empty
      }
  }

  "Libraries" should {
      "bind the arguments of a statement prepared from a constant" in {
          val cpg = tagged(code(
            """
          |import Database from "better-sqlite3";
          |export const db = new Database("app.db");
          |export function search(term) {
          |  return db.prepare("SELECT id FROM posts WHERE title LIKE ?").all(`%${term}%`);
          |}
          |export function exact(slug) {
          |  return db.prepare(`SELECT id FROM posts WHERE slug = '${slug}'`).get();
          |}
          |""".stripMargin,
            "db.server.ts"
          ))
          // `.all(term)` binds `term` to the `?`
          cpg.tag.name("framework-output|sql").call.nameExact("all").l shouldBe empty
          cpg.tag.name("sql").call.code.l.map(_.take(30)) shouldBe List(
            "db.prepare(`SELECT id FROM pos"
          )
      }

      "make a parse of an all-numeric schema a sanitiser" in {
          val cpg = tagged(code(
            """
          |import { z } from "zod";
          |const Quantity = z.object({ id: z.coerce.number().int(), qty: z.coerce.number() });
          |const Note = z.object({ id: z.coerce.number(), text: z.string() });
          |export async function action({ request }) {
          |  const form = Object.fromEntries(await request.formData());
          |  const parsed = Quantity.safeParse(form);
          |  const note = Note.safeParse(form);
          |  return [parsed, note.data.id, note.data.text];
          |}
          |""".stripMargin,
            "cart.ts"
          ))
          cpg.tag.name("sanitizer").call.name.l should contain("safeParse")
          cpg.tag.name("sanitizer").call.code.l.filter(_.startsWith("Note")) shouldBe empty
          cpg.tag.name("predicate").call.code.l shouldBe List("note.data.id")
      }
  }

  "The engine" should {
      "not hand a plain call's callback the caller's this" in {
          val cpg = code(
            """
          |export function Calc({ total }) {
          |  useEffect(() => { evaluate("1 + 1"); }, [total]);
          |}
          |function evaluate(expression) {
          |  return new Function(`return (${expression});`)();
          |}
          |""".stripMargin,
            "calc.js"
          )
          val sink = cpg.call.code("new Function.*").l
          sink.iterator.reachableByFlows(cpg.parameter.nameExact("param1_0").l.iterator).l shouldBe empty
      }
  }
end JsPrecisionTest

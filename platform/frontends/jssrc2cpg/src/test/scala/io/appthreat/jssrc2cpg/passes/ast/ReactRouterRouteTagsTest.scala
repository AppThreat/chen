package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.dataflowengineoss.language.*
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.semanticcpg.language.*

/** React Router and React component boundary semantics.
  *
  * React registers routes either declaratively as JSX (`<Route path=... element={...}/>`) or as a
  * config object (`createBrowserRouter([{ path, element }])`); the URL reaches components through
  * the `useParams`/`useSearchParams`/`useLocation` hooks, and component data arrives through the
  * props parameter.
  */
class ReactRouterRouteTagsTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def routes(cpg: Cpg): List[String] =
      cpg.method.where(_.tag.name("framework-route")).name.sorted.l

  "React Router JSX routes" should {

      "tag the path attribute of a <Route> element and its component as the handler" in {
          val cpg = tagged(code(
            """
          |import { Route } from 'react-router-dom';
          |function Profile(props) { return <div>{props.name}</div>; }
          |export default function App() {
          |  return <Route path="/profile" element={<Profile />} />;
          |}
          |""".stripMargin,
            "app.jsx"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.l shouldBe List("\"/profile\"")
          // the rendered component is a route entrypoint, and its props parameter web-facing input
          routes(cpg) shouldBe List("Profile")
          cpg.tag.name("framework-input").parameter.name.distinct.l shouldBe List("props")
      }

      "tag the legacy component= attribute form too" in {
          val cpg = tagged(code(
            """
          |import { Route } from 'react-router-dom';
          |function About(p) { return <div/>; }
          |export default <Route path="/about" component={About} />;
          |""".stripMargin,
            "routes.jsx"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.l shouldBe List("\"/about\"")
          routes(cpg) shouldBe List("About")
      }

      "not treat a non-Route element's path attribute as a route" in {
          val cpg = tagged(code(
            """
          |import React from 'react';
          |export default function Svg() {
          |  return <path d="M10 10" />;
          |}
          |""".stripMargin,
            "svg.jsx"
          ))

          cpg.literal.where(_.tag.name("framework-route")).l shouldBe empty
      }
  }

  "React Router hooks" should {

      "tag useParams and useSearchParams calls as framework-input" in {
          val cpg = tagged(code(
            """
          |import { useParams, useSearchParams, useLocation } from 'react-router-dom';
          |export default function Page() {
          |  const { userId } = useParams();
          |  const [params] = useSearchParams();
          |  const loc = useLocation();
          |  return <div>{userId}{params.get('q')}{loc.hash}</div>;
          |}
          |""".stripMargin,
            "page.jsx"
          ))

          cpg.tag.name("framework-input").call.name.sorted.l shouldBe
              List("useLocation", "useParams", "useSearchParams")
      }

      "close a flow from useParams to a raw-HTML render" in {
          val cpg = code(
            """
          |import { useParams } from 'react-router-dom';
          |export default function Profile() {
          |  const { bio } = useParams();
          |  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
          |}
          |""".stripMargin,
            "profile.jsx"
          )
          new ChennaiTagsPass(cpg).createAndApply()
          new EasyTagsPass(cpg).createAndApply()

          val sources = cpg.tag.name("framework-input").call.nameExact("useParams").l
          val sinks   = cpg.tag.name("framework-output").call.l
          sources should not be empty
          sinks should not be empty
          sinks.iterator.reachableByFlows(sources.iterator).size should be > 0
      }
  }

  "React function components" should {

      "tag the props parameter of a capitalized component that renders a template" in {
          val cpg = tagged(code(
            """
          |import React from 'react';
          |function Welcome(props) { return <h1>{props.title}</h1>; }
          |function helper(x) { return x; }
          |""".stripMargin,
            "welcome.jsx"
          ))

          cpg.tag.name("framework-input").parameter.name.distinct.l shouldBe List("props")
      }
  }

  "React Router data routers" should {

      "tag createBrowserRouter route records" in {
          val cpg = tagged(code(
            """
          |import { createBrowserRouter } from 'react-router-dom';
          |function Root() { return <div/>; }
          |const router = createBrowserRouter([
          |  { path: '/', element: <Root /> },
          |  { path: '/dash', element: <div>Dash</div> }
          |]);
          |""".stripMargin,
            "router.jsx"
          ))

          cpg.literal.where(_.tag.name("framework-route")).code.sorted.l shouldBe List(
            "\"/\"",
            "\"/dash\""
          )
      }
  }

  "Next.js file conventions" should {

      "tag HTTP verb exports of an app-router route file" in {
          val cpg = tagged(code(
            """
          |export async function GET(request) { return new Response(request.url); }
          |export async function POST({ params }) { return new Response(params.id); }
          |function helper() { return 1; }
          |""".stripMargin,
            "app/api/users/route.ts"
          ))

          routes(cpg) shouldBe List("GET", "POST")
          // a destructured `{ params }` parameter is renamed by the frontend (param1_0); the
          // file-name heuristic in tagJsRoutes also tags these parameters, so dedup the tags
          cpg.tag.name("framework-input").parameter.name.distinct.sorted.l shouldBe
              List("param1_0", "request")
      }

      "tag every export of a pages/api handler" in {
          val cpg = tagged(code(
            """
          |export default function handler(req, res) { res.send(req.query.q); }
          |""".stripMargin,
            "pages/api/search.js"
          ))

          routes(cpg) shouldBe List("handler")
          cpg.tag.name("framework-input").parameter.name.distinct.sorted.l shouldBe List(
            "req",
            "res"
          )
      }

      "tag page-data loaders and middleware" in {
          val cpg = tagged(code(
            """
          |export async function getServerSideProps(context) {
          |  return { props: { referer: context.req.headers.referer } };
          |}
          |export function middleware(request) { return NextResponse.next(); }
          |""".stripMargin,
            "src/middleware.ts"
          ))

          routes(cpg).sorted.l shouldBe List("getServerSideProps", "middleware")
      }
  }
end ReactRouterRouteTagsTest

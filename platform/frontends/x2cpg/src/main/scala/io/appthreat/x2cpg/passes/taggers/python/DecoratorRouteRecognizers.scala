package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{
    Annotation,
    AnnotationParameterAssign,
    Method
}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** Recognizes decorator-based routing, the shape shared by Flask, FastAPI, Starlette, Sanic, Bottle
  * and aiohttp's RouteTableDef:
  *
  * {{{
  * @app.route("/cmd", methods=["POST"])    @api.post("/items")     @routes.get("/q")
  * def run_cmd():                          async def create(..):   async def handle(request):
  * }}}
  *
  * The decorator surfaces as an `ANNOTATION` node whose LAST dotted segment is an HTTP verb (or
  * `route`), with the route path as the first positional `ANNOTATION_PARAMETER_ASSIGN` and any
  * `methods=[...]` keyword as a keyword assign - all structural facts, no `code` parsing.
  *
  * Emits: `framework-route` on the handler, `route-path`/`http-method` key/value tags on the
  * parameter-assign node, and `framework-input` on every non-self handler parameter.
  */
class DecoratorRouteRecognizer(
  override val name: String,
  gateRoots: Set[String],
  extraVerbs: Set[String] = Set.empty
) extends PythonFrameworkRecognizer:

  private lazy val verbs: Set[String] = ROUTE_VERBS ++ extraVerbs

  def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, gateRoots)

  def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val routeAnnotations =
        cpg.annotation.l.filter(a => verbs.contains(lastSegment(a.name.toLowerCase)))
    routeAnnotations.foreach { annotation =>
        annotation.inAst.collectAll[Method].filter(isUserMethod).foreach { handler =>
          tagHandler(handler)
          routePathAssign(annotation).foreach { case (_, path) =>
              tag(handler, ROUTE_PATH_TAG, stripQuotes(path))
          }
          declaredVerbs(annotation).foreach(verb => tag(handler, HTTP_METHOD_TAG, verb))
        }
    }

  private def stripQuotes(s: String): String =
      if s.length >= 2 && (s.startsWith("\"") && s.endsWith("\"") ||
            s.startsWith("'") && s.endsWith("'"))
      then s.substring(1, s.length - 1)
      else s

  private def routePathAssign(
    annotation: Annotation
  ): Option[(AnnotationParameterAssign, String)] =
      positionalValueAssigns(annotation)
          .find(p => p._2.startsWith("\"") || p._2.startsWith("'"))
end DecoratorRouteRecognizer

/** Flask (`@app.route("/cmd", methods=["POST"])`, `@app.get("/q")`). */
object FlaskRecognizer
    extends DecoratorRouteRecognizer("flask", gateRoots = Set("flask"))

/** FastAPI (`@api.post("/items")`, `@app.get("/search")`). */
object FastAPIRecognizer
    extends DecoratorRouteRecognizer("fastapi", gateRoots = Set("fastapi"))

/** Starlette (`@app.route("/x", methods=["GET"])`). */
object StarletteRecognizer
    extends DecoratorRouteRecognizer("starlette", gateRoots = Set("starlette"))

/** Sanic (`@app.get("/x")`). */
object SanicRecognizer extends DecoratorRouteRecognizer("sanic", gateRoots = Set("sanic"))

/** Bottle (`@app.route("/x")`, bare `@route("/x")`). */
object BottleRecognizer extends DecoratorRouteRecognizer("bottle", gateRoots = Set("bottle"))

/** aiohttp's RouteTableDef (`@routes.get("/x")`) and `web.route`. */
object AiohttpRouteRecognizer
    extends DecoratorRouteRecognizer("aiohttp", gateRoots = Set("aiohttp"))

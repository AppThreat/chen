package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** Helpers for frameworks whose handlers are METHODS OF A CLASS rather than decorated functions:
  * Django CBVs / DRF viewsets, Tornado RequestHandlers and Falcon resources. Entry points are found
  * via `INHERITS_FROM` full names or fixed method-name conventions - never file names.
  */
object ClassBasedRouteRecognizers:

  /** HTTP-verb method names as used by Django CBVs / Tornado handlers (lower case). */
  val VerbMethods: Set[String] =
      Set("get", "post", "put", "patch", "delete", "head", "options")

  /** DRF viewset actions. */
  val DrfActions: Set[String] =
      Set("list", "create", "retrieve", "update", "partial_update", "destroy")

  /** True when the type inherits (transitive names are not resolved; the frontend records the
    * base's last segment, e.g. `grpc.py:<module>.Servicer`) a base whose last segment satisfies
    * `matches`.
    *
    * NB: a class's real methods are NOT `CONTAINS` children of the instance TYPE_DECL (they hang
    * off the synthetic `<body>` scope), so they are collected by their class-qualified full name
    * (`pkg.py:<module>.<Class>.<method>`) instead of `typeDecl.method`.
    */
  def inheritsMatching(cpg: Cpg, matches: String => Boolean): List[Method] =
    val classNames = cpg.typeDecl
        .filter(td => td.inheritsFromTypeFullName.exists(b => matches(lastSegment(b))))
        .name.l
    if classNames.isEmpty then Nil
    else
      val pattern = classNames
          .map(n => "(?s).*\\." + java.util.regex.Pattern.quote(n) + "\\.[^.]+")
          .mkString("|")
      cpg.method.fullName(pattern).filter(isUserMethod).l
end ClassBasedRouteRecognizers

/** Tornado: handlers are methods named after the HTTP verb on `RequestHandler` subclasses (`class
  * MainHandler(tornado.web.RequestHandler): def get(self, ...)`).
  */
object TornadoRecognizer extends PythonFrameworkRecognizer:
  import ClassBasedRouteRecognizers.*

  override val name: String = "tornado"

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("tornado"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val handlers = inheritsMatching(cpg, lastSegmentOf => lastSegmentOf == "RequestHandler")
        .filter(m => VerbMethods.contains(m.name))
    handlers.foreach(m => tagHandler(m))

/** Falcon: resources expose responders named `on_get`, `on_post`, ... (`class Things: def
  * on_get(self, req, resp)`). Falcon resources do not have to inherit anything, so the method-name
  * convention is the structural signal within the falcon-gated project.
  */
object FalconRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "falcon"

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, Set("falcon"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val responders =
        cpg.method.name("on_(get|post|put|patch|delete|head|options)").filterNot(
          _.isExternal
        ).filter(isUserMethod).l
    responders.foreach(m => tagHandler(m))

/** Django function views are covered by [[RequestObjectRecognizer]] (their first parameter is
  * `request` in every web framework). This recognizer covers the class-based shapes that need
  * inheritance facts instead:
  *   - CBVs: `class UserDetail(DetailView)` / `APIView` subclasses with verb methods,
  *   - DRF viewsets (`ViewSet`/`ModelViewSet`...) with the standard action methods,
  *   - DRF function-based views (`@api_view(["GET"])`) and `@action` methods.
  */
object DjangoRecognizer extends PythonFrameworkRecognizer:
  import ClassBasedRouteRecognizers.*

  override val name: String = "django"

  override def applies(cpg: Cpg): Boolean =
      importsAnyOf(cpg, Set("django", "rest_framework"))

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff

    // CBVs / viewsets: base last segment ends in View/ViewSet covers the django generic views,
    // DRF APIView and the *ViewSet family at once.
    val cbvMethods = inheritsMatching(cpg, b => b.endsWith("View") || b.endsWith("ViewSet"))
        .filter(m => VerbMethods.contains(m.name) || DrfActions.contains(m.name))
    cbvMethods.foreach(m => tagHandler(m))

    // DRF function views and viewset actions: `@api_view(["GET"])` / `@action(detail=True)`.
    val drfAnnotations =
        cpg.annotation.l.filter(a =>
            Set("api_view", "action").contains(lastSegment(a.name.toLowerCase))
        )
    drfAnnotations.foreach { annotation =>
        annotation.inAst.collectAll[Method].filter(isUserMethod).foreach(m => tagHandler(m))
    }
end DjangoRecognizer

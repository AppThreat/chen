package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Method, MethodParameterIn}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** B2 - models as taint carriers. A pydantic `BaseModel`, dataclass, attrs class or TypedDict bound
  * to a handler parameter makes EVERY FIELD a source:
  *
  * {{{
  * class Item(BaseModel):
  *     name: str
  *     cmd: str
  * @api.post("/items")
  * async def create(item: Item):
  *     return subprocess.run(item.cmd, shell=True)   # item.cmd must be a source
  * }}}
  *
  * Structure used: `inheritsFromTypeFullName` (`pydantic.py:<module>.BaseModel`), class-level
  * decorator annotations (`@dataclass`, `attr.s`, `attrs.define`), the model's MEMBER nodes (the
  * declared fields), and the handler parameter's declared type annotation (surfaced as
  * `TYPE_FULL_NAME` on the parameter).
  *
  * NB (Task 5 input): field accesses are matched on the receiver's source name (`item.cmd` ->
  * receiver identifier `item`) because identifier typing is still ANY - a proper join would use the
  * receiver's recovered type. Multi-level accesses (`item.meta.cmd`) match by the `item.` code
  * prefix and the final field name.
  */
object ModelTaintRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "model-taint"

  private val GateRoots = Set("pydantic", "dataclasses", "attrs", "attr")

  private val ModelBaseNames = Set("BaseModel", "BaseModelWithConfig", "TypedDict")

  private val ModelDecoratorNames = Set(
    "dataclass",
    "dataclasses.dataclass",
    "define",
    "attrs.define",
    "mutable",
    "frozen"
  )

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, GateRoots)

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff
    val models             = cpg.typeDecl.l.filter(isModel)
    if models.isEmpty then return

    val byShortName = models.groupBy(_.name)

    val carrierParams = cpg.parameter.l.filter { p =>
        !SELF_NAMES.contains(p.name) && isModelType(p, byShortName)
    }

    carrierParams.foreach { p =>
      tag(p, INPUT_TAG)
      // every field access on the carrier parameter is a source
      val fields = byShortName
          .get(shortName(p.typeFullName))
          .map(_.member.name.l.toSet)
          .getOrElse(Set.empty)
      p.method.call.nameExact(Operators.fieldAccess).l.foreach { access =>
          receiverAndField(access).foreach { case (receiver, field) =>
              if receiver == p.name && fields.contains(field) then tag(access, INPUT_TAG)
          }
      }
    }
  end run

  private def isModel(td: io.shiftleft.codepropertygraph.generated.nodes.TypeDecl): Boolean =
      td.inheritsFromTypeFullName.exists(b => ModelBaseNames.contains(lastSegment(b))) ||
          td.annotation.name.l.exists(n =>
              ModelDecoratorNames.contains(n) || ModelDecoratorNames.contains(lastSegment(n))
          )

  private def isModelType(
    p: MethodParameterIn,
    byShortName: Map[String, Seq[io.shiftleft.codepropertygraph.generated.nodes.TypeDecl]]
  ): Boolean =
      if p.typeFullName == null || p.typeFullName.isEmpty || p.typeFullName == "ANY" then false
      else byShortName.contains(shortName(p.typeFullName))

  private def shortName(typeFullName: String): String = lastSegment(typeFullName)

  /** The receiver name and accessed field of a `<operator>.fieldAccess` call, when shaped as
    * `receiver.field` (receiver = identifier or a chain rooted at one).
    */
  private def receiverAndField(access: Call): Option[(String, String)] =
    val args =
        access.argument.l.sortBy(a => if a.argumentIndex < 0 then Int.MaxValue else a.argumentIndex)
    for
      receiver <- args.headOption.map(_.code)
      field    <- args.lift(1).map(_.code)
    yield (receiver, field)
end ModelTaintRecognizer

/** B3 - request objects as handler parameters (`async def search(q, request: Request)`, aiohttp's
  * `async def handle(request)`, Django's `def profile(request)`). This is the parameter form,
  * complementing the module-level proxy access tagging in EasyTagsPass. Django function views are
  * the case that needs it: they carry no decorator and inherit nothing, so the parameter is the
  * only signal there is.
  *
  * Two tiers, because "takes a request" and "is an entry point" are different claims:
  *
  *   - A parameter that IS a request object is tagged `framework-input` unconditionally. That holds
  *     wherever it appears: a request passed into a helper still carries attacker data.
  *   - The method is only tagged `framework-route` - and its OTHER parameters only become sources
  *     - when something corroborates that it is a registered handler. Without that second tier
  *       every `def log_request(request, level)`, `def is_admin(request)` and `def process(self,
  *       request, response)` became an entry point whose every parameter was attacker-controlled,
  *       which put `framework-input` on a response object and made `framework-route` (itself a
  *       source tag) fire on middleware and helpers. That is the same false-positive shape as the
  *       filename-keyed PY_REQUEST_PATTERNS this task deleted, keyed on a parameter name instead of
  *       a file name.
  *
  * Corroboration is structural and cheap: a decorator of any kind, a URL registration naming the
  * method (`path("x/", views.search)`), or a framework response constructor in the body. Every
  * genuine view satisfies at least one - a view that returns no response is not a view.
  *
  * Typed parameters (`request: Request`) carry the type in TYPE_FULL_NAME; untyped parameters are
  * recognized by the framework-wide `request` naming convention. NB (Task 5 input): untyped
  * parameters force a name-based rule - a real type join would use the proxy class of the gating
  * framework, and would also let the second tier drop the response-constructor heuristic.
  */
object RequestObjectRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "request-object"

  private val GateRoots = Set(
    "fastapi",
    "starlette",
    "aiohttp",
    "django",
    "flask",
    "sanic",
    "tornado",
    "bottle",
    "falcon",
    "quart",
    "cherrypy",
    "pyramid"
  )

  private val RequestNames = Set("request", "req")

  /** Calls that register a handler against a URL. The handler is one of the arguments. */
  private val UrlRegistrationCalls =
      Set("path", "re_path", "url", "add_url_rule", "add_route", "register", "add_view")

  /** Framework response constructors. A function that builds one of these is producing an HTTP
    * response, which is what a view does and what a helper does not.
    */
  private val ResponseConstructors = Set(
    "HttpResponse",
    "HttpResponseRedirect",
    "HttpResponseForbidden",
    "HttpResponseNotFound",
    "HttpResponseBadRequest",
    "JsonResponse",
    "StreamingHttpResponse",
    "FileResponse",
    "TemplateResponse",
    "render",
    "render_to_response",
    "redirect",
    "Response",
    "jsonify",
    "make_response",
    "json_response",
    "PlainTextResponse",
    "HTMLResponse",
    "RedirectResponse"
  )

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, GateRoots)

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff

    // Names appearing as arguments of a URL registration, e.g. `path("s/", views.search)` gives
    // `search`. Name-indexed lookups, so this stays cheap on a large project.
    val registeredNames: Set[String] = cpg.call
        .name(UrlRegistrationCalls.mkString("|"))
        .argument
        .code
        .l
        .map(c => lastSegment(c.takeWhile(ch => ch != '(' && ch != ',')).trim)
        .filter(_.nonEmpty)
        .toSet

    cpg.method.internal.l.filter(isUserMethod).foreach { method =>
      val userParams   = method.parameter.l.filterNot(p => SELF_NAMES.contains(p.name))
      val requestParam = userParams.find(isRequest)
      requestParam.foreach { p =>
        // Tier 1: the request object itself is attacker-controlled wherever it is passed.
        tag(p, INPUT_TAG)
        // Tier 2: only a corroborated handler is an entry point with all-parameters-tainted.
        if isRegisteredHandler(method, registeredNames) then
          tag(method, ROUTE_TAG)
          userParams.filterNot(_ == p).foreach(other => tag(other, INPUT_TAG))
      }
    }
  end run

  private def isRegisteredHandler(method: Method, registeredNames: Set[String]): Boolean =
      method.annotation.nonEmpty ||
          registeredNames.contains(method.name) ||
          method.call.name(ResponseConstructors.mkString("|")).nonEmpty

  private def isRequest(p: MethodParameterIn): Boolean =
      RequestNames.contains(p.name) || lastSegment(p.typeFullName) == "Request"
end RequestObjectRecognizer

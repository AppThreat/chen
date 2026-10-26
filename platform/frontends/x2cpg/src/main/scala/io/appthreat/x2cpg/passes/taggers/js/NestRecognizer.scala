package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** NestJS controllers. An HTTP-verb decorator (`@Get()`, `@Post()`, ...) on a method declares the
  * endpoint - there is no `router.get(path, handler)` call to read. The method is the entrypoint,
  * which makes its `return` the response; its parameters are web-facing input, and a request-data
  * decorator (`@Body()`, `@Param()`, `@Query()`, ...) says so wherever it appears, as
  * `@RequestParam` does for Spring.
  *
  * A decorator counts only when its file imports it from `@nestjs/common`, under whatever name.
  * Transpiled output lowers decorators to `__decorate` calls and is not recognised here.
  */
object NestRecognizer extends JsFrameworkRecognizer:

  val name: String = "nest"

  private val Package = "@nestjs/common"

  private val HttpVerbs = Set("Get", "Post", "Put", "Delete", "Patch", "Head", "Options", "All")

  /** The body, a route or query parameter, headers, the client IP, the session. */
  private val RequestData = Set("Body", "Param", "Query", "Headers", "Ip", "Session", "HostParam")

  def applies(ctx: JsContext): Boolean = ctx.modules.uses(Package)

  def run(ctx: JsContext): Unit =
    val files = ctx.modules.filesImporting(Package)
    def decorated(file: String, annotations: Iterator[Annotation], exported: Set[String]) =
        files.contains(file) && annotations.exists(a =>
            exported.exists(e => ctx.modules.localNamesOf(file, Package, e).contains(a.name))
        )
    val handlers =
        ctx.cpg.method.internal.filter(m => decorated(m.filename, m.annotation, HttpVerbs)).l
    ctx.tagger.tag(handlers.iterator, ROUTE)
    ctx.tagger.tag(handlers.iterator.flatMap(params), INPUT)
    ctx.tagger.tag(
      ctx.cpg.parameter.filter(p => decorated(p.method.filename, p.annotation, RequestData)),
      INPUT
    )
end NestRecognizer

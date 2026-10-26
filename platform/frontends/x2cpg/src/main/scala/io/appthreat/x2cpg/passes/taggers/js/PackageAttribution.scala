package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Names the npm package behind each sink the recognizers tagged, with a `pkg:npm/...` purl tag -
  * the attribution `CdxPass` gives from an SBOM, here from the project's own manifests. A request
  * sink - the part of a URL that decides the target - carries the package of the request.
  *
  * The package is the one the callee is bound to: a named or default import (`import { redirect }
  * from 'next/navigation'`), a member of a module binding (`axios.get`, `DOMPurify.sanitize`), a
  * handle made from one (`pool = new pg.Pool()` -> `pool.query`), or - for Angular - the type a
  * member was injected as (`this.sanitizer` from `@angular/platform-browser`). Where none of those
  * names a package, the resolved callee name already carries one (`express:Response:send`). A
  * member read made a sink (`resource.list`) is attributed through its base, by the same rules as a
  * call receiver. The version is the one the project's lockfile resolved (`package-lock.json`,
  * `yarn.lock`, `pnpm-lock.yaml`, `bun.lock`), or else the one the `package.json` range names; a
  * package the lockfiles resolve to more than one version carries no version rather than a guess.
  * Node.js built-ins are no package.
  *
  * Only sinks are attributed: a purl tag is itself a sink tag for reachables (`pkg.*`), so on a
  * source it would make the source a sink too.
  */
object PackageAttribution:

  private val SinkTags =
      Seq(OUTPUT, CODE_EXEC, HTTP_CLIENT, SSRF, "sql", "shell-exec", "file-io")

  private val NodeBuiltins = Set(
    "fs",
    "path",
    "child_process",
    "vm",
    "http",
    "https",
    "url",
    "util",
    "crypto",
    "os",
    "net",
    "tls",
    "zlib",
    "stream",
    "events",
    "buffer",
    "querystring",
    "dns",
    "worker_threads",
    "sqlite"
  )

  def run(ctx: JsContext, typeOf: Expression => Option[JsTypeRef]): Unit =
    val versions = ctx.project.resolvedVersions
    // A sink call is attributed itself; a request sink is the part of the URL that decides the
    // target (`q` in `axios.get(q)`), attributed to the request it is passed to. A member read
    // made a sink is attributed through its base. A sink tagged by an earlier pass counts too:
    // EasyTagsPass's response and SDK sinks are in the graph, not in this run's memo.
    val requestSinkIds = ctx.tagger.taggedIds(HTTP_CLIENT, SSRF).toSet ++
        ctx.cpg.tag.name(HTTP_CLIENT, SSRF).l.flatMap(_._taggedByIn.collect {
            case e: Expression => e.id()
        })
    val sinkIds = ctx.tagger.taggedIds(SinkTags*).toSet ++
        ctx.cpg.tag.name(SinkTags*).l.flatMap(_._taggedByIn.collect {
            case e: Expression => e.id()
        })
    val attributed = sinkIds.iterator
        .flatMap(id => Option(ctx.cpg.graph.node(id)))
        .flatMap {
            case e: Expression if requestSinkIds.contains(e.id()) && requestOf(e).nonEmpty =>
                requestOf(e).map(request => packageOf(ctx, request, typeOf) -> e)
            case c: Call if c.name == Operators.fieldAccess =>
                fieldBase(c).map(base => packageOfBase(ctx, base, typeOf) -> c)
            case c: Call if !c.name.startsWith("<operator>") =>
                Some(packageOf(ctx, c, typeOf) -> c)
            case _ => None
        }
    // With manifests in the project, a module they do not declare is no package of it - a
    // tsconfig path alias (`@components/x`), a workspace-relative import.
    val declared = ctx.project.dependencies.keySet ++ versions.keySet
    attributed.foreach { (pkg, sink) =>
        pkg.filterNot(isBuiltin)
            .filter(p => declared.isEmpty || declared.contains(p)).foreach { p =>
                ctx.tagger.tag(Iterator(sink), purl(p, versions.get(p)))
            }
    }
  end run

  private val UrlOperators = Set(
    Operators.addition,
    Operators.formatString,
    "<operator>.formattedValue",
    Operators.conditional,
    Operators.logicalOr
  )

  /** The call a URL part is an argument of, through the operators that build the URL. */
  private def requestOf(e: Expression): Option[Call] =
      e.astParent match
        case c: Call if UrlOperators.contains(c.name)                            => requestOf(c)
        case c: Call if !c.name.startsWith("<operator>") && e.argumentIndex >= 1 => Some(c)
        case _                                                                   => None

  private def isBuiltin(pkg: String): Boolean =
      NodeBuiltins.contains(pkg) || NodeBuiltins.contains(pkg.stripPrefix("node:"))

  /** `pkg:npm/%40angular/core@20.3.0`: the scope's `@` percent-encoded, as the purl spec asks. */
  def purl(pkg: String, version: Option[String]): String =
    val name = if pkg.startsWith("@") then "%40" + pkg.drop(1) else pkg
    version.filter(_.nonEmpty).map(v => s"pkg:npm/$name@$v").getOrElse(s"pkg:npm/$name")

  private def packageOf(
    ctx: JsContext,
    call: Call,
    typeOf: Expression => Option[JsTypeRef]
  ): Option[String] =
    val file = call.method.filename
    def binding(local: String): Option[String] =
        ctx.modules.resolve(file, local).flatMap(_.packageName)
    val callee = call.receiver.headOption.flatMap(memberPath)
    val fromReceiver = callee match
      // `redirect(url)`, `exec(cmd)`, `$(html)`
      case Some(List(local)) => binding(local)
      // `axios.get(url)`, `DOMPurify.sanitize(x)`, `this.sanitizer.bypassSecurityTrustHtml(x)`
      case Some(path) if path.size >= 2 =>
          binding(path.head).filterNot(_ => path.head == "this").orElse {
              receiverOf(call).flatMap(r =>
                  typeOf(r).flatMap(_.pkg).orElse(handlePackage(ctx, file, r))
              )
          }
      case _ => receiverOf(call).flatMap(r => handlePackage(ctx, file, r))
    fromReceiver.orElse(packageOfResolvedName(ctx, call))
  end packageOf

  /** The package behind a member read made a sink (`resource.list`): its base, by the same rules as
    * a call receiver - the binding the base's root name is imported as, the injected type it
    * resolved to, or the import a handle was made from.
    */
  private def packageOfBase(
    ctx: JsContext,
    base: Expression,
    typeOf: Expression => Option[JsTypeRef]
  ): Option[String] =
    val file = base.method.filename
    memberPath(base) match
      case Some(List(local)) =>
          ctx.modules.resolve(file, local).flatMap(_.packageName)
              .orElse(typeOf(base).flatMap(_.pkg))
              .orElse(handlePackage(ctx, file, base))
      case Some(path) if path.size >= 2 =>
          ctx.modules.resolve(file, path.head).flatMap(_.packageName)
              .filterNot(_ => path.head == "this")
              .orElse(typeOf(base).flatMap(_.pkg))
              .orElse(handlePackage(ctx, file, base))
      case _ => typeOf(base).flatMap(_.pkg).orElse(handlePackage(ctx, file, base))

  /** The package a resolved callee name already carries: `express:Response:send` is a call on
    * express's Response, `marked:parse` a call of marked's parse, `express` a call of the module
    * itself. The module part can itself contain `:` (`node:fs`) and `/` (`@angular/common/http`),
    * so the prefix is matched against the module specifiers this project imports - longest first -
    * rather than split at a separator. A built-in the file never imports still names no package.
    */
  private def packageOfResolvedName(ctx: JsContext, call: Call): Option[String] =
    val name = call.methodFullName
    if name.isEmpty || name.startsWith("<") || name.contains("::program") then None
    else
      val imported = ctx.modules.imports.map(_.module).distinct
      imported
          .filter(m => name == m || name.startsWith(m + ":"))
          .maxByOption(_.length)
          .flatMap(JsModules.packageOf)

  /** The package a handle was made from: `new pg.Pool()`, `axios.create()`, `$('#x')`. */
  private def handlePackage(ctx: JsContext, file: String, receiver: Expression): Option[String] =
    def rootBinding(e: Expression, depth: Int): Option[String] =
        if depth <= 0 then None
        else
          JsValues.origin(e) match
            case id: Identifier => ctx.modules.resolve(file, id.name).flatMap(_.packageName)
            case c: Call if c.name == Operators.fieldAccess =>
                fieldBase(c).flatMap(rootBinding(_, depth - 1))
            case c: Call =>
                c.receiver.headOption.flatMap(memberPath).flatMap(_.headOption)
                    .flatMap(local => ctx.modules.resolve(file, local).flatMap(_.packageName))
                    .orElse {
                        // `new pg.Pool()` is a block around the constructor call
                        val ctor = c.code.stripPrefix("new ").takeWhile(ch =>
                            ch.isLetterOrDigit || ch == '_' || ch == '$'
                        )
                        ctx.modules.resolve(file, ctor).flatMap(_.packageName)
                    }
            case b: Block =>
                val ctor = b.code.stripPrefix("new ").takeWhile(ch =>
                    ch.isLetterOrDigit || ch == '_' || ch == '$'
                )
                ctx.modules.resolve(file, ctor).flatMap(_.packageName)
            case _ => None
    rootBinding(receiver, 4)
  end handlePackage
end PackageAttribution

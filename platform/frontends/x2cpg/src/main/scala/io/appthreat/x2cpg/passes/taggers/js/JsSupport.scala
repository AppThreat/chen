package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** Tag vocabulary of the JavaScript framework recognizers. The names are the pipeline-wide contract
  * read by atom's reachables (`DEFAULT_SOURCE_TAGS` / `DEFAULT_SINK_TAGS`); the category tags
  * (`xss`, `redirect`, ...) ride along on a sink so that a sanitiser declaring the same category
  * (`sanitizer-xss`) neutralises exactly the flows it protects.
  */
object JsTags:
  // Sources
  val INPUT: String   = "framework-input"
  val INGRESS: String = "service-ingress"
  // Entry points
  val ROUTE: String = "framework-route"

  /** A route's data function (`load`, a loader, a form action): an entrypoint whose return value
    * goes to the page that renders it, not out as the response - no sink.
    */
  val DATA: String = "framework-data"
  // Sinks
  val OUTPUT: String      = "framework-output"
  val CODE_EXEC: String   = "code-execution"
  val HTTP_CLIENT: String = "http-client"
  val SSRF: String        = "ssrf"
  // Sink categories
  val XSS: String      = "xss"
  val REDIRECT: String = "redirect"
  // Neutralisers
  val SANITIZER: String                      = "sanitizer"
  def sanitizerFor(category: String): String = s"sanitizer-$category"

  /** A call that returns a boolean or a number about its arguments (`allow.has(x)`,
    * `url.startsWith('/')`, `Number.isFinite(n)`): a value that comes OUT of it carries nothing to
    * inject. Unlike a sanitiser, its arguments go on unchanged, so only a flow through the call's
    * result is neutralised.
    */
  val PREDICATE: String = "predicate"

  /** True for a node this run or an earlier pass tagged as neutralising: a sanitising or predicate
    * call, or a read a guard has validated.
    */
  def neutralises(tagger: JsTagger, c: StoredNode): Boolean =
      tagger.has(c.id(), SANITIZER) || tagger.has(c.id(), PREDICATE) ||
          c.tag.name.exists(n => n == SANITIZER || n == PREDICATE)

  /** Raw HTML reaching the DOM. */
  val HtmlSink: Seq[String] = Seq(OUTPUT, XSS)

  /** A URL the browser navigates to (open redirect, and `javascript:` execution). */
  val NavigationSink: Seq[String] = Seq(OUTPUT, REDIRECT)

  /** A string the JavaScript engine evaluates. */
  val CodeSink: Seq[String] = Seq(CODE_EXEC)

  /** A request whose target the caller does not fix. */
  val RequestSink: Seq[String] = Seq(HTTP_CLIENT)
end JsTags

/** Emits tags, at most once per (node, tag) across every recognizer of one run.
  *
  * The recognizers reach the same node from several angles - a component's props are tagged as a
  * routed handler and as a component, a `fetch` both as a request and as remote data - and a
  * duplicate TAG node surfaces as a duplicate tag in downstream output. The memo is supplied by the
  * caller so that a pass running other taggers first (ChennaiTagsPass) shares it.
  */
final class JsTagger(
  dstGraph: DiffGraphBuilder,
  memo: mutable.HashSet[(Long, String)] = mutable.HashSet.empty
):
  def tag[T <: StoredNode](nodes: IterableOnce[T], names: String*): Unit =
      nodes.iterator.foreach { node =>
          names.foreach { name =>
              if memo.add((node.id(), name)) then
                Iterator(node).newTagNode(name).store()(using dstGraph)
          }
      }

  /** Resolves a call the frontend left unresolved to the method it calls, with the CALL edge and
    * full name the dataflow engine follows into the callee. Only for a call with no callee yet.
    */
  def resolveCall(call: Call, method: Method): Unit =
      if memo.add((call.id(), s"<call>${method.id()}")) then
        resolutions.update(method.id(), call :: resolutions.getOrElse(method.id(), Nil))
        targets.update(call.id(), method :: targets.getOrElse(call.id(), Nil))
        dstGraph.addEdge(call, method, io.shiftleft.codepropertygraph.generated.EdgeTypes.CALL)
        dstGraph.setNodeProperty(
          call,
          io.shiftleft.codepropertygraph.generated.PropertyNames.METHOD_FULL_NAME,
          method.fullName
        )

  /** Where the value behind a bridged node came from, by node id: `src/middleware.ts#14`. */
  private val origins = mutable.HashMap.empty[Long, Set[String]]

  /** Tags `nodes` as a source of kind `name` that a bridge carried there from `from` - the value
    * the bridge read (`context.locals.banner = <value>`, `this.id = <value>`) and the node the
    * source was found at behind it. A node that was itself bridged contributes where its own value
    * came from as well as where it is, so the places name the whole way the value went. Each node
    * also gets a `via:<file>#<line>` tag per place, so a reported flow that starts at a bridged
    * read says where its value came from.
    */
  def tagVia[T <: StoredNode](nodes: IterableOnce[T], name: String, from: StoredNode*): Unit =
    val where = from.flatMap(n =>
        origins.getOrElse(n.id(), Set.empty) ++ JsTagger.locationOf(n).toSet
    ).toSet
    nodes.iterator.foreach { n =>
      tag(Iterator(n), name)
      origins.update(n.id(), origins.getOrElse(n.id(), Set.empty) ++ where)
      where.foreach(w => tag(Iterator(n), s"via:$w"))
    }

  /** Call sites resolved to a method this run. The CALL edge lands in the graph only when the pass
    * ends, so a same-run reader (a bridge deciding what a parameter carries) consults this.
    */
  val resolutions: mutable.HashMap[Long, List[Call]] = mutable.HashMap.empty

  def callSitesOf(method: Method): List[Call] = resolutions.getOrElse(method.id(), Nil)

  private val targets = mutable.HashMap.empty[Long, List[Method]]

  /** The methods this run resolved a call to. */
  def targetsOf(call: Call): List[Method] = targets.getOrElse(call.id(), Nil)

  /** Ids of the nodes this run tagged with any of `names`. */
  def taggedIds(names: String*): Iterator[Long] =
      memo.iterator.collect { case (id, n) if names.contains(n) => id }

  private[js] def graphBuilder: DiffGraphBuilder = dstGraph

  /** True when this run has tagged the node with `name`. */
  def has(nodeId: Long, name: String): Boolean = memo.contains((nodeId, name))

  def tagPair[T <: StoredNode](node: T, name: String, value: String): Unit =
      if memo.add((node.id(), s"$name=$value")) then
        Iterator(node).newTagNodePair(name, value).store()(using dstGraph)
end JsTagger

object JsTagger:
  /** `file#line` of a node, for provenance. */
  def locationOf(n: StoredNode): Option[String] =
      n match
        case p: MethodParameterIn => p.lineNumber.map(l => s"${p.method.filename}#$l")
        case c: CfgNode           => c.lineNumber.map(l => s"${c.method.filename}#$l")
        case m: Member            => m.lineNumber.map(l => s"${m.typeDecl.filename}#$l")
        case _                    => None

/** How an ESM specifier bound its local name. */
enum ImportKind:
  case Named, Default, Namespace, Require, SideEffect

/** One local binding created by an import in one file.
  *
  * @param module
  *   the module specifier as written (`@angular/core`, `./feedback.service`).
  * @param imported
  *   the exported name the binding refers to; for a default or namespace import, and for a
  *   `require`, the local name (that is how the frontend records them).
  */
final case class JsImport(
  file: String,
  local: String,
  module: String,
  imported: String,
  kind: ImportKind
):
  /** The npm package the specifier names (`@scope/pkg/sub` -> `@scope/pkg`), or None for a relative
    * or absolute path.
    */
  def packageName: Option[String] = JsModules.packageOf(module)

/** The imports of a graph, indexed by file and by package.
  *
  * The frontend lowers an ESM import to `"<module>:<name>"` with `importedAs` the local name - the
  * exported name for a named import, the local name for a default or namespace one - and a
  * `require(...)` to the bare specifier. Telling a named import from a default/namespace one needs
  * the declaration's code, which the IMPORT node keeps.
  */
final class JsModules(cpg: Cpg):

  val imports: Seq[JsImport] =
      cpg.imports.l.flatMap { imp =>
        val entity = imp.importedEntity.getOrElse("")
        val local  = imp.importedAs.getOrElse("")
        val file   = Iterator(imp).call.file.name.headOption.getOrElse("")
        if entity.isEmpty then None
        else
          val (module, name) = JsModules.splitEntity(entity)
          val kind =
              if name.isEmpty then
                if local.isEmpty || local == module then ImportKind.SideEffect
                else ImportKind.Require
              else JsModules.kindOf(imp.code, local)
          Some(JsImport(file, if local.nonEmpty then local else name, module, name, kind))
      }.distinct

  private val byFile: Map[String, Seq[JsImport]] = imports.groupBy(_.file)

  /** Every npm package imported anywhere in the graph. */
  val packages: Set[String] = imports.flatMap(_.packageName).toSet

  /** True when any file imports one of the packages, or a subpath of one (`@angular` matches every
    * `@angular/...` package, `next` matches `next/navigation`).
    */
  def uses(pkgs: String*): Boolean =
      packages.exists(p => pkgs.exists(q => JsModules.packageMatches(p, q)))

  def importsOf(file: String): Seq[JsImport] = byFile.getOrElse(file, Nil)

  /** The binding a local name refers to in a file, if it came from an import. */
  def resolve(file: String, local: String): Option[JsImport] =
      importsOf(file).find(_.local == local)

  /** Local names bound in a file to `exported` of a module matching `pkg`. Covers renamed imports
    * (`import { input as field }`).
    */
  def localNamesOf(file: String, pkg: String, exported: String): Set[String] =
      importsOf(file)
          .filter(i =>
              i.kind == ImportKind.Named && i.imported == exported &&
                  i.packageName.exists(JsModules.packageMatches(_, pkg))
          )
          .map(_.local)
          .toSet

  /** Local names bound in a file to the whole module - a default, namespace or `require` binding.
    */
  def moduleBindingsOf(file: String, pkg: String): Set[String] =
      importsOf(file)
          .filter(i =>
              i.kind != ImportKind.Named && i.kind != ImportKind.SideEffect &&
                  i.packageName.exists(JsModules.packageMatches(_, pkg))
          )
          .map(_.local)
          .toSet

  /** Files that import from a package matching one of `pkgs`. */
  def filesImporting(pkgs: String*): Set[String] =
      imports
          .filter(i => i.packageName.exists(p => pkgs.exists(JsModules.packageMatches(p, _))))
          .map(_.file)
          .toSet
end JsModules

object JsModules:

  /** A relative specifier made a project path: `../keys` from `/app/src/views/A.vue` is
    * `/app/src/keys`. Two importers of one module get one path. A package specifier is returned as
    * written.
    */
  def resolveRelative(fromFile: String, module: String): String =
      if !module.startsWith(".") then module
      else
        val dir      = fromFile.substring(0, math.max(fromFile.lastIndexOf('/'), 0))
        val resolved = scala.collection.mutable.ArrayBuffer.empty[String]
        (dir.split("/").toSeq ++ module.split("/").toSeq).filter(_.nonEmpty).foreach {
            case "."  =>
            case ".." => if resolved.nonEmpty then resolved.trimEnd(1)
            case part => resolved += part
        }
        resolved.mkString(if fromFile.startsWith("/") then "/" else "", "/", "")

  /** `@angular/core:inject` -> (`@angular/core`, `inject`); `vue` -> (`vue`, ""). A Windows drive
    * letter or a URL scheme is not a separator, so only the LAST colon counts, and only when what
    * follows it is an identifier.
    */
  def splitEntity(entity: String): (String, String) =
    val idx = entity.lastIndexOf(':')
    if idx <= 0 then (entity, "")
    else
      val name = entity.substring(idx + 1)
      if name.nonEmpty && name.forall(c => c.isLetterOrDigit || c == '_' || c == '$') then
        (entity.substring(0, idx), name)
      else (entity, "")

  def packageOf(module: String): Option[String] =
      if module.isEmpty || module.startsWith(".") || module.startsWith("/") ||
        module.startsWith("#") || module.startsWith("~") || module.startsWith("$")
      then
        // `#imports`/`#app` (Nuxt), `~/x` and `$lib`/`$app` (SvelteKit) are aliases, not packages,
        // but `$app/*` and `#app` name framework modules the recognizers care about; they are
        // reported as their own pseudo-packages.
        if module.startsWith("$app/") || module == "#imports" || module.startsWith("#app") then
          Some(module.takeWhile(_ != '/'))
        else None
      else
        val parts = module.split('/')
        // `@/lib/db` and `@components/x` are path aliases (tsconfig `paths`), not scoped packages
        if module.startsWith("@") && parts.length >= 2 && parts(0).length > 1 then
          Some(s"${parts(0)}/${parts(1)}")
        else if module.startsWith("@") then None
        else Some(parts(0).stripPrefix("node:"))

  /** `@angular/core` matches `@angular`; `react-router-dom` matches `react-router-dom` only; `next`
    * matches `next` (the package `next/navigation` resolves to).
    */
  def packageMatches(pkg: String, wanted: String): Boolean =
      pkg == wanted || pkg.startsWith(s"$wanted/")

  private val BraceContent = "\\{([^}]*)\\}".r

  def kindOf(code: String, local: String): ImportKind =
    val named = BraceContent
        .findFirstMatchIn(code)
        .exists(m =>
            m.group(1).split(',').map(_.trim).exists { spec =>
              val parts = spec.split("\\s+as\\s+").map(_.trim.stripPrefix("type "))
              parts.lastOption.contains(local)
            }
        )
    if named then ImportKind.Named
    else if code.contains("* as") then ImportKind.Namespace
    else ImportKind.Default
end JsModules

/** What the project's manifests declare: the dependencies of every `package.json` outside
  * `node_modules`. Frameworks that auto-import their APIs (Nuxt, Nitro, SvelteKit's `$app`) leave
  * no import to gate on, so the manifest is the evidence that the framework is there.
  */
final class JsProject(cpg: Cpg):
  private val DependencyKeys =
      Seq("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")

  val dependencies: Map[String, String] =
      cpg.configFile.l
          .filter(f =>
              (f.name == "package.json" || f.name.endsWith("/package.json") ||
                  f.name.endsWith("\\package.json")) && !f.name.contains("node_modules")
          )
          .flatMap(f => io.circe.parser.parse(f.content).toOption)
          .flatMap { json =>
              DependencyKeys.flatMap(k =>
                  json.hcursor.downField(k).as[Map[String, io.circe.Json]].toOption.toList
                      .flatMap(_.toList.map((name, v) => name -> v.asString.getOrElse("")))
              )
          }
          .toMap

  /** The version each dependency resolved to: `package-lock.json` (lockfile v2/v3 `packages`, v1
    * `dependencies`) where there is one, else the version a `package.json` range names (`^19.1.0`
    * -> `19.1.0`). A range that names no version (`latest`, `workspace:*`, a URL) gives none.
    */
  lazy val resolvedVersions: Map[String, String] =
    val fromRanges = dependencies.flatMap { (name, range) =>
        "(\\d+\\.\\d+\\.\\d+[\\w.+-]*|\\d+\\.\\d+|\\d+)".r
            .findFirstMatchIn(range.dropWhile(c => !c.isDigit))
            .filter(_ => !range.contains(":") && !range.contains("/"))
            .map(m => name -> m.group(1))
    }
    val fromLocks = cpg.configFile.l
        .filter(f =>
            (f.name == "package-lock.json" || f.name.endsWith("/package-lock.json") ||
                f.name.endsWith("\\package-lock.json")) && !f.name.contains("node_modules")
        )
        .flatMap(f => io.circe.parser.parse(f.content).toOption)
        .flatMap { json =>
          val v2 = json.hcursor.downField("packages").as[Map[String, io.circe.Json]].toOption
              .toList.flatMap(_.toList.flatMap { (path, entry) =>
                // the root package is keyed "", a nested copy "node_modules/a/node_modules/b"
                val marker = path.lastIndexOf("node_modules/")
                if marker < 0 || path.indexOf("node_modules/") != marker then None
                else
                  entry.hcursor.downField("version").as[String].toOption
                      .map(path.substring(marker + "node_modules/".length) -> _)
              })
          val v1 = json.hcursor.downField("dependencies").as[Map[String, io.circe.Json]].toOption
              .toList.flatMap(_.toList.flatMap((name, entry) =>
                  entry.hcursor.downField("version").as[String].toOption.map(name -> _)
              ))
          v2 ++ v1
        }
        .toMap
    fromRanges ++ fromLocks
  end resolvedVersions

  /** The major version a dependency's range pins (`^19.1.0` -> 19, `~18.3` -> 18), when it does. */
  def majorVersionOf(name: String): Option[Int] =
      dependencies.get(name).flatMap(range =>
          "(\\d+)".r.findFirstMatchIn(range.dropWhile(c => !c.isDigit)).map(_.group(1).toInt)
      )

  def dependsOn(names: String*): Boolean =
      names.exists(n => dependencies.keys.exists(d => d == n || d.startsWith(s"$n/")))

  def hasFile(regex: String): Boolean = cpg.file.name(regex).nonEmpty
end JsProject

/** Structural helpers over the shapes jssrc2cpg lowers JavaScript to. */
object JsShapes:

  /** The method name of a call. An optional call (`a?.b.c(x)`) is lowered to a call whose NAME is
    * the whole callee text, so the name is its last segment.
    */
  def callName(call: Call): String =
      if call.name.startsWith("<") || !call.name.contains('.') then call.name
      else call.name.substring(call.name.lastIndexOf('.') + 1)

  /** `a.b` -> `b`; None for anything that is not a field access. */
  def fieldName(call: Call): Option[String] =
      if call.name != Operators.fieldAccess then None
      else
        call.argumentOption(2).map {
            case f: FieldIdentifier => f.canonicalName
            case other              => other.code
        }

  /** The receiver (`a` in `a.b`) of a field access. */
  def fieldBase(call: Call): Option[Expression] =
      if call.name != Operators.fieldAccess then None else call.argumentOption(1)

  /** Looks through the temporaries the frontend introduces for chained receivers: `a.b().c` lowers
    * to `(_tmp_0 = a.b()).c`, so the receiver of `.c` is the assignment, or the bare `_tmp_0` read
    * in a later statement.
    */
  def unwrap(expr: Expression): Expression =
      expr match
        case c: Call if c.name == Operators.assignment && c.argumentOption(1).exists(isTemp) =>
            c.argumentOption(2).map(unwrap).getOrElse(expr)
        case id: Identifier if isTemp(id) =>
            tempDefinition(id).map(unwrap).getOrElse(expr)
        case _ => expr

  private def isTemp(e: Expression): Boolean =
      e match
        case id: Identifier => id.name.startsWith("_tmp_")
        case _              => false

  /** The value most recently assigned to a temporary in the same method. */
  private def tempDefinition(id: Identifier): Option[Expression] =
      JsIndexes.assignedValues(id.method, id.name)
          .filter(v => v.lineNumber.zip(id.lineNumber).forall((x, y) => x.intValue <= y.intValue))
          .lastOption

  /** A member read and the reads that continue it (`a.b` -> `a.b.c`, `a.b.c['d']`), up to the first
    * one that is called rather than read. The dataflow engine does not carry a value from a field
    * read into a read of one of its fields, so a source tag on `route.snapshot.queryParams` alone
    * never reaches `route.snapshot.queryParams.q`; tagging the whole chain does.
    */
  def readChain(read: Call): List[Call] =
      read :: (read.astParent match
        case p: Call
            if (p.name == Operators.fieldAccess || p.name == Operators.indexAccess) &&
                p.argumentOption(1).exists(_.id() == read.id()) && p._receiverIn.isEmpty =>
            readChain(p)
        case _ => Nil
      )

  /** [[readChain]] of every read. */
  def readChains(reads: IterableOnce[Call]): Iterator[Call] = reads.iterator.flatMap(readChain)

  /** The dotted path of a pure member chain (`window.location.hash` -> Seq(window, location,
    * hash)), looking through temporaries. None when any link is a call or a computed index.
    */
  def memberPath(expr: Expression): Option[List[String]] =
      unwrap(expr) match
        case id: Identifier => Some(List(id.name))
        case c: Call if c.name == Operators.fieldAccess =>
            for
              base  <- fieldBase(c)
              path  <- memberPath(base)
              field <- fieldName(c)
            yield path :+ field
        case _ => None

  /** The method a callback argument refers to: an inline function (METHOD_REF) or a named function
    * passed by reference.
    */
  def callbackMethod(arg: Expression): Option[Method] =
      arg match
        case ref: MethodRef => ref.out(EdgeTypes.REF).collectFirst { case m: Method => m }
        case id: Identifier =>
            // A function declaration is referenced directly; `const onMessage = (e) => ...` through
            // the local it is assigned to.
            id.out(EdgeTypes.REF).collectFirst { case m: Method => m }.orElse(
              JsValues.origin(id) match
                case ref: MethodRef if ref.id() != id.id() => callbackMethod(ref)
                case _                                     => None
            ).orElse(
              // `function onMessage(e) {...}` declared at module level and passed from inside a
              // function: the declaration's binding is in another method, so look it up by name.
              id.method.file.method.nameExact(id.name).headOption
            ).orElse(
              // an imported function (`loader: previewLoader` in a router config): the one
              // project function of that name, if it is unambiguous
              Cpg(using id.graph).method.internal.nameExact(id.name).l match
                case only :: Nil => Some(only)
                case _           => None
            )
        case _ => None

  /** Callbacks in an argument: the function itself, or each function-valued property of an object
    * literal (`{ next: (v) => ..., error: ... }`, lowered to `_tmp.next = <ref>` assignments in a
    * block) whose key is in `keys` (every key when empty).
    */
  def callbacksIn(arg: Expression, keys: Set[String] = Set.empty): List[Method] =
      arg match
        case b: Block =>
            b.astChildren.isCall.nameExact(Operators.assignment).l.flatMap { a =>
              val key = a.argumentOption(1).collect { case c: Call => fieldName(c) }.flatten
              if keys.isEmpty || key.exists(keys.contains) then
                a.argumentOption(2).flatMap(callbackMethod)
              else None
            }
        case other => callbackMethod(other).toList

  /** The first non-`this` parameter of a method - the value a callback receives. */
  def firstParam(m: Method): Option[MethodParameterIn] =
      m.parameter.filterNot(_.name == "this").sortBy(_.index).headOption

  /** Every parameter but `this`. */
  def params(m: Method): List[MethodParameterIn] =
      m.parameter.filterNot(_.name == "this").sortBy(_.index).l

  /** True for a string literal argument. */
  def isStringLiteral(e: Expression): Boolean =
      e match
        case l: Literal => l.code.headOption.exists(c => c == '"' || c == '\'' || c == '`')
        case _          => false

  def literalValue(e: Expression): Option[String] =
      e match
        case l: Literal if isStringLiteral(l) && l.code.length >= 2 =>
            Some(l.code.substring(1, l.code.length - 1))
        case _ => None

  /** An expression of constants only (`-1`, `'a' + 'b'`): `navigate(-1)` goes back in history. */
  def isConstantExpr(e: Expression): Boolean =
      e match
        case _: Literal => true
        case c: Call
            if c.name.startsWith("<operator>.") && c.name != Operators.fieldAccess &&
                c.name != Operators.indexAccess =>
            c.argument.nonEmpty && c.argument.forall(isConstantExpr)
        case _ => false

  /** The left-most operand of a string concatenation or template literal, for deciding whether a
    * URL's origin is fixed by the code.
    */
  def leftmostOperand(e: Expression): Expression =
      e match
        case c: Call
            if c.name == Operators.addition || c.name == Operators.formatString ||
                c.name == "<operator>.formattedValue" =>
            c.argumentOption(1).map(leftmostOperand).getOrElse(e)
        case _ => e

  /** True when a URL expression fixes its own origin: a constant, or a concatenation/template that
    * starts with a same-origin path (`/api/...`) or an absolute URL with a path (`https://host/`).
    * Such a request can carry attacker data but cannot be pointed somewhere else, so it is not a
    * request-forgery sink.
    */
  def hasFixedOrigin(url: Expression): Boolean =
      url match
        case l: Literal                   => true
        case c: Call if isConstantExpr(c) => true
        case _ =>
            literalValue(leftmostOperand(url)).exists(fixesOrigin)

  /** The parts of a string built by concatenation or a template literal, left to right. */
  def urlParts(e: Expression): List[Expression] =
      e match
        case c: Call if c.name == Operators.addition =>
            c.argument.sortBy(_.argumentIndex).l.flatMap(urlParts)
        case c: Call if c.name == Operators.formatString =>
            // a template literal starts and ends with a quasi, empty when a value is at either end
            c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l.flatMap(urlParts)
                .filterNot(p => literalValue(p).contains(""))
        case c: Call if c.name == "<operator>.formattedValue" =>
            c.argument.sortBy(_.argumentIndex).l.flatMap(urlParts)
        case other => List(other)

  /** A literal URL prefix that keeps the request or link on a fixed origin: an absolute path, a URL
    * with its host, a relative path (`./a`, `../a`, `assets/a` - a segment before any `:`), or a
    * query or fragment of the current page (`?/deleteComment&id=`, `#top`).
    */
  private def fixesOrigin(prefix: String): Boolean =
      (prefix.startsWith("/") && !prefix.startsWith("//")) ||
          prefix.matches("(?i)^[a-z][a-z0-9+.-]*://[^/?#]+[/?#].*") ||
          prefix.startsWith("./") || prefix.startsWith("../") ||
          prefix.startsWith("?") || prefix.startsWith("#") ||
          prefix.matches("^[\\w.~-]+/.*")

  /** The nodes to tag as request sinks for a request to `url`: the parts of the URL that decide
    * where the request goes, never the request call itself - what reaches its body, its options or
    * its receiver is no forgery.
    *
    *   - A constant URL, or a value placed only in the query or fragment of a URL whose origin the
    *     code fixes (`/search?q=${q}`), is no sink.
    *   - A variable that decides the origin - the whole URL, a prefix (`${base}/items`), or the
    *     host after a bare scheme (`wss://${host}/live`) - is a sink. A prefix that is
    *     configuration - a field (`this.apiUrl`), a member of a config object (`environment.host`)
    *     or a SCREAMING_CASE constant - is not.
    *   - A variable in the PATH of a URL (`/api/items/${id}`, `${this.apiUrl}/items/${id}`) is a
    *     sink for client-side path traversal: `../` in it reaches another endpoint of the same
    *     origin with the page's credentials.
    *   - A whole URL that is configuration - a service's own field (`this.http.put(this.host,
    *     body)`), a SCREAMING_CASE constant, a member of `environment`/`config`/`process.env` - is
    *     no sink.
    */
  def requestSinksFor(call: Call, url: Expression): List[CfgNode] =
    def isConstant(e: Expression) = e.isInstanceOf[Literal]
    // the variable parts before the query or the fragment starts
    def variablesInPath(parts: List[Expression], from: Int): List[CfgNode] =
      var text = ""
      parts.drop(from).flatMap {
          case part if isConstant(part) =>
              text += literalValue(part).getOrElse(part.code)
              Nil
          case part: CfgNode if !text.contains('?') && !text.contains('#') => List(part)
          case _                                                           => Nil
      }
    url match
      case _: Literal => Nil
      case c: Call if c.name == Operators.addition || c.name == Operators.formatString =>
          val parts    = urlParts(c)
          val firstVar = parts.indexWhere(p => !isConstant(p))
          if firstVar < 0 then Nil
          else if firstVar == 0 then
            val base = parts.head match
              case c: Call if c.name == Operators.fieldAccess => Nil
              case id: Identifier if isConfiguredUrl(id)      => Nil
              case base: CfgNode                              => List(base)
              case _                                          => Nil
            base ++ variablesInPath(parts, 1)
          else
            val prefix = parts.take(firstVar).flatMap(literalValue).mkString
            if fixesOrigin(prefix) && (prefix.contains('?') || prefix.contains('#')) then Nil
            else variablesInPath(parts, firstVar)
      case e if isConfiguredUrl(e) => Nil
      case e: CfgNode              => List(e)
      case _                       => List(call)
    end match
  end requestSinksFor

  private val ConfigRoots = Set("environment", "env", "config", "process", "import.meta")

  private def isConfiguredUrl(url: Expression): Boolean =
      url match
        case id: Identifier =>
            id.name.length > 1 && id.name.forall(ch => ch.isUpper || ch.isDigit || ch == '_')
        case c: Call if c.name == Operators.fieldAccess =>
            memberPath(c).exists {
                case List("this", _) => true
                case root :: _       => ConfigRoots.contains(root)
                case _               => false
            } || c.code.startsWith("import.meta.env.")
        case _ => false

  /** A tagged template call (`` sql`... ${x}` ``), lowered to a call of the tag with the template
    * as `<operator>.formatString(...)`: the tag function receives the values separately - a SQL tag
    * binds them as parameters.
    */
  def isTaggedTemplateCall(c: Call): Boolean =
      c.name != Operators.formatString &&
          (c.code.matches("(?s)^[\\w$.]+`.*") ||
              c.code.matches("(?s)^[\\w$.]+\\(<operator>\\.formatString\\(.*"))

  /** What a file exports as default: `export default function Card() {}` and `export default Card`
    * lower to `exports["default"] = Card`, an arrow function to a reference to it.
    */
  def defaultExportValue(ctx: JsContext, file: String): Option[Expression] =
      ctx.cpg.file.nameExact(file).method.nameExact(":program")
          .flatMap(_.ast.isCall.nameExact(Operators.assignment))
          .find(_.argumentOption(1).exists(_.code.matches("""exports\[["']default["']\]""")))
          .flatMap(_.argumentOption(2))

  /** Functions exported under one of `names` - `export function getServerSideProps() {}`, and
    * `export const getServerSideProps = (async (context) => {...}) satisfies GetServerSideProps`,
    * whose function is anonymous - as (export name, function).
    */
  def exportedFunctions(ctx: JsContext, names: Set[String]): List[(String, Method)] =
      ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(fa: Call), Some(v)) if fa.code.startsWith("exports.") =>
                fieldName(fa).filter(names.contains).flatMap { name =>
                  val value = JsValues.origin(v)
                  callbackMethod(v).orElse(callbackMethod(value)).orElse(value match
                    // a cast or `satisfies` around the function
                    case c: Call if c.name.startsWith("<operator>.") =>
                        c.argument.isMethodRef.headOption.flatMap(callbackMethod)
                    case _ => None
                  ).map(name -> _)
                }
            case _ => None
      }.distinctBy(_._2.id())

  /** The value a project module exports under the name an identifier was imported as: `export const
    * tooltipHtml = { mounted() {...} }` for `import { tooltipHtml } from './directives/tooltipHtml'`
    * (a relative or `@/` specifier).
    */
  def importedValue(ctx: JsContext, id: Identifier): Option[Expression] =
    val file = id.method.filename
    ctx.modules.resolve(file, id.name).flatMap { imp =>
      val base =
          if imp.module.startsWith(".") then Some(JsModules.resolveRelative(file, imp.module))
          else if imp.module.startsWith("@/") || imp.module.startsWith("~/") then
            Some("src/" + imp.module.drop(2))
          else None
      base.flatMap { b =>
        val exported = if imp.kind == ImportKind.Default then "default" else imp.imported
        ctx.cpg.file.filter(f => f.name == b || f.name.startsWith(b + "."))
            .method.nameExact(":program").l.iterator
            .flatMap(_.ast.isCall.nameExact(Operators.assignment))
            .find(_.argumentOption(1).exists(t =>
                t.code == s"exports.$exported" || t.code.matches(s"""exports\\[["']$exported["']\\]""")
            ))
            .flatMap(_.argumentOption(2))
            .map(JsValues.origin(_))
      }
    }

  def hasDefaultExport(ctx: JsContext, file: String): Boolean =
      defaultExportValue(ctx, file).nonEmpty

  /** True for the target of an assignment (`x.y` in `x.y = v`), which is written, not read. */
  def isAssignmentTarget(e: Expression): Boolean =
      e.astParent match
        case a: Call if a.name.startsWith("<operator>.assignment") =>
            a.argumentOption(1).exists(_.id() == e.id())
        case _ => false

  /** Files whose code runs on the server of a meta-framework: Nitro/Nuxt `server/`, Next.js route
    * handlers, API routes and middleware, SvelteKit `+server`/`*.server` modules and `$lib/server`,
    * Astro endpoints and middleware, Remix/React Router `.server` modules. A request such code
    * makes to a URL the caller chose is server-side request forgery.
    */
  private val ServerFile = (
    "(?:.*[/\\\\])?(" +
        "server[/\\\\](api|routes|middleware|plugins|tasks|utils)[/\\\\].*" +
        "|app[/\\\\](.*[/\\\\])?route\\.[cm]?[jt]sx?" +
        "|pages[/\\\\]api[/\\\\].*" +
        "|(src[/\\\\])?middleware\\.[cm]?[jt]s" +
        "|.*\\+(page|layout)\\.server\\.[cm]?[jt]s|.*\\+server\\.[cm]?[jt]s|hooks\\.server\\.[cm]?[jt]s" +
        "|lib[/\\\\]server[/\\\\].*" +
        "|.*\\.server\\.[cm]?[jt]sx?" +
        ")"
  ).r

  def isServerFile(filename: String): Boolean = ServerFile.matches(filename)

  /** Assignments (`=`, `+=`) whose target is a field access named one of `fields`. An object
    * literal's keys (`{ innerHTML: x }`, lowered to `_tmp_0.innerHTML = x`) are not writes to an
    * object anyone renders, and are left out.
    */
  def propertyWrites(cpg: Cpg, fields: Set[String]): Iterator[Call] =
      cpg.call
          .nameExact(Operators.assignment, Operators.assignmentPlus)
          .filter(_.argumentOption(1).exists {
              case c: Call =>
                  fieldName(c).exists(fields.contains) && !fieldBase(c).exists {
                      case id: Identifier => id.name.startsWith("_tmp_")
                      case _              => false
                  }
              case _ => false
          })

  /** An object literal argument (`{ path: '/x', query }`), lowered to a block of property writes -
    * as opposed to the block a `new C(...)` is lowered to.
    */
  def isObjectLiteral(e: Expression): Boolean =
      e match
        case b: Block => b.code.trim.startsWith("{")
        case _        => false

  /** An object literal's own properties - `{ a: v, b }` lowers to a block of writes `_tmp.a = v`,
    * `_tmp.b = b` ending in the temporary - or None where a spread or a computed key puts members
    * there that the code does not name.
    */
  def objectProperties(literal: Block): Option[Map[String, Expression]] =
    val writes = literal.astChildren.collect { case c: Call => c }.l.map { c =>
        (c.name, c.argumentOption(1), c.argumentOption(2)) match
          case (Operators.assignment, Some(fa: Call), Some(v))
              if fieldBase(fa).exists(_.code.startsWith("_tmp_")) =>
              fieldName(fa).map(_ -> v)
          case _ => None
    }
    Option.when(writes.forall(_.nonEmpty))(writes.flatten.toMap)

  /** The value written by an assignment. */
  def assignedValue(assignment: Call): Option[Expression] = assignment.argumentOption(2)

  /** The receiver of a method call (`a.b(...)` -> `a`), looking through temporaries. */
  def receiverOf(call: Call): Option[Expression] =
      call.receiver.headOption.collect { case c: Call => c }.flatMap(fieldBase).map(unwrap)

  /** The class a method - or an arrow function nested in one, whose `this` is the class's - belongs
    * to. The `this` parameter's type is consulted first: every function gets a TYPE_DECL of its
    * own, so the AST-defining declaration of a closure is the closure.
    */
  def enclosingTypeDecl(m: Method): Option[TypeDecl] =
      m.parameter.nameExact("this").typeFullName.headOption
          .flatMap(t => Cpg(using m.graph).typeDecl.fullNameExact(t).headOption)
          .orElse(m.definingTypeDecl)

  /** The methods of a class, with the arrow functions nested in them (whose `this` is the class's).
    */
  def classMethods(td: TypeDecl): List[Method] =
      JsIndexes.methodsUnder(td.graph, td.fullName + ":")

  /** The functions nested in a method (closures, handlers), by full-name prefix. */
  def nestedMethods(m: Method): List[Method] = JsIndexes.methodsUnder(m.graph, m.fullName + ":")

  /** The simple name of a type full name (`@angular/router:ActivatedRoute` -> `ActivatedRoute`,
    * `ActivatedRoute<T>` -> `ActivatedRoute`).
    */
  def simpleTypeName(fullName: String): String =
    val noGenerics = fullName.takeWhile(_ != '<').trim
    noGenerics.substring(math.max(noGenerics.lastIndexOf(':'), noGenerics.lastIndexOf('.')) + 1)

  /** The annotated type in a declaration's code (`private route: ActivatedRoute` ->
    * `ActivatedRoute`), for parameters and members whose type the frontend left unresolved.
    */
  def annotatedType(code: String): Option[String] =
    val idx = code.indexOf(':')
    if idx < 0 then None
    else
      val t = code.substring(idx + 1).trim.takeWhile(c => c.isLetterOrDigit || c == '_' || c == '$')
      Option.when(t.nonEmpty)(t)
end JsShapes

/** Per-graph and per-method lookups the recognizers make repeatedly, built once. A method's
  * full-name prefix query used to be a regex scan of every method of the graph, and a local's
  * assignments a walk of its method's whole AST - per query.
  */
object JsIndexes:
  private val methodIndexes =
      java.util.Collections.synchronizedMap(
        new java.util.WeakHashMap[overflowdb.Graph, java.util.TreeMap[String, List[Method]]]()
      )
  private val assignmentIndexes =
      java.util.Collections.synchronizedMap(
        new java.util.WeakHashMap[Method, Map[String, List[Expression]]]()
      )

  /** Methods whose full name starts with `prefix`. */
  def methodsUnder(graph: overflowdb.Graph, prefix: String): List[Method] =
    val index = methodIndexes.computeIfAbsent(
      graph,
      _ =>
        val tree = new java.util.TreeMap[String, List[Method]]()
        Cpg(using graph).method.foreach { m =>
            tree.merge(m.fullName, List(m), (a, b) => a ++ b)
        }
        tree
    )
    import scala.jdk.CollectionConverters.*
    index.subMap(prefix, true, prefix + Char.MaxValue, true).values().asScala.flatten.toList

  /** The method with exactly this full name. */
  def methodByFullName(graph: overflowdb.Graph, fullName: String): Option[Method] =
      methodsUnder(graph, fullName).find(_.fullName == fullName)

  /** What a method assigns to a plain variable, by name (`x = v` -> v). */
  def assignedValues(m: Method, name: String): List[Expression] =
      assignmentIndexes.computeIfAbsent(
        m,
        method =>
            // the method's own assignments: a nested function's are its own (a callback that
            // destructures `([quantities, products])` binds new names, not the outer ones)
            Iterator(method).assignment.filter(_.method.id() == method.id()).l.flatMap { a =>
                (a.argumentOption(1), a.argumentOption(2)) match
                  case (Some(t: Identifier), Some(v)) => Some(t.name -> v)
                  case _                              => None
            }.groupMap(_._1)(_._2)
      ).getOrElse(name, Nil)

  /** Forget everything built for a graph (between runs over a mutated graph). */
  def clear(): Unit =
    methodIndexes.clear()
    assignmentIndexes.clear()
end JsIndexes

/** Where values come from and where asynchronous values go. */
object JsValues:

  /** The expression a value was produced by: through the frontend's temporaries, and through a
    * local that the method assigns exactly once (`const obs = this.http.get(...)`). A local
    * assigned more than once is left alone - which assignment reaches a use is the dataflow
    * engine's job.
    */
  def origin(expr: Expression, depth: Int = 4): Expression =
    val e = JsShapes.unwrap(expr)
    if depth <= 0 then e
    else
      e match
        case id: Identifier if id.name != "this" =>
            JsIndexes.assignedValues(id.method, id.name) match
              case single :: Nil => origin(single, depth - 1)
              case Nil           =>
                  // a variable of an enclosing function, captured: `const navigate =
                  // useNavigate()` at the top of a component, called in a handler
                  enclosingAssignment(id.method, id.name).map(origin(_, depth - 1)).getOrElse(e)
              case _ => e
        case _ => e

  /** The single value an enclosing function (by full-name prefix, innermost first) assigns to
    * `name`, for a closure that reads it without assigning it.
    */
  private def enclosingAssignment(m: Method, name: String): Option[Expression] =
    if m.parameter.nameExact(name).nonEmpty then return None
    val segments = m.fullName.split(':')
    (segments.length - 1 to 1 by -1).iterator
        .map(n => segments.take(n).mkString(":"))
        .flatMap(prefix => JsIndexes.methodByFullName(m.graph, prefix))
        .map(outer =>
            if outer.parameter.nameExact(name).nonEmpty then Some(Nil)
            else
              JsIndexes.assignedValues(outer, name) match
                case Nil => None
                case vs  => Some(vs)
        )
        .collectFirst { case Some(vs) => vs }
        .flatMap {
            case single :: Nil => Some(single)
            case _             => None
        }

  /** rxjs operators whose callback receives each emitted value. */
  val ValueOperators: Set[String] = Set(
    "map",
    "switchMap",
    "mergeMap",
    "concatMap",
    "exhaustMap",
    "flatMap",
    "tap",
    "filter",
    "takeWhile",
    "skipWhile",
    "first",
    "last",
    "find"
  )

  /** rxjs combinators whose output carries every input's values. */
  val Combinators: Set[String] =
      Set("forkJoin", "combineLatest", "zip", "merge", "concat", "race", "from", "defer")

  /** The callback parameters that receive the values a producer delivers, where the producer is a
    * Promise (`p.then(cb)`) or an Observable (`o.subscribe(cb)`, `o.subscribe({ next: cb })`,
    * `o.pipe(map(cb), ...)`), following the chain (`then` returns a promise of the callback's
    * result, `pipe` an observable) and rxjs combinators (`forkJoin([a, b]).subscribe(cb)`).
    *
    * A promise awaited instead (`const r = await fetch(u)`) needs no help: the dataflow engine
    * carries the awaited value from the producer call itself.
    */
  def consumersOf(producer: Expression, depth: Int = 6): List[MethodParameterIn] =
    if depth <= 0 then return Nil
    val method                               = producer.method
    val producerId                           = producer.id()
    def fromProducer(e: Expression): Boolean = origin(e).id() == producerId
    val calls                                = method.call.l
    val chained = calls
        .filter(c =>
            (c.name == "then" || c.name == "subscribe" || c.name == "pipe") &&
                JsShapes.receiverOf(c).exists(fromProducer)
        )
        .flatMap { c =>
            c.name match
              case "then" =>
                  c.argument.filter(_.argumentIndex == 1).l
                      .flatMap(a => JsShapes.callbacksIn(a))
                      .flatMap(JsShapes.firstParam) ++ consumersOf(c, depth - 1)
              case "subscribe" =>
                  c.argument.filter(_.argumentIndex == 1).l
                      .flatMap(a => JsShapes.callbacksIn(a, Set("next")))
                      .flatMap(JsShapes.firstParam)
              case _ =>
                  c.argument.filter(_.argumentIndex >= 1).isCall
                      .filter(op => ValueOperators.contains(op.name))
                      .l
                      .flatMap(op => op.argument.filter(_.argumentIndex >= 1).l)
                      .flatMap(a => JsShapes.callbacksIn(a))
                      .flatMap(JsShapes.firstParam) ++ consumersOf(c, depth - 1)
        }
    // `forkJoin([a, b])`, `combineLatest({ a, b })`: the array/object literal is lowered into a
    // block of pushes or property writes, so the producer is found among the argument's reads.
    val combined = calls
        .filter(c => Combinators.contains(c.name))
        .filter(_.argument.filter(_.argumentIndex >= 1).ast.isIdentifier.exists(fromProducer))
        .flatMap(consumersOf(_, depth - 1))
    (chained ++ combined).distinctBy(_.id())
  end consumersOf
end JsValues

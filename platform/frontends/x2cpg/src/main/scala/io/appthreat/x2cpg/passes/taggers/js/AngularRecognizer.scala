package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsShapes.*
import JsTags.*

/** A type a value is known to have: the exported name, and the npm package it comes from (None for
  * a class of the project itself).
  */
final case class JsTypeRef(name: String, pkg: Option[String]):
  def is(typeName: String, pkgPrefix: String): Boolean =
      name == typeName && pkg.exists(p => p == pkgPrefix || p.startsWith(s"$pkgPrefix/"))

/** Angular (v2 through v20): https://angular.dev
  *
  * Angular code reaches framework objects through dependency injection - a constructor parameter
  * (`constructor(private route: ActivatedRoute)`) or a field initialised by `inject(...)` - and
  * then uses them as `this.route`, so the recognizer first types each class's injected members and
  * then works from those types rather than from what a member happens to be called.
  *
  * Sources:
  *   - `ActivatedRoute` / `ActivatedRouteSnapshot`: `params`, `queryParams`, `paramMap`,
  *     `queryParamMap`, `fragment`, `data`, `url` - read from a snapshot, or delivered to the
  *     callbacks of the observables (`this.route.paramMap.subscribe(p => ...)`, `.pipe(map(p =>
  *     ...))`); also through `parent`/`root`/`firstChild`, and in resolvers and guards (`(route:
  *     ActivatedRouteSnapshot) => ...`, `const r: ResolveFn<T> = (route) => ...`);
  *   - `Router.url`, `Location.path()`, `PlatformLocation` URL parts;
  *   - component inputs: `@Input()` members (and setters), signal `input()` / `input.required()`
  *     and `model()` / `model.required()` members, and their `this.x` reads. With
  *     `withComponentInputBinding()` the router binds path and query parameters straight to these,
  *     so a routed component's inputs are URL data;
  *   - `@HostListener('window:message', ['$event'])` handlers;
  *   - HttpClient responses (`service-ingress`), followed through the service methods that return
  *     them (`find() { return this.http.get(...).pipe(...) }` -> `this.svc.find().subscribe(cb)`).
  *
  * Sinks: the `DomSanitizer.bypassSecurityTrust*` escape hatches (their result is rendered without
  * sanitisation), `Renderer2.setProperty`/`setAttribute` with a markup or URL property, and
  * HttpClient requests whose URL is not fixed. Template bindings such as `[innerHTML]` are
  * sanitised by Angular itself and are not sinks; `DomSanitizer.sanitize(...)` is a sanitiser.
  *
  * `@Output()` emitters are not sinks: an emitted value goes to the parent component, not out of
  * the application.
  */
object AngularRecognizer extends JsFrameworkRecognizer:

  val name: String = "angular"

  def applies(ctx: JsContext): Boolean = ctx.modules.uses("@angular")

  private val RoutePkg  = "@angular/router"
  private val CorePkg   = "@angular/core"
  private val CommonPkg = "@angular/common"

  /** Route state carrying URL data. */
  private val RouteDataFields =
      Set("params", "queryParams", "paramMap", "queryParamMap", "fragment", "data", "url")

  /** Hops from one route to another, or to its snapshot. */
  private val RouteHops = Set("snapshot", "parent", "root", "firstChild")

  private val HttpVerbs =
      Set("get", "post", "put", "patch", "delete", "head", "options", "jsonp", "request")

  /** The injected type of an expression (`this.sanitizer` -> DomSanitizer from
    * `@angular/platform-browser`), for attributing calls on it to a package.
    */
  def injectedTypes(ctx: JsContext): Expression => Option[JsTypeRef] =
    val di = Di(ctx)
    e => di.typeOf(e)

  def run(ctx: JsContext): Unit =
    val di = Di(ctx)
    resolveServiceCalls(ctx, di)
    tagRouteSources(ctx, di)
    tagLocationSources(ctx, di)
    tagDecoratorInputs(ctx)
    tagSignalInputs(ctx)
    tagHostListeners(ctx)
    tagGuardsAndResolvers(ctx)
    tagHttp(ctx, di)
    tagHttpResources(ctx)
    tagForms(ctx)
    tagHostMetadata(ctx)
    tagSinks(ctx)
    tagNavigation(ctx, di)

  // -----------------------------------------------------------------------------------------
  // Dependency injection
  // -----------------------------------------------------------------------------------------

  /** The types of injected values: constructor parameters, `inject(X)` initialisers and annotated
    * members, per class; and parameters and `inject(X)` locals in functions.
    */
  private final class Di(ctx: JsContext):
    private val memberCache = mutable.HashMap.empty[String, Map[String, JsTypeRef]]

    /** A type name as written in a file, resolved through that file's imports. */
    def resolve(file: String, typeName: String): JsTypeRef =
        ctx.modules.resolve(file, typeName) match
          case Some(imp) => JsTypeRef(imp.imported, imp.packageName)
          case None      => JsTypeRef(typeName, None)

    /** The type of a declared value from its type full name, or from its annotation in the code. */
    def declared(file: String, typeFullName: String, code: String): Option[JsTypeRef] =
      val (module, name) = JsModules.splitEntity(typeFullName.takeWhile(_ != '<'))
      if name.nonEmpty && JsModules.packageOf(module).isDefined && !module.contains("<returnValue>")
      then Some(JsTypeRef(name, JsModules.packageOf(module)))
      else
        val simple = simpleTypeName(typeFullName)
        val typeName =
            if simple.isEmpty || simple == "ANY" || simple.contains("<returnValue>") ||
              typeFullName.contains("<returnValue>")
            then annotatedType(code)
            else Some(simple)
        typeName.filterNot(_ == "ANY").map(resolve(file, _))

    /** `inject(X)` (or a renamed import of it) -> the type X names. */
    def injected(call: Call): Option[JsTypeRef] =
      val file = call.method.filename
      if call.name == "inject" || ctx.modules.localNamesOf(file, CorePkg, "inject").contains(
          call.name
        )
      then
        call.argument.filter(_.argumentIndex == 1).headOption.collect {
            case id: Identifier                               => resolve(file, id.name)
            case fa: Call if fa.name == Operators.fieldAccess =>
                // `inject(tokens.HttpClient)` - rare; the field name is the best guess
                resolve(file, fieldName(fa).getOrElse(fa.code))
        }
      else None

    def memberTypes(td: TypeDecl): Map[String, JsTypeRef] =
        memberCache.getOrElseUpdate(
          td.fullName, {
              val file    = td.file.name.headOption.getOrElse("")
              val methods = classMethods(td)
              val ctor    = methods.filter(_.name == "<init>")
              val fromParams = ctor.flatMap(params).flatMap(p =>
                  declared(file, p.typeFullName, p.code).map(p.name -> _)
              )
              val fromInject = ctor.flatMap(m => Iterator(m).assignment.l).flatMap { a =>
                  (a.argumentOption(1), a.argumentOption(2).map(JsShapes.unwrap)) match
                    case (Some(id: Identifier), Some(init: Call)) =>
                        injected(init).map(id.name -> _)
                    case (Some(fa: Call), Some(init: Call)) if fa.code.startsWith("this.") =>
                        fieldName(fa).flatMap(f => injected(init).map(f -> _))
                    case _ => None
              }
              val fromMembers = td.member.l.flatMap(m =>
                  declared(file, m.typeFullName, m.code).map(m.name -> _)
              )
              (fromMembers ++ fromParams ++ fromInject).toMap
          }
        )

    /** The type of `this.m`, of a parameter, or of a local initialised by `inject(X)`. */
    def typeOf(expr: Expression): Option[JsTypeRef] =
        JsShapes.unwrap(expr) match
          case fa: Call if fa.name == Operators.fieldAccess =>
              (fieldBase(fa), fieldName(fa)) match
                case (Some(base: Identifier), Some(field)) if base.name == "this" =>
                    enclosingTypeDecl(fa.method).flatMap(td => memberTypes(td).get(field))
                case _ => None
          case id: Identifier =>
              val file = id.method.filename
              id.method.parameter.nameExact(id.name).headOption
                  .flatMap(p => declared(file, p.typeFullName, p.code))
                  .orElse(JsValues.origin(id) match
                    case init: Call => injected(init)
                    case _          => None
                  )
          case _ => None
  end Di

  /** `this.products.fetchPartnerFeed(url)`, where `products` was injected as the project's own
    * `ProductService`: the frontend leaves the call unresolved (it cannot know the member's type),
    * so a value handed to a service never reached the request the service makes. The call is
    * resolved to the service's method of that name.
    */
  private def resolveServiceCalls(ctx: JsContext, di: Di): Unit =
    val classes = ctx.cpg.typeDecl.internal.l.groupBy(_.name)
    ctx.cpg.call.filterNot(_.name.startsWith("<operator>")).foreach { call =>
        if call.callee(using NoResolve).isEmpty then
          receiverOf(call).flatMap(di.typeOf).filter(_.pkg.isEmpty).foreach { t =>
              classes.getOrElse(t.name, Nil) match
                case td :: Nil =>
                    td.method.nameExact(call.name).headOption.foreach(ctx.tagger.resolveCall(
                      call,
                      _
                    ))
                case _ =>
          }
    }

  // -----------------------------------------------------------------------------------------
  // Sources
  // -----------------------------------------------------------------------------------------

  private def isRouteType(t: JsTypeRef): Boolean =
      t.is("ActivatedRoute", RoutePkg) || t.is("ActivatedRouteSnapshot", RoutePkg)

  /** Names an `ActivatedRoute` is idiomatically injected as. Used only when the injection itself
    * cannot be typed (an untyped parameter, an `any` member) and the file imports ActivatedRoute.
    */
  private val RouteMemberNames = Set("route", "activatedRoute", "activeRoute", "currentRoute")

  private def tagRouteSources(ctx: JsContext, di: Di): Unit =
    val routeFiles = ctx.modules.imports
        .filter(i =>
            i.packageName.contains(RoutePkg) &&
                (i.imported == "ActivatedRoute" || i.imported == "ActivatedRouteSnapshot")
        )
        .map(_.file)
        .toSet
    def isRoute(expr: Expression): Boolean =
        di.typeOf(expr).exists(isRouteType) ||
            (routeFiles.contains(expr.method.filename) && (JsShapes.unwrap(expr) match
              case fa: Call =>
                  fieldBase(fa).exists(_.code == "this") &&
                  fieldName(fa).exists(n => RouteMemberNames.contains(n.stripPrefix("_")))
              case id: Identifier => RouteMemberNames.contains(id.name)
              case _              => false
            ))
    // Strip `snapshot`/`parent`/`root`/`firstChild` hops to find the route the read starts from.
    def routeOf(expr: Expression): Option[Expression] =
        JsShapes.unwrap(expr) match
          case fa: Call
              if fa.name == Operators.fieldAccess && fieldName(fa).exists(RouteHops.contains) =>
              fieldBase(fa).flatMap(routeOf).orElse(Option.when(isRoute(fa))(fa))
          case other => Option.when(isRoute(other))(other)

    val reads = ctx.fieldAccesses.filter(fa =>
        fieldName(fa).exists(RouteDataFields.contains) && fieldBase(fa).flatMap(routeOf).nonEmpty
    )
    ctx.tagger.tag(readChains(reads), INPUT)
    // The observables deliver to callbacks, which no dataflow edge reaches.
    reads.foreach(r => ctx.tagger.tag(JsValues.consumersOf(r).iterator, INPUT))
  end tagRouteSources

  private def tagLocationSources(ctx: JsContext, di: Di): Unit =
    // `this.router.url`: the current URL.
    val routerUrl = ctx.fieldAccesses.filter(fa =>
        fieldName(fa).contains("url") &&
            fieldBase(fa).flatMap(di.typeOf).exists(_.is("Router", RoutePkg))
    )
    ctx.tagger.tag(readChains(routerUrl), INPUT)
    // `this.location.path()`, `this.platformLocation.hash`
    val locationPath = ctx.cpg.call.nameExact("path").filter(c =>
        receiverOf(c).flatMap(di.typeOf).exists(_.is("Location", CommonPkg))
    )
    ctx.tagger.tag(locationPath, INPUT)
    val platformLocation = ctx.fieldAccesses.filter(fa =>
        fieldName(fa).exists(Set("href", "hash", "search", "pathname").contains) &&
            fieldBase(fa).flatMap(di.typeOf).exists(_.is("PlatformLocation", CommonPkg))
    )
    ctx.tagger.tag(readChains(platformLocation), INPUT)

  /** `this.<member>` reads in the methods of a member's class. Matched on the whole code of the
    * field access, which IS `this.<member>`: a substring match would bleed an `@Input() id` onto
    * `this.idx`.
    */
  private def thisReads(td: TypeDecl, member: String): Iterator[Call] =
      classMethods(td).iterator.flatMap(_.ast.isCall)
          .nameExact(Operators.fieldAccess)
          .codeExact(s"this.$member")

  /** `@Input()` members and setters. */
  private def tagDecoratorInputs(ctx: JsContext): Unit =
      ctx.cpg.annotation.nameExact("Input").foreach { annotation =>
          annotation.astParent match
            case member: Member =>
                ctx.tagger.tag(Iterator(member), INPUT)
                ctx.tagger.tag(thisReads(member.typeDecl, member.name), INPUT)
            case setter: Method =>
                ctx.tagger.tag(params(setter).iterator, INPUT)
            case _ =>
      }

  /** Signal inputs: `input()`, `input.required()`, `model()`, `model.required()` from
    * `@angular/core`.
    *
    * The calls are found through the import of `input`/`model` in the same file, so a renamed
    * import still counts and a local function that happens to be called `input` does not. Their
    * full names cannot be used: type recovery names `input.required()` after the type of `input`,
    * which stops being the import once the TypeScript types of an installed `@angular/core` (or a
    * typed parameter or local called `input`) replace it, and it names `input()` after a method of
    * the same file that is also called `input`.
    *
    * The field initialiser `bio = input<string>('')` is lowered into the constructor as an
    * assignment to an identifier with the code of the member, which is how the member is found. The
    * field access `this.bio` is tagged, as for `@Input()`: it is under every read `this.bio()` and
    * it is all there is when the signal is handed on without being called.
    *
    * Not covered: an initialiser wrapped in `as T`, `!` or a conditional; `this.x = input()` in the
    * constructor body; an `input` reached through `import * as ng` or a re-export.
    */
  private def tagSignalInputs(ctx: JsContext): Unit =
      Seq("input", "model").foreach { exported =>
          ctx.modules.imports
              .filter(i =>
                  i.kind == ImportKind.Named && i.imported == exported &&
                      i.packageName.contains(CorePkg)
              )
              .foreach { imp =>
                val alias = imp.local
                val initialisers = ctx.cpg.file.nameExact(imp.file).method.ast.isCall.filter {
                    call =>
                      val isPlain = call.name == alias &&
                          call.receiver.isIdentifier.nameExact(alias).nonEmpty
                      val isRequired = call.name == "required" &&
                          call.argumentOption(0).exists {
                              case id: Identifier => id.name == alias
                              case _              => false
                          }
                      isPlain || isRequired
                }
                initialisers.foreach { initialiser =>
                    for
                      enclosing <- initialiser.inCall.headOption
                      if enclosing.name == Operators.assignment
                      if enclosing.argumentOption(1).exists(_.isInstanceOf[Identifier])
                      typeDecl <- initialiser.method.typeDecl
                      member   <- typeDecl.member.codeExact(enclosing.code).headOption
                    do
                      ctx.tagger.tag(Iterator(member), INPUT)
                      ctx.tagger.tag(thisReads(typeDecl, member.name), INPUT)
                }
              }
      }

  /** `@HostListener('window:message', ['$event'])`: a message from any origin. Also the URL changes
    * (`window:hashchange`, `window:popstate`).
    */
  private val HostListenerEvents =
      "(?s).*HostListener\\(\\s*['\"`]window:(message|hashchange|popstate)['\"`].*"

  private def tagHostListeners(ctx: JsContext): Unit =
      ctx.cpg.annotation.nameExact("HostListener").filter(_.code.matches(HostListenerEvents))
          .foreach { annotation =>
              annotation.astParent match
                case handler: Method => ctx.tagger.tag(firstParam(handler).iterator, INPUT)
                case _               =>
          }

  private val GuardTypes =
      "ResolveFn|CanActivateFn|CanActivateChildFn|CanMatchFn|CanLoadFn|MaybeAsync"

  /** Functional resolvers and guards receive the route being activated: `export const heroResolver:
    * ResolveFn<Hero> = (route, state) => ...`, or inline in a route record (`resolve: { hero:
    * (route) => ... }`, `canActivate: [(route) => ...]`). Their parameters are route data; a typed
    * `ActivatedRouteSnapshot` parameter anywhere is handled with the other route reads.
    */
  private def tagGuardsAndResolvers(ctx: JsContext): Unit =
    val typedAssignments = ctx.cpg.call.nameExact(Operators.assignment).filter(a =>
        a.code.matches(s"(?s)^(export\\s+)?(const|let|var)\\s+[\\w$$]+\\s*:\\s*($GuardTypes)\\b.*")
    )
    val typedHandlers = typedAssignments.flatMap(_.argumentOption(2)).flatMap(callbacksIn(_))
    // In a Routes array: `_tmp.resolve = {...}` / `_tmp.canActivate = [...]` property writes.
    val routeKeys = Set("resolve", "canActivate", "canActivateChild", "canMatch", "canLoad")
    val inlineHandlers = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(1).exists {
                case fa: Call => fieldName(fa).exists(routeKeys.contains)
                case _        => false
            } && ctx.modules.importsOf(a.method.filename).exists(_.packageName.contains(RoutePkg))
        )
        .flatMap(_.argumentOption(2))
        .flatMap(v => v.ast.collectAll[MethodRef].flatMap(r => callbackMethod(r)))
    ctx.tagger.tag((typedHandlers ++ inlineHandlers).flatMap(firstParam), INPUT)

  /** HttpClient responses, and the service methods that hand them on. */
  private def tagHttp(ctx: JsContext, di: Di): Unit =
    def isHttpClient(e: Expression): Boolean =
        di.typeOf(e).exists(_.is("HttpClient", CommonPkg))
    val httpCalls = ctx.cpg.call.filter(c =>
        HttpVerbs.contains(c.name) && receiverOf(c).exists(isHttpClient)
    ).l
    val producers = mutable.LinkedHashSet.from[Call](httpCalls)

    // A producer, or a `pipe`/`then` chain on one.
    def isProducer(e: Expression, depth: Int = 6): Boolean =
        depth > 0 && (JsValues.origin(e) match
          case c: Call =>
              producers.contains(c) ||
              ((c.name == "pipe" || c.name == "then") &&
                  receiverOf(c).exists(isProducer(_, depth - 1)))
          case _ => false
        )

    // Service methods returning a producer, to a fixpoint (a method may return another's result).
    val serviceMethods = ctx.cpg.method.internal
        .filter(m => !m.name.startsWith("<") && !m.name.startsWith("anonymous"))
        .filter(_.ast.isReturn.nonEmpty)
        .l
    val producerMethods = mutable.LinkedHashSet.empty[Method]
    var changed         = true
    var rounds          = 0
    while changed && rounds < 4 do
      changed = false
      rounds += 1
      serviceMethods.filterNot(producerMethods.contains).foreach { m =>
          if m.ast.isReturn.astChildren.collect { case e: Expression => e }.exists(isProducer(_))
          then
            producerMethods += m
            changed = true
      }
      // Calls of the producer methods are producers themselves.
      producerMethods.foreach { m =>
        val owner = enclosingTypeDecl(m)
        ctx.cpg.call.nameExact(m.name).foreach { c =>
          val calledOnOwner = receiverOf(c).exists { r =>
              di.typeOf(r).exists(t => owner.exists(_.name == t.name) && t.pkg.isEmpty) ||
              (r.code == "this" && owner.exists(o => enclosingTypeDecl(c.method).contains(o)))
          }
          if calledOnOwner && producers.add(c) then changed = true
        }
      }
    end while
    // The values reach the callbacks of the observable. The producing calls themselves are not
    // tagged: an Observable is not its values, and a tagged call is a source for everything its
    // arguments reach - including, through `this`, the body of the service method it calls.
    producers.foreach(p => ctx.tagger.tag(JsValues.consumersOf(p).iterator, INGRESS))
    // ... except where rxjs turns the observable into its value: `await firstValueFrom(obs)`,
    // `toSignal(obs)`.
    val unwrapped = ctx.cpg.call.nameExact("firstValueFrom", "lastValueFrom", "toSignal").filter(
      _.argument.filter(_.argumentIndex == 1).exists(isProducer(_))
    )
    ctx.tagger.tag(unwrapped, INGRESS)

    // A request whose URL is not fixed by the code.
    val requests = httpCalls.flatMap { c =>
      val urlIndex = if c.name == "request" then 2 else 1
      c.argument.filter(_.argumentIndex == urlIndex).headOption.toList.flatMap(requestSinksFor(
        c,
        _
      ))
    }
    ctx.tagger.tag(requests.iterator, RequestSink*)
  end tagHttp

  /** `httpResource(() => url)`: the URL the callback returns is requested, judged like the URL of
    * an `HttpClient` request.
    */
  private def tagHttpResources(ctx: JsContext): Unit =
    val urls = ctx.cpg.call.nameExact("httpResource").l.flatMap { c =>
        c.argument.filter(_.argumentIndex == 1).l.flatMap(callbacksIn(_))
            .flatMap(_.ast.isReturn.astChildren.collect { case e: Expression => e }.l)
            .flatMap(requestSinksFor(c, _))
    }
    ctx.tagger.tag(urls.iterator, RequestSink*)

  /** Reactive forms: what a user types arrives through `valueChanges`. */
  private def tagForms(ctx: JsContext): Unit =
      ctx.fieldAccesses.filter(fa => fieldName(fa).contains("valueChanges")).foreach { changes =>
          ctx.tagger.tag(JsValues.consumersOf(changes).iterator, INPUT)
      }

  /** `@Component({ host: { '(window:message)': 'onMessage($event)' } })` binds a handler by name.
    */
  private val HostBinding =
      """['"`]\(window:(message|hashchange|popstate)\)['"`]\s*:\s*['"`]\s*([\w$]+)\s*\(""".r

  private def tagHostMetadata(ctx: JsContext): Unit =
      ctx.cpg.annotation.nameExact("Component", "Directive").foreach { annotation =>
          HostBinding.findAllMatchIn(annotation.code).map(_.group(2)).foreach { handler =>
              annotation.astParent match
                case td: TypeDecl =>
                    ctx.tagger.tag(td.method.nameExact(handler).flatMap(firstParam), INPUT)
                case _ =>
          }
      }

  /** `router.navigateByUrl(url)` navigates within the app to whatever the caller chose. A command
    * array (`navigate(['/product', id])`) fixes the route and is no sink.
    */
  private def tagNavigation(ctx: JsContext, di: Di): Unit =
    val byUrl = ctx.cpg.call.nameExact("navigateByUrl").filter(c =>
        receiverOf(c).flatMap(di.typeOf).exists(_.is("Router", RoutePkg)) &&
            c.argument.filter(_.argumentIndex == 1).headOption.exists(t =>
                !isObjectLiteral(t) && !hasFixedOrigin(t)
            )
    )
    ctx.tagger.tag(byUrl, NavigationSink*)

  // -----------------------------------------------------------------------------------------
  // Sinks and sanitisers
  // -----------------------------------------------------------------------------------------

  private val BypassCalls = Set(
    "bypassSecurityTrustHtml",
    "bypassSecurityTrustScript",
    "bypassSecurityTrustStyle",
    "bypassSecurityTrustUrl",
    "bypassSecurityTrustResourceUrl"
  )

  private val RendererProperties = Set("innerHTML", "outerHTML", "srcdoc", "href", "src")

  private def tagSinks(ctx: JsContext): Unit =
    ctx.tagger.tag(ctx.cpg.call.nameExact(BypassCalls.toSeq*), HtmlSink*)

    // Renderer2: setProperty(el, 'innerHTML', v), setAttribute(el, 'href', v)
    val rendererWrites = ctx.cpg.call.nameExact("setProperty", "setAttribute").filter { c =>
      val args = c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
      args.size >= 3 && args.lift(1).flatMap(literalValue).exists(n =>
          RendererProperties.contains(n) || n.toLowerCase.startsWith("on")
      )
    }
    ctx.tagger.tag(rendererWrites, HtmlSink*)

    // DomSanitizer.sanitize(SecurityContext.HTML, value)
    val sanitize = ctx.cpg.call.nameExact("sanitize").filter(
      _.argument.filter(_.argumentIndex == 1).exists(_.code.contains("SecurityContext."))
    )
    ctx.tagger.tag(sanitize, SANITIZER, sanitizerFor(XSS), sanitizerFor(REDIRECT))
end AngularRecognizer

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

  /** rxjs operators that replace each value with what an inner observable emits. */
  private val SwitchingOperators = Set("switchMap", "mergeMap", "concatMap", "exhaustMap")

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
    tagTemplateBindings(ctx)

  private val TemplateUrl = """templateUrl\s*:\s*['"`]([^'"`]+)['"`]""".r
  private val Selector    = """selector\s*:\s*['"`]([^'"`]+)['"`]""".r
  private val Binding     = """\[\(?([\w$]+)\)?\]\s*=\s*"([^"]*)"""".r
  private val InputAlias  = """(?:alias\s*:\s*|@Input\(\s*)['"`]([\w$-]+)['"`]""".r
  private val LeadingName = """^\s*(?:this\.)?([A-Za-z_$][\w$]*)""".r

  /** Components and directives by what their selector matches: an element name (`app-rich-text`),
    * or an attribute (`[appHighlight]`).
    */
  private def selectors(ctx: JsContext): List[(TypeDecl, Either[String, String])] =
      ctx.cpg.annotation.nameExact("Component", "Directive").l.flatMap { annotation =>
          annotation.astParent match
            case td: TypeDecl =>
                Selector.findFirstMatchIn(annotation.code).toList
                    .flatMap(_.group(1).split(',').map(_.trim))
                    .flatMap {
                        case e if e.matches("[a-z][\\w-]*") => Some(td -> Left(e))
                        case a if a.matches("\\[[\\w$-]+\\]") =>
                            Some(td -> Right(a.drop(1).dropRight(1)))
                        case _ => None
                    }
            case _ => None
      }

  /** The template text of each component: the inline `template`, or the elements of its
    * `templateUrl` file.
    */
  private def templateTexts(ctx: JsContext): List[(TypeDecl, String)] =
    val external = componentTemplates(ctx).map((td, html) =>
        td -> ctx.cpg.templateDom.nameExact("JSXElement").where(_.file.nameExact(html)).code.l
            .mkString("\n")
    )
    val inlined = ctx.cpg.annotation.nameExact("Component").l.flatMap { annotation =>
        annotation.astParent match
          case td: TypeDecl if annotation.code.contains("template:") => Some(td -> annotation.code)
          case _                                                     => None
    }
    external ++ inlined

  /** The member each binding name of a class's inputs stands for: the member's own name, or the
    * alias it is declared with (`@Input('promoHtml')`, `@Input({ alias: 'promoHtml' })`, `input('',
    * { alias: 'promoHtml' })`).
    */
  private def inputNames(ctx: JsContext, td: TypeDecl): Map[String, String] =
    val initialisers = ctx.memberWrites.filter(_._1.id() == td.id())
        .groupMap(_._2)(_._3.code)
    val annotated = ctx.cpg.annotation.nameExact("Input").l.flatMap { a =>
        a.astParent match
          case m: Member if m.typeDecl.id() == td.id() => Some(m.name -> a.code)
          case m: Method if enclosingTypeDecl(m).exists(_.id() == td.id()) =>
              Some(m.name -> a.code)
          case _ => None
    }
    (annotated ++ initialisers.toList.flatMap((name, codes) => codes.map(name -> _)))
        .flatMap((name, code) => InputAlias.findFirstMatchIn(code).map(_.group(1) -> name))
        .toMap

  /** The inputs a parent's template binds on another component or directive: (the child, the input
    * member, the parent, the bound expression's text).
    */
  private def templateBindings(ctx: JsContext): List[(TypeDecl, String, TypeDecl, String)] =
    val bySelector = selectors(ctx)
    if bySelector.isEmpty then return Nil
    val aliases = mutable.HashMap.empty[Long, Map[String, String]]
    def member(child: TypeDecl, bound: String) =
        aliases.getOrElseUpdate(child.id(), inputNames(ctx, child)).getOrElse(bound, bound)
    templateTexts(ctx).flatMap { (parent, text) =>
        bySelector.flatMap {
            case (child, Left(element)) =>
                ("(?s)<" + java.util.regex.Pattern.quote(element) + "(\\s[^>]*)?>").r
                    .findAllMatchIn(text).toList.flatMap(m =>
                        Binding.findAllMatchIn(Option(m.group(1)).getOrElse("")).map(b =>
                            (child, member(child, b.group(1)), parent, b.group(2))
                        )
                    )
            case (child, Right(attribute)) =>
                ("\\[" + java.util.regex.Pattern.quote(attribute) + "\\]\\s*=\\s*\"([^\"]*)\"").r
                    .findAllMatchIn(text).toList
                    .map(b => (child, member(child, attribute), parent, b.group(1)))
        }
    }
  end templateBindings

  /** True when a bound expression is a member of the parent - whose value the bridge can follow -
    * or a constant.
    */
  private def isFollowable(parent: TypeDecl, expr: String): Boolean =
      expr.trim.matches("""'[^']*'|-?\d+(\.\d+)?|true|false|null""") ||
          LeadingName.findFirstMatchIn(expr).map(_.group(1)).exists(name =>
              parent.member.nameExact(name).nonEmpty || classMethods(parent).exists(_.name == name)
          )

  /** Components and directives some template renders, and of their inputs those a parent binds to
    * something the bridge cannot follow (a template variable, `@if (product(); as p)`): those stay
    * sources.
    */
  private def fedInputs(ctx: JsContext): (Set[Long], Set[(Long, String)]) =
    val bySelector = selectors(ctx)
    val texts      = templateTexts(ctx).map(_._2)
    val fed = bySelector.collect {
        case (td, Left(element)) if texts.exists(_.contains(s"<$element")) => td.id()
        case (td, Right(attr)) if texts.exists(_.contains(s"[$attr]"))     => td.id()
    }.toSet
    val unfollowable = templateBindings(ctx).collect {
        case (child, input, parent, expr) if !isFollowable(parent, expr) => child.id() -> input
    }.toSet
    (fed, unfollowable)

  /** A child's input is what its parents bind to it: `<app-rich-text [html]="sellerNote" />` hands
    * the parent's `sellerNote` to the child's `html`. Where a source reaches the parent member's
    * value, the child's reads of the input (`this.html`, its setter's parameter, its template's
    * `html()`) are tagged with that source, with where the value came from. Runs with the bridges.
    */
  def bridgeInputs(ctx: JsContext): Unit =
    val bindings = templateBindings(ctx)
    if bindings.isEmpty then return
    val members        = ctx.memberWrites.groupMap(w => (w._1.id(), w._2))(_._3)
    lazy val templates = componentTemplates(ctx).groupMap(_._1.id())(_._2)
    bindings.filter(b => isFollowable(b._3, b._4))
        .groupMap(b => (b._1, b._2))(b => (b._3, b._4)).foreach { case ((child, input), from) =>
            from.iterator.flatMap { (parent, expr) =>
                LeadingName.findFirstMatchIn(expr).map(_.group(1)).toList
                    .flatMap(name => members.getOrElse((parent.id(), name), Nil))
                    .flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v))
            }.nextOption().foreach { (found, value) =>
              val setters = classMethods(child).filter(_.name == input).flatMap(params)
              val reads   = thisReads(child, input).toList
              val inTemplate =
                  templates.getOrElse(child.id(), Nil).flatMap(templateReads(ctx, _, input))
              ctx.tagger.tagVia(
                readChains(reads) ++ setters ++ inTemplate,
                found.tag,
                found.places(value)*
              )
            }
        }
  end bridgeInputs
  private val PipeName = """name\s*:\s*['"`]([\w$-]+)['"`]""".r

  /** Components and their external templates: `@Component({ templateUrl: './x.component.html' })`,
    * the URL resolved from the component's own file. astgen lowers the template to the bindings'
    * expressions, which read the component's members by bare name.
    */
  def componentTemplates(ctx: JsContext): List[(TypeDecl, String)] =
      ctx.cpg.annotation.nameExact("Component").l.flatMap { annotation =>
          annotation.astParent match
            case td: TypeDecl =>
                TemplateUrl.findFirstMatchIn(annotation.code).map(_.group(1)).flatMap { url =>
                  val html = JsModules.resolveRelative(td.filename, url)
                  ctx.cpg.file.nameExact(html).headOption.map(_ => td -> html)
                }
            case _ => None
      }

  /** Reads of a component member in its template: `term`, and `caption()` for a signal. */
  def templateReads(ctx: JsContext, template: String, member: String): List[CfgNode] =
    val methods = ctx.cpg.method.filenameExact(template).l
    methods.flatMap(_.ast.isIdentifier.nameExact(member)).filterNot(isAssignmentTarget) ++
        methods.flatMap(_.call.nameExact(member))

  /** A template's bindings read the component's members, so a member that is a source is one there
    * too: an `input()` read as `caption()`, a field the user types into through `[(ngModel)]` -
    * which writes the field with the control's value - read anywhere in the component. A pipe
    * (`caption() | safeHtml`, lowered to `safeHtml(caption())`) is resolved to its class's
    * `transform`, so a pipe that bypasses the sanitiser is reached through its own code.
    */
  private def tagTemplateBindings(ctx: JsContext): Unit =
    val templates = componentTemplates(ctx)
    if templates.isEmpty then return
    val inputMembers = ctx.tagger.taggedIds(INPUT).l
        .flatMap(id =>
            ctx.cpg.graph.node(id) match
              case m: Member => Some(m)
              case _         => None
        )
    templates.foreach { (td, html) =>
      val fields = ctx.cpg.templateDom.nameExact("JSXAttribute")
          .where(_.file.nameExact(html))
          .code("""\[\(ngModel\)\]\s*=.*""").l
          .flatMap(a =>
              """=\s*["']([A-Za-z_$][\w$]*)["']""".r.findFirstMatchIn(a.code).map(_.group(1))
          )
          .toSet
      fields.foreach { f =>
        ctx.tagger.tag(thisReads(td, f), INPUT)
        ctx.tagger.tag(templateReads(ctx, html, f), INPUT)
      }
      inputMembers.filter(_.typeDecl.id() == td.id()).map(_.name).distinct.foreach { input =>
          ctx.tagger.tag(templateReads(ctx, html, input), INPUT)
      }
    }
    resolvePipes(ctx, templates.map(_._2).toSet)
  end tagTemplateBindings

  private def resolvePipes(ctx: JsContext, templates: Set[String]): Unit =
    val transforms = ctx.cpg.annotation.nameExact("Pipe").l.flatMap { annotation =>
        annotation.astParent match
          case td: TypeDecl =>
              PipeName.findFirstMatchIn(annotation.code).map(_.group(1)).flatMap(name =>
                  td.method.nameExact("transform").headOption.map(name -> _)
              )
          case _ => None
    }.groupBy(_._1).collect { case (name, (_, transform) :: Nil) => name -> transform }
    if transforms.isEmpty then return
    ctx.cpg.call
        .filter(c => transforms.contains(c.name) && templates.contains(c.method.filename))
        .foreach(c => ctx.tagger.resolveCall(c, transforms(c.name)))

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
          // `inject(ActivatedRoute).snapshot.queryParamMap`, read straight off the injection
          case c: Call => injected(c)
          case _       => None
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
    // and after a `map`, the next operator's callback receives what the map returned
    reads.foreach(r =>
        JsValues.mappedInto(r).foreach((param, returned) =>
            ctx.tagger.tagVia(Iterator(param), INPUT, returned*)
        )
    )
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
          .filterNot(isAssignmentTarget)

  /** `@Input()` members and setters - of a component no template renders (a routed one, bound from
    * the URL); the others' are what their parents bind ([[bridgeInputs]]). An input transformed to
    * a number or a boolean holds no text.
    */
  private def tagDecoratorInputs(ctx: JsContext): Unit =
    val (fed, unfollowable) = fedInputs(ctx)
    def bound(td: TypeDecl, name: String) =
        fed.contains(td.id()) && !unfollowable.contains(td.id() -> name)
    ctx.cpg.annotation.nameExact("Input")
        .filterNot(a => a.code.contains("numberAttribute") || a.code.contains("booleanAttribute"))
        .foreach { annotation =>
            annotation.astParent match
              case member: Member if bound(member.typeDecl, member.name)                     =>
              case setter: Method if enclosingTypeDecl(setter).exists(bound(_, setter.name)) =>
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
    * assignment to `this.bio` whose code is the member's declaration, which is how the member is
    * found and told apart from `this.bio = input()` in the constructor body (whose member's code is
    * the write itself). The field access `this.bio` is tagged, as for `@Input()`: it is under every
    * read `this.bio()` and it is all there is when the signal is handed on without being called.
    *
    * Not covered: an initialiser wrapped in `as T`, `!` or a conditional; `this.x = input()` in the
    * constructor body; an `input` reached through `import * as ng` or a re-export.
    */
  private def tagSignalInputs(ctx: JsContext): Unit =
    val (fed, unfollowable) = fedInputs(ctx)
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
                    if enclosing.argumentOption(1).exists(_.code.startsWith("this."))
                    if !initialiser.code.matches("(?s).*\\b(numberAttribute|booleanAttribute)\\b.*")
                    typeDecl <- initialiser.method.typeDecl
                    // a field initialiser's member code is the declaration (`bio = input('')`); a
                    // member made by a write in the constructor body starts with `this.`
                    member <- typeDecl.member.codeExact(enclosing.code)
                        .filterNot(_.code.startsWith("this.")).headOption
                    if !fed.contains(typeDecl.id()) ||
                        unfollowable.contains(typeDecl.id() -> member.name)
                  do
                    ctx.tagger.tag(Iterator(member), INPUT)
                    ctx.tagger.tag(thisReads(typeDecl, member.name), INPUT)
              }
            }
    }
  end tagSignalInputs

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
    // Each producer of response data, with the requests behind it - where the data came from.
    val producers = mutable.LinkedHashMap.from[Call, List[Call]](httpCalls.map(c => c -> List(c)))

    // The requests behind a producer: a request, a service call returning one, or a `pipe`/`then`
    // chain on one - or a pipe whose `switchMap(x => request)` swaps its values for a response.
    def requestsBehind(e: Expression, depth: Int = 6): List[Call] =
        if depth <= 0 then Nil
        else
          JsValues.origin(e) match
            case c: Call if producers.contains(c) => producers(c)
            case c: Call if c.name == "pipe" || c.name == "then" =>
                receiverOf(c).toList.flatMap(requestsBehind(_, depth - 1)) ++
                    c.argument.filter(_.argumentIndex >= 1).isCall
                        .filter(op => SwitchingOperators.contains(op.name)).l
                        .flatMap(_.argument.l.flatMap(callbacksIn(_)))
                        .flatMap(_.ast.isReturn.astChildren.collect { case r: Expression => r }.l)
                        .flatMap(requestsBehind(_, depth - 1))
            case _ => Nil
    def isProducer(e: Expression): Boolean = requestsBehind(e).nonEmpty

    // Service methods returning a producer, to a fixpoint (a method may return another's result).
    val serviceMethods = ctx.cpg.method.internal
        .filter(m => !m.name.startsWith("<") && !m.name.startsWith("anonymous"))
        .filter(_.ast.isReturn.nonEmpty)
        .l
    val producerMethods = mutable.LinkedHashMap.empty[Method, List[Call]]
    var changed         = true
    var rounds          = 0
    while changed && rounds < 4 do
      changed = false
      rounds += 1
      serviceMethods.filterNot(producerMethods.contains).foreach { m =>
        val behind = m.ast.isReturn.astChildren.collect { case e: Expression => e }.l
            .flatMap(requestsBehind(_))
        if behind.nonEmpty then
          producerMethods.update(m, behind.distinctBy(_.id()))
          changed = true
      }
      // Calls of the producer methods are producers themselves.
      producerMethods.foreach { (m, behind) =>
        val owner = enclosingTypeDecl(m)
        ctx.cpg.call.nameExact(m.name).foreach { c =>
          val calledOnOwner = receiverOf(c).exists { r =>
              di.typeOf(r).exists(t => owner.exists(_.name == t.name) && t.pkg.isEmpty) ||
              (r.code == "this" && owner.exists(o => enclosingTypeDecl(c.method).contains(o)))
          }
          if calledOnOwner && !producers.contains(c) then
            producers.update(c, behind)
            changed = true
        }
      }
    end while
    // The values reach the callbacks of the observable. The producing calls themselves are not
    // tagged: an Observable is not its values, and a tagged call is a source for everything its
    // arguments reach - including, through `this`, the body of the service method it calls.
    producers.foreach((p, behind) =>
        ctx.tagger.tagVia(JsValues.consumersOf(p).iterator, INGRESS, behind*)
    )
    // ... except where rxjs turns the observable into its value: `await firstValueFrom(obs)`,
    // `toSignal(obs)`.
    ctx.cpg.call.nameExact("firstValueFrom", "lastValueFrom", "toSignal").l.foreach { c =>
      val behind = c.argument.filter(_.argumentIndex == 1).l.flatMap(requestsBehind(_))
      if behind.nonEmpty then ctx.tagger.tagVia(Iterator(c), INGRESS, behind*)
    }

    // A request whose URL is not fixed by the code.
    val requests = httpCalls.flatMap { c =>
      val urlIndex = if c.name == "request" then 2 else 1
      c.argument.filter(_.argumentIndex == urlIndex).headOption.toList.flatMap { url =>
          // a local the URL was built into (`const endpoint = this.host + '/submitKey'`) keeps
          // its origin's shape; judging the bare identifier would sink every such request
          requestSinksFor(c, JsValues.origin(url))
      }
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

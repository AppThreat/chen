package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Vue 3, Vue Router 4 and the application side of Nuxt (https://vuejs.org,
  * https://router.vuejs.org, https://nuxt.com).
  *
  * Sources:
  *   - the route: `useRoute()` and the Options API's `this.$route` (also `$route` in templates);
  *     the `to` location of navigation guards (`router.beforeEach`, `beforeEnter`,
  *     `onBeforeRouteUpdate`, Nuxt route middleware);
  *   - component props: `defineProps()`/`withDefaults()`/`defineModel()`, `setup(props)`, and the
  *     Options API's declared `props` read as `this.<prop>` - with `props: true` on a route record
  *     the router passes path parameters straight in, and parents pass whatever they hold;
  *   - custom directives: the `binding` a directive hook receives is the bound template value;
  *   - Nuxt's request composables (`useCookie`, `useRequestHeaders`, `useRequestURL`, ...) and its
  *     data fetching (`useFetch`, `useAsyncData`: remote data).
  *
  * Sinks: `v-html` and URL bindings are template sinks (EasyTagsPass, DomRecognizer); here, render
  * functions (`h('div', { innerHTML })`), `useHead({ script: [{ innerHTML }] })`, `navigateTo(url,
  * { external: true })`, and router navigation to a target the code does not fix.
  *
  * Nuxt auto-imports all of these, so they are matched by name in a project that is a Vue/Nuxt one
  * by its imports or its manifest.
  */
object VueRecognizer extends JsFrameworkRecognizer:

  val name: String = "vue"

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("vue", "@vue", "vue-router", "nuxt", "#imports", "#app", "pinia") ||
          ctx.project.dependsOn("vue", "nuxt") || ctx.project.hasFile(".*\\.vue")

  private val GuardRegistrations = Set("beforeEach", "beforeResolve", "afterEach")
  private val InComponentGuards  = Set("onBeforeRouteUpdate", "onBeforeRouteLeave")
  private val Middleware         = Set("defineNuxtRouteMiddleware", "addRouteMiddleware")

  private val RequestComposables =
      Set("useCookie", "useRequestHeaders", "useRequestHeader", "useRequestURL", "useRequestEvent")

  private val DataComposables = Set("useFetch", "useLazyFetch", "useAsyncData", "useLazyAsyncData")

  private val DirectiveHooks =
      Set("created", "beforeMount", "mounted", "beforeUpdate", "updated", "getSSRProps")

  def run(ctx: JsContext): Unit =
    tagRoute(ctx)
    tagProps(ctx)
    tagGuards(ctx)
    ctx.tagger.tag(ctx.cpg.call.nameExact(RequestComposables.toSeq*), INPUT)
    ctx.tagger.tag(ctx.cpg.call.nameExact(DataComposables.toSeq*), INGRESS)
    tagSinks(ctx)
    linkProvideInject(ctx)
    linkPiniaActions(ctx)
    linkComposableReturns(ctx)
    tagRouterPropsFunctions(ctx)

  /** `provide(key, value)` / `inject(key)`: the injected value IS the provided one, keyed by the
    * same InjectionKey or literal. The engine link is a resolved call from `inject(key)` to the
    * method that produces the value - a derivation's callback for `provide(key, computed(() =>
    * ...))`, the provided value being what that callback returns.
    */
  private def linkProvideInject(ctx: JsContext): Unit =
    def keyOf(expr: Expression): Option[String] = expr match
      case l: Literal => literalValue(l)
      case id: Identifier =>
          ctx.modules.resolve(id.method.filename, id.name).map(i =>
              s"${JsModules.resolveRelative(i.file, i.module)}:${i.imported}"
          )
      case _ => None
    val providers = ctx.cpg.call.nameExact("provide").l.flatMap { call =>
        for
          key   <- call.argument.filter(_.argumentIndex == 1).headOption.flatMap(keyOf)
          value <- call.argument.filter(_.argumentIndex == 2).headOption
          producer <- JsValues.origin(value) match
            case c: Call if ReactiveBridge.isDerivationCall(c) =>
                ReactiveBridge.derivationCallback(c)
            case _ => None
        yield key -> producer
    }.toMap
    if providers.isEmpty then return
    ctx.cpg.call.nameExact("inject").foreach { call =>
        call.argument.filter(_.argumentIndex == 1).headOption.flatMap(keyOf)
            .flatMap(providers.get)
            .foreach(producer => ctx.tagger.resolveCall(call, producer))
    }
  end linkProvideInject

  /** A Pinia store: `useSearchStore = defineStore('search', () => { ...; return { term, setTerm }
    * })`, by the hook a store's file exports. Names shared by more than one store are left alone.
    */
  private def piniaStores(ctx: JsContext): Map[String, Method] =
    if !(ctx.modules.uses("pinia") || ctx.project.dependsOn("pinia")) then return Map.empty
    val setups = ctx.cpg.call.nameExact("defineStore").l.flatMap { call =>
        call.argument.filter(_.argumentIndex >= 2).sortBy(_.argumentIndex).headOption
            .map(a => JsShapes.callbacksIn(a)).getOrElse(Nil)
    }
    if setups.isEmpty then return Map.empty
    // `const useSearchStore = defineStore(...)` - the hook a store's file exports
    ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(2).exists {
                case c: Call => c.name == "defineStore"
                case _       => false
            }
        )
        .flatMap(_.argumentOption(1)).collect { case id: Identifier => id }
        .l
        .flatMap(id => setups.find(s => s.filename == id.method.filename).map(s => id.name -> s))
        .groupMap(_._1)(_._2)
        .collect { case (name, setup :: Nil) => name -> setup }
  end piniaStores

  /** A store's method calls (`store.setTerm(v)`, the receiver one of the store hooks' results) are
    * resolved to the functions the setup returns under that name, carrying the argument in.
    */
  private def linkPiniaActions(ctx: JsContext): Unit =
    val setupByHook = piniaStores(ctx)
    if setupByHook.isEmpty then return
    val methodsOf = setupByHook.values.toList.flatMap { setup =>
        DataLinkBridge.returnedValues(setup).collect { case b: Block => b }
            .flatMap(objectProperties(_).getOrElse(Map.empty))
            .flatMap((k, fn) => JsShapes.callbacksIn(fn).map(k -> _))
    }.groupMap(_._1)(_._2).collect { case (name, m :: Nil) => name -> m }
    ctx.cpg.call.filter(c =>
        methodsOf.contains(c.name) &&
            receiverOf(c).exists(r =>
                JsValues.origin(r) match
                  case h: Call => setupByHook.contains(h.name)
                  case _       => false
            )
    ).foreach(c => methodsOf.get(c.name).foreach(m => ctx.tagger.resolveCall(c, m)))

  /** Every caller's `useSearchStore()` receives the setup's returned object, and reads one member
    * of it at a time - `store.term`, `storeToRefs(store)`'s `term`, `term.value`. Each such read is
    * tagged with the source behind what the setup returns under that member, so a store holding one
    * tainted member and one constant one taints only the first. Runs with the bridges.
    */
  def bridgePiniaStores(ctx: JsContext): Unit =
    val setupByHook = piniaStores(ctx)
    if setupByHook.isEmpty then return
    val consumers = ctx.cpg.call.filter(c => setupByHook.contains(c.name)).method.dedup.l
        .map(m => if m.name == ":program" then m else topLevel(m))
        .distinctBy(_.id())
    DataLinkBridge.bridgeReads(
      ctx,
      consumers,
      (root, path) =>
          root match
            case c: Call if path.nonEmpty =>
                setupByHook.get(c.name).map(setup => DataLinkBridge.produced(List(setup), path))
            case _ => None
    )

  /** The outermost function a method is nested in, below the file's `:program`. */
  private def topLevel(m: Method): Method =
    val segments = m.fullName.split(':')
    val program  = segments.indexWhere(_ == "program")
    if program < 0 || segments.length <= program + 2 then m
    else
      JsIndexes.methodByFullName(m.graph, segments.take(program + 2).mkString(":")).getOrElse(m)

  /** A composable that returns a derived value (`return computed(() => route.query[name])`):
    * resolving its callers' calls to the function carries the derivation - tagged as a source by
    * the reactive bridge - out to every caller. Only functions that return a derivation are linked,
    * so ordinary helper calls stay as they are.
    */
  private def linkComposableReturns(ctx: JsContext): Unit =
    val returning = ctx.cpg.method.internal.l.filter(m =>
        !m.isExternal && m.name != ":program" &&
            m.ast.isReturn.astChildren.collect { case e: Expression => e }.exists { e =>
                JsShapes.unwrap(e) match
                  case c: Call => ReactiveBridge.isDerivationCall(c)
                  case _       => false
            }
    )
    if returning.isEmpty then return
    val byName = returning.groupBy(_.name)
    ctx.cpg.call.filter(c => byName.contains(c.name)).foreach { call =>
        byName.get(call.name) match
          case Some(only :: Nil) => ctx.tagger.resolveCall(call, only)
          case _                 =>
    }

  /** `useRoute()`, `this.$route...`, and `$route...` in a template. */
  private def tagRoute(ctx: JsContext): Unit =
    ctx.tagger.tag(ctx.cpg.call.nameExact("useRoute"), INPUT)
    val routeReads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter { fa =>
        fieldName(fa).contains("$route") ||
        fieldBase(fa).exists {
            case id: Identifier => id.name == "$route"
            case _              => false
        }
    }
    ctx.tagger.tag(readChains(routeReads), INPUT)

  private val PropsTypeKeys = """([A-Za-z_$][\w$]*)\s*\??\s*:""".r

  /** The props a `<script setup>` component declares: the keys of `defineProps<{ html: string
    * }>()`'s type argument, of a `defineProps({ html: String })` object, or the names in
    * `defineProps(['html'])`.
    */
  private def declaredProps(define: Call): Set[String] =
    val typed = define.code.indexOf('<') match
      case i if i >= 0 && define.code.startsWith("defineProps<") =>
          val body = define.code.substring(i + 1).takeWhile(_ != '>')
          PropsTypeKeys.findAllMatchIn(body).map(_.group(1)).toSet
      case _ => Set.empty[String]
    val runtime = define.argument.filter(_.argumentIndex == 1).l.flatMap { arg =>
      val keys = arg.ast.isCall.nameExact(Operators.assignment).flatMap(_.argumentOption(1))
          .collect { case fa: Call => fa }.flatMap(fieldName).l
      if keys.nonEmpty then keys else arg.ast.isLiteral.flatMap(literalValue).l
    }
    (typed ++ runtime).filter(n =>
        n.nonEmpty && n.forall(c => c.isLetterOrDigit || c == '_' || c == '$')
    )

  /** The props a single-file component declares with `defineProps`. */
  def declaredPropNames(ctx: JsContext, file: String): Set[String] =
      ctx.cpg.file.nameExact(file).method.flatMap(_.call.nameExact("defineProps")).l
          .flatMap(declaredProps).toSet

  /** Reads of a single-file component's declared props by bare name, as its template uses them
    * (`v-html="html"`) - not of a script binding that shadows one.
    */
  def templatePropReads(ctx: JsContext, file: String): List[Identifier] =
    val methods = ctx.cpg.file.nameExact(file).method.l
    val names   = declaredPropNames(ctx, file)
    if names.isEmpty then Nil
    else
      methods.flatMap(m =>
          m.ast.isIdentifier.nameExact(names.toSeq*)
              .filterNot(isAssignmentTarget)
              .filter(id => JsIndexes.assignedValues(id.method, id.name).isEmpty)
              .filter(id => id.method.parameter.nameExact(id.name).isEmpty)
              .l
      )

  /** Route records with a `props` function - `{ component: () => import('./Profile.vue'), props:
    * (route) => ({ bio: route.query.bio }) }` - as (the props function, the component's file).
    */
  private def routePropsFunctions(ctx: JsContext): List[(Method, String)] =
      ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(fa: Call), Some(v)) if fieldName(fa).contains("props") =>
                val record = fieldBase(fa).map(_.code).getOrElse("")
                val component = a.astParent.astChildren.isCall.nameExact(Operators.assignment).l
                    .find(_.argumentOption(1).exists {
                        case c: Call =>
                            fieldName(c).contains("component") &&
                            fieldBase(c).exists(_.code == record)
                        case _ => false
                    })
                    .flatMap(_.argumentOption(2))
                for
                  fn   <- callbackMethod(v)
                  comp <- component
                  file <- routeComponentFile(ctx, a.method.filename, comp)
                yield fn -> file
            case _ => None
      }

  private val DynamicImport = """import\(\s*['"]([^'"]+)['"]\s*\)""".r

  /** The file of a route's component: an imported binding, or a lazy `() => import('...')`. */
  private def routeComponentFile(ctx: JsContext, from: String, comp: Expression): Option[String] =
    val module = comp match
      case id: Identifier => ctx.modules.resolve(from, id.name).map(_.module)
      case other =>
          callbackMethod(other).flatMap(m => DynamicImport.findFirstMatchIn(m.code))
              .orElse(DynamicImport.findFirstMatchIn(other.code)).map(_.group(1))
    module.flatMap { m =>
      val tail = m.dropWhile(c => c == '.' || c == '/' || c == '@' || c == '~')
      val base = if m.startsWith(".") then JsModules.resolveRelative(from, m) else tail
      ctx.cpg.file.name.l.filter(f => f == base || f.endsWith("/" + tail)) match
        case only :: Nil => Some(only)
        case _           => None
    }

  /** A route `props` function receives the route. */
  private def tagRouterPropsFunctions(ctx: JsContext): Unit =
      ctx.tagger.tag(routePropsFunctions(ctx).flatMap((fn, _) => firstParam(fn)).iterator, INPUT)

  /** A route component's props are what its route's `props` function returns: each prop read is
    * tagged with the source behind the member of that name. Runs with the bridges.
    */
  def bridgeRouterProps(ctx: JsContext): Unit =
      routePropsFunctions(ctx).groupMap(_._2)(_._1).foreach { (file, fns) =>
        val names = declaredPropNames(ctx, file)
        DataLinkBridge.bridgeReads(
          ctx,
          ctx.cpg.file.nameExact(file).method.l,
          (root, path) =>
              root match
                case c: Call if PropsEntries.contains(c.name) && path.nonEmpty =>
                    Some(DataLinkBridge.produced(fns, path))
                case id: Identifier if names.contains(id.name) =>
                    Some(DataLinkBridge.produced(fns, id.name :: path))
                case _ => None
        )
      }

  private val PropsEntries = Set("defineProps", "withDefaults")

  /** Components whose props come from somewhere the code shows: an element rendering them, or a
    * route `props` function. Their props are no sources of their own.
    */
  private def fedComponents(ctx: JsContext): Set[String] =
      ctx.elements.renderedFiles ++ routePropsFunctions(ctx).map(_._2)

  private def tagProps(ctx: JsContext): Unit =
    val fed                        = fedComponents(ctx)
    def unfed(n: CfgNode): Boolean = !fed.contains(n.method.filename)
    ctx.tagger.tag(
      ctx.cpg.call.nameExact("defineProps", "withDefaults", "defineModel").filter(unfed),
      INPUT
    )
    ctx.cpg.file.name(".*\\.vue").name.l.filterNot(fed.contains).foreach(f =>
        ctx.tagger.tag(templatePropReads(ctx, f), INPUT)
    )
    // setup(props, ctx)
    ctx.tagger.tag(
      ctx.cpg.method.internal.nameExact("setup").filterNot(m => fed.contains(m.filename))
          .flatMap(firstParam),
      INPUT
    )
    // Options API: `props: ['title']` or `props: { title: String }`, read as `this.title`
    val declarations = ctx.cpg.call.nameExact(Operators.assignment).filter { a =>
        a.argumentOption(1).exists {
            case fa: Call => fieldName(fa).contains("props")
            case _        => false
        } && (a.method.filename.endsWith(".vue") ||
            ctx.modules.importsOf(a.method.filename).exists(_.packageName.contains("vue"))) &&
        !fed.contains(a.method.filename) && callbackMethod(a.argumentOption(2).get).isEmpty
    }.l
    declarations.groupBy(_.method.filename).foreach { (file, decls) =>
      val names = decls.flatMap(_.argumentOption(2)).flatMap { value =>
        // array: pushes of literal names; object: property writes `_tmp.title = ...`
        val literals = value.ast.isLiteral.flatMap(literalValue).l
        val keys = value.ast.isCall.nameExact(Operators.assignment).flatMap(_.argumentOption(1))
            .collect { case fa: Call => fa }.flatMap(fieldName).l
        if keys.nonEmpty then keys else literals
      }.filter(n => n.nonEmpty && n.forall(c => c.isLetterOrDigit || c == '_' || c == '$')).toSet
      if names.nonEmpty then
        val reads = ctx.fieldAccesses.filter(fa =>
            fa.method.filename == file && !isAssignmentTarget(fa) &&
                fieldBase(fa).exists(_.code == "this") && fieldName(fa).exists(names.contains)
        )
        ctx.tagger.tag(readChains(reads), INPUT)
    }
  end tagProps

  private def tagGuards(ctx: JsContext): Unit =
    val registered =
        ctx.cpg.call.nameExact((GuardRegistrations ++ InComponentGuards ++ Middleware).toSeq*)
            .l.flatMap(c => c.argument.filter(_.argumentIndex >= 1).l.flatMap(callbacksIn(_)))
    // `beforeEnter: (to) => ...` on a route record
    val perRoute = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(_.argumentOption(1).exists {
            case fa: Call => fieldName(fa).contains("beforeEnter")
            case _        => false
        })
        .flatMap(_.argumentOption(2)).flatMap(callbacksIn(_)).l
    // Options API in-component guards: beforeRouteEnter(to, from, next) / beforeRouteUpdate(to)
    val options = ctx.cpg.method.internal.nameExact("beforeRouteEnter", "beforeRouteUpdate").l
    ctx.tagger.tag((registered ++ perRoute ++ options).flatMap(firstParam).iterator, INPUT)

  /** Custom directives by the name a template uses them by - `app.directive('raw-html', hooks)`,
    * and in `<script setup>` a `const vRawHtml = hooks` - with the hook functions (`mounted`,
    * `updated`, ..., or one function for all).
    */
  private def directives(ctx: JsContext): Map[String, List[Method]] =
    def hooks(arg: Expression): List[Method] =
      // `app.directive('tooltip-html', tooltipHtml)`: the hooks object a local or an import holds
      val value = arg match
        case id: Identifier => importedValue(ctx, id).getOrElse(JsValues.origin(id))
        case other          => other
      callbacksIn(value, DirectiveHooks) match
        case Nil => callbackMethod(arg).toList
        case hs  => hs
    val registered = ctx.cpg.call.nameExact("directive").l.flatMap { c =>
        (
          c.argument.filter(_.argumentIndex == 1).headOption.flatMap(literalValue),
          c.argument.filter(_.argumentIndex == 2).headOption
        ) match
          case (Some(name), Some(arg)) => Some(name -> hooks(arg))
          case _                       => None
    }
    val local = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(_.method.filename.endsWith(".vue")).l
        .flatMap { a =>
            (a.argumentOption(1), a.argumentOption(2)) match
              case (Some(id: Identifier), Some(arg)) if id.name.matches("v[A-Z]\\w*") =>
                  // vRawHtml -> raw-html
                  val name = id.name.drop(1).replaceAll("([a-z0-9])([A-Z])", "$1-$2").toLowerCase
                  Some(name -> hooks(arg))
              case _ => None
        }
    (registered ++ local).groupMapReduce(_._1)(_._2)(_ ++ _)
  end directives

  /** A directive hook's `binding` holds what the template bound: `v-raw-html="$route.query.note"`
    * hands `$route.query.note` to `binding.value`. Where a template binds a directive to a value a
    * source reaches, the hooks' `binding` parameters are that source's kind, with where the value
    * came from. Runs with the bridges, as the bound value may be one a bridge made a source.
    */
  def bridgeDirectives(ctx: JsContext): Unit =
    if !applies(ctx) then return
    val byName = directives(ctx)
    if byName.isEmpty then return
    ctx.cpg.templateDom.nameExact("JSXAttribute").l.foreach { attr =>
      val name = attr.code.stripPrefix("v-").takeWhile(c => c != '=' && c != ':' && c != '.')
      if attr.code.startsWith("v-") then
        byName.get(name).foreach { hooks =>
            attr.ast.isCall.filterNot(_.astParent.isInstanceOf[Call]).l.iterator
                .flatMap(v => MemberTaintBridge.sourceOf(ctx, v).map(_ -> v)).nextOption()
                .foreach { (found, value) =>
                    ctx.tagger.tagVia(
                      hooks.flatMap(m => params(m).lift(1)),
                      found.tag,
                      found.places(value)*
                    )
                }
        }
    }
  end bridgeDirectives

  /** An object literal's own properties: `{ notice() {...}, msg: v }` lowers to writes `_tmp.notice
    * \= notice` and `_tmp.msg = v` directly in its block.
    */
  private def literalProperties(literal: Expression): Map[String, Expression] =
      literal.astChildren.isCall.nameExact(Operators.assignment).l.flatMap { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(fa: Call), Some(v)) if fieldBase(fa).exists(_.code.startsWith("_tmp_")) =>
                fieldName(fa).map(_ -> v)
            case _ => None
      }.toMap

  /** Options API: `export default defineComponent({ computed: { notice() {...} }, data() { return {
    * msg: ... } } })`. The template reads computed properties and data by bare name, the
    * component's methods as `this.<name>`; where a source reaches what a computed property returns
    * or what `data()` holds under a key, those reads are that source's kind, with where the value
    * came from. Runs with the bridges.
    */
  def bridgeOptionsApi(ctx: JsContext): Unit =
      ctx.cpg.file.name(".*\\.vue").name.l.foreach { file =>
        // `defineComponent({...})` (lowered beside the default export, which names the helper),
        // or a plain `export default {...}`
        val defined =
            ctx.cpg.file.nameExact(file).method.flatMap(_.call.nameExact("defineComponent"))
                .flatMap(_.argument.filter(_.argumentIndex == 1)).headOption
        val options = defined.orElse(defaultExportValue(ctx, file).filter {
            case id: Identifier => false
            case _              => true
        })
        options.map(literalProperties).foreach { top =>
          val computed = top.get("computed").map(literalProperties).getOrElse(Map.empty)
              .flatMap((k, v) => callbackMethod(v).map(k -> _))
          val data = top.get("data").flatMap(callbackMethod).toList
              .flatMap(_.ast.isReturn.astChildren.collect { case e: Expression => e }.l)
              .flatMap(e => literalProperties(e).toList).toMap
          def reads(key: String): List[CfgNode] =
              ctx.cpg.file.nameExact(file).method.l.flatMap(m =>
                  m.ast.isIdentifier.nameExact(key).filterNot(isAssignmentTarget)
                      .filter(id => JsIndexes.assignedValues(id.method, key).isEmpty)
                      .filter(id => id.method.parameter.nameExact(key).isEmpty).l ++
                      m.ast.isCall.nameExact(Operators.fieldAccess).codeExact(s"this.$key")
                          .filterNot(isAssignmentTarget).l
              )
          computed.foreach { (key, m) =>
              m.ast.isReturn.astChildren.collect { case e: Expression => e }.l.iterator
                  .flatMap(e => MemberTaintBridge.sourceOf(ctx, e).map(_ -> e)).nextOption()
                  .foreach((found, e) => ctx.tagger.tagVia(reads(key), found.tag, found.places(e)*))
          }
          data.foreach { (key, v) =>
              MemberTaintBridge.sourceOf(ctx, v).foreach(found =>
                  ctx.tagger.tagVia(reads(key), found.tag, found.places(v)*)
              )
          }
        }
      }

  /** Keys of an object literal argument whose value is computed: `{ innerHTML: x }` is lowered to
    * `_tmp.innerHTML = x` writes inside the argument.
    */
  private def computedKeys(arg: Expression): Set[String] =
      computedWrites(arg).flatMap(a =>
          a.argumentOption(1).collect { case fa: Call => fa }.flatMap(fieldName)
      ).toSet

  /** The writes of an object literal argument that put a computed value under a key:
    * `_tmp.innerHTML = snippet` for `{ innerHTML: snippet }`.
    */
  private def computedWrites(arg: Expression): List[Call] =
      arg.ast.isCall.nameExact(Operators.assignment).l.filter { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(fa: Call), Some(v)) =>
                fa.name == Operators.fieldAccess && !v.isInstanceOf[Literal]
            case _ => false
      }

  private def tagSinks(ctx: JsContext): Unit =
    // navigateTo(url, { external: true }) - and `open: { target }`, which opens a window
    val external = ctx.cpg.call.nameExact("navigateTo").filter { c =>
        c.argument.filter(_.argumentIndex == 2).exists(o =>
            o.code.matches("(?s).*\\bexternal\\s*:\\s*true.*") || o.code.matches(
              "(?s).*\\bopen\\s*:.*"
            )
        ) && c.argument.filter(_.argumentIndex == 1).exists(!_.isInstanceOf[Literal])
    }
    ctx.tagger.tag(external, NavigationSink*)

    // useHead({ script: [{ innerHTML: x }] }) - useHeadSafe drops these keys. The sink is the value
    // written under the key, where the head entry takes it.
    val headKeys = Set("innerHTML", "textContent", "src")
    val heads = ctx.cpg.call.nameExact("useHead", "useServerHead").l
        .flatMap(_.argument.filter(_.argumentIndex == 1).l)
        .flatMap(computedWrites)
        .filter(w =>
            w.argumentOption(1).collect { case fa: Call => fa }.flatMap(fieldName).exists(
              headKeys.contains
            )
        )
    ctx.tagger.tag(heads.iterator, HtmlSink*)

    // h('div', { innerHTML: x }), h('a', { href: x })
    val renders = ctx.cpg.call.nameExact("h", "createVNode", "createElementVNode").filter(c =>
        c.argument.filter(_.argumentIndex == 2).exists(a =>
            computedKeys(a).exists(k =>
                Set("innerHTML", "outerHTML", "srcdoc", "href", "src").contains(k)
            )
        )
    )
    ctx.tagger.tag(renders, HtmlSink*)

    // router.push(target) / replace(target): in-app navigation, a sink only for a target the code
    // does not anchor - a literal path prefix or a location object cannot be redirected.
    val pushes = ctx.cpg.call.nameExact("push", "replace").filter { c =>
        receiverOf(c).exists(r =>
            r.code == "this.$router" || r.code == "$router" || (JsValues.origin(r) match
              case u: Call => u.name == "useRouter"
              case _       => false
            )
        ) && c.argument.filter(_.argumentIndex == 1).headOption.exists(t =>
            !isObjectLiteral(t) && !hasFixedOrigin(t)
        )
    }
    ctx.tagger.tag(pushes, NavigationSink*)
  end tagSinks
end VueRecognizer

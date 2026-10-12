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
    tagDirectives(ctx)
    ctx.tagger.tag(ctx.cpg.call.nameExact(RequestComposables.toSeq*), INPUT)
    ctx.tagger.tag(ctx.cpg.call.nameExact(DataComposables.toSeq*), INGRESS)
    tagSinks(ctx)
    linkProvideInject(ctx)
    linkPiniaStores(ctx)
    linkComposableReturns(ctx)

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
              s"${VueRecognizer.normalisedModule(i.file, i.module)}:${i.imported}"
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
    * })`. Every caller's `useSearchStore()` receives the setup's return value, so the call is
    * resolved to the setup callback - carrying the store's derived state out - and its method calls
    * (`store.setTerm(v)`) to the functions the setup returns, carrying the argument in. Names
    * shared by more than one store are left alone.
    */
  private def linkPiniaStores(ctx: JsContext): Unit =
    if !(ctx.modules.uses("pinia") || ctx.project.dependsOn("pinia")) then return
    val setups = ctx.cpg.call.nameExact("defineStore").l.flatMap { call =>
        call.argument.filter(_.argumentIndex >= 2).sortBy(_.argumentIndex).headOption
            .map(a => JsShapes.callbacksIn(a)).getOrElse(Nil)
    }
    if setups.isEmpty then return
    // `const useSearchStore = defineStore(...)` - the hook a store's file exports
    val hookOf = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(2).exists {
                case c: Call => c.name == "defineStore"
                case _       => false
            }
        )
        .flatMap(_.argumentOption(1)).collect { case id: Identifier => id }
        .l
        .flatMap(id => setups.find(s => s.filename == id.method.filename).map(s => id.name -> s))
    val setupByHook = hookOf.groupMap(_._1)(_._2).collect {
        case (name, setup :: Nil) => name -> setup
    }
    // the functions the setup's returned object holds, by the key they are returned under
    val methodsOf = setups.flatMap { setup =>
        setup.ast.isReturn.astChildren.l.flatMap {
            case b: io.shiftleft.codepropertygraph.generated.nodes.Block =>
                b.astChildren.isCall.nameExact(Operators.assignment).l.flatMap { a =>
                    (a.argumentOption(1), a.argumentOption(2)) match
                      case (Some(fa: Call), Some(fn: Expression)) =>
                          fieldName(fa).toList.flatMap(k =>
                              JsShapes.callbacksIn(fn).map(m => k -> m)
                          )
                      case _ => Nil
                }
            case _ => Nil
        }
    }.groupMap(_._1)(_._2).collect { case (name, m :: Nil) => name -> m }
    // the store hooks' calls: useSearchStore() -> the setup
    ctx.cpg.call.filter(c => setupByHook.contains(c.name))
        .foreach(c => setupByHook.get(c.name).foreach(m => ctx.tagger.resolveCall(c, m)))
    // store.setTerm(v) where the receiver is one of the store hooks' results -> the returned fn
    ctx.cpg.call.filter(c =>
        methodsOf.contains(c.name) &&
            receiverOf(c).exists(r =>
                JsValues.origin(r) match
                  case h: Call => setupByHook.contains(h.name)
                  case _       => false
            )
    ).foreach(c => methodsOf.get(c.name).foreach(m => ctx.tagger.resolveCall(c, m)))
  end linkPiniaStores

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

  private def tagProps(ctx: JsContext): Unit =
    ctx.tagger.tag(ctx.cpg.call.nameExact("defineProps", "withDefaults", "defineModel"), INPUT)
    // setup(props, ctx)
    ctx.tagger.tag(ctx.cpg.method.internal.nameExact("setup").flatMap(firstParam), INPUT)
    // Options API: `props: ['title']` or `props: { title: String }`, read as `this.title`
    val declarations = ctx.cpg.call.nameExact(Operators.assignment).filter { a =>
        a.argumentOption(1).exists {
            case fa: Call => fieldName(fa).contains("props")
            case _        => false
        } && (a.method.filename.endsWith(".vue") ||
            ctx.modules.importsOf(a.method.filename).exists(_.packageName.contains("vue")))
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

  /** `app.directive('raw', { mounted(el, binding) {...} })`, `const vRaw = { mounted(el, binding)
    * }` in `<script setup>`: `binding.value` is the template expression the directive is bound to.
    */
  private def tagDirectives(ctx: JsContext): Unit =
    val registered = ctx.cpg.call.nameExact("directive").l
        .flatMap(_.argument.filter(_.argumentIndex == 2).l)
        .flatMap(callbacksIn(_, DirectiveHooks))
    val local = ctx.cpg.call.nameExact(Operators.assignment)
        .filter(a =>
            a.argumentOption(1).exists {
                case id: Identifier => id.name.matches("v[A-Z]\\w*")
                case _              => false
            } && a.method.filename.endsWith(".vue")
        )
        .flatMap(_.argumentOption(2)).l.flatMap(callbacksIn(_, DirectiveHooks))
    ctx.tagger.tag((registered ++ local).flatMap(m => params(m).lift(1)).iterator, INPUT)

  /** Keys of an object literal argument whose value is computed: `{ innerHTML: x }` is lowered to
    * `_tmp.innerHTML = x` writes inside the argument.
    */
  private def computedKeys(arg: Expression): Set[String] =
      arg.ast.isCall.nameExact(Operators.assignment).l.flatMap { a =>
          (a.argumentOption(1), a.argumentOption(2)) match
            case (Some(fa: Call), Some(v)) if !v.isInstanceOf[Literal] => fieldName(fa)
            case _                                                     => None
      }.toSet

  /** A relative import specifier written from its own file (`./keys`, `../keys`) names the same
    * module from every importer; this normalises it to a project-relative path so two importers of
    * one module produce one key.
    */
  private def normalisedModule(file: String, module: String): String =
      if !module.startsWith(".") then module
      else
        val dir      = file.substring(0, math.max(file.lastIndexOf('/'), 0))
        val parts    = (dir.split("/").toSeq ++ module.split("/").toSeq).filter(_.nonEmpty)
        val resolved = scala.collection.mutable.ArrayBuffer.empty[String]
        parts.foreach {
            case "."  => ()
            case ".." => if resolved.nonEmpty then resolved.trimEnd(1)
            case p    => resolved += p
        }
        resolved.mkString("/", "/", "")

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

    // useHead({ script: [{ innerHTML: x }] }) - useHeadSafe drops these keys
    val heads = ctx.cpg.call.nameExact("useHead", "useServerHead").filter(c =>
        c.argument.filter(_.argumentIndex == 1).exists(a =>
            computedKeys(a).exists(k => k == "innerHTML" || k == "textContent" || k == "src")
        )
    )
    ctx.tagger.tag(heads, HtmlSink*)

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

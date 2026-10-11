package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** Vue 3, Vue Router 4 and the application side of Nuxt (https://vuejs.org, https://router.vuejs.org,
  * https://nuxt.com).
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
  * functions (`h('div', { innerHTML })`), `useHead({ script: [{ innerHTML }] })`,
  * `navigateTo(url, { external: true })`, and router navigation to a target the code does not fix.
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
  private val Middleware = Set("defineNuxtRouteMiddleware", "addRouteMiddleware")

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
    val registered = ctx.cpg.call.nameExact((GuardRegistrations ++ InComponentGuards ++ Middleware).toSeq*)
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

  /** `app.directive('raw', { mounted(el, binding) {...} })`, `const vRaw = { mounted(el, binding) }`
    * in `<script setup>`: `binding.value` is the template expression the directive is bound to.
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

  private def tagSinks(ctx: JsContext): Unit =
    // navigateTo(url, { external: true }) - and `open: { target }`, which opens a window
    val external = ctx.cpg.call.nameExact("navigateTo").filter { c =>
        c.argument.filter(_.argumentIndex == 2).exists(o =>
            o.code.matches("(?s).*\\bexternal\\s*:\\s*true.*") || o.code.matches("(?s).*\\bopen\\s*:.*")
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
              case _       => false)
        ) && c.argument.filter(_.argumentIndex == 1).headOption.exists(t =>
            !isObjectLiteral(t) && !hasFixedOrigin(t)
        )
    }
    ctx.tagger.tag(pushes, NavigationSink*)
  end tagSinks
end VueRecognizer

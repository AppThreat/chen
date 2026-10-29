package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** The browser platform every frontend framework sits on: the attacker-influenced values a page can
  * read, the DOM APIs that turn a string into markup, script or navigation, the requests a page
  * makes, and the library calls that neutralise a value on the way.
  *
  * Sources follow the DOM-based vulnerability taxonomy (PortSwigger, OWASP DOM XSS cheat sheet):
  * the URL (`location.*`, `document.URL`, `document.referrer`), `document.cookie`, `window.name`,
  * Web Storage, and cross-document messages. Sinks follow the Trusted Types injection sinks
  * (`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `srcdoc`, `eval`, string
  * timers, `Function`) plus navigation (`location.href =`, `location.assign`, `window.open`).
  *
  * Most HTML and navigation sinks are property WRITES, which the frontend lowers to an
  * `<operator>.assignment` whose target is a field access. The assignment itself is tagged: it is
  * the node a flow into the written value ends at, and its code is the whole statement.
  */
object DomRecognizer extends JsFrameworkRecognizer:

  val name: String = "dom"

  /** The platform is always there. */
  def applies(ctx: JsContext): Boolean = true

  /** Names under which code reaches the global object. */
  private val WindowNames =
      Set("window", "self", "globalThis", "top", "parent", "frames", "$window")

  private val LocationReads = Set("href", "hash", "search", "pathname")
  private val DocumentReads = Set("URL", "documentURI", "baseURI", "referrer", "cookie")
  private val StorageNames  = Set("localStorage", "sessionStorage")

  /** `location`, `window.location`, `document.location`, `this.document.location`. */
  private def isLocation(path: List[String]): Boolean =
      path.lastOption.contains("location") &&
          (path.size == 1 || WindowNames.contains(path(path.size - 2)) ||
              path(path.size - 2) == "document")

  /** `document`, `window.document`, `this.document` (Angular's injected DOCUMENT). */
  private def isDocument(path: List[String]): Boolean =
      path.lastOption.contains("document") &&
          (path.size == 1 || WindowNames.contains(path(path.size - 2)) || path.head == "this")

  private def isWindow(path: List[String]): Boolean =
      path.size == 1 && WindowNames.contains(path.head) ||
          path.size == 2 && path.head == "this" && WindowNames.contains(path(1))

  /** The member path of a call's callee: `window.open(...)` -> Seq(window, open), `eval(...)` ->
    * Seq(eval).
    */
  private def calleePath(call: Call): Option[List[String]] =
      call.receiver.headOption.flatMap(memberPath).orElse(
        Option.when(call.name.nonEmpty)(List(call.name))
      )
          .filter(_.lastOption.contains(call.name))

  /** A call of a global function (`eval(x)`, `window.eval(x)`), not a method of some object. */
  private def isGlobalCall(call: Call, names: Set[String]): Boolean =
      names.contains(call.name) && calleePath(call).exists(p => p.size == 1 || isWindow(p.init))

  def run(ctx: JsContext): Unit =
    tagSources(ctx)
    tagMessageHandlers(ctx)
    tagRemoteData(ctx)
    tagHtmlSinks(ctx)
    tagResponseBodies(ctx)
    tagTemplateSinks(ctx)
    tagNavigationSinks(ctx)
    tagCodeSinks(ctx)
    tagRequestSinks(ctx)
    tagSanitizers(ctx)

  // -----------------------------------------------------------------------------------------
  // Sources
  // -----------------------------------------------------------------------------------------

  private def tagSources(ctx: JsContext): Unit =
    val reads = ctx.fieldAccesses.filterNot(isAssignmentTarget).filter { fa =>
        fieldName(fa).exists { field =>
            (LocationReads.contains(field) || DocumentReads.contains(field) || field == "name") &&
            fieldBase(fa).flatMap(memberPath).exists { base =>
                (LocationReads.contains(field) && isLocation(base)) ||
                (DocumentReads.contains(field) && isDocument(base)) ||
                (field == "name" && isWindow(base))
            }
        }
    }
    ctx.tagger.tag(readChains(reads), INPUT)

    // Web Storage reads: whatever another page (or an earlier XSS) stored. Stored data, like a
    // response: a source for markup, but no URL the attacker chose.
    val storageReads = ctx.cpg.call.nameExact("getItem").filter { c =>
        receiverOf(c).flatMap(memberPath).exists(p =>
            p.lastOption.exists(StorageNames.contains) &&
                (p.size == 1 || isWindow(p.init))
        )
    }
    ctx.tagger.tag(storageReads, INGRESS)
  end tagSources

  /** Cross-document messages and URL changes: `addEventListener('message', cb)`, `onmessage = cb`
    * and `hashchange`. A message to the window can come from any origin, so its event is input; a
    * message from a WebSocket or EventSource is what the server sent, so its event is remote data.
    * Messages from a page's own workers and channels are neither.
    */
  private def tagMessageHandlers(ctx: JsContext): Unit =
    def classify(receiver: Option[Expression]): Option[String] =
        receiver match
          case None => Some(INPUT)
          case Some(r) =>
              val path = memberPath(r)
              if path.exists(p => isWindow(p) || p == List("this")) then Some(INPUT)
              else if constructedBy(
                  r,
                  Set("WebSocket", "EventSource", "io", "ReconnectingWebSocket")
                )
              then Some(INGRESS)
              else None

    ctx.cpg.call.nameExact("addEventListener").foreach { call =>
      val event = call.argument.filter(_.argumentIndex == 1).flatMap(literalValue).headOption
      val tagName = event match
        case Some("message") => classify(receiverOf(call))
        case Some("hashchange") if receiverOf(call).forall(r => memberPath(r).exists(isWindow)) =>
            Some(INPUT)
        case _ => None
      tagName.foreach { t =>
          call.argument.filter(_.argumentIndex == 2).l
              .flatMap(callbacksIn(_))
              .filterNot(checksOrigin)
              .flatMap(firstParam)
              .foreach(p => ctx.tagger.tag(Iterator(p), t))
      }
    }
    propertyWrites(ctx.cpg, Set("onmessage")).foreach { write =>
      val target = write.argumentOption(1).collect { case c: Call => c }.flatMap(fieldBase)
      classify(target.filterNot(t => memberPath(t).exists(isWindow))).foreach { t =>
          assignedValue(write).toList.flatMap(callbacksIn(_)).flatMap(firstParam)
              .foreach(p => ctx.tagger.tag(Iterator(p), t))
      }
    }
    // Svelte: `<svelte:window onmessage={handler} />` (5), `on:message={handler}` (4)
    ctx.cpg.templateDom.nameExact("JSXAttribute")
        .filter(attr =>
            attr.code.matches("(?s)(on:message|onmessage)\\s*=.*") &&
                attr.astParent.isInstanceOf[TemplateDom] &&
                attr.astParent.asInstanceOf[TemplateDom].code.startsWith("<svelte:window")
        )
        .l
        .flatMap(_.ast.collect { case e: Expression => e }.l)
        .flatMap(callbacksIn(_))
        .distinctBy(_.id())
        .filterNot(checksOrigin)
        .flatMap(firstParam)
        .foreach(p => ctx.tagger.tag(Iterator(p), INPUT))
  end tagMessageHandlers

  /** A message handler that compares `event.origin` by equality before using the message accepts
    * only the origins it names (`if (e.origin !== 'https://app.example') return`). A substring test
    * (`indexOf`, `startsWith`, `endsWith`, `includes` on the string) is no such check.
    */
  private def checksOrigin(handler: Method): Boolean =
      firstParam(handler).exists { event =>
          handler.ast.isCall.nameExact(
            Operators.equals,
            Operators.notEquals,
            "<operator>.identity",
            "<operator>.notIdentity"
          ).exists(_.argument.isCall.exists(a =>
              fieldName(a).contains("origin") && a.code == s"${event.name}.origin"
          )) ||
          // `ALLOWED.has(e.origin)`, `[...].includes(e.origin)` with the origin as the argument
          handler.ast.isCall.nameExact("has", "includes").exists(
            _.argument.filter(_.argumentIndex == 1).exists(_.code == s"${event.name}.origin")
          )
      }

  /** True when `expr` holds an object made by `new C(...)` (or `C(...)`) for one of `ctors`: the
    * single assignment of a local, or an assignment to the same `this.<field>` in the class.
    */
  private[taggers] def constructedBy(expr: Expression, ctors: Set[String]): Boolean =
    def madeBy(value: Expression): Boolean =
        value match
          case c: Call =>
              val callee =
                  if c.name == Operators.alloc || c.name == "<operator>.new" then
                    c.code.stripPrefix("new ").takeWhile(ch => ch.isLetterOrDigit || ch == '_')
                  else c.name
              ctors.contains(callee) ||
              ctors.exists(ctor => c.code.startsWith(s"new $ctor(") || c.code.startsWith(s"$ctor("))
          case b: Block => b.astChildren.isCall.exists(madeBy)
          case _        => false
    JsValues.origin(expr) match
      case c: Call if c.name == Operators.fieldAccess =>
          // `this.ws` assigned elsewhere in the class
          (fieldBase(c).flatMap(memberPath), fieldName(c)) match
            case (Some(List("this")), Some(field)) =>
                enclosingTypeDecl(c.method).toList
                    .flatMap(classMethods)
                    .flatMap(m => Iterator(m).assignment.l)
                    .filter(_.argumentOption(1).exists {
                        case t: Call => t.code == s"this.$field"
                        case _       => false
                    })
                    .flatMap(_.argumentOption(2))
                    .exists(madeBy)
            case _ => false
      case other => madeBy(other)
  end constructedBy

  /** Remote data: the body of a `fetch`, an `XMLHttpRequest` and the HTTP clients a frontend
    * imports. The producing call is tagged (an awaited response flows from it), and so is every
    * callback that receives its value through `then`.
    */
  private def tagRemoteData(ctx: JsContext): Unit =
    val producers = requestCalls(ctx).l
    ctx.tagger.tag(producers.iterator, INGRESS)
    producers.foreach(p => ctx.tagger.tag(JsValues.consumersOf(p).iterator, INGRESS))
    // XMLHttpRequest response bodies. The field names are distinctive; `.response` alone is not
    // (it is also an axios error's response), so it needs an XHR receiver.
    val xhrReads = ctx.fieldAccesses.filter { fa =>
        fieldName(fa).exists {
            case "responseText" | "responseXML" => true
            case "response" =>
                fieldBase(fa).exists(b => constructedBy(b, Set("XMLHttpRequest")))
            case _ => false
        }
    }
    ctx.tagger.tag(readChains(xhrReads), INGRESS)

  /** Calls that issue an HTTP request: `fetch`, and the request methods of axios, ky, ofetch and
    * superagent bindings in the importing file.
    */
  private[js] def requestCalls(ctx: JsContext): Iterator[Call] =
    // `$fetch` is Nuxt/Nitro's global ofetch instance.
    val globalFetch = ctx.cpg.call.nameExact("fetch", "$fetch")
        .filter(isGlobalCall(_, Set("fetch", "$fetch")))
    // every way to a client call binds a name from one of the packages in the call's own file
    val clientCalls = ctx.cpg.call.filter { c =>
        HttpClientMethods.contains(c.name) &&
        ctx.modules.gate(c.method.filename, HttpClientPackages, "client") &&
        receiverOf(c).exists { r =>
            memberPath(r).exists {
                case List(binding) =>
                    HttpClientPackages.exists(pkg =>
                        ctx.modules.moduleBindingsOf(c.method.filename, pkg).contains(binding)
                    ) || isClientInstance(ctx, r)
                case List("this", _) => isClientInstance(ctx, r)
                case _               => false
            }
        }
    }
    // `axios(config)`, `ky(url)`, `ofetch(url)`, `$fetch(url)`: the binding called directly,
    // under whatever name the file gave it (`import { ofetch as get }`).
    val directCalls = ctx.cpg.call.filter { c =>
        c.receiver.headOption.flatMap(memberPath).exists {
            case List(binding) =>
                val f = c.method.filename
                binding == c.name && ctx.modules.gate(f, HttpClientPackages, "direct") &&
                ctx.modules.resolve(f, binding).exists(i =>
                    i.kind != ImportKind.SideEffect &&
                        i.packageName.exists(p =>
                            HttpClientPackages.exists(JsModules.packageMatches(p, _))
                        )
                )
            case _ => false
        }
    }
    (globalFetch ++ clientCalls ++ directCalls).dedup.cast[Call]
  end requestCalls

  private val HttpClientPackages = Seq("axios", "ky", "ofetch", "superagent", "redaxios", "wretch")
  private val HttpClientMethods =
      Set("get", "post", "put", "patch", "delete", "head", "options", "request", "fetch")

  /** `api.get(...)` where `api = axios.create(...)` (or `ky.create`/`extend`, `ofetch.create`). */
  private def isClientInstance(ctx: JsContext, receiver: Expression): Boolean =
    val file = receiver.method.filename
    if !ctx.modules.importsAny(file, HttpClientPackages) then false
    else
      JsValues.origin(receiver) match
        case c: Call if c.name == "create" || c.name == "extend" =>
            receiverOf(c).flatMap(memberPath).exists {
                case List(binding) =>
                    HttpClientPackages.exists(pkg =>
                        ctx.modules.moduleBindingsOf(file, pkg).contains(binding)
                    )
                case _ => false
            }
        case _ => false

  // -----------------------------------------------------------------------------------------
  // Sinks
  // -----------------------------------------------------------------------------------------

  private val HtmlProperties = Set("innerHTML", "outerHTML", "srcdoc")

  /** Element properties that load or link a URL: a `javascript:` URL in any of them runs script. */
  private val UrlProperties = Set("href", "src", "action", "formAction")

  private val UrlAttributes = Set("href", "src", "action", "formaction", "srcdoc", "xlink:href")

  private def nonConstant(e: Option[Expression]): Boolean = e.exists(v => !v.isInstanceOf[Literal])

  private def tagHtmlSinks(ctx: JsContext): Unit =
    val markupWrites =
        propertyWrites(ctx.cpg, HtmlProperties).filter(w => nonConstant(assignedValue(w)))
    ctx.tagger.tag(markupWrites, HtmlSink*)

    // URL properties of an element; `location.href` is navigation and handled there, and
    // `exports.action = action` is a module export.
    val urlWrites = propertyWrites(ctx.cpg, UrlProperties)
        .filter(w => nonConstant(assignedValue(w)))
        .filterNot(w =>
            w.argumentOption(1).collect { case c: Call => c }.flatMap(fieldBase)
                .flatMap(memberPath).exists(p =>
                    isLocation(p) || p.headOption.contains("exports") ||
                        p.take(2) == List("module", "exports") ||
                        // `this.href = v` writes a component's own field (a Lit or Angular
                        // property), which its template renders - there is the sink
                        p == List("this")
                )
        )
    ctx.tagger.tag(urlWrites, HtmlSink*)

    val markupCalls = ctx.cpg.call.filter { c =>
        callName(c) match
          case "insertAdjacentHTML" | "createContextualFragment" | "setHTMLUnsafe" |
              "parseHTMLUnsafe" =>
              true
          case "write" | "writeln" =>
              receiverOf(c).exists(r =>
                  memberPath(r).exists(isDocument) ||
                      (r match
                        case fa: Call => fieldName(fa).contains("document")
                        case _        => false
                      )
              )
          case _ => false
    }
    ctx.tagger.tag(markupCalls, HtmlSink*)

    // `el.setAttribute('href', v)`, `el.setAttribute('onclick', v)`: two arguments, the first a
    // literal naming a URL attribute or an event handler. (Angular's Renderer2.setAttribute takes
    // the element first and is recognised by AngularRecognizer.)
    val attributeCalls = ctx.cpg.call.nameExact("setAttribute", "setAttributeNS").filter { c =>
      val args    = c.argument.filter(_.argumentIndex >= 1).sortBy(_.argumentIndex).l
      val nameArg = if c.name == "setAttributeNS" then args.lift(1) else args.headOption
      nameArg.flatMap(literalValue).exists(n =>
          UrlAttributes.contains(n.toLowerCase) || n.toLowerCase.startsWith("on")
      ) && nonConstant(args.lastOption)
    }
    ctx.tagger.tag(attributeCalls, HtmlSink*)
  end tagHtmlSinks

  /** Content types a browser does not render as a page. */
  // an SVG image is markup: opened from the site's origin, its scripts run
  private val DataContentType =
      "(?i)^(application/json|text/plain|text/csv|application/octet-stream|image/(?!svg)[\\w.+-]+)(\\s*;.*)?$".r

  /** A server handler's `new Response(body, init)` serves `body` from the site's origin: markup the
    * code did not fix - an attacker-chosen upstream's body, a reflected parameter - is rendered as
    * the site's own page. Not a sink where `init` sets a constant data content type
    * (`application/json`, `text/plain`), or where a string is served with the default `text/plain`
    * \- a template, a concatenation, `JSON.stringify(...)`.
    */
  private def tagResponseBodies(ctx: JsContext): Unit =
    def contentType(init: Option[Expression]): Option[Expression] =
        init.toList.flatMap(_.ast.isCall.nameExact(Operators.assignment).l).collectFirst {
            case a if a.argumentOption(1).exists {
                    case fa: Call =>
                        fieldName(fa).orElse(fa.argumentOption(2).flatMap(literalValue))
                            .exists(_.equalsIgnoreCase("content-type"))
                    case _ => false
                } => a.argumentOption(2)
        }.flatten
    def isText(body: Expression): Boolean = body match
      case c: Call =>
          c.name == Operators.formatString || c.name == Operators.addition ||
          (callName(c) == "stringify" && calleePath(c).contains(List("JSON", "stringify")))
      case _: Literal => true
      case _          => false
    val bodies = ctx.cpg.call.nameExact("<operator>.new")
        .filter(c => c.code.startsWith("new Response(") && isServerFile(c.method.filename))
        .filter { c =>
          val body = c.argumentOption(1).filter(_.argumentIndex == 1)
          val init = c.argument.filter(_.argumentIndex == 2).headOption
          body.exists(b => !b.isInstanceOf[Literal]) && (contentType(init) match
            case Some(t) => !literalValue(t).exists(v => DataContentType.matches(v.trim))
            case None    => !body.exists(isText)
          )
        }
    ctx.tagger.tag(bodies, HtmlSink*)
  end tagResponseBodies

  /** Attribute bindings in templates (JSX, Vue and Svelte SFCs) that put a value into markup or a
    * URL: `:href="x"`, `href={x}`, `innerHTML={x}` (Solid, Preact), `:srcdoc`, `bind:innerHTML`
    * (Svelte), `set:html` (Astro). A `src` is a sink only on an element that loads a document or
    * script from it - an image does not run a `javascript:` URL. Raw-HTML directives (`v-html`,
    * `{@html}`, `dangerouslySetInnerHTML`) are EasyTagsPass's.
    *
    * As there, the interpolation inside the attribute is tagged: it is the call the bound value
    * flows into.
    */
  private val MarkupAttributes     = Set("innerhtml", "outerhtml", "srcdoc", "set:html")
  private val UrlBindingAttributes = Set("href", "xlink:href", "action", "formaction")
  private val DocumentLoaders      = Set("iframe", "frame", "script", "embed", "object")

  private def attributeName(code: String): String =
      // Svelte's shorthand `{href}` is `href={href}`
      (if code.matches("""^\{\s*[A-Za-z_$][\w$]*\s*\}$""") then code.drop(1).dropRight(1).trim
       else code)
          .takeWhile(c => c != '=' && !c.isWhitespace)
          .stripPrefix("v-bind:")
          .stripPrefix("x-bind:")
          .stripPrefix("bind:")
          .stripPrefix(":")
          .stripPrefix(".")
          .toLowerCase

  /** React 19 replaces a `javascript:` URL in `href`, `src`, `action` and `formAction` with an
    * error-throwing one, so in a project on React 19 or later those JSX attributes are no sinks.
    * Markup attributes stay sinks everywhere; Vue, Svelte, Solid, Preact and Lit sanitise nothing.
    */
  private def reactBlocksScriptUrls(ctx: JsContext, file: String): Boolean =
      (file.endsWith(".jsx") || file.endsWith(".tsx")) &&
          ctx.project.majorVersionOf("react").exists(_ >= 19) &&
          !ctx.modules.uses("preact", "solid-js", "@builder.io/qwik", "@qwik.dev")

  /** The element an attribute is written on: `Form` for `<Form action={ack}>`. */
  private def elementOf(attr: TemplateDom): Option[String] =
      attr.astParent match
        case element: TemplateDom =>
            Some(element.code.drop(1).takeWhile(c => c.isLetterOrDigit || c == '-' || c == '.'))
        case _ => None

  /** A capitalised element is a component, whose attributes are its props: only a link component's
    * `href` ends up in an anchor; `<Form action={ack}>` (Qwik, Remix) takes an action object,
    * `<Image src>` an image.
    */
  private def isComponent(element: String): Boolean =
      element.headOption.exists(_.isUpper)

  /** An Angular property binding (`[innerHTML]="x"`, astgen keeps the brackets) goes through the
    * framework's DomSanitizer: markup is sanitised, a `javascript:` URL blocked, a resource URL
    * refused - only a value from `bypassSecurityTrust*`, itself the sink, gets through. A link the
    * user clicks to another site is no redirect either: no binding is a sink.
    */
  private def isAngularBinding(name: String): Boolean = name.startsWith("[")

  private def tagTemplateSinks(ctx: JsContext): Unit =
    // the elements of the project's own components: the component decides what a prop does
    val rendered = (ctx.elements.functions.map(_._1) ++ ctx.elements.files.map(_._1))
        .flatMap(_.astChildren.collectAll[TemplateDom].l).map(_.id()).toSet
    val attributes = ctx.cpg.templateDom.nameExact("JSXAttribute").filter { attr =>
      val name      = attributeName(attr.code)
      val element   = elementOf(attr).getOrElse("")
      val component = isComponent(element)
      // an attribute sits in the element's opening tag
      val owner = attr.astParent match
        case opening: TemplateDom if opening.name == "JSXOpeningElement" => opening.astParent
        case parent                                                      => parent
      !rendered.contains(owner.id()) && (
        !isAngularBinding(name) && MarkupAttributes.contains(name) ||
            (UrlBindingAttributes.contains(name) && (!component || name == "href") &&
                !reactBlocksScriptUrls(ctx, attr.file.name.headOption.getOrElse(""))) ||
            (name == "src" && !component && DocumentLoaders.contains(element.toLowerCase))
      )
    }.l
    ctx.tagger.tag(boundValues(attributes), HtmlSink*)
  end tagTemplateSinks

  /** The values attributes bind - each one's outermost expression, not every read nested inside it
    * \- where the code does not anchor them: `href="/profile/@{name}"` can never become
    * `javascript:` or another site.
    */
  private def boundValues(attributes: List[TemplateDom]): Iterator[Call] =
      attributes.iterator.flatMap { attr =>
          attr.ast.collectAll[Call].filterNot(c => c.astParent.isInstanceOf[Call]).l
      }.filter { value =>
        // a template interpolation is wrapped: `<operator>.interpolation(expr)`
        val expr =
            if value.name == "<operator>.interpolation" then
              value.argumentOption(1).getOrElse(value)
            else value
        !hasFixedOrigin(expr)
      }.dedup

  private def tagNavigationSinks(ctx: JsContext): Unit =
    // `location = x`, `window.location = x`, `location.href = x`
    // A declaration (`const location = useLocation()`) binds a local of that name; it navigates
    // nowhere, and neither does a write to a local or parameter called `location`.
    // A target whose origin the code fixes (`'/search?q=' + q`) stays on the site and cannot become
    // `javascript:`.
    def unanchored(v: Option[Expression]) =
        v.exists(t => !t.isInstanceOf[Literal] && !hasFixedOrigin(t))
    val locationWrites = ctx.cpg.call.nameExact(Operators.assignment).filter { a =>
        unanchored(assignedValue(a)) && !isDeclaration(a) &&
        // a lowering temporary is written, not navigated: `(_tmp = location.href).substr(...)`
        !a.argumentOption(1).exists(_.code.startsWith("_tmp_")) &&
        a.argumentOption(1).flatMap(memberPath).exists {
            // `location = url`, but not a class field called `location` (`private location =
            // inject(Location)` is lowered to an assignment to an identifier too)
            case List("location") =>
                a.code.startsWith("location") && !declaresLocal(a.method, "location")
            case p => isLocation(p) || (p.lastOption.contains("href") && isLocation(p.init))
        }
    }
    ctx.tagger.tag(locationWrites, NavigationSink*)

    val navigationCalls = ctx.cpg.call.filter { c =>
        callName(c) match
          case "assign" | "replace" =>
              receiverOf(c).flatMap(memberPath).exists(isLocation)
          case "open" =>
              receiverOf(c).flatMap(memberPath).exists(isWindow)
          case "navigate" =>
              receiverOf(c).flatMap(memberPath).exists(p =>
                  p.lastOption.contains("navigation") && (p.size == 1 || isWindow(p.init))
              )
          case _ => false
    }.filter(c => unanchored(c.argument.filter(_.argumentIndex == 1).headOption))
    ctx.tagger.tag(navigationCalls, NavigationSink*)

    // `target.postMessage(secret, '*')` hands the data to whatever document is in that window
    val wildcardMessages = ctx.cpg.call.filter(c => callName(c) == "postMessage").filter(c =>
        c.argument.filter(_.argumentIndex == 2).headOption.flatMap(literalValue).contains("*") &&
            nonConstant(c.argument.filter(_.argumentIndex == 1).headOption)
    )
    ctx.tagger.tag(wildcardMessages, OUTPUT)

    // `document.cookie = ...` - cookie manipulation
    val cookieWrites = propertyWrites(ctx.cpg, Set("cookie")).filter(w =>
        nonConstant(assignedValue(w)) &&
            w.argumentOption(1).collect { case fa: Call => fa }.flatMap(fieldBase).flatMap(
              memberPath
            )
                .exists(isDocument)
    )
    ctx.tagger.tag(cookieWrites, OUTPUT)
  end tagNavigationSinks

  private def isDeclaration(a: Call): Boolean =
      a.code.startsWith("const ") || a.code.startsWith("let ") || a.code.startsWith("var ")

  private def declaresLocal(m: Method, name: String): Boolean =
      m.local.nameExact(name).nonEmpty || m.parameter.nameExact(name).nonEmpty

  private def tagCodeSinks(ctx: JsContext): Unit =
    val evalCalls = ctx.cpg.call.filter(c =>
        isGlobalCall(c, Set("eval", "execScript", "importScripts")) ||
            (c.name == "Function" && isGlobalCall(c, Set("Function")))
    )
    ctx.tagger.tag(evalCalls, CodeSink*)
    val functionCtors = ctx.cpg.call.nameExact("<operator>.new", Operators.alloc)
        .filter(_.code.startsWith("new Function("))
    ctx.tagger.tag(functionCtors, CodeSink*)
    // String timers evaluate their first argument; a function argument is just a callback.
    // Only a value that is a string is evaluated: a computed string, or a variable holding one. A
    // parameter or a function reference (`setTimeout(resolve, 500)`) is a callback.
    def isStringValue(e: Expression): Boolean =
        e match
          case c: Call =>
              c.name == Operators.addition || c.name == Operators.formatString ||
              !c.name.startsWith("<operator>")
          case _ => false
    val stringTimers = ctx.cpg.call
        .filter(c => isGlobalCall(c, Set("setTimeout", "setInterval", "setImmediate")))
        .filter(_.argument.filter(_.argumentIndex == 1).headOption.exists {
            case id: Identifier =>
                !id.name.startsWith("_tmp_") && callbackMethod(id).isEmpty &&
                isStringValue(JsValues.origin(id))
            case other => isStringValue(other)
        })
    ctx.tagger.tag(stringTimers, CodeSink*)
    // `import(url)` with a computed specifier loads and runs code from it.
    val dynamicImports = ctx.cpg.call.nameExact("import")
        .filter(_.argument.filter(_.argumentIndex == 1).exists(a => !a.isInstanceOf[Literal]))
    ctx.tagger.tag(dynamicImports, CodeSink*)
  end tagCodeSinks

  /** A request whose target is not fixed by the code. A path-relative or absolute URL with a
    * literal origin can carry attacker data but cannot be pointed elsewhere, so it is no
    * request-forgery sink - every `fetch('/api/items?q=' + q)` would otherwise be one.
    */
  private def tagRequestSinks(ctx: JsContext): Unit =
    def urlArg(c: Call): Option[Expression] =
        if c.name == "request" then
          // axios.request({ url }) / HttpClient.request(method, url): the URL is in a config
          // object or second; either way not a plain first argument to judge.
          None
        else c.argument.filter(_.argumentIndex == 1).headOption
    val requests = requestCalls(ctx).flatMap(c => urlArg(c).toList.flatMap(requestSinksFor(c, _))).l
    val (server, browser) = requests.partition(n => isServerFile(n.method.filename))
    ctx.tagger.tag(browser.iterator, RequestSink*)
    ctx.tagger.tag(server.iterator, (RequestSink :+ SSRF)*)

    val xhrOpens = ctx.cpg.call.nameExact("open")
        .filter(c => receiverOf(c).exists(r => constructedBy(r, Set("XMLHttpRequest"))))
        .flatMap(c =>
            c.argument.filter(_.argumentIndex == 2).headOption.toList.flatMap(requestSinksFor(c, _))
        )
    ctx.tagger.tag(xhrOpens, RequestSink*)

    val channels = ctx.cpg.call.nameExact("<operator>.new", Operators.alloc)
        .filter(c => c.code.startsWith("new WebSocket(") || c.code.startsWith("new EventSource("))
        .flatMap(c =>
            c.argument.filter(_.argumentIndex == 1).headOption.toList.flatMap(requestSinksFor(c, _))
        )
    ctx.tagger.tag(channels, RequestSink*)
    val beacons = ctx.cpg.call.nameExact("sendBeacon")
        .flatMap(c =>
            c.argument.filter(_.argumentIndex == 1).headOption.toList.flatMap(requestSinksFor(c, _))
        )
    ctx.tagger.tag(beacons, RequestSink*)
  end tagRequestSinks

  // -----------------------------------------------------------------------------------------
  // Sanitisers
  // -----------------------------------------------------------------------------------------

  /** HTML sanitiser libraries, keyed by package, with the call that sanitises - and
    * `@braintree/sanitize-url`, which turns a `javascript:`, `data:` or `vbscript:` URL into
    * `about:blank`: no script runs from a link or a frame it fills.
    */
  private val HtmlSanitizers: Seq[(String, Set[String])] = Seq(
    "@braintree/sanitize-url" -> Set("sanitizeUrl"),
    "dompurify"               -> Set("sanitize"),
    "isomorphic-dompurify"    -> Set("sanitize"),
    "sanitize-html"           -> Set("sanitizeHtml", "sanitize-html"),
    "xss"                     -> Set("filterXSS", "xss"),
    "escape-html"             -> Set("escapeHtml", "escape"),
    "he"                      -> Set("encode", "escape"),
    "validator"               -> Set("escape"),
    "lodash"                  -> Set("escape"),
    "lodash-es"               -> Set("escape"),
    "lodash.escape"           -> Set("escape")
  )

  /** `x.origin === location.origin` (or `!==`, or against a constant): a URL object whose origin
    * the code compares before use is checked for where it points. The `new URL(...)` that made it
    * is tagged a sanitiser for navigation, requests and markup URLs. A string compared this way
    * gets nothing - the dataflow engine has no notion of the branch that follows.
    */
  private def tagOriginChecks(ctx: JsContext): Unit =
    val comparisons = ctx.cpg.call.nameExact(
      Operators.equals,
      Operators.notEquals,
      "<operator>.identity",
      "<operator>.notIdentity"
    ).filter(_.argument.isCall.exists(a => fieldName(a).contains("origin"))).l
    val checkedUrls = comparisons.flatMap(_.argument.isCall.l).filter(a =>
        fieldName(a).contains("origin")
    )
        .flatMap(fieldBase).filterNot(b => memberPath(b).exists(p => isLocation(p) || isWindow(p)))
        .map(JsValues.origin(_))
        .flatMap {
            // `new URL(raw, base)` is lowered to a block around the `<operator>.new` call
            case b: Block if b.code.startsWith("new URL(") =>
                b.ast.isCall.nameExact("<operator>.new").headOption
            case c: Call if c.code.startsWith("new URL(") || c.code.startsWith("URL.parse(") =>
                Some(c)
            case _ => None
        }
    ctx.tagger.tag(
      checkedUrls.iterator,
      SANITIZER,
      sanitizerFor(REDIRECT),
      sanitizerFor(HTTP_CLIENT),
      sanitizerFor(XSS)
    )
  end tagOriginChecks

  private val Predicates = Set(
    "hasOwn",
    "hasOwnProperty",
    "has",
    "includes",
    "startsWith",
    "endsWith",
    "test",
    "isFinite",
    "isInteger",
    "isSafeInteger",
    "isNaN",
    "isArray",
    "some",
    "every",
    "indexOf",
    "lastIndexOf",
    "localeCompare",
    "contains"
  )

  private def tagSanitizers(ctx: JsContext): Unit =
    tagOriginChecks(ctx)
    val sanitizerPackages = HtmlSanitizers.map(_._1).toSeq
    val htmlSanitizerCalls = ctx.cpg.call.filter { c =>
      val f = c.method.filename
      (ctx.modules.gate(f, sanitizerPackages, "sanitizer") &&
          HtmlSanitizers.exists { (pkg, names) =>
            val moduleBindings = ctx.modules.moduleBindingsOf(f, pkg)
            calleePath(c).exists {
                // `DOMPurify.sanitize(x)`, `he.encode(x)`
                case List(binding, method) =>
                    names.contains(method) && moduleBindings.contains(binding)
                // `sanitizeHtml(x)`, `filterXSS(x)` - a default or named binding called directly
                case List(binding) =>
                    moduleBindings.contains(binding) ||
                    names.exists(n => ctx.modules.localNamesOf(f, pkg, n).contains(binding))
                case _ => false
            }
          }) ||
      // DOMPurify loaded from a script tag is a global
      (c.name == "sanitize" && calleePath(c).exists(_.headOption.exists(h =>
          h == "DOMPurify" || h == "purify"
      )))
    }
    ctx.tagger.tag(htmlSanitizerCalls, SANITIZER, sanitizerFor(XSS))

    // URL-encoding makes a value inert as markup and keeps it inside one URL component, so it can
    // neither become `javascript:` nor move a request to another origin.
    val encoders = ctx.cpg.call.filter(isGlobalCall(_, Set("encodeURIComponent")))
    ctx.tagger.tag(
      encoders,
      SANITIZER,
      sanitizerFor(XSS),
      sanitizerFor(REDIRECT),
      sanitizerFor(HTTP_CLIENT)
    )

    // An object URL (`blob:`) names data the page itself holds; it cannot be pointed elsewhere.
    val objectUrls = ctx.cpg.call.nameExact("createObjectURL")
        .filter(c => receiverOf(c).flatMap(memberPath).contains(List("URL")))
    ctx.tagger.tag(objectUrls, SANITIZER)

    // A JSON response - `Response.json(x)`, Next.js's `NextResponse.json(x)`, SvelteKit's
    // `json(x)` - is served as `application/json`: a handler returning one returns no markup.
    val jsonResponses = ctx.cpg.call.nameExact("json").filter { c =>
      val file = c.method.filename
      calleePath(c).exists {
          // the global, unless the code binds the name itself (a captured global is a local too)
          case List("Response", "json") =>
              JsIndexes.assignedValues(c.method, "Response").isEmpty &&
              c.method.parameter.nameExact("Response").isEmpty
          case List(binding, "json") =>
              ctx.modules.localNamesOf(file, "next", "NextResponse").contains(binding)
          case List(binding) =>
              ctx.modules.localNamesOf(file, "@sveltejs/kit", "json").contains(binding)
          case _ => false
      }
    }
    ctx.tagger.tag(jsonResponses, SANITIZER)

    // A lookup in a Map of constants (`PORTALS.get(partner)`, `new Map([['a', 'https://...']])`)
    // returns one of the code's own values, whatever the key: the key picks, it does not write.
    val constantLookups = ctx.cpg.call.nameExact("get").filter { c =>
        receiverOf(c).collect { case id: Identifier => JsValues.origin(id) }.exists {
            case made: Expression =>
                made.code.trim.matches("(?s)new\\s+Map\\b.*") &&
                made.ast.isIdentifier.name.forall(n => n == "Map" || n.startsWith("_tmp_")) &&
                made.ast.isLiteral.nonEmpty
            case null => false
        }
    }
    ctx.tagger.tag(constantLookups, SANITIZER)

    // Predicates and position lookups: their result is a boolean or a number.
    val predicates = ctx.cpg.call.filter(c => Predicates.contains(callName(c)))
    ctx.tagger.tag(predicates, PREDICATE)

    // Numeric conversions leave nothing to inject, whatever the sink.
    val numeric = ctx.cpg.call.filter(c =>
        isGlobalCall(c, Set("Number", "parseInt", "parseFloat", "Boolean")) ||
            (c.name == "isNaN" && isGlobalCall(c, Set("isNaN")))
    )
    ctx.tagger.tag(numeric, SANITIZER)
  end tagSanitizers
end DomRecognizer

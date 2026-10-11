package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*
import JsTags.*

/** jQuery (https://api.jquery.com), imported or - as often - a page global.
  *
  * Sinks: `$(html)` and `jQuery(html)` (a string starting with `<` is parsed as markup), the
  * manipulation methods that take markup (`html`, `append`, `prepend`, `after`, `before`,
  * `replaceWith`, `wrap`, `wrapAll`, `wrapInner`, `add`), `$.parseHTML`, `attr`/`prop` with a URL
  * attribute, an event handler or `innerHTML`; `$.globalEval` and `$.getScript` run code;
  * `$.ajax`/`$.get`/`$.getJSON`/`$.post`/`.load` request a URL - `dataType: 'script'` or JSONP
  * runs the response.
  *
  * Sources: the responses of those requests (`.done(cb)`, `.then(cb)`, `success: cb`), and
  * `message`/`hashchange` events bound with `$(window).on(...)`.
  */
object JQueryRecognizer extends JsFrameworkRecognizer:

  val name: String = "jquery"

  private val Bindings = Set("$", "jQuery")

  def applies(ctx: JsContext): Boolean =
      ctx.modules.uses("jquery") || ctx.project.dependsOn("jquery") ||
          ctx.cpg.call.nameExact(Bindings.toSeq*).nonEmpty

  private val MarkupMethods = Set(
    "html",
    "append",
    "prepend",
    "after",
    "before",
    "replaceWith",
    "wrap",
    "wrapAll",
    "wrapInner",
    "add",
    "appendTo",
    "prependTo",
    "insertAfter",
    "insertBefore"
  )

  private val UrlAttributes = Set("href", "src", "action", "formaction", "srcdoc", "xlink:href")

  private val RequestMethods = Set("ajax", "get", "post", "getJSON", "load")

  private def argument(c: Call, index: Int): Option[Expression] =
      c.argument.filter(_.argumentIndex == index).headOption

  private def computed(e: Option[Expression]): Boolean = e.exists(!_.isInstanceOf[Literal])

  /** `$` / `jQuery` itself, called. */
  private def isFactory(c: Call): Boolean =
      Bindings.contains(c.name) && c.receiver.headOption.flatMap(memberPath).exists(_.size == 1)

  /** `$.ajax(...)`: a static method on the binding. */
  private def isStatic(c: Call, names: Set[String]): Boolean =
      names.contains(c.name) && receiverOf(c).flatMap(memberPath).exists(p =>
          p.size == 1 && Bindings.contains(p.head)
      )

  /** A jQuery collection: the result of `$(...)`, a chain on one, or a `$name` variable. */
  private def isCollection(e: Expression, depth: Int = 6): Boolean =
      depth > 0 && (JsValues.origin(e) match
        case c: Call if isFactory(c)                    => true
        case c: Call if c.name == Operators.fieldAccess => false
        case c: Call                                    => receiverOf(c).exists(isCollection(_, depth - 1))
        case id: Identifier                             => id.name.startsWith("$") && id.name.length > 1
        case _                                          => false)

  def run(ctx: JsContext): Unit =
    // $(html): only a computed argument, and not an element or the window/document
    val factories = ctx.cpg.call.filter(isFactory).filter(c =>
        argument(c, 1).exists {
          case _: Literal => false
          case id: Identifier => !Set("this", "window", "document", "self").contains(id.name)
          case _: MethodRef   => false // $(function () { ... }) - document ready
          case _              => true
        }
    )
    ctx.tagger.tag(factories, HtmlSink*)

    val markup = ctx.cpg.call.nameExact(MarkupMethods.toSeq*).filter(c =>
        computed(argument(c, 1)) && receiverOf(c).exists(isCollection(_))
    )
    ctx.tagger.tag(markup, HtmlSink*)

    val parsed = ctx.cpg.call.filter(c => isStatic(c, Set("parseHTML")) && computed(argument(c, 1)))
    ctx.tagger.tag(parsed, HtmlSink*)

    val attributes = ctx.cpg.call.nameExact("attr", "prop").filter { c =>
        argument(c, 1).flatMap(literalValue).exists(n =>
            UrlAttributes.contains(n.toLowerCase) || n.toLowerCase.startsWith("on") ||
                n == "innerHTML" || n == "outerHTML"
        ) && computed(argument(c, 2)) && receiverOf(c).exists(isCollection(_))
    }
    ctx.tagger.tag(attributes, HtmlSink*)

    val code = ctx.cpg.call.filter(c => isStatic(c, Set("globalEval", "getScript")) && computed(argument(c, 1)))
    ctx.tagger.tag(code, CodeSink*)

    // Requests; their responses are remote data
    val requests = ctx.cpg.call.filter(c =>
        isStatic(c, RequestMethods) || (c.name == "load" && receiverOf(c).exists(isCollection(_)))
    ).l
    requests.foreach { c =>
        argument(c, 1).foreach {
          case cfg: Block =>
              // $.ajax({ url, dataType: 'script' | 'jsonp', success })
              if cfg.code.matches("(?s).*dataType\\s*:\\s*['\"](script|jsonp)['\"].*") then
                ctx.tagger.tag(Iterator(c), CodeSink*)
              else if cfg.code.matches("(?s).*\\burl\\s*:.*") then
                val url = cfg.ast.isCall.nameExact(Operators.assignment)
                    .filter(_.argumentOption(1).exists {
                        case fa: Call => fieldName(fa).contains("url")
                        case _        => false
                    })
                    .flatMap(_.argumentOption(2)).headOption
                url.filterNot(hasFixedOrigin).foreach(_ => ctx.tagger.tag(Iterator(c), RequestSink*))
              ctx.tagger.tag(callbacksIn(cfg, Set("success")).flatMap(firstParam).iterator, INGRESS)
          case url =>
              // $.getJSON(url + '?callback=?') runs the response as script
              if c.name == "getJSON" && url.code.contains("callback=?") then
                ctx.tagger.tag(Iterator(c), CodeSink*)
              else if !hasFixedOrigin(url) then ctx.tagger.tag(Iterator(c), RequestSink*)
        }
        // $.get(url, function (data) {...}) and the jqXHR promise
        ctx.tagger.tag(
          c.argument.filter(_.argumentIndex >= 2).l.flatMap(callbacksIn(_)).flatMap(firstParam).iterator,
          INGRESS
        )
        val chained = c.method.call.nameExact("done", "then", "always").filter(d =>
            receiverOf(d).exists(r => JsValues.origin(r).id() == c.id())
        ).l
        ctx.tagger.tag(
          chained.flatMap(_.argument.filter(_.argumentIndex == 1).l).flatMap(callbacksIn(_))
              .flatMap(firstParam).iterator,
          INGRESS
        )
    }

    // $(window).on('message', handler): a message from any origin
    val windowEvents = ctx.cpg.call.nameExact("on", "one", "bind").filter { c =>
        receiverOf(c).exists(r =>
            JsValues.origin(r) match
              case f: Call if isFactory(f) =>
                  argument(f, 1).exists(a => a.code == "window" || a.code == "self")
              case _ => false
        ) && argument(c, 1).flatMap(literalValue).exists(e => e == "message" || e == "hashchange")
    }.l
    ctx.tagger.tag(
      windowEvents.flatMap(_.argument.filter(_.argumentIndex >= 2).l).flatMap(callbacksIn(_))
          .flatMap(firstParam).iterator,
      INPUT
    )
  end run
end JQueryRecognizer

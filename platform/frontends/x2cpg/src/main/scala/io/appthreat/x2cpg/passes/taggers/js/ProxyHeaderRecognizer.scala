package io.appthreat.x2cpg.passes.taggers.js

import io.appthreat.x2cpg.passes.taggers.ForwardedHeaders
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import JsShapes.*

/** Forwarded-header semantics of the Node server frameworks (Express, Koa, Fastify, NestJS, ...):
  * the request values a client can choose through the `X-Forwarded-*` headers behind a trusted
  * proxy (`req.ip`, `req.hostname`, `req.protocol`, ...), the configuration that turns on that
  * handling (`app.set('trust proxy', ...)`, Koa's `app.proxy = true`, Fastify's `trustProxy`
  * factory option), and direct reads of the headers by name (`req.get('x-forwarded-for')`,
  * `req.headers['x-forwarded-for']`).
  *
  * The receiver evidence for the generic names (`ip`, `host`, `protocol`) is the framework's
  * request convention: a receiver named `req`, `request` or `ctx` (Express and Fastify name it
  * `req`/`request`, Koa `ctx`, NestJS `@Req() request`) in a file that imports a server framework.
  * The same names on a domain object (`device.ip`) or a Map (`map.get('X-Forwarded-For')`) stay
  * untagged.
  *
  * Tags (see [[ForwardedHeaders]]): `proxy-derived` (`client-ip`/`host`/`scheme`),
  * `trusted-proxy-config`, `trusted-proxy-headers`, `forwarded-header-read`. Opt-in reachables
  * sources, not default ones.
  */
object ProxyHeaderRecognizer extends JsFrameworkRecognizer:

  val name: String = "proxy-headers"

  private val ServerPackages =
      Seq("express", "koa", "@koa", "fastify", "@nestjs", "hono", "restify", "polka", "connect")

  /** Express names it `req`, Fastify and NestJS `request`, Koa `ctx`. */
  private val RequestNames = Set("req", "request", "ctx")

  /** `req.ip`/`ctx.protocol` and friends, as field reads. */
  private val FieldAccessors: Map[String, String] = Map(
    "ip"       -> ForwardedHeaders.CLIENT_IP,
    "ips"      -> ForwardedHeaders.CLIENT_IP,
    "hostname" -> ForwardedHeaders.HOST,
    "host"     -> ForwardedHeaders.HOST,
    "protocol" -> ForwardedHeaders.SCHEME,
    "secure"   -> ForwardedHeaders.SCHEME
  )

  def applies(ctx: JsContext): Boolean = ctx.modules.uses(ServerPackages*)

  def run(ctx: JsContext): Unit =
    // Per-file gate: the file itself imports a server framework (a frontend file that happens to
    // name a local `ctx` is out of reach).
    def serverFile(c: Call): Boolean = ctx.modules.importsAny(c.method.filename, ServerPackages)

    // The request names as they appear as handler parameters, keyed by the method: a bare local
    // named `ctx` is not the framework's context, a parameter named `ctx` of a function in a
    // server file is.
    val requestParams: Set[(Long, String)] =
        ctx.cpg.parameter.name(RequestNames.toSeq*).l.map(p => (p.method.id, p.name)).toSet

    // (a) request accessors: `req.ip`, `ctx.host`, ...
    ctx.fieldAccesses.foreach { access =>
        for
          field <- fieldName(access)
          base  <- fieldBase(access)
          id    <- requestIdentifier(base, requestParams)
          kind  <- FieldAccessors.get(field)
        do
          if serverFile(access) then
            ctx.tagger.tagPair(access, ForwardedHeaders.PROXY_DERIVED, kind)
    }

    // (b) direct header reads.
    // `req.headers['x-forwarded-for']`: an index access over the request's headers object.
    ctx.cpg.call.nameExact(Operators.indexAccess).foreach { access =>
      val base = access.argument
          .filter(_.argumentIndex == 1)
          .headOption
          .collect { case c: Call if c.name == Operators.fieldAccess => c }
      val header = access.argument
          .filter(_.argumentIndex == 2)
          .isLiteral
          .headOption
          .flatMap(l => ForwardedHeaders.canonicalHeader(l.code))
      (base.flatMap(b => fieldName(b)), header) match
        case (Some(field), Some(h)) if field == "headers" =>
            if base.exists(b =>
                  fieldBase(b).exists(requestIdentifier(_, requestParams).isDefined) &&
                      serverFile(access)
              )
            then ctx.tagger.tagPair(access, ForwardedHeaders.FORWARDED_HEADER_READ, h)
        case _ =>
    }
    // `req.get('x-forwarded-for')`: Express's and Koa's header getter, on the request receiver.
    ctx.cpg.call.nameExact("get").foreach { call =>
      val header = call.argument
          .filter(_.argumentIndex >= 1)
          .isLiteral
          .headOption
          .flatMap(l => ForwardedHeaders.canonicalHeader(l.code))
      (header, receiverOf(call)) match
        case (Some(h), Some(recv))
            if requestIdentifier(recv, requestParams).isDefined && serverFile(call) =>
            ctx.tagger.tagPair(call, ForwardedHeaders.FORWARDED_HEADER_READ, h)
        case _ =>
    }

    // (c) configuration. Express: `app.set('trust proxy', ...)` / `app.enable('trust proxy')`; a
    // `false` value or `app.disable` turns it off. The value is read from the raw literal code:
    // `false`/`true` are not quoted strings.
    ctx.cpg.call.nameExact("set", "enable").foreach { call =>
      val setting = call.argument
          .filter(_.argumentIndex == 1)
          .isLiteral
          .headOption
          .flatMap(literalValue)
          .getOrElse("")
      val value = call.argument.filter(_.argumentIndex == 2).isLiteral.code.headOption
      if setting.equalsIgnoreCase("trust proxy") then
        val off = call.name == "set" && value.contains("false")
        if !off && receiverIsNamed(call, "app") then
          ctx.tagger.tagPair(call, ForwardedHeaders.TRUSTED_PROXY_CONFIG, "express")
    }
    // Koa: `app.proxy = true` - the assignment call, on the application object.
    ctx.cpg.call.nameExact(Operators.assignment).foreach { assign =>
      val target = assign.argument
          .filter(_.argumentIndex == 1)
          .headOption
          .collect { case c: Call if c.name == Operators.fieldAccess => c }
      (target.flatMap(fieldName), target.flatMap(fieldBase).map(unwrap)) match
        case (Some("proxy"), Some(base)) if isNamedIdentifier(base, "app") =>
            val value = assign.argument.filter(_.argumentIndex == 2).isLiteral.code.headOption
            if value.contains("true") then
              ctx.tagger.tagPair(assign, ForwardedHeaders.TRUSTED_PROXY_CONFIG, "koa")
        case _ =>
    }
    // Fastify: the factory call given a `trustProxy` option - `fastify({ trustProxy: true })` or
    // `require('fastify')({ trustProxy: ... })`. The object literal lowers to a block of property
    // writes; a false literal turns it off.
    ctx.cpg.call.filter(c => c.argument.isBlock.nonEmpty && serverFile(c)).foreach { call =>
        call.argument.isBlock.flatMap(b => objectProperties(b)).foreach { props =>
            props.get("trustProxy").foreach { value =>
              val literalCode = value match
                case l: Literal => Some(l.code)
                case _          => None
              if literalCode.contains("false") then ()
              else
                ctx.tagger.tagPair(call, ForwardedHeaders.TRUSTED_PROXY_CONFIG, "fastify")
                // Fastify's trustProxy derives request.ip from X-Forwarded-For.
                if literalCode.exists(c => c == "true" || c == "1" || c.startsWith("\"")) then
                  ctx.tagger.tagPair(
                    call,
                    ForwardedHeaders.TRUSTED_PROXY_HEADERS,
                    ForwardedHeaders.X_FORWARDED
                  )
            }
        }
    }
  end run

  /** The identifier behind a request receiver, looking through the frontend's temporaries: a
    * parameter of the enclosing method named `req`/`request`/`ctx` (the framework convention), or
    * `this.request` (a controller's injected request). A bare local of the same name is not
    * evidence - it is whatever that file assigned to it.
    */
  private def requestIdentifier(
    base: Expression,
    requestParams: Set[(Long, String)]
  ): Option[Identifier] =
      unwrap(base) match
        case id: Identifier
            if RequestNames.contains(id.name) && requestParams.contains((id.method.id, id.name)) =>
            Some(id)
        case c: Call
            if c.name == Operators.fieldAccess && fieldBase(c).exists(_.code == "this") &&
                fieldName(c).contains("request") =>
            fieldBase(c).collect { case id: Identifier => id }
        case _ => None

  /** True for the plain identifier `expected` (the framework's application object, by convention).
    */
  private def isNamedIdentifier(expr: Expression, expected: String): Boolean =
      expr match
        case id: Identifier => id.name == expected
        case _              => false

  /** True when the receiver of `app.<name>(...)` unwraps to the identifier `app`. */
  private def receiverIsNamed(call: Call, expected: String): Boolean =
      receiverOf(call).exists(isNamedIdentifier(_, expected))
end ProxyHeaderRecognizer

package io.appthreat.x2cpg.passes.taggers.python

import io.appthreat.x2cpg.passes.taggers.ForwardedHeaders
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Expression, Identifier}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** Forwarded-header semantics: the request values a client can choose through the `Forwarded` and
  * `X-Forwarded-*` headers behind a passing proxy (the client IP, host and scheme accessors of
  * Django, Flask/Werkzeug and the WSGI frameworks), the configuration that turns on that handling
  * (Werkzeug's `ProxyFix`, Django's `USE_X_FORWARDED_HOST`/`SECURE_PROXY_SSL_HEADER`), and direct
  * reads of the headers by name.
  *
  * The receiver evidence for the generic accessor names (`host`, `scheme`, `ip`) is the framework's
  * own request object: a parameter or module-level proxy named `request`/`req` (Django names the
  * view parameter `request`, Flask imports `request`, aiohttp handlers name their parameter
  * `request`), or `self.request` in a class-based view. `remote_addr`, `access_route`, `get_host`
  * and `build_absolute_uri` are framework vocabulary and match under the same receiver rule, which
  * the import gate already restricts to Python web projects.
  *
  * Tags (see [[io.appthreat.x2cpg.passes.taggers.ForwardedHeaders]]): `proxy-derived` with value
  * `client-ip`/`host`/`scheme`, `trusted-proxy-config`, `trusted-proxy-headers`,
  * `forwarded-header-read`. They are opt-in reachables sources, not default ones.
  */
object ProxyHeaderRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "proxy-headers"

  private val GateRoots = Set(
    "django",
    "flask",
    "werkzeug",
    "quart",
    "bottle",
    "sanic",
    "tornado",
    "aiohttp",
    "falcon",
    "pyramid",
    "cherrypy",
    "starlette",
    "fastapi"
  )

  private val RequestReceiverNames = Set("request", "req")

  /** Attribute reads on the request object. Werkzeug's `url_root` and Django's `META` live on the
    * same receivers; the kind names what the value decides.
    */
  private val FieldAccessors: Map[String, String] = Map(
    "remote_addr"  -> "client-ip",
    "access_route" -> "client-ip",
    "host"         -> "host",
    "host_url"     -> "host",
    "url_root"     -> "host",
    "root_url"     -> "host",
    "base_url"     -> "host",
    "url"          -> "host",
    "scheme"       -> "scheme",
    "is_secure"    -> "scheme"
  )

  /** Method calls on the request object (Django's `get_host()`/`build_absolute_uri()`, the shared
    * `is_secure()`).
    */
  private val CallAccessors: Map[String, String] = Map(
    "get_host"           -> "host",
    "build_absolute_uri" -> "host",
    "is_secure"          -> "scheme",
    "get_port"           -> "host"
  )

  /** The attributes that hold the header/environment mappings: Django's `META`, Werkzeug's
    * `environ`, and the `headers` mapping of both.
    */
  private val HeaderAttributes = Set("META", "headers", "environ")

  /** Django settings that turn on X-Forwarded-* handling, by the name they are assigned to. */
  private val DjangoForwardedSettings =
      Set("USE_X_FORWARDED_HOST", "USE_X_FORWARDED_PORT", "SECURE_PROXY_SSL_HEADER")

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, GateRoots)

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff

    // (a) request accessors.
    cpg.call.nameExact(Operators.fieldAccess).foreach { access =>
        receiverAndField(access) match
          case Some((receiver, field)) if isRequestReceiver(receiver) =>
              FieldAccessors.get(field).foreach(kind =>
                  tag(access, ForwardedHeaders.PROXY_DERIVED, kind)
              )
          case _ =>
    }
    cpg.call
        .name(CallAccessors.keys.mkString("|"))
        .foreach { call =>
          // `request.get_host()`: the receiver is the fieldAccess `request.get_host`; its base
          // identifier is the request.
          val base = call.receiver.collect { case c: Call if c.name == Operators.fieldAccess => c }
              .headOption
              .flatMap(_.argument.filter(_.argumentIndex == 1).headOption)
          if base.exists(b => isRequestReceiver(b.code)) then
            tag(call, ForwardedHeaders.PROXY_DERIVED, CallAccessors(call.name))
        }
    // `request.META["REMOTE_ADDR"]`: the socket address as the WSGI server reports it, which a
    // proxy-fixing middleware (Werkzeug's ProxyFix) rewrites from X-Forwarded-For.
    cpg.call.nameExact(Operators.indexAccess).foreach { access =>
        if isHeaderBase(access) && literalKey(access).exists(_.equalsIgnoreCase("REMOTE_ADDR")) then
          tag(access, ForwardedHeaders.PROXY_DERIVED, ForwardedHeaders.CLIENT_IP)
    }

    // (b) direct header reads: `request.META['HTTP_X_FORWARDED_FOR']`,
    // `request.headers['X-Forwarded-For']`, `request.headers.get('X-Forwarded-For')`. Only a
    // literal name is evidence; a computed key reads anything and gets nothing.
    cpg.call.nameExact(Operators.indexAccess).foreach { access =>
        if isHeaderBase(access) then
          literalKey(access)
              .flatMap(ForwardedHeaders.canonicalHeader)
              .foreach(h => tag(access, ForwardedHeaders.FORWARDED_HEADER_READ, h))
    }
    cpg.call.nameExact("get").foreach { call =>
        resolvedHeaderBase(call).foreach { _ =>
            call.argument.isLiteral.headOption.foreach { lit =>
              ForwardedHeaders.canonicalHeader(lit.code)
                  .foreach(h => tag(call, ForwardedHeaders.FORWARDED_HEADER_READ, h))
              // The same mapping's REMOTE_ADDR - Django's spelling of the socket address,
              // which a proxy-fixing middleware rewrites from X-Forwarded-For.
              if unquote(lit.code).equalsIgnoreCase("REMOTE_ADDR") then
                tag(call, ForwardedHeaders.PROXY_DERIVED, ForwardedHeaders.CLIENT_IP)
            }
        }
    }

    // (c) configuration. ProxyFix adjusts the WSGI environ from the X-Forwarded-* headers only.
    cpg.call.nameExact("ProxyFix").foreach { call =>
      tag(call, ForwardedHeaders.TRUSTED_PROXY_CONFIG, "werkzeug")
      tag(call, ForwardedHeaders.TRUSTED_PROXY_HEADERS, ForwardedHeaders.X_FORWARDED)
    }
    // Django settings: assigned anywhere (the settings module need not be named settings.py); the
    // names are unambiguous Django settings. A False/None literal turns the setting off; a tuple
    // value (SECURE_PROXY_SSL_HEADER) is a literal-less argument and is on.
    cpg.call.nameExact(Operators.assignment).foreach { assign =>
      val target = assign.argument.isIdentifier.name.headOption
      val value  = assign.argument.isLiteral.code.headOption
      target match
        case Some(name) if DjangoForwardedSettings.contains(name) =>
            if !value.contains("False") && !value.contains("None") then
              tag(assign, ForwardedHeaders.TRUSTED_PROXY_CONFIG, "django")
              tag(assign, ForwardedHeaders.TRUSTED_PROXY_HEADERS, ForwardedHeaders.X_FORWARDED)
        case _ =>
    }
    // Flask's `url_for(..., _external=True)` builds an absolute URL from the current request's
    // scheme and host; without `_external` it returns a path. The keyword carries the flag.
    cpg.call.nameExact("url_for").foreach { call =>
      val external = call.argument.exists { a =>
          a.argumentName.contains("_external") && a.code != "False"
      }
      if external then tag(call, ForwardedHeaders.PROXY_DERIVED, ForwardedHeaders.HOST)
    }
  end run

  /** The receiver name and accessed field of a `receiver.field` access (as in
    * [[ModelTaintRecognizer]]), when shaped that way.
    */
  private def receiverAndField(access: Call): Option[(String, String)] =
    val args = access.argument.l.sortBy(a =>
        if a.argumentIndex < 0 then Int.MaxValue else a.argumentIndex
    )
    for
      receiver <- args.headOption
      field    <- args.lift(1)
    yield (receiver.code, field.code)

  /** True for the receiver text of a request access: the parameter or imported proxy `request` /
    * `req`, or `self.request` in a class-based view.
    */
  private def isRequestReceiver(code: String): Boolean =
      RequestReceiverNames.contains(code) || code == "self.request"

  /** The literal key of an index access, when it is one. */
  private def literalKey(access: Call): Option[String] =
      access.argument.isLiteral.headOption.map(l => unquote(l.code))

  /** True when an index access reads `request.<headerAttribute>[...]`. */
  private def isHeaderBase(access: Call): Boolean =
    val base = access.argument.argumentIndex(1).headOption
    base.exists {
        case f: Call if f.name == Operators.fieldAccess =>
            receiverAndField(f) match
              case Some((receiver, field)) =>
                  isRequestReceiver(receiver) && HeaderAttributes.contains(field)
              case None => false
        case _ => false
    }

  /** Resolves the receiver of a `.get(...)` call to the header mapping it reads, through the
    * temporary the frontend introduces: `tmp = request.headers; tmp.get('X-Forwarded-For')`.
    * Returns the mapping's field name when the chain lands on the request object.
    */
  private def resolvedHeaderBase(call: Call): Option[String] =
    val base = call.receiver.collect { case c: Call if c.name == Operators.fieldAccess => c }
        .headOption
        .flatMap(fieldBaseOf)
    base.collect { case i: Identifier => i }.flatMap { id =>
        call.method.call
            .nameExact(Operators.assignment)
            .filter(_.argument.isIdentifier.name(id.name).nonEmpty)
            .l
            .flatMap(_.argument.isCall.nameExact(Operators.fieldAccess).l)
            .findLast { f =>
                receiverAndField(f).exists((receiver, field) =>
                    isRequestReceiver(receiver) && HeaderAttributes.contains(field)
                )
            }
            .flatMap(receiverAndField(_).map(_._2))
    }

  /** The receiver expression of a fieldAccess call (`tmp0.get` -> the `tmp0` identifier). */
  private def fieldBaseOf(access: Call): Option[Expression] =
      access.argument
          .filter(_.argumentIndex == 1)
          .headOption
end ProxyHeaderRecognizer

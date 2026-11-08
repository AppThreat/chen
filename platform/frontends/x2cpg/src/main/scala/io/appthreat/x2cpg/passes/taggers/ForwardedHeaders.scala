package io.appthreat.x2cpg.passes.taggers

/** Vocabulary shared by every language's forwarded-header tagging.
  *
  * A reverse proxy in front of an application usually passes the client-supplied `Forwarded` and
  * `X-Forwarded-*` headers through unchanged, and several frameworks read them when they decide the
  * client IP, the host or the scheme the application sees. The values an application reads through
  * those accessors are therefore client-choosable behind such a proxy. Static analysis cannot see
  * the proxy, so the tags below record the two facts it can see - where an application reads the
  * request's client IP, host or scheme, and where it turns on forwarded-header handling - and leave
  * the deployment question (is a proxy passing the headers through?) to the reader.
  *
  * The tags ride on CALL nodes as key/value pairs, so they surface in the `tags` field of slice
  * records the way `framework-input` does, and are opt-in sources for reachables through
  * `--source-tag proxy-derived` (they are deliberately absent from atom's DEFAULT_SOURCE_TAGS, so
  * no default run changes).
  */
object ForwardedHeaders:

  /** A call returning the client IP, host or scheme as the framework resolves it, which behind a
    * passing proxy reflects the forwarded headers. Values: `client-ip`, `host`, `scheme`.
    */
  val PROXY_DERIVED: String = "proxy-derived"

  val CLIENT_IP: String = "client-ip"
  val HOST: String      = "host"
  val SCHEME: String    = "scheme"

  /** A call (or assignment) that turns on forwarded-header handling. Value: the framework
    * (`express`, `koa`, `fastify`, `spring`, `jetty`, `reactor-netty`, `werkzeug`, `django`,
    * `symfony`, `laravel`, `rails`).
    */
  val TRUSTED_PROXY_CONFIG: String = "trusted-proxy-config"

  /** Which header family the configuration says to trust, where a literal names it. Values:
    * `forwarded` (RFC 7239), `x-forwarded`, `all` (both).
    */
  val TRUSTED_PROXY_HEADERS: String = "trusted-proxy-headers"

  /** A direct read of a forwarded header by name. Value: the header, lower-cased as written
    * (`x-forwarded-for`, or the CGI spelling `http_x_forwarded_for`).
    */
  val FORWARDED_HEADER_READ: String = "forwarded-header-read"

  /** The headers whose direct read is tagged: the RFC 7239 header, its de-facto `X-Forwarded-*`
    * family, and the two single-value client-IP spellings proxies emit.
    */
  val FORWARDED_HEADERS: Set[String] = Set(
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-forwarded-port",
    "x-real-ip",
    "client-ip"
  )

  /** The canonical form of a header name read as the string literal `code`, when it is one of
    * [[FORWARDED_HEADERS]] in either spelling: as written (`X-Forwarded-For`) or CGI
    * (`HTTP_X_FORWARDED_FOR`). Comparison is case-insensitive.
    */
  def canonicalHeader(code: String): Option[String] =
    val asWritten = code.trim.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
    val lower     = asWritten.toLowerCase
    if FORWARDED_HEADERS.contains(lower) then Some(lower)
    else if lower.startsWith("http_") then
      val decoded = lower.stripPrefix("http_").replace('_', '-')
      Option.when(FORWARDED_HEADERS.contains(decoded))(decoded)
    else None

  /** The CGI (WSGI/Rack/PHP `$_SERVER`) spelling of a canonical header name, e.g. `x-forwarded-for`
    * -> `HTTP_X_FORWARDED_FOR`.
    */
  def cgiSpelling(header: String): String = "HTTP_" + header.toUpperCase.replace('-', '_')

  /** The header-family value for a bit-flag expression over Symfony/Laravel `HEADER_*` constants,
    * read from the expression's source text: `HEADER_FORWARDED` alone means the RFC 7239 header,
    * `HEADER_X_FORWARDED_*` means the X-Forwarded family, and both mean all of them.
    */
  def headerFamilyFromFlags(flagsText: String): Option[String] =
    val forwarded  = flagsText.contains("HEADER_FORWARDED")
    val xForwarded = flagsText.contains("HEADER_X_FORWARDED")
    if forwarded && xForwarded then Some("all")
    else if forwarded then Some(FORWARDED)
    else if xForwarded then Some(X_FORWARDED)
    else None

  val FORWARDED: String   = "forwarded"
  val X_FORWARDED: String = "x-forwarded"
  val ALL: String         = "all"
end ForwardedHeaders

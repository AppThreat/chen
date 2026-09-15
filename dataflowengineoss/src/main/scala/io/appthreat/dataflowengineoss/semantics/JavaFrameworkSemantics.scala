package io.appthreat.dataflowengineoss.semantics

/** Framework flow semantics for Java graphs (javasrc2cpg and the JVM byte-code frontends).
  *
  * This object is the Java counterpart of [[PhpFrameworkSemantics]]: the single documented home of
  * the framework taint vocabulary. It records, per concern, the `methodFullName` shapes as they
  * appear in a Java CPG:
  *
  *   1. SANITIZERS drive taint clearing. Every entry in [[allSanitizerFullNames]] becomes a
  *      `FlowSemantic` with an EMPTY mapping list, so taint does not pass from the argument to the
  *      return of the call (see MethodFlowSummary: a declared semantic is authoritative and an
  *      undeclared parameter is treated as sanitized). They are consumed by
  *      [[io.appthreat.dataflowengineoss.DefaultSemantics.javaFlows]].
  *
  * 2. CARRIERS are pass-through/propagation summaries for calls whose result legitimately carries
  * its argument's taint (a deserialised object is its JSON; a formatted string embeds its
  * arguments; a builder accumulates what is appended).
  *
  * Every name here is fully qualified (`org.owasp.encoder.Encode.forHtml`), so - unlike the PHP
  * sanitizer list, which is gated on the graph's language through
  * `DefaultSemantics.flowsForLanguage` - these summaries are safe in the LANGUAGE NEUTRAL
  * `javaFlows` list: a bare name collision in a C/JS/Python graph is impossible.
  */
object JavaFrameworkSemantics:

  /** HTML/JavaScript/URL escapers - the output-encoding neutralisers.
    *
    * OWASP Encoder is the reference implementation; Spring's HtmlUtils and commons-text's
    * StringEscapeUtils are the escapers most Spring/commons projects already carry. A value that
    * passed through one of these is safe to interpolate into markup, so the argument's taint does
    * not reach the call's result.
    */
  object Sanitizers:
    val owaspEncoderFullNames: Set[String] = Set(
      "org.owasp.encoder.Encode.forHtml:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forHtmlContent:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forJava:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forJavaScript:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forJavaScriptBlock:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forJavaScriptSource:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forUrl:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forXml:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forXmlAttribute:java.lang.String(java.lang.String)",
      "org.owasp.encoder.Encode.forCssString:java.lang.String(java.lang.String)"
    )

    val springFullNames: Set[String] = Set(
      "org.springframework.web.util.HtmlUtils.htmlEscape:java.lang.String(java.lang.String)",
      "org.springframework.web.util.HtmlUtils.htmlEscapeHex:java.lang.String(java.lang.String)",
      "org.springframework.web.util.UriUtils.encode:java.lang.String(java.lang.String,java.lang.String)",
      "org.springframework.web.util.UriUtils.encodeFragment:java.lang.String(java.lang.String,java.lang.String)"
    )

    val commonsTextFullNames: Set[String] = Set(
      "org.apache.commons.text.StringEscapeUtils.escapeHtml4:java.lang.String(java.lang.String)",
      "org.apache.commons.text.StringEscapeUtils.escapeXml11:java.lang.String(java.lang.String)",
      "org.apache.commons.text.StringEscapeUtils.escapeXml10:java.lang.String(java.lang.String)",
      "org.apache.commons.text.StringEscapeUtils.escapeEcmaScript:java.lang.String(java.lang.String)",
      "org.apache.commons.text.StringEscapeUtils.escapeJava:java.lang.String(java.lang.String)"
    )

    /** The JDK's own escaper for URIs (query-parameter encoding). */
    val jdkFullNames: Set[String] = Set(
      "java.net.URLEncoder.encode:java.lang.String(java.lang.String,java.lang.String)"
    )
  end Sanitizers

  /** Result-carrying calls: the result legitimately embeds the argument's data, so taint must
    * survive the call (an undeclared summary would SANITIZE, which is wrong here). All entries are
    * consumed as `PTF` summaries - every non-receiver parameter flows to the return.
    *
    * `String.format` and `String.concat` are the same concern but declare explicit index mappings
    * directly in `DefaultSemantics.javaFlows` because their receiver (parameter 0) participates in
    * the flow.
    */
  object Carriers:
    val fullNames: Set[String] = Set(
      // A deserialised object is its JSON: whatever tainted the input string taints the object.
      "com.fasterxml.jackson.databind.ObjectMapper.readValue:java.lang.Object(java.lang.String)",
      "com.fasterxml.jackson.databind.ObjectMapper.readValue:java.lang.Object(java.lang.String,java.lang.Class)",
      "com.google.gson.Gson.fromJson:java.lang.Object(java.lang.String,java.lang.Class)"
    )

  /** Request-data accessors of the servlet/Spring request objects.
    *
    * `request.getParameter("q")` RETURNS request data: the taint step that matters is receiver
    * (parameter 0) to return (-1). The names are BARE - `getParameter` is only meaningful relative
    * to a request receiver, and the call is frequently unresolved (the servlet API jar is not on
    * the inference classpath) - so these flows are gated on the graph's language through
    * `DefaultSemantics.flowsForLanguage`, exactly like the PHP sanitizer names.
    */
  object RequestReaders:
    val callNames: Set[String] = Set(
      // HttpServletRequest / ServletRequest
      "getParameter",
      "getParameterValues",
      "getParameterMap",
      "getHeader",
      "getHeaders",
      "getHeaderNames",
      "getCookies",
      "getQueryString",
      "getRequestURI",
      "getRequestURL",
      "getInputStream",
      "getReader",
      "getPart",
      "getParts",
      "getAttribute",
      "getRemoteAddr",
      "getRemoteHost",
      // Vert.x RoutingContext request accessors share the same shapes
      "getParam",
      "queryParams",
      "pathParam",
      "body",
      "getBodyAsJson",
      "fileUploads"
    )
  end RequestReaders

  /** Every sanitizer full name. Drives `DefaultSemantics.javaFlows`. */
  val allSanitizerFullNames: Set[String] =
      Sanitizers.owaspEncoderFullNames ++ Sanitizers.springFullNames ++
          Sanitizers.commonsTextFullNames ++ Sanitizers.jdkFullNames

  /** Every carrier full name. */
  val allCarrierFullNames: Set[String] = Carriers.fullNames
end JavaFrameworkSemantics

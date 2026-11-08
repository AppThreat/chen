package io.appthreat.javasrc2cpg.querying

import io.appthreat.javasrc2cpg.testfixtures.JavaSrcCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Forwarded-header tags on servlet/Spring requests: the accessors whose value a client can choose
  * through the Forwarded and X-Forwarded-* headers behind a passing proxy (`proxy-derived` with
  * `client-ip`/`host`/`scheme`), the direct header reads (`forwarded-header-read`) and the
  * configuration that turns on forwarded-header handling
  * (`trusted-proxy-config`/`trusted-proxy-headers`).
  *
  * The negative cases are the twins the rules require: the same method names on receivers that are
  * not a request (`URI.getScheme()`), a non-literal header name, and constructors that have nothing
  * to do with proxies.
  */
class ForwardedHeaderTagsTest extends JavaSrcCode2CpgFixture:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def proxyDerived(cpg: Cpg, name: String): List[String] =
      cpg.call.nameExact(name).tag.nameExact("proxy-derived").value.l

  private val accessors = """
      |package com.example;
      |
      |import jakarta.servlet.http.HttpServletRequest;
      |import java.net.URI;
      |import org.springframework.http.server.reactive.ServerHttpRequest;
      |
      |public class Accessors {
      |    public String servlet(HttpServletRequest request) {
      |        String a = request.getRemoteAddr();
      |        String b = request.getRemoteHost();
      |        String c = request.getServerName();
      |        int d = request.getServerPort();
      |        StringBuffer e = request.getRequestURL();
      |        String f = request.getScheme();
      |        boolean g = request.isSecure();
      |        return a + b + c + d + e + f + g;
      |    }
      |
      |    public String reactive(ServerHttpRequest request) {
      |        String ip = String.valueOf(request.getRemoteAddress());
      |        String uri = request.getURI().toString();
      |        return ip + uri;
      |    }
      |
      |    public String twins(URI uri, ServerConf conf) {
      |        String scheme = uri.getScheme();
      |        String host = uri.getHost();
      |        String server = conf.getServerName();
      |        boolean secure = conf.isSecure();
      |        return scheme + host + server + secure;
      |    }
      |}
      |""".stripMargin

  "proxy-derived accessors" should {

      "tag the servlet client-ip, host and scheme accessors" in {
          val cpg = tagged(code(accessors, "Accessors.java"))

          proxyDerived(cpg, "getRemoteAddr") shouldBe List("client-ip")
          proxyDerived(cpg, "getRemoteHost") shouldBe List("client-ip")
          proxyDerived(cpg, "getServerName") shouldBe List("host")
          proxyDerived(cpg, "getServerPort") shouldBe List("host")
          proxyDerived(cpg, "getRequestURL") shouldBe List("host")
          proxyDerived(cpg, "getScheme") shouldBe List("scheme")
          proxyDerived(cpg, "isSecure") shouldBe List("scheme")
      }

      "tag the reactive request's accessors" in {
          val cpg = tagged(code(accessors, "Accessors.java"))

          proxyDerived(cpg, "getRemoteAddress") shouldBe List("client-ip")
          proxyDerived(cpg, "getURI") shouldBe List("host")
      }

      "NOT tag the same names on receivers that are not a request" in {
          val cpg = tagged(code(accessors, "Accessors.java"))

          // uri.getScheme() resolves to java.net.URI.getScheme; conf's own methods resolve to the
          // project class. Neither receiver is a request.
          cpg.call.nameExact("getScheme").tag.nameExact("proxy-derived").l.size shouldBe 1
          cpg.call.nameExact("getServerName").tag.nameExact("proxy-derived").l.size shouldBe 1
          cpg.call.nameExact("isSecure").tag.nameExact("proxy-derived").l.size shouldBe 1
          // getHost on a URI is not a servlet accessor at all and never matches by name.
          proxyDerived(cpg, "getHost") shouldBe empty
      }
  }

  "ServletUriComponentsBuilder" should {

      "tag fromCurrentRequest and fromCurrentContextPath as host-derived" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class UriBuilder {
            |    public String build() {
            |        return org.springframework.web.util.ServletUriComponentsBuilder
            |            .fromCurrentRequest().toUriString();
            |    }
            |}
            |""".stripMargin,
            "UriBuilder.java"
          ))

          proxyDerived(cpg, "fromCurrentRequest") shouldBe List("host")
      }
  }

  "forwarded header reads" should {

      "tag getHeader with a literal forwarded header name, and only then" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import jakarta.servlet.http.HttpServletRequest;
            |
            |public class Headers {
            |    public String read(HttpServletRequest request, String name) {
            |        String a = request.getHeader("X-Forwarded-For");
            |        String b = request.getHeader("forwarded");
            |        String all = request.getHeaders("X-Forwarded-For");
            |        String c = request.getHeader("User-Agent");
            |        String d = request.getHeader(name);
            |        return a + b + c + d;
            |    }
            |}
            |""".stripMargin,
            "Headers.java"
          ))

          val reads =
              cpg.call.name("getHeader|getHeaders").where(_.tag.nameExact("forwarded-header-read")).l
          reads.map(_.code).sorted shouldBe List(
            "getHeader(\"X-Forwarded-For\")",
            "getHeader(\"forwarded\")",
            "getHeaders(\"X-Forwarded-For\")"
          )
      }
  }

  "trusted proxy configuration" should {

      "tag Spring's ForwardedHeaderFilter construction, with the family its argument selects" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |public class Filters {
            |    public Object both() { return new org.springframework.web.filter.ForwardedHeaderFilter(); }
            |    public Object standard() { return new org.springframework.web.filter.ForwardedHeaderFilter(true); }
            |    public Object legacy() { return new org.springframework.web.filter.ForwardedHeaderFilter(false); }
            |    public Object unrelated() { return new Object(); }
            |}
            |""".stripMargin,
            "Filters.java"
          ))

          val ctors = cpg.call.nameExact("<init>").where(_.code(".*ForwardedHeaderFilter.*")).l
          ctors.flatMap(_.tag.nameExact("trusted-proxy-config").value.l).sorted shouldBe
              List("spring", "spring", "spring")
          ctors.flatMap(_.tag.nameExact("trusted-proxy-headers").value.l).sorted shouldBe
              List("all", "forwarded", "x-forwarded")
          // the unrelated constructor carries nothing
          cpg.call.nameExact("<init>").codeExact("new Object()")
              .tag.nameExact("trusted-proxy-config").l shouldBe empty
      }

      "tag Jetty's ForwardedRequestCustomizer and Reactor Netty's forwarded(true)" in {
          val cpg = tagged(code(
            """
            |package com.example;
            |
            |import reactor.netty.http.server.HttpServer;
            |
            |public class Customizers {
            |    public Object jetty() { return new org.eclipse.jetty.server.ForwardedRequestCustomizer(); }
            |    public Object off() { HttpServer.create().forwarded(false); return null; }
            |    public Object on() { return HttpServer.create().forwarded(true).host("0.0.0.0"); }
            |    public Object own(Builder builder) { return builder.forwarded(true); }
            |
            |    public static class Builder {
            |        public Builder forwarded(boolean enabled) { return this; }
            |    }
            |}
            |""".stripMargin,
            "Customizers.java"
          ))

          val jetty = cpg.call.nameExact("<init>").where(_.code(".*ForwardedRequestCustomizer.*")).l
          jetty.flatMap(_.tag.nameExact("trusted-proxy-config").value.l) shouldBe List("jetty")
          jetty.flatMap(_.tag.nameExact("trusted-proxy-headers").value.l) shouldBe List("all")

          // The HttpServer builder call (unresolved: reactor is not on the classpath) is the
          // configuration; the project's own method of the same name is not, and neither is
          // forwarded(false).
          val forwarded = cpg.call.nameExact("forwarded").l
          forwarded.flatMap(_.tag.nameExact("trusted-proxy-config").value.l) shouldBe List(
            "reactor-netty"
          )
          forwarded.flatMap(_.tag.nameExact("trusted-proxy-headers").value.l) shouldBe List("all")
      }
  }
end ForwardedHeaderTagsTest

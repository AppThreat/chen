package io.appthreat.ruby2atom.parsing

import io.appthreat.ruby2atom.testfixtures.RubyCode2CpgFixture
import io.appthreat.x2cpg.passes.taggers.ChennaiTagsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** Forwarded-header tags on a Rails/Rack request: the accessors whose value a client can choose
  * through the Forwarded and X-Forwarded-* headers behind a passing proxy (`proxy-derived`), the
  * direct header reads (`forwarded-header-read`) and the trusted-proxy setting
  * (`trusted-proxy-config`). The fixture pairs live in `resources/ruby/forwarded_headers.rb`.
  */
class ForwardedHeaderTagsTests extends RubyCode2CpgFixture:

  private def tagged(fixtureNames: String*): Cpg =
    val cpg = fixture(fixtureNames*)
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def proxyDerivedValues(cpg: Cpg, code: String): List[String] =
      cpg.call.codeExact(code).tag.nameExact("proxy-derived").value.l

  "request accessors" should {

      "tag the client IP, host and scheme accessors of `request`" in {
          val cpg = tagged("forwarded_headers")

          proxyDerivedValues(cpg, "request.remote_ip") shouldBe List("client-ip")
          proxyDerivedValues(cpg, "request.ip") shouldBe List("client-ip")
          proxyDerivedValues(cpg, "request.host") shouldBe List("host")
          proxyDerivedValues(cpg, "request.host_with_port") shouldBe List("host")
          cpg.method.nameExact("show").call.nameExact("raw_host_with_port")
              .tag.nameExact("proxy-derived").value.l shouldBe List("host")
          proxyDerivedValues(cpg, "request.base_url") shouldBe List("host")
          proxyDerivedValues(cpg, "request.url") shouldBe List("host")
          proxyDerivedValues(cpg, "request.protocol") shouldBe List("scheme")
          proxyDerivedValues(cpg, "request.scheme") shouldBe List("scheme")
          proxyDerivedValues(cpg, "request.ssl?") shouldBe List("scheme")
          // the method-call form lowers to a call whose receiver resolves, through the
          // frontend's temporary, to the same `self.request`
          cpg.method.nameExact("update").call.nameExact("remote_ip")
              .tag.nameExact("proxy-derived").value.l shouldBe List("client-ip")
          cpg.method.nameExact("update").call.nameExact("host")
              .tag.nameExact("proxy-derived").value.l shouldBe List("host")
      }

      "NOT tag the same names on receivers that are not the request" in {
          val cpg = tagged("forwarded_headers")

          proxyDerivedValues(cpg, "device.ip") shouldBe empty
          proxyDerivedValues(cpg, "config.host") shouldBe empty
          proxyDerivedValues(cpg, "device.remote_ip") shouldBe empty
      }
  }

  "direct header reads" should {

      "tag `request.headers[...]` and `request.env[...]` with a literal forwarded header" in {
          val cpg = tagged("forwarded_headers")

          cpg.call.codeExact("request.headers['X-Forwarded-For']")
              .tag.nameExact("forwarded-header-read")
              .value
              .l shouldBe List("x-forwarded-for")
          cpg.call.codeExact("request.env['HTTP_X_FORWARDED_FOR']")
              .tag.nameExact("forwarded-header-read")
              .value
              .l shouldBe List("x-forwarded-for")
          cpg.method.nameExact("show").call.nameExact("get_header")
              .tag.nameExact("forwarded-header-read").value.l shouldBe List("x-real-ip")
      }
  }

  "trusted proxy configuration" should {

      "tag config.action_dispatch.trusted_proxies" in {
          val cpg = tagged("forwarded_headers")

          cpg.call.tag.nameExact("trusted-proxy-config").value.l shouldBe List("rails")
      }
  }
end ForwardedHeaderTagsTests

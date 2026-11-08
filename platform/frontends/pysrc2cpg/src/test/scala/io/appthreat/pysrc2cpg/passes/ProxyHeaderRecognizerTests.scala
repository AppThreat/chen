package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.python.PythonFrameworkRecognizersPass
import io.shiftleft.semanticcpg.language.*

/** Forwarded-header tags on Django/Flask/Werkzeug requests: the accessors whose value a client can
  * choose through the Forwarded and X-Forwarded-* headers behind a passing proxy (`proxy-derived`),
  * the direct header reads (`forwarded-header-read`), and the configuration that turns the handling
  * on (`trusted-proxy-config`). The negative cases are the twins the receiver rules require: the
  * same fields on a non-request object, a computed header key, and settings unrelated to proxies.
  */
class ProxyHeaderRecognizerTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def withRecognizers(cpg: io.shiftleft.codepropertygraph.Cpg)(
    body: => Unit
  ): Unit =
    new PythonFrameworkRecognizersPass(cpg).createAndApply()
    body

  private def proxyDerived(cpg: io.shiftleft.codepropertygraph.Cpg, code: String): List[String] =
      cpg.call.codeExact(code).tag.nameExact("proxy-derived").value.l

  "request accessors" should {

      val flaskApp = """
            |from flask import Flask, request
            |app = Flask(__name__)
            |
            |@app.route('/ip')
            |def show_ip():
            |    remote = request.remote_addr
            |    route = request.access_route
            |    fwd = request.headers.get('X-Forwarded-For')
            |    env = request.environ.get('HTTP_X_FORWARDED_FOR')
            |    return str(remote)
            |
            |@app.route('/host')
            |def show_host():
            |    host = request.host
            |    root = request.url_root
            |    scheme = request.scheme
            |    return host
            |
            |@app.route('/twins')
            |def twins(device):
            |    ip = device.remote_addr
            |    host = device.host
            |    return str(ip)
            |""".stripMargin

      "tag the Flask/Werkzeug request fields by kind" in {
          val cpg = code(flaskApp, "app.py")
          withRecognizers(cpg) {
              proxyDerived(cpg, "request.remote_addr") shouldBe List("client-ip")
              proxyDerived(cpg, "request.access_route") shouldBe List("client-ip")
              proxyDerived(cpg, "request.host") shouldBe List("host")
              proxyDerived(cpg, "request.url_root") shouldBe List("host")
              proxyDerived(cpg, "request.scheme") shouldBe List("scheme")
          }
      }

      "NOT tag the same fields on objects that are not the request" in {
          val cpg = code(flaskApp, "app.py")
          withRecognizers(cpg) {
              proxyDerived(cpg, "device.remote_addr") shouldBe empty
              proxyDerived(cpg, "device.host") shouldBe empty
          }
      }

      "tag META.get('REMOTE_ADDR') as the client ip, and only on the request" in {
          val cpg = code(
            """
            |from django.http import HttpResponse
            |
            |def view(request):
            |    ip = request.META.get('REMOTE_ADDR')
            |    return HttpResponse(ip)
            |""".stripMargin,
            "remote.py"
          )
          withRecognizers(cpg) {
              cpg.call.codeExact("tmp0.get('REMOTE_ADDR')").tag.nameExact("proxy-derived").value.l shouldBe
                  List("client-ip")
              // a plain dict's get of the same key is not the request
              // a plain mapping's get of the same key is not the request: only the one call
              // (the request's) carries the tag
              cpg.call.nameExact("get").where(_.argument.code("'REMOTE_ADDR'"))
                  .where(_.tag.nameExact("proxy-derived")).size shouldBe 1
          }
      }

      "tag Django's get_host, build_absolute_uri, is_secure and META['REMOTE_ADDR']" in {
          val cpg = code(
            """
            |from django.http import HttpResponse
            |
            |def view(request):
            |    host = request.get_host()
            |    port = request.get_port()
            |    absolute = request.build_absolute_uri()
            |    secure = request.is_secure()
            |    scheme = request.scheme
            |    ip = request.META['REMOTE_ADDR']
            |    return HttpResponse(host)
            |""".stripMargin,
            "views.py"
          )
          withRecognizers(cpg) {
              proxyDerived(cpg, "request.get_host()") shouldBe List("host")
              proxyDerived(cpg, "request.get_port()") shouldBe List("host")
              proxyDerived(cpg, "request.build_absolute_uri()") shouldBe List("host")
              proxyDerived(cpg, "request.is_secure()") shouldBe List("scheme")
              proxyDerived(cpg, "request.scheme") shouldBe List("scheme")
              proxyDerived(cpg, "request.META['REMOTE_ADDR']") shouldBe List("client-ip")
          }
      }

      "tag url_for only when _external is set" in {
          val cpg = code(
            """
            |from flask import Flask, url_for
            |app = Flask(__name__)
            |
            |@app.route('/links')
            |def links():
            |    a = url_for('index')
            |    b = url_for('index', _external=True)
            |    return a + b
            |""".stripMargin,
            "links.py"
          )
          withRecognizers(cpg) {
              val tagged = cpg.call.nameExact("url_for").where(_.tag.nameExact("proxy-derived")).l
              tagged.map(_.code) shouldBe List("url_for('index', _external = True)")
              proxyDerived(cpg, "url_for('index', _external = True)") shouldBe List("host")
          }
      }
  }

  "forwarded header reads" should {

      "tag literal reads of META, headers and environ, and only those" in {
          val cpg = code(
            """
            |from flask import Flask, request
            |app = Flask(__name__)
            |
            |@app.route('/h')
            |def headers():
            |    a = request.headers['X-Forwarded-For']
            |    b = request.headers.get('X-Forwarded-Proto')
            |    c = request.environ['HTTP_FORWARDED']
            |    d = request.META.get('HTTP_CLIENT_IP')
            |    e = request.headers[name]
            |    f = request.headers.get('Accept')
            |    return str(a)
            |""".stripMargin,
            "headers.py"
          )
          withRecognizers(cpg) {
              val reads = cpg.call.tag.nameExact("forwarded-header-read").l
              reads.map(_.value).sorted shouldBe List(
                "forwarded",
                "x-forwarded-for",
                "x-forwarded-proto",
                "client-ip"
              ).sorted
          }
      }
  }

  "trusted proxy configuration" should {

      "tag ProxyFix and Django's forwarded settings, and not unrelated settings" in {
          val cpg = code(
            """
            |from flask import Flask
            |from werkzeug.middleware.proxy_fix import ProxyFix
            |
            |app = Flask(__name__)
            |app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
            |
            |USE_X_FORWARDED_HOST = True
            |SECURE_PROXY_SSL_HEADER = ('HTTP_X_FORWARDED_PROTO', 'https')
            |DEBUG = True
            |USE_X_FORWARDED_PORT = False
            |""".stripMargin,
            "settings.py"
          )
          withRecognizers(cpg) {
              val configs = cpg.call.tag.nameExact("trusted-proxy-config").l
              configs.map(_.value).sorted shouldBe List("django", "django", "werkzeug")
              val headers = cpg.call.tag.nameExact("trusted-proxy-headers").l
              headers.map(_.value).sorted shouldBe List("x-forwarded", "x-forwarded", "x-forwarded")
          }
      }
  }
end ProxyHeaderRecognizerTests

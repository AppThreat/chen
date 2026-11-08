package io.appthreat.php2atom.passes

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language.*

/** Tests for [[PhpFrameworkTagsPass]] - the pass that turns the framework taint vocabulary declared
  * in `PhpFrameworkSemantics` into `framework-input` / `framework-output` / `sql` tags on the
  * graph.
  *
  * The pass runs as part of `Php2Atom.createCpg`, so nothing in these tests registers it: the tags
  * asserted here are exactly the tags a real run produces.
  *
  * The negative cases matter as much as the positive ones. The declared vocabulary contains bare
  * call names (`input`, `all`, `query`, `post`, `get`, `raw`, `statement`) that also name ordinary
  * collection / ORM / HTTP-client methods, so the pass gates them on a receiver heuristic.
  */
class PhpFrameworkTagsPassTests extends PhpCode2CpgFixture:

  private val FrameworkInput  = "framework-input"
  private val FrameworkOutput = "framework-output"
  private val Sql             = "sql"

  "framework sources" should {

      "tag a qualified static request accessor (Request::input)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return Request::input('name');
          |}
          |""".stripMargin)

          cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a namespace-qualified static request accessor" in {
          val cpg = code("""<?php
          |function handle() {
          |  return \App\Http\Request::input('name');
          |}
          |""".stripMargin)

          cpg.call.name("input").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a bare accessor on a request-like receiver ($request->all)" in {
          val cpg = code("""<?php
          |function handle($request) {
          |  return $request->all();
          |}
          |""".stripMargin)

          cpg.call.name("all").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "tag a bare accessor on the request() helper (request()->query)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return request()->query('page');
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkInput)).size shouldBe 1
      }

      "NOT tag the same bare accessor on a collection receiver ($collection->all)" in {
          val cpg = code("""<?php
          |function handle($collection) {
          |  return $collection->all();
          |}
          |""".stripMargin)

          cpg.call.name("all").where(_.tag.nameExact(FrameworkInput)).size shouldBe 0
      }

      "NOT tag ->get on an unrelated receiver ($cache->get)" in {
          val cpg = code("""<?php
          |function handle($cache) {
          |  return $cache->get('key');
          |}
          |""".stripMargin)

          cpg.call.name("get").where(_.tag.nameExact(FrameworkInput)).size shouldBe 0
      }

      "tag a superglobal read ($_POST)" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_POST['name'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "tag an attacker-controlled $_SERVER read ($_SERVER['HTTP_REFERER'])" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['HTTP_REFERER'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "tag $_SERVER['REQUEST_URI']" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['REQUEST_URI'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "NOT tag a non-request $_SERVER key ($_SERVER['DOCUMENT_ROOT'])" in {
          val cpg = code("""<?php
          |function handle() {
          |  return $_SERVER['DOCUMENT_ROOT'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 0
      }

      "tag a dynamically keyed $_SERVER read (conservative)" in {
          val cpg = code("""<?php
          |function handle($key) {
          |  return $_SERVER[$key];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 1
      }

      "NOT tag an ordinary array read" in {
          val cpg = code("""<?php
          |function handle($items) {
          |  return $items['first'];
          |}
          |""".stripMargin)

          cpg.call.nameExact("<operator>.indexAccess").where(
            _.tag.nameExact(FrameworkInput)
          ).size shouldBe 0
      }
  }

  "framework sinks" should {

      "tag a qualified raw query builder (DB::raw) as framework-output and sql" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  DB::raw($q);
          |}
          |""".stripMargin)

          cpg.call.name("raw").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("raw").where(_.tag.nameExact(Sql)).size shouldBe 1
      }

      "tag $wpdb->query and $wpdb->get_results" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  $wpdb->query($q);
          |  $wpdb->get_results($q);
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("get_results").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
          cpg.call.name("get_results").where(_.tag.nameExact(Sql)).size shouldBe 1
      }

      "tag echo output" in {
          val cpg = code("""<?php
          |function handle($q) {
          |  echo $q;
          |}
          |""".stripMargin)

          cpg.call.name("echo").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      }

      "tag Doctrine createQuery" in {
          val cpg = code("""<?php
          |function handle($em, $q) {
          |  $em->createQuery($q);
          |}
          |""".stripMargin)

          cpg.call.name("createQuery").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 1
      }

      "NOT tag ->query on an unrelated receiver ($collection->query)" in {
          val cpg = code("""<?php
          |function handle($collection, $q) {
          |  $collection->query($q);
          |}
          |""".stripMargin)

          cpg.call.name("query").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 0
      }

      "NOT tag ->raw on an unrelated receiver ($twig->raw)" in {
          val cpg = code("""<?php
          |function handle($twig, $q) {
          |  $twig->raw($q);
          |}
          |""".stripMargin)

          cpg.call.name("raw").where(_.tag.nameExact(FrameworkOutput)).size shouldBe 0
      }
  }

  "the pass" should {

      "leave a graph with no framework constructs untagged" in {
          val cpg = code("""<?php
          |function add($a, $b) {
          |  return $a + $b;
          |}
          |""".stripMargin)

          cpg.tag.name(FrameworkInput).size shouldBe 0
          cpg.tag.name(FrameworkOutput).size shouldBe 0
      }
  }

  // The pass runs as part of Php2Atom.createCpg, so the tags asserted here are the tags a real
  // run produces.
  private val accessors = """<?php
        |use Symfony\Component\HttpFoundation\Request;
        |
        |function ip_action(Request $request) {
        |  $ip = $request->getClientIp();
        |  $ips = $request->getClientIps();
        |  $laravelIp = $request->ip();
        |  return $ip;
        |}
        |
        |function host_action(Request $request) {
        |  $host = $request->getHost();
        |  $schemeHost = $request->getSchemeAndHttpHost();
        |  $uri = $request->getUri();
        |  $scheme = $request->getScheme();
        |  $secure = $request->isSecure();
        |  $laravelSecure = $request->secure();
        |  return $host;
        |}
        |
        |function twins($collection, $image) {
        |  $all = $collection->all();
        |  $ip = $collection->ip();
        |  $host = $image->getHost();
        |  return $all;
        |}
        |""".stripMargin

  "forwarded header tags" should {

      "tag the request's client-ip, host and scheme accessors" in {
          val cpg = code(accessors)

          def kind(callCode: String): List[String] =
              cpg.call.codeExact(callCode).tag.nameExact("proxy-derived").value.l

          kind("$request->getClientIp()") shouldBe List("client-ip")
          kind("$request->getClientIps()") shouldBe List("client-ip")
          kind("$request->ip()") shouldBe List("client-ip")
          kind("$request->getHost()") shouldBe List("host")
          kind("$request->getSchemeAndHttpHost()") shouldBe List("host")
          kind("$request->getUri()") shouldBe List("host")
          kind("$request->getScheme()") shouldBe List("scheme")
          kind("$request->isSecure()") shouldBe List("scheme")
          kind("$request->secure()") shouldBe List("scheme")
      }

      "tag Laravel's receiver-less url() helper, and not the argumented form" in {
          val cpg = code("""<?php
          |function current() {
          |  return url();
          |}
          |
          |function fixed() {
          |  return url('/assets/app.css');
          |}
          |""".stripMargin)

          cpg.call.codeExact("url()").tag.nameExact("proxy-derived").value.l shouldBe List("host")
          cpg.call.codeExact("url('/assets/app.css')").tag.nameExact("proxy-derived").size shouldBe 0
      }

      "NOT tag the same calls on receivers that are not the request" in {
          val cpg = code(accessors)

          cpg.call.codeExact("$collection->ip()").tag.nameExact("proxy-derived").size shouldBe 0
          cpg.call.codeExact("$image->getHost()").tag.nameExact("proxy-derived").size shouldBe 0
      }

      "tag header reads from the headers/server bags and the $_SERVER superglobal" in {
          val cpg = code("""<?php
          |use Symfony\Component\HttpFoundation\Request;
          |
          |function read(Request $request) {
          |  $a = $request->headers->get('X-Forwarded-For');
          |  $b = $request->server->get('HTTP_X_FORWARDED_PROTO');
          |  $c = $_SERVER['HTTP_FORWARDED'];
          |  $d = $request->headers->get('Accept');
          |  $e = $request->headers->get($name);
          |  $f = $request->header('X-Forwarded-Host');
          |  $g = $request->server('HTTP_X_REAL_IP');
          |  $h = $response->header('X-Forwarded-For');
          |  return $a;
          |}
          |""".stripMargin)

          val reads = cpg.call.tag.nameExact("forwarded-header-read").l
          reads.map(_.value).sorted shouldBe List(
            "forwarded",
            "x-forwarded-for",
            "x-forwarded-host",
            "x-forwarded-proto",
            "x-real-ip"
          )
          cpg.call.codeExact("$response->header('X-Forwarded-For')")
              .tag.nameExact("forwarded-header-read").size shouldBe 0
      }

      "tag setTrustedProxies with the flag family it names" in {
          val cpg = code("""<?php
          |use Symfony\Component\HttpFoundation\Request;
          |
          |Request::setTrustedProxies(['10.0.0.1'], Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST);
          |Request::setTrustedProxies(['10.0.0.2'], Request::HEADER_FORWARDED);
          |Request::setTrustedProxies(['10.0.0.3']);
          |""".stripMargin)

          cpg.call.name("setTrustedProxies").tag.nameExact("trusted-proxy-config").value.l shouldBe
              List("symfony", "symfony", "symfony")
          cpg.call.name("setTrustedProxies").tag.nameExact("trusted-proxy-headers").value.l.sorted shouldBe
              List("forwarded", "x-forwarded")
      }

      "tag the TrustProxies middleware's proxies and headers fields" in {
          val cpg = code("""<?php
          |namespace App\Http\Middleware;
          |
          |use Illuminate\Http\Middleware\TrustProxies as Middleware;
          |use Illuminate\Http\Request;
          |
          |class TrustProxies extends Middleware
          |{
          |    protected $proxies = '*';
          |    protected $headers = Request::HEADER_X_FORWARDED_FOR | Request::HEADER_X_FORWARDED_HOST;
          |}
          |""".stripMargin)

          val configs = cpg.call.tag.nameExact("trusted-proxy-config").l
          configs.map(_.value).sorted shouldBe List("laravel", "laravel")
          cpg.call.tag.nameExact("trusted-proxy-headers").value.l shouldBe List("x-forwarded")
      }

      "tag Laravel 11's trustProxies() middleware configuration" in {
          val cpg = code("""<?php
          |use Illuminate\Foundation\Configuration\Middleware;
          |use Illuminate\Http\Request;
          |
          |function configure(Middleware $middleware) {
          |  $middleware->trustProxies(at: '*', headers: Request::HEADER_FORWARDED);
          |}
          |""".stripMargin)

          cpg.call.nameExact("trustProxies").tag.nameExact("trusted-proxy-config").value.l shouldBe
              List("laravel")
          cpg.call.nameExact("trustProxies").tag.nameExact("trusted-proxy-headers").value.l shouldBe
              List("forwarded")
      }
  }
end PhpFrameworkTagsPassTests

package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** Forwarded-header tags on the Node server frameworks: the request accessors whose value a client
  * can choose through the X-Forwarded-* headers behind a trusted proxy (`proxy-derived`), the
  * direct header reads (`forwarded-header-read`), and the configuration that turns the handling on
  * (`trusted-proxy-config`, `trusted-proxy-headers`). Fixtures follow Express, Koa and Fastify
  * shapes; the negative cases are the twins the receiver rules require (`device.ip`,
  * `map.get('X-Forwarded-For')`, `user.proxy = true`).
  */
class ProxyHeaderRecognizerTest extends DataFlowCodeToCpgSuite:
  given io.shiftleft.semanticcpg.language.NoResolve.type =
      io.shiftleft.semanticcpg.language.NoResolve

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def proxyDerived(cpg: Cpg, code: String): List[String] =
      cpg.call.codeExact(code).tag.nameExact("proxy-derived").value.l

  "Express request accessors" should {

      val express = """
        |const express = require('express');
        |const app = express();
        |
        |app.get('/ip', (req, res) => {
        |  const ip = req.ip;
        |  const ips = req.ips;
        |  const host = req.hostname;
        |  const proto = req.protocol;
        |  const secure = req.secure;
        |  res.send(ip + ips + host + proto + secure);
        |});
        |
        |app.get('/twins', (req, res) => {
        |  const device = { ip: '10.0.0.1' };
        |  const ctx = { host: 'internal' };
        |  const map = new Map();
        |  const xf = map.get('X-Forwarded-For');
        |  res.send(device.ip + ctx.host + xf);
        |});
        |""".stripMargin

      "tag req.ip/ips/hostname/protocol/secure by kind" in {
          val cpg = tagged(code(express, "server.js"))

          proxyDerived(cpg, "req.ip") shouldBe List("client-ip")
          proxyDerived(cpg, "req.ips") shouldBe List("client-ip")
          proxyDerived(cpg, "req.hostname") shouldBe List("host")
          proxyDerived(cpg, "req.protocol") shouldBe List("scheme")
          proxyDerived(cpg, "req.secure") shouldBe List("scheme")
      }

      "NOT tag the same reads on objects that are not the request" in {
          val cpg = tagged(code(express, "server.js"))

          proxyDerived(cpg, "device.ip") shouldBe empty
          proxyDerived(cpg, "ctx.host") shouldBe empty
      }

      "NOT tag a request-named parameter in a file that imports no server framework" in {
          // `req` here is whatever this client-side file passes around, not a framework request.
          val client = """
            |export function render(req) {
            |  return req.ip + req.protocol;
            |}
            |""".stripMargin
          val cpg = tagged(code(express, "server.js").moreCode(client, "client.js"))

          cpg.call.codeExact("req.ip").where(_.file.name(".*client.js"))
              .tag.nameExact("proxy-derived").l shouldBe empty
          cpg.call.codeExact("req.protocol").where(_.file.name(".*client.js"))
              .tag.nameExact("proxy-derived").l shouldBe empty
      }
  }

  "Koa and Fastify accessors" should {

      "tag ctx.host and ctx.protocol on the Koa context" in {
          val cpg = tagged(code(
            """
            |const Koa = require('koa');
            |const app = new Koa();
            |app.use(async ctx => {
            |  ctx.body = ctx.ip + ctx.host + ctx.protocol;
            |});
            |""".stripMargin,
            "koa.js"
          ))

          proxyDerived(cpg, "ctx.ip") shouldBe List("client-ip")
          proxyDerived(cpg, "ctx.host") shouldBe List("host")
          proxyDerived(cpg, "ctx.protocol") shouldBe List("scheme")
      }
  }

  "forwarded header reads" should {

      "tag req.get and req.headers[...] with a literal forwarded name, and only then" in {
          val cpg = tagged(code(
            """
            |const express = require('express');
            |const app = express();
            |app.get('/h', (req, res) => {
            |  const fwd = req.get('x-forwarded-for');
            |  const hdr = req.headers['x-forwarded-for'];
            |  const proto = req.headers['x-forwarded-proto'];
            |  const ua = req.get('user-agent');
            |  const dyn = req.headers[name];
            |  const map = new Map();
            |  const xf = map.get('X-Forwarded-For');
            |  res.send(fwd + hdr + proto + ua + dyn + xf);
            |});
            |""".stripMargin,
            "headers.js"
          ))

          val reads = cpg.call.where(_.tag.nameExact("forwarded-header-read")).l
          reads.map(c =>
              c.code + " => " + c.tag.nameExact("forwarded-header-read").value.head
          ).sorted shouldBe List(
            "req.get('x-forwarded-for') => x-forwarded-for",
            "req.headers[\"x-forwarded-for\"] => x-forwarded-for",
            "req.headers[\"x-forwarded-proto\"] => x-forwarded-proto"
          ).sorted
      }
  }

  "trusted proxy configuration" should {

      "tag Express's trust proxy setting, and not other settings" in {
          val cpg = tagged(code(
            """
            |const express = require('express');
            |const app = express();
            |app.set('trust proxy', 1);
            |app.set('view engine', 'pug');
            |app.set('trust proxy', false);
            |app.enable('trust proxy');
            |""".stripMargin,
            "config.js"
          ))

          val configs = cpg.call.where(_.tag.nameExact("trusted-proxy-config")).l
          configs.map(c =>
              c.tag.nameExact("trusted-proxy-config").value.head
          ).sorted shouldBe List("express", "express")
          configs.map(_.code).sorted shouldBe List(
            "app.enable('trust proxy')",
            "app.set('trust proxy', 1)"
          )
      }

      "tag Koa's app.proxy = true, and not the same field elsewhere" in {
          val cpg = tagged(code(
            """
            |const Koa = require('koa');
            |const app = new Koa();
            |app.proxy = true;
            |const user = { proxy: false };
            |user.proxy = true;
            |app.proxy = false;
            |""".stripMargin,
            "koa-config.js"
          ))

          val configs = cpg.call.where(_.tag.nameExact("trusted-proxy-config")).l
          configs.map(c => c.tag.nameExact("trusted-proxy-config").value.head) shouldBe List("koa")
          configs.map(_.code) shouldBe List("app.proxy = true")
      }

      "tag Fastify's trustProxy factory option with the X-Forwarded family" in {
          val cpg = tagged(code(
            """
            |const fastify = require('fastify');
            |const app = fastify({ trustProxy: true });
            |const other = fastify({ logger: true });
            |const off = fastify({ trustProxy: false });
            |""".stripMargin,
            "fastify.js"
          ))

          val configs = cpg.call.where(_.tag.nameExact("trusted-proxy-config")).l
          configs.map(c => c.tag.nameExact("trusted-proxy-config").value.head) shouldBe List(
            "fastify"
          )
          val headers = cpg.call.where(_.tag.nameExact("trusted-proxy-headers")).l
          headers.map(c => c.tag.nameExact("trusted-proxy-headers").value.head) shouldBe List(
            "x-forwarded"
          )
      }
  }
end ProxyHeaderRecognizerTest

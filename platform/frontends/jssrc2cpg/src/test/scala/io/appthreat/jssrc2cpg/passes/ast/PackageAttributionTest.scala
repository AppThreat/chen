package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** The npm-package attribution of a tagged sink: the resolved-callee-name fallback, member-read
  * sinks attributed through their base, and the purl taken from the project's SBOM.
  */
class PackageAttributionTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  /** Gives the fixture's `send` calls the resolved name a typed astgen run gives them. The untyped
    * frontend the suite builds with writes the source text there instead.
    */
  private def resolvedAsExpressResponse(cpg: Cpg): Unit =
    val diff = new DiffGraphBuilder
    cpg.call.nameExact("send").l.foreach(c =>
        diff.setNodeProperty(c, PropertyNames.METHOD_FULL_NAME, "express:Response:send")
    )
    overflowdb.BatchedUpdate.applyDiff(cpg.graph, diff)

  private def purlsOf(cpg: Cpg): Seq[(String, String)] =
      cpg.tag.name("pkg:npm/.*").l.flatMap { t =>
          t._taggedByIn.collectFirst {
              case n: io.shiftleft.codepropertygraph.generated.nodes.Call =>
                  n.name -> t.name
          }
      }.sorted

  /** A cdxgen-shaped SBOM with these component purls. */
  private def bom(purls: String*): String =
      purls.map(p => s"""{ "type": "library", "purl": "$p" }""")
          .mkString("""{ "bomFormat": "CycloneDX", "components": [""", ", ", "] }")

  /** The fixture chain starts fresh per test: the harness forbids adding code once the graph was
    * read.
    */
  private def expressServer =
      code(
        """
      |import express from 'express';
      |const app = express();
      |app.get('/x', (req, res) => { res.send(req.query.q); });
      |export default app;
      |""".stripMargin,
        "server.ts"
      )

  "PackageAttribution" should {

      "attribute a sink call from its resolved callee name when no binding, type or handle does" in {
          // `res` is a plain parameter: no import binding, no injected type, no handle. Typed
          // astgen runs resolve the callee to `express:Response:send` - retarget the name the
          // way they do, and the module prefix names the package.
          val cpg0 = expressServer.moreCode(bom("pkg:npm/express@4.17.1"), "bom.json")
          resolvedAsExpressResponse(cpg0)
          val cpg = tagged(cpg0)
          purlsOf(cpg) shouldBe Seq("send" -> "pkg:npm/express@4.17.1")
      }

      "attribute a member read made a sink through its base, like a call receiver" in {
          // juice-shop's `finale.resource(...)` handles: the sink is the member READ
          // `resource.create.send`, the package is behind the local the base chain is made from.
          val cpg = tagged(code(
            """
          |import * as finale from 'finale-rest';
          |import { WalletModel } from './models/wallet';
          |export function init(server: any) {
          |  const resource = finale.resource(server, { model: WalletModel, endpoints: ['/x'] });
          |  resource.create.send.before((req, res, context) => {
          |    WalletModel.create({ UserId: context.instance.id });
          |    return context.continue;
          |  });
          |}
          |""".stripMargin,
            "server.ts"
          ).moreCode(bom("pkg:npm/finale-rest@1.3.0"), "bom.json"))
          val purls = cpg.tag.name("pkg:npm/.*").l.flatMap { t =>
              t._taggedByIn.collectFirst {
                  case c: io.shiftleft.codepropertygraph.generated.nodes.Call =>
                      c.code.take(30) -> t.name
              }
          }.sorted
          purls shouldBe Seq(
            "resource.create"      -> "pkg:npm/finale-rest@1.3.0",
            "resource.create.send" -> "pkg:npm/finale-rest@1.3.0"
          )
      }

      "carry no purl without an SBOM, whatever the manifests and lockfiles say" in {
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.0" } }""",
            "package.json"
          ).moreCode(
            """{ "lockfileVersion": 3, "packages": { "": {}, "node_modules/express": { "version": "4.18.2" } } }""",
            "package-lock.json"
          )
          resolvedAsExpressResponse(cpg0)
          purlsOf(tagged(cpg0)) shouldBe Nil
      }

      "carry the purl of every version the SBOM has of the package, as cdxgen attributes usages" in {
          val cpg0 = expressServer.moreCode(
            bom(
              "pkg:npm/express@4.16.4",
              "pkg:npm/express@4.18.2",
              "pkg:npm/%40types/express@4.17.21"
            ),
            "bom.json"
          )
          resolvedAsExpressResponse(cpg0)
          purlsOf(tagged(cpg0)) shouldBe Seq(
            "send" -> "pkg:npm/express@4.16.4",
            "send" -> "pkg:npm/express@4.18.2"
          )
      }

      "read a scoped package's purl from a nested component, exactly as the SBOM writes it" in {
          val cpg = tagged(code(
            """
          |import { Component, inject } from '@angular/core';
          |import { ActivatedRoute } from '@angular/router';
          |import { DomSanitizer } from '@angular/platform-browser';
          |@Component({ selector: 'app-p', template: '' })
          |export class PComponent {
          |  private route = inject(ActivatedRoute);
          |  private sanitizer = inject(DomSanitizer);
          |  load() { this.html = this.sanitizer.bypassSecurityTrustHtml(this.route.snapshot.queryParams.q); }
          |}
          |""".stripMargin,
            "p.component.ts"
          ).moreCode(
            """{ "bomFormat": "CycloneDX", "components": [ { "purl": "pkg:npm/%40angular/core@20.3.0",
              |  "components": [ { "purl": "pkg:npm/%40angular/platform-browser@20.3.0?arch=any" } ] } ] }"""
                .stripMargin,
            "bom.json"
          ))
          purlsOf(cpg) shouldBe Seq(
            "bypassSecurityTrustHtml" -> "pkg:npm/%40angular/platform-browser@20.3.0?arch=any"
          )
      }

      "tag a built-in with its name and kind, not a purl, even when the SBOM has its namesake" in {
          // `fs` on npm is a placeholder package; Node resolves the specifier to the built-in
          val cpg = tagged(code(
            """
          |import { writeFile } from 'fs';
          |export function save(p: string, data: string) { writeFile(p, data, () => {}); }
          |""".stripMargin,
            "io.ts"
          ).moreCode(bom("pkg:npm/fs@0.0.1-security"), "bom.json"))
          cpg.call.nameExact("writeFile").map(c => c.tag.name.l.sorted).l shouldBe
              List(List("file-io", "node:fs"))
      }

      "tag a built-in http request with what it reaches, the source untouched" in {
          val cpg = tagged(code(
            """
          |import express from 'express';
          |import https from 'node:https';
          |const app = express();
          |app.get('/p', (req, res) => { https.get(req.query.url); res.send('ok'); });
          |""".stripMargin,
            "proxy.ts"
          ).moreCode(bom("pkg:npm/express@4.21.2"), "bom.json"))
          val sinkTags = cpg.tag.name("node:https").l.flatMap(_._taggedByIn).flatMap {
              case n: io.shiftleft.codepropertygraph.generated.nodes.StoredNode =>
                  n._taggedByOut.collect {
                      case t: io.shiftleft.codepropertygraph.generated.nodes.Tag => t.name
                  }
          }.distinct.sorted
          (sinkTags should contain).allOf("node:https", "http", "web", "network", "ssl")
          sinkTags should not contain "framework"
          sinkTags.filter(_.startsWith("pkg:")) shouldBe empty
      }
  }
end PackageAttributionTest

package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** The npm-package attribution of a tagged sink: the resolved-callee-name fallback, member-read
  * sinks attributed through their base, and versions from the yarn/pnpm lockfiles.
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
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.1" } }""",
            "package.json"
          ).moreCode(
            """# yarn lockfile v1
                |
                |express@^4.17.1:
                |  version "4.17.1"
                |""".stripMargin,
            "yarn.lock"
          )
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
          ).moreCode(
            """{ "name": "s", "dependencies": { "finale-rest": "^1.2.2" } }""",
            "package.json"
          ).moreCode(
            """# yarn lockfile v1
                |
                |finale-rest@^1.2.2:
                |  version "1.3.0"
                |""".stripMargin,
            "yarn.lock"
          ))
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

      "read the version the pnpm lockfile resolved, not the one the range names" in {
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.0" } }""",
            "package.json"
          ).moreCode(
            """lockfileVersion: '9.0'
                |
                |importers:
                |
                |  .:
                |    dependencies:
                |      express:
                |        specifier: ^4.17.0
                |        version: 4.18.2
                |
                |packages:
                |  express@4.18.2:
                |    resolution: {integrity: sha512-...}
                |""".stripMargin,
            "pnpm-lock.yaml"
          )
          resolvedAsExpressResponse(cpg0)
          val cpg = tagged(cpg0)
          purlsOf(cpg) shouldBe Seq("send" -> "pkg:npm/express@4.18.2")
      }

      "carry no version when the lockfile resolves a name to more than one version" in {
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.0" } }""",
            "package.json"
          ).moreCode(
            """{ "name": "other", "dependencies": { "express": "^4.16.0" } }""",
            "apps/other/package.json"
          ).moreCode(
            """lockfileVersion: '9.0'
                |
                |importers:
                |
                |  .:
                |    dependencies:
                |      express:
                |        specifier: ^4.17.0
                |        version: 4.18.2
                |
                |  apps/other:
                |    dependencies:
                |      express:
                |        specifier: ^4.16.0
                |        version: 4.16.4
                |""".stripMargin,
            "pnpm-lock.yaml"
          )
          resolvedAsExpressResponse(cpg0)
          val cpg = tagged(cpg0)
          purlsOf(cpg) shouldBe Seq("send" -> "pkg:npm/express")
      }

      "take the version that served the manifest's range, not a transitive copy's" in {
          // one block serves both declared ranges; another package pulled in express 3
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.1" } }""",
            "package.json"
          ).moreCode(
            """{ "name": "t", "dependencies": { "express": "^4.17.0" } }""",
            "tools/package.json"
          ).moreCode(
            """# yarn lockfile v1
                |
                |express@^3.0.0:
                |  version "3.21.2"
                |
                |express@^4.17.0, express@^4.17.1:
                |  version "4.17.1"
                |""".stripMargin,
            "yarn.lock"
          )
          resolvedAsExpressResponse(cpg0)
          val cpg = tagged(cpg0)
          purlsOf(cpg) shouldBe Seq("send" -> "pkg:npm/express@4.17.1")
      }

      "read a v2 npm lockfile, which names every version twice" in {
          val cpg0 = expressServer.moreCode(
            """{ "name": "s", "dependencies": { "express": "^4.17.0" } }""",
            "package.json"
          ).moreCode(
            """{
                |  "lockfileVersion": 2,
                |  "packages": { "": { "name": "s" }, "node_modules/express": { "version": "4.18.2" } },
                |  "dependencies": { "express": { "version": "4.18.2" } }
                |}""".stripMargin,
            "package-lock.json"
          )
          resolvedAsExpressResponse(cpg0)
          val cpg = tagged(cpg0)
          purlsOf(cpg) shouldBe Seq("send" -> "pkg:npm/express@4.18.2")
      }

      "leave a built-in the resolved name carries unattributed" in {
          val cpg = tagged(code(
            """
          |import { writeFile } from 'node:fs/promises';
          |export function save(p: string, data: string) { writeFile(p, data); }
          |""".stripMargin,
            "io.ts"
          ).moreCode(
            """{ "name": "s", "dependencies": { "typescript": "^5.0.0" } }""",
            "package.json"
          ))
          cpg.call.nameExact("writeFile").map(c => c.tag.name.l).l shouldBe List(List("file-io"))
      }
  }
end PackageAttributionTest

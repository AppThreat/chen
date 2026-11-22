package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.{ChennaiTagsPass, EasyTagsPass}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, PropertyNames}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, NewTag}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** The sinks on calls project code makes into npm packages: calls bound to an import or to a handle
  * made from one, members a project class inherits from a package class, and the calls that stay no
  * sink of this step (built-ins, the project's own code, sinks already tagged).
  */
class DependencyBoundaryTest extends DataFlowCodeToCpgSuite:

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new ChennaiTagsPass(cpg).createAndApply()
    cpg

  private def tagsOf(cpg: Cpg, name: String): List[List[String]] =
      cpg.call.nameExact(name).map(_.tag.name.l.sorted).l

  private def bom(purls: String*): String =
      purls.map(p => s"""{ "type": "library", "purl": "$p" }""")
          .mkString("""{ "bomFormat": "CycloneDX", "components": [""", ", ", "] }")

  /** Gives each call named `name` the full name a typed astgen run gives a member the class
    * inherits (`<class's full name>:<member>`); the untyped frontend the suite builds with writes
    * the source text there.
    */
  private def resolvedOnClass(cpg: Cpg, className: String, name: String, via: String = ""): Unit =
    val owner = if via.nonEmpty then via else cpg.typeDecl.nameExact(className).fullName.head
    val diff  = new DiffGraphBuilder
    cpg.call.nameExact(name).l.foreach(c =>
        diff.setNodeProperty(c, PropertyNames.METHOD_FULL_NAME, s"$owner:$name")
    )
    overflowdb.BatchedUpdate.applyDiff(cpg.graph, diff)

  private val sequelizeModel =
      """
      |import { Model } from 'sequelize';
      |export class ChallengeModel extends Model {
      |  static seed() {}
      |}
      |export async function load(items: any[]) {
      |  await ChallengeModel.bulkCreate(items);
      |  const challenge = new ChallengeModel();
      |  await challenge.save();
      |}
      |""".stripMargin

  "DependencyBoundary" should {

      "tag a member a project class inherits from a package class, with the SBOM's purl" in {
          val cpg0 = code(sequelizeModel, "models.ts").moreCode(
            bom("pkg:npm/sequelize@6.37.3"),
            "bom.json"
          )
          resolvedOnClass(cpg0, "ChallengeModel", "bulkCreate")
          resolvedOnClass(cpg0, "ChallengeModel", "save")
          val cpg = tagged(cpg0)
          tagsOf(cpg, "bulkCreate") shouldBe List(List("library-call", "pkg:npm/sequelize@6.37.3"))
          tagsOf(cpg, "save") shouldBe List(List("library-call", "pkg:npm/sequelize@6.37.3"))
      }

      "tag an inherited member named through the import of the class" in {
          val cpg0 = code(
            """
            |import { Model } from 'sequelize';
            |export class OrderModel extends Model {}
            |""".stripMargin,
            "models/order.ts"
          ).moreCode(
            """
            |import { OrderModel } from './models/order';
            |export function count() { return OrderModel.count(); }
            |""".stripMargin,
            "app.ts"
          )
          resolvedOnClass(cpg0, "OrderModel", "count", via = "models/order:OrderModel")
          tagsOf(tagged(cpg0), "count") shouldBe List(List("library-call"))
      }

      "tag a member inherited through a project ancestor" in {
          val cpg0 = code(
            """
            |import { Model } from 'sequelize';
            |class Base extends Model {}
            |class UserModel extends Base {}
            |export async function load() { await UserModel.findAll(); }
            |""".stripMargin,
            "models.ts"
          )
          resolvedOnClass(cpg0, "UserModel", "findAll")
          tagsOf(tagged(cpg0), "findAll") shouldBe List(List("library-call"))
      }

      "leave a member the project class declares itself untagged" in {
          val cpg0 = code(
            """
            |import { Model } from 'sequelize';
            |export class ChallengeModel extends Model {
            |  async save() { return 1; }
            |}
            |export async function load() {
            |  const challenge = new ChallengeModel();
            |  await challenge.save();
            |}
            |""".stripMargin,
            "models.ts"
          )
          resolvedOnClass(cpg0, "ChallengeModel", "save")
          tagsOf(tagged(cpg0), "save") shouldBe List(Nil)
      }

      "leave a member of a class with no package ancestor untagged" in {
          val cpg0 = code(
            """
            |class Plain {}
            |export function load() { return Plain.bulkCreate(); }
            |""".stripMargin,
            "plain.ts"
          )
          resolvedOnClass(cpg0, "Plain", "bulkCreate")
          tagsOf(tagged(cpg0), "bulkCreate") shouldBe List(Nil)
      }

      "tag a call on a module bound with require, an unresolved callee" in {
          val cpg = tagged(code(
            """
            |const helper = require('lodash');
            |function run(x) { return helper.load(x); }
            |""".stripMargin,
            "run.js"
          ).moreCode(bom("pkg:npm/lodash@4.17.21"), "bom.json"))
          tagsOf(cpg, "load") shouldBe List(List("library-call", "pkg:npm/lodash@4.17.21"))
      }

      "tag a call on a module bound with an import" in {
          val cpg = tagged(code(
            """
            |import helper from 'lodash';
            |export function run(x: any) { return helper.load(x); }
            |""".stripMargin,
            "run.ts"
          ))
          tagsOf(cpg, "load") shouldBe List(List("library-call"))
      }

      "tag a call on a handle made from a package" in {
          val cpg = tagged(code(
            """
            |import pg from 'pg';
            |const pool = new pg.Pool();
            |export function open() { return pool.connect(); }
            |""".stripMargin,
            "db.ts"
          ).moreCode(bom("pkg:npm/pg@8.11.3"), "bom.json"))
          tagsOf(cpg, "connect") shouldBe List(List("library-call", "pkg:npm/pg@8.11.3"))
      }

      "tag a call into a known request client as http-client" in {
          val cpg = tagged(code(
            """
            |import axios from 'axios';
            |export function fetchIt(u: string) { return axios.get(u); }
            |""".stripMargin,
            "client.ts"
          ).moreCode(bom("pkg:npm/axios@1.7.2"), "bom.json"))
          val tags = tagsOf(cpg, "get").flatten
          tags should contain("http-client")
          tags should not contain "library-call"
          tags should contain("pkg:npm/axios@1.7.2")
      }

      "not tag a call into a Node built-in" in {
          val cpg = tagged(code(
            """
            |import * as fs from 'fs';
            |import { inspect } from 'node:util';
            |export function read(p: string) { inspect(p); return fs.readFileSync(p); }
            |""".stripMargin,
            "io.ts"
          ))
          cpg.call.nameExact("readFileSync", "inspect").flatMap(_.tag.name.l).toSet should
              not contain "library-call"
      }

      "not tag a call into a function the project declares" in {
          val cpg0 = code(
            """
            |import _ from 'lodash';
            |function merge(a: any, b: any) { return a; }
            |export function run(a: any, b: any) { return _.merge(a, b); }
            |""".stripMargin,
            "workspace.ts"
          )
          val diff = new DiffGraphBuilder
          diff.addEdge(
            cpg0.call.nameExact("merge").head,
            cpg0.method.nameExact("merge").head,
            EdgeTypes.CALL
          )
          overflowdb.BatchedUpdate.applyDiff(cpg0.graph, diff)
          tagsOf(tagged(cpg0), "merge") shouldBe List(Nil)
      }

      "keep only the tag of a call that is a sink already" in {
          // EasyTagsPass makes a pg handle's `query` a SQL sink
          val cpg = tagged(code(
            """
            |import pg from 'pg';
            |const pool = new pg.Pool();
            |export function find(q: string) { return pool.query(q); }
            |""".stripMargin,
            "db.ts"
          ))
          tagsOf(cpg, "query") shouldBe List(List("sql"))
      }

      "not tag a call into a package that a recognizer made a framework input" in {
          val cpg = tagged(code(
            """
            |import { getCookie } from 'h3';
            |export default defineEventHandler((event) => {
            |  const session = getCookie(event, 'session');
            |  return session;
            |});
            |""".stripMargin,
            "session.ts"
          ))
          val tags = tagsOf(cpg, "getCookie").flatten
          tags should contain("framework-input")
          tags should not contain "library-call"
      }
  }
end DependencyBoundaryTest

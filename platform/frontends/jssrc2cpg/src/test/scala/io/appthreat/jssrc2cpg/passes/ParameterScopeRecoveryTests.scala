package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** A parameter is the variable of its method: another method's variable of the same name is not it.
  */
class ParameterScopeRecoveryTests extends DataFlowCodeToCpgSuite:

  "a variable named like the parameter of another method" should {
      val cpg = code(
        """
        |import { Node } from "prosemirror-model";
        |import { JSDOM } from "jsdom";
        |export class Helper {
        |  static toJson(doc: Node) { return doc.toJSON(); }
        |  static render(html: string) {
        |    const doc = new JSDOM(html);
        |    return doc.serialize();
        |  }
        |  static again(doc: Node) { return doc.eq(doc); }
        |}
        |""".stripMargin,
        "helper.ts"
      )

      "keep the call on the variable with its own type" in {
          cpg.call.nameExact("serialize").methodFullName.l shouldBe List("jsdom:JSDOM:serialize")
      }

      "keep the calls on each parameter with its own type" in {
          cpg.call.nameExact("toJSON").methodFullName.l shouldBe List(
            "prosemirror-model:Node:toJSON"
          )
          cpg.call.nameExact("eq").methodFullName.l shouldBe List("prosemirror-model:Node:eq")
      }

      "not add the type of the parameter to the variable" in {
          val doc = cpg.method.nameExact("render").ast.isIdentifier.nameExact("doc").l
          doc should not be empty
          doc.flatMap(i => i.typeFullName +: i.dynamicTypeHintFullName).distinct
              .filter(_.contains("prosemirror")) shouldBe Nil
      }
  }
end ParameterScopeRecoveryTests

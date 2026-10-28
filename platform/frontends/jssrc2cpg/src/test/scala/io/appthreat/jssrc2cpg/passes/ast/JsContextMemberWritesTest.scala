package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.js.{JsContext, JsModules, JsTagger}
import overflowdb.BatchedUpdate.DiffGraphBuilder

class JsContextMemberWritesTest extends DataFlowCodeToCpgSuite:

  "JsContext.memberWrites" should {

      "be computed once and handed to every caller" in {
          val cpg = code(
            """
          |export class Card {
          |  title = 'x';
          |  count = 0;
          |  refresh() { this.count = 1; }
          |}
          |""".stripMargin,
            "card.ts"
          )
          val ctx = JsContext(cpg, JsModules(cpg), JsTagger(new DiffGraphBuilder))

          ctx.memberWrites.map(w => (w._1.name, w._2)).toSet shouldBe
              Set(("Card", "title"), ("Card", "count"))
          (ctx.memberWrites should be).theSameInstanceAs(ctx.memberWrites)
      }

      "leave out what a static initialiser, a static method and a function nested in one write" in {
          val cpg = code(
            """
          |export class Cache {
          |  static seed = 1;
          |  size = 0;
          |  static reset() {
          |    this.entries = 0;
          |    const clear = () => { this.nested = 0; };
          |    clear();
          |  }
          |  grow() { this.size = 1; }
          |}
          |""".stripMargin,
            "cache.ts"
          )
          val ctx = JsContext(cpg, JsModules(cpg), JsTagger(new DiffGraphBuilder))

          ctx.memberWrites.map(w => (w._1.name, w._2)).toSet shouldBe Set(("Cache", "size"))
      }
  }
end JsContextMemberWritesTest

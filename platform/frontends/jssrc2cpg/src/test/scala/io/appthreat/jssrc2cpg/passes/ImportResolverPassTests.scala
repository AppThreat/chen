package io.appthreat.jssrc2cpg.passes

import io.appthreat.jssrc2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

class ImportResolverPassTests extends DataFlowCodeToCpgSuite:

  "a require of an expression with a quote in it" should {
      "keep its import and the rest of the file in the graph" in {
          val cpg = code(
            """
          |const a = "lo";
          |const b = "dash";
          |let m;
          |m = require(a + "-" + b);
          |function used(v) { return v; }
          |""".stripMargin
          )

          cpg.imports.importedEntity.l shouldBe List("""a + "-" + b""")
          cpg.method.nameExact("used").size shouldBe 1
      }
  }

  "a local import with a query in its specifier" should {
      "keep the ESM import and the rest of the file in the graph" in {
          val cpg = code(
            """
          |import url from "./logo.svg?url";
          |function used(v) { return v; }
          |used(url);
          |""".stripMargin
          )

          cpg.imports.importedEntity.l shouldBe List("./logo.svg?url:url")
          cpg.method.nameExact("used").size shouldBe 1
      }

      "keep the require's imports and the rest of the file in the graph" in {
          val cpg = code(
            """
          |const url = require("./logo.svg?url");
          |function used(v) { return v; }
          |used(url);
          |""".stripMargin
          )

          cpg.imports.importedEntity.l shouldBe List("./logo.svg?url", "./logo.svg?url")
          cpg.method.nameExact("used").size shouldBe 1
      }
  }
end ImportResolverPassTests

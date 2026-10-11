package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.testfixtures.JsSrc2CpgSuite
import io.shiftleft.semanticcpg.language.*

/** astgen's offsets count a UTF-8 byte-order mark as the file's first character: the code of every
  * node is read at those offsets.
  */
class ByteOrderMarkTests extends JsSrc2CpgSuite:

  "a file with a byte-order mark" should {
      val cpg = code(
        "﻿// héllo wörld\nvar x = \"café\";\nfoo(x);\nfunction foo(a) { return a; }\n",
        "bom.js"
      )

      "keep the code of its nodes" in {
          cpg.call.nameExact("foo").code.l shouldBe List("foo(x)")
          cpg.literal.code.l should contain("\"café\"")
          cpg.method.nameExact("foo").code.l shouldBe List("function foo(a) { return a; }")
          cpg.method.nameExact(":program").code.l.forall(!_.startsWith("﻿")) shouldBe true
      }
  }

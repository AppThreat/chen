package io.appthreat.php2atom.querying

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.{Identifier, Literal}

class ScalarTests extends PhpCode2CpgFixture {
  "int scalars should be represented correctly" in {
    val cpg = code("<?php\n2;")

    inside(cpg.literal.l) { case List(intLiteral) =>
      intLiteral.code shouldBe "2"
      intLiteral.typeFullName shouldBe "int"
      intLiteral.lineNumber shouldBe Some(2)
    }
  }

  "float scalars should be represented correctly" in {
    val cpg = code("<?php\n2.1;")

    inside(cpg.literal.l) { case List(floatLiteral) =>
      floatLiteral.code shouldBe "2.1"
      floatLiteral.typeFullName shouldBe "float"
      floatLiteral.lineNumber shouldBe Some(2)
    }
  }

  "string scalars should be represented correctly" in {
    val cpg = code("<?php\n\"hello\";")

    inside(cpg.literal.l) { case List(stringLiteral) =>
      stringLiteral.code shouldBe "\"hello\""
      stringLiteral.typeFullName shouldBe "string"
      stringLiteral.lineNumber shouldBe Some(2)
    }
  }

  "encapsed string scalars should be represented correctly" in {
    val cpg = code("<?php\n\"hello${x}$y world\";")

    inside(cpg.call.l) { case List(encapsed) =>
      encapsed.name shouldBe "encaps"
      encapsed.typeFullName shouldBe "string"
      encapsed.code shouldBe "\"hello\" . $x . $y . \" world\""
      encapsed.lineNumber shouldBe Some(2)

      inside(encapsed.astChildren.l) { case List(hello: Literal, x: Identifier, y: Identifier, world: Literal) =>
        hello.code shouldBe "\"hello\""
        hello.typeFullName shouldBe "string"
        hello.lineNumber shouldBe Some(2)

        world.code shouldBe "\" world\""
        world.typeFullName shouldBe "string"
        world.lineNumber shouldBe Some(2)

        x.name shouldBe "x"
        x.lineNumber shouldBe Some(2)

        y.name shouldBe "y"
        y.lineNumber shouldBe Some(2)
      }
    }
  }

  "booleans should be represented as literals" in {
    val cpg = code("<?php\ntrue; false;")

    inside(cpg.literal.l) { case List(trueBool, falseBool) =>
      trueBool.code shouldBe "true"
      trueBool.lineNumber shouldBe Some(2)
      trueBool.typeFullName shouldBe "bool"

      falseBool.code shouldBe "false"
      falseBool.lineNumber shouldBe Some(2)
      falseBool.typeFullName shouldBe "bool"
    }
  }
  "null should be represented as a literal" in {
    val cpg = code("<?php\nNULL;")

    inside(cpg.literal.l) { case List(nullLiteral) =>
      nullLiteral.code shouldBe "NULL"
      nullLiteral.lineNumber shouldBe Some(2)
      nullLiteral.typeFullName shouldBe "null"
    }
  }
}

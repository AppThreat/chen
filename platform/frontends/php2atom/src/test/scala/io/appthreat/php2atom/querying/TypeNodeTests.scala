package io.appthreat.php2atom.querying

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.appthreat.x2cpg.Defines
import io.shiftleft.codepropertygraph.generated.{ModifierTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Identifier, Literal, Local, Member, Method}
import io.shiftleft.semanticcpg.language._
import io.shiftleft.codepropertygraph.generated.nodes.Block

class TypeNodeTests extends PhpCode2CpgFixture {
    "TypeDecls with inheritsFrom types" should {
        val cpg = code(
            """<?php
              |namespace foo;
              |class A extends B implements C, D {}
              |""".stripMargin)

        "have type nodes created for the TypeDecl and inherited types" in {
            cpg.typ.fullName.toSet shouldEqual Set("ANY", "foo\\A", "foo\\B", "foo\\C", "foo\\D")
        }

        "have TypeDecl stubs created for inherited types" in {
            cpg.typeDecl.external.fullName.toSet shouldEqual Set("ANY", "foo\\B", "foo\\C", "foo\\D")
        }
    }
}

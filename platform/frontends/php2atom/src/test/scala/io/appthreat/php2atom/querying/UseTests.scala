package io.appthreat.php2atom.querying

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language._

class UseTests extends PhpCode2CpgFixture {

  "normal use statements without aliases should be represented correctly" in {
    val cpg = code("<?php\nuse A\\B;")

    inside(cpg.imports.l) { case List(importStmt) =>
      importStmt.code shouldBe "use A\\B"
      importStmt.importedEntity should contain("A\\B")
      importStmt.importedAs.isEmpty shouldBe true
    }
  }

  "normal use statements including multiple namespaces should be enclosed in a block" in {
    val cpg = code("<?php\nuse A, B;")

    inside(cpg.imports.l.sortBy(_.code)) { case List(aImport, bImport) =>
      aImport.code shouldBe "use A"
      aImport.importedEntity should contain("A")
      aImport.importedAs.isEmpty shouldBe true

      bImport.code shouldBe "use B"
      bImport.importedEntity should contain("B")
      bImport.importedAs.isEmpty shouldBe true
    }
  }

  "use statements with aliases should be correctly represented" in {
    val cpg = code("<?php\nuse A\\B as C;")

    inside(cpg.imports.l) { case List(importStmt) =>
      importStmt.code shouldBe "use A\\B as C"
      importStmt.importedEntity should contain("A\\B")
      importStmt.importedAs should contain("C")
    }
  }

  "function uses should have the correct code field" in {
    val cpg = code("<?php\nuse function foo\\bar;")

    inside(cpg.imports.l) { case List(importStmt) =>
      importStmt.code shouldBe "use function foo\\bar"
      importStmt.importedEntity should contain("foo\\bar")
      importStmt.importedAs.isEmpty shouldBe true
    }
  }

  "const uses should have the correct code field" in {
    val cpg = code("<?php\nuse const foo\\BAR;")

    inside(cpg.imports.l) { case List(importStmt) =>
      importStmt.code shouldBe "use const foo\\BAR"
      importStmt.importedEntity should contain("foo\\BAR")
      importStmt.importedAs.isEmpty shouldBe true
    }
  }

  "group uses should have the correct names for all elements in the group" in {
    val cpg = code("<?php\nuse A\\{B\\C, D}")

    inside(cpg.imports.l.sortBy(_.code)) { case List(aImport, bImport) =>
      aImport.code shouldBe "use A\\B\\C"
      aImport.importedEntity should contain("A\\B\\C")
      aImport.importedAs.isEmpty shouldBe true

      bImport.code shouldBe "use A\\D"
      bImport.importedEntity should contain("A\\D")
      bImport.importedAs.isEmpty shouldBe true
    }
  }
}

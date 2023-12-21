package io.appthreat.php2atom.querying

import io.appthreat.php2atom.testfixtures.PhpCode2CpgFixture
import io.shiftleft.semanticcpg.language._

class CommentTests extends PhpCode2CpgFixture {

  "parsing a file containing a Nop-wrapped comment should not result in a crash" in {
    val cpg = code("""<?php
        |// This should not cause a crash
        |foo()
        |// And neither should this
        |""".stripMargin)

    cpg.call.name("foo").isEmpty shouldBe false
  }
}

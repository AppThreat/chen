package io.appthreat.macros

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import QueryMacros.withStrRep
import io.appthreat.console.*
import io.shiftleft.semanticcpg.language.*

class QueryMacroTests extends AnyWordSpec with Matchers {
  "Query macros" should {
    "have correct string representation" in {
      withStrRep(cpg => cpg.method).strRep shouldBe "cpg => cpg.method"
    }
  }

}

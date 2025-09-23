package io.appthreat.console

import io.appthreat.console.workspacehandling.Project
import io.appthreat.console.workspacehandling.Project
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class HelpTests extends AnyWordSpec with Matchers {

  "Help" should {
    "provide overview of commands as table" in {
      Help.overview(classOf[Console[Project]]).contains("CPG") shouldBe true
    }
  }

}

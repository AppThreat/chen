package io.appthreat.x2cpg.utils

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.{Failure, Success}

class ExternalCommandTest extends AnyWordSpec with Matchers {
  "ExternalCommand.run" should {
    "be able to run `date` successfully" taggedAs IgnoreInWindows in {
      File.usingTemporaryDirectory("sample") { sourceDir =>
        val cmd = "date"
        ExternalCommand.run(cmd, sourceDir.pathAsString) should be a Symbol("success")
      }
    }
  }

}

package io.appthreat.x2cpg.utils

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.{Failure, Success}

class ExternalCommandTest extends AnyWordSpec with Matchers {
  "ExternalCommand.run" should {
    "be able to run `date` successfully" in {
      File.usingTemporaryDirectory("sample") { sourceDir =>
        val cmd = "date"
        ExternalCommand.run(cmd, sourceDir.pathAsString) should be a Symbol("success")
      }
    }
  }

  "ExternalCommand.runMultiple" should {
    "be able to run multiple `date` invocations successfully" in {
      File.usingTemporaryDirectory("sample") { sourceDir =>
        File.usingTemporaryFile(parent = Some(sourceDir)) { _ =>
          val cmd    = "date && date"
          val result = ExternalCommand.runMultiple(cmd, sourceDir.pathAsString)
          result match {
            case Success(value) => value.split("\n").length shouldBe 2
            case Failure(_)     => false shouldBe true
          }
        }
      }
    }
  }
}

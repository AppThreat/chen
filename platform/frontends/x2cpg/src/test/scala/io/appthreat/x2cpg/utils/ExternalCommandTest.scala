package io.appthreat.x2cpg.utils

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import scala.util.{Failure, Success}

class ExternalCommandTest extends AnyWordSpec with Matchers:
  "ExternalCommand.run" should {
      "be able to run `date` successfully" taggedAs IgnoreInWindows in {
          File.usingTemporaryDirectory("sample") { sourceDir =>
            val cmd = "date"
            (ExternalCommand.run(cmd, sourceDir.pathAsString) should be).a(Symbol("success"))
          }
      }
  }

  "ExternalCommand.runWithResult" should {
      "stop a command and the processes it started when the timeout expires" taggedAs IgnoreInWindows in {
          File.usingTemporaryDirectory("timeout") { dir =>
            val result = ExternalCommand.runWithResult(
              Seq("sh", "-c", "sleep 30 & echo $!; wait"),
              dir.pathAsString,
              timeoutMillis = 1000
            )
            result.timedOut shouldBe true
            result.toTry.isFailure shouldBe true
            val childPid = result.stdOut.head.trim.toLong
            val deadline = System.currentTimeMillis() + 5000
            while ProcessHandle.of(childPid).isPresent && System.currentTimeMillis() < deadline do
              Thread.sleep(50)
            ProcessHandle.of(childPid).isPresent shouldBe false
          }
      }
  }
end ExternalCommandTest

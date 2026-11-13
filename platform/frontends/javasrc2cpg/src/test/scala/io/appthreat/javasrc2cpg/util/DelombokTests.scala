package io.appthreat.javasrc2cpg.util

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class DelombokTests extends AnyWordSpec with Matchers:

  "the delombok command" should {
      "keep each path one argument, whatever characters it holds" in {
          File.usingTemporaryDirectory("delombok $(touch marker); x") { out =>
              Delombok.delombokToTempDirCommand(out, Some("/opt/jdk/bin/java")).foreach {
                  (java, args) =>
                    java shouldBe "/opt/jdk/bin/java"
                    args.take(1) shouldBe Seq("-cp")
                    args.drop(2) shouldBe Seq(
                      "lombok.launch.Main",
                      "delombok",
                      ".",
                      "-d",
                      out.canonicalPath
                    )
              }
          }
      }
  }
end DelombokTests

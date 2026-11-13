package io.appthreat.x2cpg.utils.dependency

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths

class MavenDependenciesTests extends AnyWordSpec with Matchers:

  /** A stand-in `mvn` that prints a class path the way the dependency plugin does, and leaves a
    * marker file next to itself when it runs.
    */
  private def fakeMvn(dir: File): File =
    val script = dir / "mvn"
    script.writeText(
      """#!/bin/sh
        |touch "$(dirname "$0")/ran"
        |echo "[INFO] Dependencies classpath:"
        |echo "/repo/a.jar:/repo/b.jar"
        |""".stripMargin
    )
    script.toJava.setExecutable(true)
    script

  "the class path from maven" should {
      "come from the mvn in an absolute PATH directory" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("tools") { tools =>
              File.usingTemporaryDirectory("project") { project =>
                fakeMvn(tools)
                MavenDependencies.get(project.path, project.path, tools.pathAsString) shouldBe
                    Some(List("/repo/a.jar", "/repo/b.jar"))
                (tools / "ran").exists shouldBe true
              }
          }
      }

      "never run an mvn the project ships" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("project") { project =>
            val module = (project / "module").createDirectories()
            fakeMvn(module)
            fakeMvn(project)
            val relative = Paths.get("").toAbsolutePath.relativize(module.path).toString
            Seq(relative, ".", module.pathAsString, project.pathAsString).foreach { path =>
                MavenDependencies.get(module.path, project.path, path) shouldBe Some(Nil)
            }
            (module / "ran").exists shouldBe false
            (project / "ran").exists shouldBe false
          }
      }
  }
end MavenDependenciesTests

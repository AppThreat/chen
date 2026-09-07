package io.appthreat.pysrc2cpg

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Task 12 A.1 - the silent empty atom is a bug in its own right. Before archive extraction
  * existed, `atom -l python -o out.atom dir/` on a directory holding only archives (or nothing at
  * all) exited 0 and wrote a ~12 KB meta-only atom with no diagnostic: indistinguishable from a
  * successful analysis of a project with no code. The frontend must fail loudly instead.
  */
class Py2CpgEmptyInputTests extends AnyWordSpec with Matchers:

  private def createCpgFor(dir: File): Option[String] =
    val out = File.newTemporaryFile("empty-input-", ".odb")
    try
      val result = new Py2CpgOnFileSystem().createCpg(
        Py2CpgOnFileSystemConfig()
            .withInputPath(dir.pathAsString)
            .withOutputPath(out.pathAsString)
      )
      result.toOption.map(_ => "succeeded")
    finally out.delete(swallowIOExceptions = true)

  "Py2CpgOnFileSystem.createCpg on an input with no Python source" should {

      "fail loudly for an empty directory" in {
          File.usingTemporaryDirectory("chen-empty-input-") { dir =>
              createCpgFor(dir) shouldBe empty
          }
      }

      "fail loudly for a directory whose only files are not Python" in {
          File.usingTemporaryDirectory("chen-empty-input-") { dir =>
            (dir / "README.txt").write("not python")
            (dir / "flask-3.0.3-py3-none-any.whl").write("a wheel is not analysed until extraction")
            createCpgFor(dir) shouldBe empty
          }
      }

      "still succeed when at least one .py file survives the filters" in {
          File.usingTemporaryDirectory("chen-empty-input-") { dir =>
            (dir / "README.txt").write("not python")
            (dir / "app.py").write("x = 1\n")
            createCpgFor(dir) shouldBe Some("succeeded")
          }
      }

      "still succeed for a requirements.txt-only input (ConfigFileCreationPass consumes it)" in {
          File.usingTemporaryDirectory("chen-empty-input-") { dir =>
            (dir / "requirements.txt").write("flask==3.0.3\n")
            createCpgFor(dir) shouldBe Some("succeeded")
          }
      }
  }
end Py2CpgEmptyInputTests

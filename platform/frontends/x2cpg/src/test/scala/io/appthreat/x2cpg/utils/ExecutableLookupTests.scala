package io.appthreat.x2cpg.utils

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.io.File.pathSeparator
import java.nio.file.{Files, Paths}

class ExecutableLookupTests extends AnyWordSpec with Matchers:

  private def tool(dir: File, name: String): File =
    val file = dir / name
    file.writeText("#!/bin/sh\necho tool\n")
    file.toJava.setExecutable(true)
    file

  private def withDirs(test: (File, File) => Unit): Unit =
      File.usingTemporaryDirectory("tools") { tools =>
          File.usingTemporaryDirectory("project") { project => test(tools, project) }
      }

  "a tool on the PATH" should {
      "be found by its absolute path in an absolute PATH directory" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, project) =>
            tool(tools, "mvn")
            ExecutableLookup.find("mvn", Seq(project.path), tools.pathAsString) shouldBe
                Some(tools.path.normalize.resolve("mvn"))
            ExecutableLookup.find("gradle", Seq(project.path), tools.pathAsString) shouldBe None
          }
      }

      "not be looked up in a relative PATH entry" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, _) =>
            tool(tools, "mvn")
            val relative = Paths.get("").toAbsolutePath.relativize(tools.path).toString
            ExecutableLookup.find("mvn", Nil, relative) shouldBe None
            ExecutableLookup.find("mvn", Nil, s".$pathSeparator$relative") shouldBe None
          }
      }

      "never be found in the scan root, even when the PATH lists it" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, project) =>
            tool((project / "bin").createDirectories(), "mvn")
            tool(tools, "mvn")
            val inProject = (project / "bin").pathAsString
            ExecutableLookup.find("mvn", Seq(project.path), inProject) shouldBe None
            ExecutableLookup.find(
              "mvn",
              Seq(project.path),
              s"$inProject$pathSeparator${tools.pathAsString}"
            ) shouldBe Some(tools.path.normalize.resolve("mvn"))
          }
      }

      "never be found through a link into the scan root" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, project) =>
            val inside = tool(project, "mvn")
            Files.createSymbolicLink(tools.path.resolve("mvn"), inside.path)
            ExecutableLookup.find("mvn", Seq(project.path), tools.pathAsString) shouldBe None
          }
      }

      "not be named with a directory part" in {
          withDirs { (tools, _) =>
            ExecutableLookup.find("./mvn", Nil, tools.pathAsString) shouldBe None
            ExecutableLookup.find("bin/mvn", Nil, tools.pathAsString) shouldBe None
            ExecutableLookup.find("bin\\mvn", Nil, tools.pathAsString) shouldBe None
            ExecutableLookup.find("..", Nil, tools.pathAsString) shouldBe None
          }
      }
  }

  "a tool on Windows" should {
      "be found by its .exe, .cmd or .bat name, never the bare one" in {
          withDirs { (tools, project) =>
            tool(tools, "mvn")
            ExecutableLookup.find(
              "mvn",
              Seq(project.path),
              tools.pathAsString,
              windows = true
            ) shouldBe
                None
            tool(tools, "mvn.cmd")
            val found =
                ExecutableLookup.find("mvn", Seq(project.path), tools.pathAsString, windows = true)
            found shouldBe Some(tools.path.normalize.resolve("mvn.cmd"))
            tool(tools, "mvn.exe")
            ExecutableLookup.find(
              "mvn",
              Seq(project.path),
              tools.pathAsString,
              windows = true
            ) shouldBe
                Some(tools.path.normalize.resolve("mvn.exe"))
          }
      }

      "be started through cmd by its absolute path only when it is a batch file" in {
          val dir = Paths.get("").toAbsolutePath
          ExecutableLookup.commandLine(dir.resolve("mvn.cmd"), Seq("-B"), windows = true) shouldBe
              Seq("cmd", "/d", "/c", "call", dir.resolve("mvn.cmd").toString, "-B")
          ExecutableLookup.commandLine(dir.resolve("gradle.BAT"), Nil, windows = true) shouldBe
              Seq("cmd", "/d", "/c", "call", dir.resolve("gradle.BAT").toString)
          ExecutableLookup.commandLine(dir.resolve("gcc.exe"), Seq("-v"), windows = true) shouldBe
              Seq(dir.resolve("gcc.exe").toString, "-v")
          ExecutableLookup.commandLine(dir.resolve("mvn.cmd"), Nil, windows = false) shouldBe
              Seq(dir.resolve("mvn.cmd").toString)
          ExecutableLookup.environment(windows = true) shouldBe
              Map("NoDefaultCurrentDirectoryInExePath" -> "1")
          ExecutableLookup.environment(windows = false) shouldBe empty
      }
  }
  "a command" should {
      "not start a batch file with an argument cmd would interpret" in {
          withDirs { (tools, project) =>
            tool(tools, "astgen.cmd")
            val path = tools.pathAsString
            ExecutableLookup.command(
              "astgen",
              Seq("-o", "out dir"),
              Seq(project.path),
              path,
              true
            ) shouldBe
                Right(Seq(
                  "cmd",
                  "/d",
                  "/c",
                  "call",
                  tools.path.resolve("astgen.cmd").toString,
                  "-o",
                  "out dir"
                ))
            Seq("a&b", "a|b", "a>b", "a<b", "a^b", "%PATH%", "!x!", "a\"b", "a\nb").foreach { arg =>
                ExecutableLookup.command("astgen", Seq("-o", arg), Seq(project.path), path, true)
                    .isLeft shouldBe true
            }
            // the same arguments are no concern without cmd
            tool(tools, "astgen.exe")
            ExecutableLookup.command("astgen", Seq("a&b"), Seq(project.path), path, true) shouldBe
                Right(Seq(tools.path.resolve("astgen.exe").toString, "a&b"))
          }
      }

      "take a program path as written, outside the scan root" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, project) =>
            val outside = tool(tools, "rbastgen")
            val inside  = tool(project, "rbastgen")
            ExecutableLookup.command(
              outside.pathAsString,
              Seq("-i", "x"),
              Seq(project.path),
              ""
            ) shouldBe
                Right(Seq(outside.pathAsString, "-i", "x"))
            ExecutableLookup.command(inside.pathAsString, Nil, Seq(project.path), "").isLeft shouldBe
                true
            ExecutableLookup.command("rbastgen", Nil, Seq(project.path), project.pathAsString)
                .isLeft shouldBe true
            ExecutableLookup.command("missing-tool", Nil, Nil, tools.pathAsString).isLeft shouldBe
                true
          }
      }
  }

  "a program started without a shell" should {
      "receive every argument as it is" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("tools") { tools =>
              File.usingTemporaryDirectory("work $(touch marker1)") { work =>
                val echo = tools / "printargs"
                echo.writeText("#!/bin/sh\nfor a in \"$@\"; do printf '%s\\n' \"$a\"; done\n")
                echo.toJava.setExecutable(true)
                val args = Seq(
                  "x';touch marker2;'",
                  "$(touch marker3)",
                  "`touch marker4`",
                  "a; touch marker5",
                  "a && touch marker6",
                  "*",
                  "with space"
                )
                ExternalCommand.runProgram(echo.pathAsString, args, work.pathAsString).get shouldBe
                    args
                work.list.map(_.name).toSeq shouldBe empty
                (1 to 6).foreach(i => (tools / s"marker$i").exists shouldBe false)
              }
          }
      }

      "fail without running anything when it is not found" in {
          ExternalCommand.runProgram("no-such-tool-anywhere", Nil, ".").isFailure shouldBe true
      }
  }
end ExecutableLookupTests

package io.appthreat.edg2atom.parser

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.ProjectSources
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class EdgaRunnerTests extends AnyWordSpec with Matchers:

  "a standard" should {
      "map to the front end's mode" in {
          EdgaRunner.cStandardOption("gnu99") shouldBe "--c99"
          EdgaRunner.cStandardOption("c11") shouldBe "--c11"
          EdgaRunner.cStandardOption("iso9899:1990") shouldBe "--c89"
          EdgaRunner.cStandardOption("c2x") shouldBe "--c23"
          EdgaRunner.cStandardOption(null) shouldBe "--c17"
          EdgaRunner.cppStandardOption("gnu++2a") shouldBe "--c++20"
          EdgaRunner.cppStandardOption("c++14") shouldBe "--c++14"
          EdgaRunner.cppStandardOption("c++latest") shouldBe "--c++23"
          EdgaRunner.cppStandardOption("") shouldBe "--c++17"
      }
  }

  "the compiler's macros" should {
      "say which compiler the front end emulates" in {
          EdgaRunner.dialectOptions(
            Map("__clang_major__" -> "17", "__clang_minor__" -> "0", "__GNUC__" -> "4"),
            cpp = true
          ) shouldBe Seq("--clang", "--clang_version=170000")
          EdgaRunner.dialectOptions(
            Map("__GNUC__" -> "13", "__GNUC_MINOR__" -> "2", "__GNUC_PATCHLEVEL__" -> "0"),
            cpp = false
          ) shouldBe Seq("--gcc", "--gnu_version=130200")
          EdgaRunner.dialectOptions(Map("_MSC_VER" -> "1938"), cpp = true) shouldBe Seq(
            "--microsoft",
            "--microsoft_version=1938"
          )
      }
  }

  "a compilation database" should {
      "give a unit its own standard, defines and include directories" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("edga-runner") { dir =>
            (dir / "inc").createDirectory()
            (dir / "inc" / "util.h").writeText("int util(void);\n")
            (dir / "a.c").writeText("#include \"util.h\"\nint a(void) { return util(); }\n")
            (dir / "b.cpp").writeText("int b() { return 0; }\n")
            (dir / "compile_commands.json").writeText(
              s"""[
               |  { "directory": "${dir.pathAsString}", "file": "a.c",
               |    "arguments": ["cc", "-std=gnu99", "-DFEATURE=2", "-Iinc", "-c", "a.c"] },
               |  { "directory": "${dir.pathAsString}", "file": "b.cpp",
               |    "arguments": ["c++", "-std=gnu++20", "-c", "b.cpp"] }
               |]""".stripMargin
            )
            val config = Config().withInputPath(dir.pathAsString)
                .withCompileCommands((dir / "compile_commands.json").pathAsString)
            val runner = new EdgaRunner(config, new ProjectSources(config))
            val c      = runner.arguments((dir / "a.c").path)
            c should contain("--c99")
            c.sliding(2).toSeq should contain(Seq("--define_macro", "FEATURE=2"))
            c.sliding(2).toSeq should contain(Seq(
              "-I",
              (dir / "inc").path.toAbsolutePath.normalize.toString
            ))
            runner.arguments((dir / "b.cpp").path) should contain("--c++20")
          }
      }
  }
end EdgaRunnerTests

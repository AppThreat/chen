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
      "keep the GNU dialect unless the unit asks for the ISO one" in {
          val gcc = Seq("--gcc", "--gnu_version=140200")
          EdgaRunner.strictnessOptions(None, gcc) shouldBe Seq("--no_strict_gnu")
          EdgaRunner.strictnessOptions(Some("gnu99"), gcc) shouldBe Seq("--no_strict_gnu")
          EdgaRunner.strictnessOptions(Some("c11"), gcc) shouldBe Seq("--strict_gnu")
          EdgaRunner.strictnessOptions(Some("iso9899:1999"), gcc) shouldBe Seq("--strict_gnu")
          EdgaRunner.strictnessOptions(Some("gnu++20"), Seq("--g++")) shouldBe Seq(
            "--no_strict_gnu"
          )
          EdgaRunner.strictnessOptions(Some("c++17"), Seq("--clang")) shouldBe Seq("--strict_gnu")
          EdgaRunner.strictnessOptions(Some("c++17"), Seq("--microsoft")) shouldBe empty
          EdgaRunner.strictnessOptions(None, Seq.empty) shouldBe empty
      }
      "spell C23's va_start with the builtin the front end has" in {
          EdgaRunner.c23VaStartShim(Seq("--c23")).sliding(2, 2).map(_.head).toSeq shouldBe Seq(
            "--define_macro",
            "--define_macro"
          )
          EdgaRunner.c23VaStartShim(Seq("--c17")) shouldBe empty
          EdgaRunner.c23VaStartShim(Seq("--c++23", "--type_traits_helpers")) shouldBe empty
      }
      "leave the MSVC keywords to the front end" in {
          EdgaRunner.isKeywordShim("__asm", "__attribute((asm))") shouldBe true
          EdgaRunner.isKeywordShim("__m128", "__attribute((m128))") shouldBe true
          EdgaRunner.isKeywordShim("__asm", "__asm__") shouldBe false
          EdgaRunner.isKeywordShim("FEATURE", "2") shouldBe false
      }
  }

  "a unit of the GNU dialect" should {
      "see the POSIX declarations the C library hides from ISO C" in {
          val edga = EdgaRunner.locate()
          assume(edga.isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edga-gnu") { dir =>
            (dir / "p.c").writeText(
              """#include <math.h>
                |#include <stdio.h>
                |#include <string.h>
                |#ifdef __STRICT_ANSI__
                |#error ISO dialect
                |#endif
                |char *copy(const char *s) { return strdup(s); }
                |FILE *run(const char *cmd) { return popen(cmd, "r"); }
                |double tau(void) { return 2 * M_PI; }
                |""".stripMargin
            )
            val config  = Config().withInputPath(dir.pathAsString)
            val runner  = new EdgaRunner(config, new ProjectSources(config))
            val dialect = runner.arguments((dir / "p.c").path).toSet
            assume(dialect("--gcc") || dialect("--clang"), "no GCC or Clang on this host")
            val unit = runner.exportUnit((dir / "p.c").path, 60)
            withClue(unit.toSeq.flatMap(_.diagnostics).map(ujson.write(_)).mkString("\n")) {
                unit.map(_.status) shouldBe Some("ok")
            }
            unit.toSeq.flatMap(_.routines).filter(r =>
                Set("strdup", "popen").contains(r("name").str)
            ).map(r => r("name").str -> r.obj.get("prototyped").exists(_.bool)).toMap shouldBe Map(
              "strdup" -> true,
              "popen"  -> true
            )
          }
      }
      "take va_start in C23 as a va_start" in {
          val edga = EdgaRunner.locate()
          assume(edga.isDefined, "edga is not installed")
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("edga-c23") { dir =>
            (dir / "v.c").writeText(
              """#include <stdarg.h>
                |int sum(int n, ...) {
                |  va_list ap;
                |  va_start(ap, n);
                |  int s = va_arg(ap, int);
                |  va_end(ap);
                |  return n + s;
                |}
                |""".stripMargin
            )
            // c2x: GCC 13 (ubuntu-24.04's) does not know -std=c23 yet
            (dir / "compile_commands.json").writeText(
              s"""[{ "directory": "${dir.pathAsString}", "file": "v.c",
                 |   "arguments": ["cc", "-std=c2x", "-c", "v.c"] }]""".stripMargin
            )
            val config = Config().withInputPath(dir.pathAsString)
                .withCompileCommands((dir / "compile_commands.json").pathAsString)
            val unit = new EdgaRunner(config, new ProjectSources(config))
                .exportUnit((dir / "v.c").path, 60)
            unit.map(_.status) shouldBe Some("ok")
            val body = unit.toSeq.flatMap(_.routines).find(_("name").str == "sum")
                .flatMap(_.obj.get("body")).map(ujson.write(_)).getOrElse("")
            body should include("\"op\":\"va_start\"")
            (body should not).include("__builtin_c23_va_start")
          }
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

  "a front end built without float128" should {
      val aarch64 = "edga 0.1.0\nEDG commit abc\nconfiguration linux-aarch64 0123"
      val x86     = "edga 0.1.0\nEDG commit abc\nconfiguration linux-x86_64 0123"
      val x86Musl = "edga 0.1.0\nEDG commit abc\nconfiguration linux-x86_64-musl 0123"
      val gcc14   = Map("__GNUC__" -> "14")
      "name `long double` `_Float128` where glibc takes it as the compiler's type" in {
          val shim = Seq("--define_macro", "_Float128=long double")
          EdgaRunner.float128Shim(aarch64, gcc14, cpp = false) shouldBe shim
          EdgaRunner.float128Shim(aarch64, gcc14, cpp = true) shouldBe shim
          EdgaRunner.float128Shim(aarch64, Map("__GNUC__" -> "12"), cpp = false) shouldBe shim
          EdgaRunner.float128Shim(x86Musl, gcc14, cpp = false) shouldBe shim
      }
      "leave it to glibc's typedef, and to a front end with float128" in {
          EdgaRunner.float128Shim(aarch64, Map("__GNUC__" -> "12"), cpp = true) shouldBe empty
          EdgaRunner.float128Shim(aarch64, Map("__GNUC__" -> "6"), cpp = false) shouldBe empty
          EdgaRunner.float128Shim(aarch64, gcc14 + ("__clang__" -> "1"), cpp = false) shouldBe empty
          EdgaRunner.float128Shim(x86, gcc14, cpp = false) shouldBe empty
      }
      "let glibc's headers compile" in {
          val edga = EdgaRunner.locate()
          assume(edga.isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edga-float128") { dir =>
            (dir / "f.c").writeText(
              "#include <stdlib.h>\n_Float128 widest(void) { return 1.0L; }\n"
            )
            val config = Config().withInputPath(dir.pathAsString)
            val runner = new EdgaRunner(config, new ProjectSources(config))
            assume(runner.identity.contains("linux-aarch64"), "edga is not built for aarch64 Linux")
            runner.exportUnit((dir / "f.c").path, 60).map(_.status) shouldBe Some("ok")
          }
      }
  }

  "the host's C++ library" should {
      "lose the vectorised algorithms libc++ keeps out when optimising for size" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edga-libcxx") { dir =>
            (dir / "v.cpp").writeText(
              "#include <vector>\nint n(const std::vector<int> &v) { return (int)v.size(); }\n"
            )
            val config = Config().withInputPath(dir.pathAsString)
            val runner = new EdgaRunner(config, new ProjectSources(config))
            val args   = runner.arguments((dir / "v.cpp").path)
            val libcxx =
                args.sliding(2).exists(w => w.head == "--sys_include" && w(1).endsWith("c++/v1"))
            assume(libcxx, "the host's C++ library is not libc++")
            args.sliding(2).toSeq should contain(Seq("--define_macro", "__OPTIMIZE_SIZE__"))
          }
      }
      "keep the NEON macros out, whose intrinsics the front end does not declare" in {
          assume(EdgaRunner.locate().isDefined, "edga is not installed")
          File.usingTemporaryDirectory("edga-neon") { dir =>
            (dir / "n.c").writeText("int n(void) { return 0; }\n")
            val config = Config().withInputPath(dir.pathAsString)
            val runner = new EdgaRunner(config, new ProjectSources(config))
            val args   = runner.arguments((dir / "n.c").path)
            val macros = args.sliding(2).collectFirst { case Seq("--preinclude_macros", f) =>
                File(f)
            }
            assume(macros.exists(_.exists), "no compiler macros on this host")
            (macros.get.contentAsString should not).include("__ARM_NEON ")
          }
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
            if c.contains("--gcc") || c.contains("--clang") then c should contain("--no_strict_gnu")
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

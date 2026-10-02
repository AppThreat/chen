package io.appthreat.c2cpg.parser

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths

class CompileCommandTests extends AnyWordSpec with Matchers:

  private val dir = Paths.get("/work/proj/build")

  "a POSIX command string" should {
      "split on whitespace and keep quoted spaces and escapes" in {
          CompileCommand.tokenize(
            """/usr/bin/g++ -DNAME="a b" -D'QUOTED=x y' -I"/opt/my include" -DESC=\"v\" -c src/a.cpp"""
          ) shouldBe Seq(
            "/usr/bin/g++",
            "-DNAME=a b",
            "-DQUOTED=x y",
            "-I/opt/my include",
            "-DESC=\"v\"",
            "-c",
            "src/a.cpp"
          )
      }
  }

  "an MSVC command string" should {
      "follow the Windows quoting rules" in {
          CompileCommand.tokenize(
            """cl.exe /nologo /I"C:\Program Files\sdk\include" /DWIN32 /D"MSG=\"hi\"" /c a.cpp"""
          ) shouldBe Seq(
            "cl.exe",
            "/nologo",
            "/IC:\\Program Files\\sdk\\include",
            "/DWIN32",
            "/DMSG=\"hi\"",
            "/c",
            "a.cpp"
          )
      }

      "read include paths, macros, forced includes and the language" in {
          val flags = CompileCommand.parseArguments(
            Seq(
              "cl.exe",
              "/Iinc",
              "/I",
              "other",
              "/DA=1",
              "/UB",
              "/FIpch.h",
              "/std:c++20",
              "/TP",
              "a.c"
            ),
            dir
          )
          flags.family shouldBe CompilerFamily.Msvc
          flags.includePaths shouldBe Seq(dir.resolve("inc"), dir.resolve("other"))
          flags.macros shouldBe Seq(MacroChange.Define("A", "1"), MacroChange.Undefine("B"))
          flags.includeFiles shouldBe Seq(dir.resolve("pch.h"))
          flags.standard shouldBe Some("c++20")
          flags.language shouldBe Some(SourceLanguage.Cpp)
      }
  }

  "GCC-style arguments" should {
      "read every option that shapes preprocessing, joined or separate" in {
          val flags = CompileCommand.parseArguments(
            Seq(
              "ccache",
              "/usr/bin/clang",
              "-Iinc",
              "-I",
              "../third_party",
              "-iquote",
              "q",
              "-isystem",
              "/sys",
              "-idirafter",
              "after",
              "-DUSE_X",
              "-D",
              "LEVEL=2",
              "-UOLD",
              "-include",
              "config.h",
              "-imacros",
              "macros.h",
              "-std=gnu11",
              "-x",
              "c++",
              "--target=aarch64-linux-gnu",
              "--sysroot",
              "/sysroot",
              "-m64",
              "-O2",
              "-fPIC",
              "-Wall",
              "-MD",
              "-MF",
              "a.d",
              "-o",
              "a.o",
              "-c",
              "a.c"
            ),
            dir
          )
          flags.compiler shouldBe Some("/usr/bin/clang")
          flags.family shouldBe CompilerFamily.Clang
          flags.includePaths shouldBe Seq(
            dir.resolve("q"),
            dir.resolve("inc"),
            Paths.get("/work/proj/third_party")
          )
          flags.systemIncludePaths shouldBe Seq(Paths.get("/sys"), dir.resolve("after"))
          flags.macros shouldBe Seq(
            MacroChange.Define("USE_X", "1"),
            MacroChange.Define("LEVEL", "2"),
            MacroChange.Undefine("OLD")
          )
          flags.includeFiles shouldBe Seq(dir.resolve("config.h"))
          flags.macroFiles shouldBe Seq(dir.resolve("macros.h"))
          flags.standard shouldBe Some("gnu11")
          flags.language shouldBe Some(SourceLanguage.Cpp)
          flags.targetOptions shouldBe Seq(
            "-std=gnu11",
            "--target=aarch64-linux-gnu",
            "--sysroot=/sysroot",
            "-m64",
            "-O2",
            "-fPIC"
          )
      }

      "take a C++ driver's files for C++" in {
          CompileCommand.parseArguments(Seq("/usr/bin/g++-13", "-c", "a.c"), dir).language shouldBe
              Some(SourceLanguage.Cpp)
          CompileCommand.parseArguments(Seq("/usr/bin/gcc", "-c", "a.c"), dir).language shouldBe None
      }

      "treat --driver-mode=cl as MSVC" in {
          val flags =
              CompileCommand.parseArguments(Seq("clang", "--driver-mode=cl", "/Iinc", "a.cpp"), dir)
          flags.family shouldBe CompilerFamily.Msvc
          flags.includePaths shouldBe Seq(dir.resolve("inc"))
      }
  }
end CompileCommandTests

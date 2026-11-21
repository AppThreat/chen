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

      "read the doubled backslash of an escaped one as the escape it is" in {
          CompileCommand.tokenize("""cc -DX=a\\b -c a.c""") shouldBe Seq(
            "cc",
            "-DX=a\\b",
            "-c",
            "a.c"
          )
      }
  }

  "a Windows compile database command string" should {
      "keep the backslashes of its paths under a gcc-family driver, quoted or not" in {
          // the shape of a database recorded on Windows: a backslash separates the segments of
          // every path, and no shell ate one, so the POSIX reading loses it and the option's
          // value with it (-IC:\lib read as -IC:lib)
          CompileCommand.tokenize(
            """cc -c -IC:\Users\appthreat\work\390\clirun\externlib -I"C:\Program Files\lib" main.c"""
          ) shouldBe Seq(
            "cc",
            "-c",
            "-IC:\\Users\\appthreat\\work\\390\\clirun\\externlib",
            "-IC:\\Program Files\\lib",
            "main.c"
          )
      }

      "keep the escaped quote of a value in double quotes" in {
          CompileCommand.tokenize("""cc -DX="\"a b\"" -IC:\lib -c a.c""") shouldBe Seq(
            "cc",
            "-DX=\"a b\"",
            "-IC:\\lib",
            "-c",
            "a.c"
          )
      }

      "read the family from a driver named by its Windows path" in {
          val command =
              """C:\msys64\usr\bin\cc.exe -c -IC:\Users\appthreat\work\390\clirun\externlib main.c"""
          CompileCommand.tokenize(command).head shouldBe "C:\\msys64\\usr\\bin\\cc.exe"
          val flags = CompileCommand.parseArguments(
            CompileCommand.tokenize(command),
            Paths.get("C:/Users/appthreat/work/390/clirun/proj")
          )
          flags.compiler shouldBe Some("C:\\msys64\\usr\\bin\\cc.exe")
          flags.family shouldBe CompilerFamily.Gcc
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
              "-arch",
              "arm64",
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
            s"--sysroot=${Paths.get("/sysroot")}",
            "-arch",
            "arm64",
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

  "the driver table" should {

      "give the table's family for every driver it names" in {
          val families = Map(
            "nvcc"              -> "Nvcc",
            "icx"               -> "IntelLlvm",
            "icpx"              -> "IntelLlvm",
            "emcc"              -> "Emscripten",
            "em++"              -> "Emscripten",
            "zig cc"            -> "Clang",
            "zig c++"           -> "Clang",
            "tcc"               -> "TinyC",
            "armclang"          -> "Clang",
            "iccarm"            -> "Iar",
            "armcl"             -> "TiArm",
            "cl430"             -> "TiMsp430",
            "arm-none-eabi-gcc" -> "Gcc",
            "arm-none-eabi-g++" -> "Gcc"
          )
          families.foreach { (driver, family) =>
              withClue(s"$driver: ") { CompileCommand.familyOf(driver).toString shouldBe family }
          }
      }

      "leave GCC, Clang, MSVC and unknown drivers as they are today" in {
          CompileCommand.familyOf("gcc").toString shouldBe "Gcc"
          CompileCommand.familyOf("arm-linux-gnueabi-gcc").toString shouldBe "Gcc"
          CompileCommand.familyOf("/usr/bin/clang-17").toString shouldBe "Clang"
          CompileCommand.familyOf("clang").toString shouldBe "Clang"
          CompileCommand.familyOf("cl").toString shouldBe "Msvc"
          CompileCommand.familyOf("clang-cl").toString shouldBe "Msvc"
          CompileCommand.familyOf("arm-none-eabi-clang").toString shouldBe "Clang"
          CompileCommand.familyOf("mycustomcc").toString shouldBe "Unknown"
          CompileCommand.familyOf("fakeformat").toString shouldBe "Unknown"
      }

      "read a two-word driver from its two arguments" in {
          val flags = CompileCommand.parseArguments(Seq("zig", "cc", "-O2", "-c", "a.c"), dir)
          flags.family shouldBe CompilerFamily.Clang
          flags.language shouldBe None
          flags.entry shouldBe Some("zig cc")
          val cppFlags = CompileCommand.parseArguments(Seq("zig", "c++", "-c", "a.c"), dir)
          cppFlags.family shouldBe CompilerFamily.Clang
          cppFlags.language shouldBe Some(SourceLanguage.Cpp)
          cppFlags.entry shouldBe Some("zig c++")
          // the probe of a two-word driver runs through its subcommand
          Toolchains.entryNamed("zig cc").flatMap(_.probe).map(_.prefixArgs) shouldBe
              Some(Seq("cc"))
      }

      "compile a nvcc CUDA unit as C++ and other nvcc files by their extension" in {
          val cu = CompileCommand.parseArguments(Seq("nvcc", "-ccbin", "g++", "-c", "a.cu"), dir)
          cu.language shouldBe Some(SourceLanguage.Cpp)
          cu.family.toString shouldBe "Nvcc"
          // the host family whose macros a .cu unit is preprocessed with is named by -ccbin and
          // kept as a target option, so the fallback can merge nvcc's macros over that family's
          cu.targetOptions shouldBe Seq("-ccbin=g++")
          Toolchains.hostFamilyOf(cu.targetOptions).map(_.toString) shouldBe Some("Gcc")
          Toolchains.hostFamilyOf(Seq("-ccbin=clang++")).map(_.toString) shouldBe Some("Clang")
          val c = CompileCommand.parseArguments(Seq("nvcc", "-c", "a.c"), dir)
          c.language shouldBe None
      }

      "compile every file as C++ for the drivers that always do" in {
          CompileCommand.parseArguments(Seq("icpx", "-c", "a.c"), dir).language shouldBe
              Some(SourceLanguage.Cpp)
          CompileCommand.parseArguments(Seq("icx", "-c", "a.c"), dir).language shouldBe None
          CompileCommand.parseArguments(Seq("em++", "-c", "a.c"), dir).language shouldBe
              Some(SourceLanguage.Cpp)
          CompileCommand.parseArguments(Seq("emcc", "-c", "a.c"), dir).language shouldBe None
      }

      "strip a wrapper driver and read the compiler behind it" in {
          val flags = CompileCommand.parseArguments(Seq("ccache", "gcc", "-O2", "-c", "a.c"), dir)
          flags.compiler shouldBe Some("gcc")
          flags.family shouldBe CompilerFamily.Gcc
          flags.entry shouldBe Some("GCC")
      }

      "record the entry a specific driver matched, not the family it belongs to" in {
          // the arm-none-eabi entry stands before the GCC family entry, whose contains:gcc
          // matcher would otherwise swallow it
          val flags = CompileCommand.parseArguments(
            Seq("arm-none-eabi-gcc", "-mcpu=cortex-m4", "-mthumb", "-c", "a.c"),
            dir
          )
          flags.family shouldBe CompilerFamily.Gcc
          flags.entry shouldBe Some("arm-none-eabi-gcc")
          CompileCommand.parseArguments(Seq("icx", "-c", "a.c"), dir).entry shouldBe Some("icx")
          CompileCommand.parseArguments(
            Seq("clang", "--driver-mode=cl", "/O2", "-c", "a.cpp"),
            dir
          ).entry shouldBe Some("clang MSVC driver mode")
          CompileCommand.parseArguments(Seq("mycustomcc", "-c", "a.c"), dir).entry shouldBe None
      }

      "ask each family's own entry for its probe and table stem, whatever stands around it" in {
          // armclang stands before the Clang family entry in the table; plain clang must not
          // inherit armclang's answers
          Toolchains.entryForFamily(CompilerFamily.Clang).map(_.name) shouldBe Some("Clang")
          Toolchains.entryForFamily(CompilerFamily.Gcc).map(_.name) shouldBe Some("GCC")
          Toolchains.entryForFamily(CompilerFamily.Nvcc).map(_.name) shouldBe Some("nvcc")
          Toolchains.entryForFamily(CompilerFamily.Msvc).map(_.name) shouldBe Some("MSVC")
          Toolchains.entryForFamily(CompilerFamily.Iar).map(_.name) shouldBe Some("iccarm")
          // the stem each family's fallback tables share, which the macro table selection reads
          Toolchains.entryForFamily(CompilerFamily.Msvc).flatMap(_.fallbackTable) shouldBe
              Some("msvc-windows")
          Toolchains.entryForFamily(CompilerFamily.Clang).flatMap(_.fallbackTable) shouldBe
              Some("clang")
      }
  }
end CompileCommandTests

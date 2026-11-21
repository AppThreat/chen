package io.appthreat.c2cpg.parser

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.utils.IncludeAutoDiscovery
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Path, Paths}

class PredefinedMacrosTests extends AnyWordSpec with Matchers:

  /** A stand-in compiler: answers `--version`, and for `-dM -E -v` prints one macro (named after
    * its language option) and a system include directory.
    */
  private def fakeCompiler(dir: File, name: String = "fake-gcc"): String =
    val script = dir / name
    script.writeText(
      """#!/bin/sh
        |if [ "$1" = "--version" ]; then echo "fakecc 1.0"; exit 0; fi
        |lang=""
        |while [ $# -gt 0 ]; do
        |  if [ "$1" = "-x" ]; then lang="$2"; fi
        |  shift
        |done
        |echo "#define __FAKECC__ 1"
        |echo "#define __FAKE_SIZE(x) sizeof(x)"
        |if [ "$lang" = "c++" ]; then echo "#define __cplusplus 202002L"; fi
        |echo "#include <...> search starts here:" 1>&2
        |echo " /fake/include" 1>&2
        |echo "End of search list." 1>&2
        |""".stripMargin
    )
    script.toJava.setExecutable(true)
    script.pathAsString
  end fakeCompiler

  "a runnable compiler" should {
      "report its macros and system include path, once per identity" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("predef") { dir =>
            val cc       = fakeCompiler(dir)
            val identity = CompilerIdentity(cc, CompilerFamily.Gcc, SourceLanguage.Cpp, Seq("-O2"))
            PredefinedMacros.clearProcessCache()
            val before = PredefinedMacros.compilerRuns.get()
            val facts  = PredefinedMacros.ofCompiler(identity, Some(dir.path)).get
            facts.macros should contain("__FAKECC__" -> "1")
            facts.macros should contain("__FAKE_SIZE(x)" -> "sizeof(x)")
            facts.macros should contain("__cplusplus" -> "202002L")
            facts.systemIncludePaths shouldBe Seq(Paths.get("/fake/include"))
            PredefinedMacros.ofCompiler(identity, Some(dir.path)) shouldBe Some(facts)
            PredefinedMacros.compilerRuns.get() shouldBe before + 1

            // a new process finds the answer on disk
            PredefinedMacros.clearProcessCache()
            PredefinedMacros.ofCompiler(identity, Some(dir.path)) shouldBe Some(facts)
            PredefinedMacros.compilerRuns.get() shouldBe before + 1

            // another option set is another identity
            PredefinedMacros.ofCompiler(identity.copy(options = Nil), Some(dir.path))
            PredefinedMacros.compilerRuns.get() shouldBe before + 2
          }
      }

      "be run from every worker of the common pool at once" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("predef") { dir =>
            val cc       = fakeCompiler(dir, "fake-gcc-pool")
            val identity = CompilerIdentity(cc, CompilerFamily.Gcc, SourceLanguage.C, Nil)
            PredefinedMacros.clearProcessCache()
            // as a parallel pass does: every worker asks for the same facts under one lock, so
            // the one running the compiler holds it while the others wait
            val lock = new java.util.concurrent.ConcurrentHashMap[String, Option[CompilerFacts]]()
            val workers = java.util.concurrent.ForkJoinPool.commonPool().getParallelism * 2
            val answers = java.util.concurrent.CompletableFuture.supplyAsync(() =>
                java.util.stream.IntStream.range(0, workers).parallel().mapToObj { _ =>
                    lock.computeIfAbsent("cc", _ => PredefinedMacros.ofCompiler(identity, None))
                }.toList
            ).get(60, java.util.concurrent.TimeUnit.SECONDS)
            import scala.jdk.CollectionConverters.*
            answers.asScala.flatten.map(_.macros("__FAKECC__")).distinct shouldBe Seq("1")
          }
      }

      "not be run when it does not exist" in {
          PredefinedMacros.ofCompiler(
            CompilerIdentity("/nonexistent/cc", CompilerFamily.Gcc, SourceLanguage.C, Nil),
            None
          ) shouldBe None
      }

      "give no facts when the probe command itself fails, and the table stands in" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("predef-probe-fail") { dir =>
            // a stand-in compiler that answers --version but fails the macro-dump probe: the
            // shape of a driver whose probe spelling does not fit it (a two-word driver asked
            // without its subcommand)
            val script = dir / "fake-driver"
            script.writeText(
              """#!/bin/sh
                |if [ "$1" = "--version" ]; then echo "fakecc 1.0"; exit 0; fi
                |exit 3
                |""".stripMargin
            )
            script.toJava.setExecutable(true)
            PredefinedMacros.clearProcessCache()
            val before = PredefinedMacros.compilerRuns.get()
            val identity =
                CompilerIdentity(script.pathAsString, CompilerFamily.Clang, SourceLanguage.C, Nil)
            PredefinedMacros.ofCompiler(identity, Some(dir.path)) shouldBe None
            PredefinedMacros.compilerRuns.get() - before shouldBe 1
            // the unit's macros then come from the family's table, never from an empty set
            val table = PredefinedMacros.fallback(
              CompilerFamily.Clang,
              SourceLanguage.C,
              Seq("--target=aarch64-unknown-linux-gnu")
            )
            (table should contain).key("__clang_major__")
          }
      }
  }

  "a database compiler's search path" should {
      "follow the unit's own include directories, in the compiler's order" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("predef") { dir =>
            val cc = fakeCompiler(dir)
            val flags = CompileCommand.parseArguments(
              Seq(cc, "-Iinc", "-isystem", "/sys", "-c", "a.cpp"),
              dir.path
            )
            PredefinedMacros.clearProcessCache()
            val settings = ProjectSources.settings(
              Config(),
              SourceLanguage.Cpp,
              Some(flags),
              None,
              pathEnvironment = dir.pathAsString
            )
            settings.includePaths shouldBe Seq(
              dir.path.resolve("inc"),
              Paths.get("/sys"),
              Paths.get("/fake/include")
            )
            settings.definedSymbols should contain("__FAKECC__" -> "1")
            settings.definedSymbols should contain("__cplusplus" -> "202002L")
          }
      }
  }

  "a database compiler from the project itself" should {
      "never be run: its family's table stands in" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("project") { dir =>
            val cc     = fakeCompiler(dir)
            val config = Config().withInputPath(dir.pathAsString)
            PredefinedMacros.clearProcessCache()
            val before = PredefinedMacros.compilerRuns.get()
            // not even when the PATH lists the project directory
            Seq(cc, "./fake-gcc", "tools/../fake-gcc", "fake-gcc").foreach { compiler =>
              val flags = CompileCommand.parseArguments(Seq(compiler, "-c", "a.c"), dir.path)
              val settings = ProjectSources.settings(
                config,
                SourceLanguage.C,
                Some(flags),
                None,
                pathEnvironment = dir.pathAsString
              )
              settings.definedSymbols should not contain key("__FAKECC__")
            }
            PredefinedMacros.compilerRuns.get() shouldBe before
          }
      }
  }

  "a database compiler outside the project" should {
      def withDirs(test: (File, File, File) => Unit): Unit =
          File.usingTemporaryDirectory("tools") { tools =>
              File.usingTemporaryDirectory("other") { other =>
                  File.usingTemporaryDirectory("project") { project =>
                      test(tools, other, project)
                  }
              }
          }

      "be run only from a directory the PATH lists" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, other, project) =>
            val config  = Config().withInputPath(project.pathAsString)
            val onPath  = fakeCompiler(tools)
            val offPath = fakeCompiler(other)
            val path    = tools.pathAsString
            ProjectSources.trustedExecutable(onPath, config, path) shouldBe
                Some(tools.path.toRealPath().resolve("fake-gcc").toString)
            ProjectSources.trustedExecutable("fake-gcc", config, path) shouldBe
                Some(tools.path.toRealPath().resolve("fake-gcc").toString)
            ProjectSources.trustedExecutable(offPath, config, path) shouldBe None
            ProjectSources.trustedExecutable(offPath, config, "") shouldBe None
            ProjectSources.trustedExecutable(onPath, config, "") shouldBe None

            PredefinedMacros.clearProcessCache()
            val before = PredefinedMacros.compilerRuns.get()
            val flags  = CompileCommand.parseArguments(Seq(offPath, "-c", "a.c"), project.path)
            ProjectSources.settings(config, SourceLanguage.C, Some(flags), None, path)
                .definedSymbols should not contain key("__FAKECC__")
            PredefinedMacros.compilerRuns.get() shouldBe before
          }
      }

      "not reach another directory through `..` segments" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, other, project) =>
            val config = Config().withInputPath(project.pathAsString)
            fakeCompiler(other)
            val through = s"${tools.pathAsString}/../${other.name}/fake-gcc"
            ProjectSources.trustedExecutable(through, config, tools.pathAsString) shouldBe None
            val intoProject = s"${tools.pathAsString}/../${project.name}/fake-gcc"
            fakeCompiler(project)
            ProjectSources.trustedExecutable(intoProject, config, tools.pathAsString) shouldBe None
          }
      }

      "not be looked up in a relative PATH entry" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, _, project) =>
            val config   = Config().withInputPath(project.pathAsString)
            val relative = Paths.get("").toAbsolutePath.relativize(tools.path).toString
            fakeCompiler(tools)
            ProjectSources.trustedExecutable("fake-gcc", config, relative) shouldBe None
            ProjectSources.trustedExecutable(
              tools.path.resolve("fake-gcc").toString,
              config,
              relative
            ) shouldBe None
          }
      }

      "be found in a PATH directory reached through a symbolic link" in {
          assume(!scala.util.Properties.isWin)
          withDirs { (tools, other, project) =>
            val config = Config().withInputPath(project.pathAsString)
            val cc     = fakeCompiler(tools)
            val link   = other.path.resolve("bin")
            java.nio.file.Files.createSymbolicLink(link, tools.path)
            ProjectSources.trustedExecutable(cc, config, link.toString) shouldBe
                Some(tools.path.toRealPath().resolve("fake-gcc").toString)
          }
      }
  }

  "the host compiler" should {
      "be found by its absolute path, never through a relative PATH entry" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("tools") { tools =>
            fakeCompiler(tools, "gcc")
            val relative = Paths.get("").toAbsolutePath.relativize(tools.path).toString
            IncludeAutoDiscovery.hostCompilerPath("gcc", tools.pathAsString) shouldBe
                Some(tools.path.normalize.resolve("gcc"))
            IncludeAutoDiscovery.hostCompilerPath("gcc", relative) shouldBe None
            IncludeAutoDiscovery.hostCompilerPath("gcc", ".") shouldBe None
          }
      }

      "be named by its absolute path when one is run for its macros" in {
          val config = Config().withIncludePathsAutoDiscovery(true)
          ProjectSources.settings(config, SourceLanguage.C, None, None).compiler.foreach {
              identity => Paths.get(identity.executable).isAbsolute shouldBe true
          }
      }
  }

  "a database command that does not name GCC or Clang" should {
      "never be run, even from outside the project" in {
          assume(!scala.util.Properties.isWin)
          File.usingTemporaryDirectory("tools") { tools =>
              File.usingTemporaryDirectory("project") { dir =>
                val config = Config().withInputPath(dir.pathAsString)
                PredefinedMacros.clearProcessCache()
                val before = PredefinedMacros.compilerRuns.get()
                Seq("fakeformat", "nvcc", "icx").foreach { name =>
                  val tool  = fakeCompiler(tools, name)
                  val flags = CompileCommand.parseArguments(Seq(tool, "-c", "a.c"), dir.path)
                  val settings =
                      ProjectSources.settings(config, SourceLanguage.C, Some(flags), None)
                  settings.definedSymbols should not contain key("__FAKECC__")
                  (settings.definedSymbols should contain).key("__STDC_VERSION__")
                }
                PredefinedMacros.compilerRuns.get() shouldBe before
              }
          }
      }
  }

  "the fallback tables" should {
      "select macros by language for the compiler family and target" in {
          val gccC =
              PredefinedMacros.fallback(
                CompilerFamily.Gcc,
                SourceLanguage.C,
                Seq("--target=x86_64-linux-gnu")
              )
          gccC.get("__GNUC__").map(_.toInt).getOrElse(0) should be >= 13
          (gccC should contain).key("__x86_64__")
          (gccC should contain).key("__STDC_VERSION__")
          gccC should not contain key("__cplusplus")
          val gccCpp = PredefinedMacros.fallback(
            CompilerFamily.Gcc,
            SourceLanguage.Cpp,
            Seq("--target=aarch64-linux-gnu")
          )
          (gccCpp should contain).key("__cplusplus")
          (gccCpp should contain).key("__aarch64__")
      }

      "describe MSVC without clang's identity" in {
          val msvc = PredefinedMacros.fallback(CompilerFamily.Msvc, SourceLanguage.Cpp, Nil)
          (msvc should contain).key("_MSC_VER")
          (msvc should contain).key("_WIN32")
          msvc should not contain key("__clang__")
          msvc should not contain key("__GNUC__")
      }

      "pick clang's MSVC-mode table by the target's architecture, not the first one" in {
          val x64 = PredefinedMacros.fallback(
            CompilerFamily.Msvc,
            SourceLanguage.C,
            Seq("--driver-mode=cl", "--target=x86_64-pc-windows-msvc")
          )
          (x64 should contain).key("__clang__")
          (x64 should contain).key("__x86_64__")
          x64 should not contain key("__aarch64__")
          val arm64 = PredefinedMacros.fallback(
            CompilerFamily.Msvc,
            SourceLanguage.C,
            Seq("--driver-mode=cl", "--target=aarch64-pc-windows-msvc")
          )
          (arm64 should contain).key("__clang__")
          (arm64 should contain).key("__aarch64__")
          arm64 should not contain key("__x86_64__")
      }

      "give a bare-metal GCC command its own table whatever the host is" in {
          val bareMetal = PredefinedMacros.fallback(
            CompilerFamily.Gcc,
            SourceLanguage.C,
            Seq("-mcpu=cortex-m4", "-mthumb")
          )
          (bareMetal should contain).key("__arm__")
          (bareMetal should contain).key("__thumb2__")
          bareMetal should not contain key("__x86_64__")
          bareMetal should not contain key("__aarch64__")
      }
  }

  "unit settings" should {
      "keep the fixed GCC identity without a compiler, and MSVC's keywords" in {
          val settings = ProjectSources.settings(Config(), SourceLanguage.C, None, None)
          settings.definedSymbols should contain("__GNUC__" -> "4")
          (settings.definedSymbols should contain).key("__declspec")
          settings.definedSymbols should not contain key("__cplusplus")
      }

      "use the host compiler's macros when include discovery is on" in {
          assume(IncludeAutoDiscovery.gccAvailable() || IncludeAutoDiscovery.clangAvailable())
          val config   = Config().withIncludePathsAutoDiscovery(true)
          val settings = ProjectSources.settings(config, SourceLanguage.Cpp, None, None)
          (settings.definedSymbols should contain).key("__STDC_HOSTED__")
          (settings.definedSymbols should contain).key("__cplusplus")
          (settings.definedSymbols should contain).key("__SIZEOF_POINTER__")
      }

      "fall back to a table for a database compiler that cannot be run" in {
          val flags = CompileCommand.parseArguments(
            Seq("/opt/missing/bin/gcc", "-DFROM_DB=3", "-U__STDC_HOSTED__", "-c", "a.c"),
            Paths.get("/work")
          )
          val settings = ProjectSources.settings(
            Config().withDefines(Set("USER")),
            SourceLanguage.C,
            Some(flags),
            None
          )
          settings.definedSymbols.get("__GNUC__").map(_.toInt).getOrElse(0) should be >= 13
          settings.definedSymbols should contain("FROM_DB" -> "3")
          settings.definedSymbols should contain("USER" -> "1")
          settings.definedSymbols should not contain key("__STDC_HOSTED__")
          settings.definedSymbols should not contain key("__declspec")
      }

      "set __cplusplus from the configured standard" in {
          val settings =
              ProjectSources.settings(
                Config().withCppStandard("c++20"),
                SourceLanguage.Cpp,
                None,
                None
              )
          settings.definedSymbols should contain("__cplusplus" -> "202002L")
          settings.definedSymbols should contain("export" -> "")
      }
  }

  "a GCC, a Clang and an MSVC database entry" should {
      val dir = Paths.get("/work/proj/build")

      // the pinned targets make the fallback table the same on every host, so the key sets
      // below hold wherever the test runs
      def settingsOf(arguments: Seq[String], language: SourceLanguage): UnitSettings =
          ProjectSources.settings(
            Config(),
            language,
            Some(CompileCommand.parseArguments(arguments, dir)),
            None
          )

      "give exactly today's settings for a GCC entry" in {
          val arguments = Seq(
            "/opt/missing/bin/gcc",
            "--target=x86_64-linux-gnu",
            "-DFROM_DB=3",
            "-c",
            "a.c"
          )
          val settings = settingsOf(arguments, SourceLanguage.C)
          settings.language shouldBe SourceLanguage.C
          settings.compiler shouldBe None
          settings.standard shouldBe None
          settings.includeFiles shouldBe Nil
          settings.macroFiles shouldBe Nil
          settings.includePaths shouldBe Nil
          settings.definedSymbols.keySet shouldBe
              expectedFallbackKeys("gcc-linux-x86_64", gccCModeNames) + "FROM_DB"
          settings.definedSymbols.get("__GNUC__").map(_.toInt).getOrElse(0) should be >= 13
          settings.definedSymbols should not contain key("__declspec")
      }

      "give exactly today's settings for a Clang entry" in {
          val arguments = Seq(
            "/opt/missing/bin/clang",
            "--target=x86_64-unknown-linux-gnu",
            "-std=gnu11",
            "-c",
            "a.c"
          )
          val settings = settingsOf(arguments, SourceLanguage.C)
          settings.language shouldBe SourceLanguage.C
          settings.compiler shouldBe None
          settings.standard shouldBe Some("gnu11")
          settings.includePaths shouldBe Nil
          settings.definedSymbols.keySet shouldBe
              expectedFallbackKeys("clang-linux-x86_64", clangCModeNames)
          settings.definedSymbols should not contain key("__declspec")
      }

      "give exactly today's settings for an MSVC entry" in {
          // cl.exe is never run and carries no target option, so the fallback reads the host's
          // platform; the expectation picks the table by the host's architecture, from the
          // resource itself
          val arguments = Seq("cl.exe", "/std:c++17", "/TP", "/DFROM_DB=3", "/c", "a.cpp")
          val settings  = settingsOf(arguments, SourceLanguage.Cpp)
          settings.language shouldBe SourceLanguage.Cpp
          settings.compiler shouldBe None
          settings.standard shouldBe Some("c++17")
          settings.definedSymbols.keySet shouldBe
              expectedFallbackKeys(msvcHostTable, msvcCppModeNames) + "FROM_DB"
          (settings.definedSymbols should contain).key("_MSC_VER")
          (settings.definedSymbols should contain).key("__declspec")
      }
  }

  // the host's architecture decides which of two tables a target-less command falls back to
  private val msvcHostTable =
      if System.getProperty("os.arch", "").toLowerCase.startsWith("aarch64") ||
        System.getProperty("os.arch", "").toLowerCase.startsWith("arm")
      then "msvc-windows-arm64"
      else "msvc-windows-x64"

  // the modes the EDG-format tables carry for one language of one compiler family
  private val gccCModeNames    = Set("all", "gnu", "gcc", "gnu_or_clang")
  private val clangCModeNames  = Set("all", "clang", "clang_c", "gnu_or_clang")
  private val msvcCppModeNames = Set("all", "cpp", "microsoft", "microsoft_cpp")

  /** The macro names the named table defines for those modes, read from the resource itself so the
    * expectation does not go through the code it checks.
    */
  private def expectedFallbackKeys(tableName: String, modes: Set[String]): Set[String] =
    val stream = getClass.getResourceAsStream(s"/predefined-macros/$tableName.txt")
    val source = scala.io.Source.fromInputStream(stream, "UTF-8")
    val names =
        try
            source
                .getLines()
                .map(_.trim)
                .filter(l => l.nonEmpty && !l.startsWith("#"))
                .flatMap { line =>
                    line.split("\\s+", 4).toList match
                      case modeList :: _ :: name :: _ =>
                          val active = modeList.split(',').exists { m =>
                              if m.startsWith("!") then !modes.contains(m.drop(1))
                              else modes.contains(m)
                          }
                          Option.when(active)(name)
                      case _ => None
                }
                .toSet
        finally source.close()
    UnitSettings.FeatureTests.keySet ++ names ++
        (if modes.contains("microsoft") then DefaultDefines.DEFAULT_CALL_CONVENTIONS.keySet
         else Set.empty) ++
        (if modes.contains("cpp") then Set("export", "__cplusplus") else Set("_Noreturn"))
  end expectedFallbackKeys

  "the toolchain fixtures" should {
      def fixtureDir(name: String): Path = Paths.get(
        getClass.getClassLoader.getResource(s"toolchains/$name").toURI
      )

      def settingsFor(name: String): (Path, UnitSettings) =
        val dir  = fixtureDir(name)
        val path = dir.resolve(fixtureSource(name))
        val config =
            Config().withInputPath(dir.toString).withCompileCommands(dir.resolve(
              CompileDatabase.FileName
            ).toString)
        (path, new ProjectSources(config).settingsFor(path))

      def fixtureSource(name: String): String = Map(
        "nvcc"              -> "vec_add.cu",
        "icx"               -> "simd_dot.c",
        "icpx"              -> "simd_dot.cpp",
        "emcc"              -> "wasm_entry.c",
        "empp"              -> "wasm_entry.cpp",
        "zig-cc"            -> "clang_guarded.c",
        "zig-cpp"           -> "clang_guarded.cpp",
        "tcc"               -> "small_kernel.c",
        "armclang"          -> "cortex_m_irq.c",
        "iccarm"            -> "arm_irq.c",
        "armcl"             -> "ti_arm_task.c",
        "cl430"             -> "msp430_blink.c",
        "clang-cl-mode"     -> "msvc_mode.cpp",
        "arm-none-eabi-gcc" -> "bare_metal_delay.c",
        "ccache"            -> "cached_build.c"
      )(name)

      /** The macros each fixture's #error guard tests, per driver. */
      def identifyingMacros(name: String): Set[String] = Map(
        "nvcc"              -> Set("__CUDACC__", "__NVCC__", "__GNUC__"),
        "icx"               -> Set("__INTEL_LLVM_COMPILER", "__clang__"),
        "icpx"              -> Set("__INTEL_LLVM_COMPILER", "__clang__", "__cplusplus"),
        "emcc"              -> Set("__EMSCRIPTEN__", "__clang__"),
        "empp"              -> Set("__EMSCRIPTEN__", "__clang__", "__cplusplus"),
        "zig-cc"            -> Set("__clang__"),
        "zig-cpp"           -> Set("__clang__", "__cplusplus"),
        "tcc"               -> Set("__TINYC__"),
        "armclang"          -> Set("__ARMCC_VERSION", "__clang__"),
        "iccarm"            -> Set("__ICCARM__"),
        "armcl"             -> Set("__TI_ARM__", "__TI_COMPILER_VERSION__"),
        "cl430"             -> Set("__MSP430__", "__TI_COMPILER_VERSION__"),
        "clang-cl-mode"     -> Set("_MSC_VER", "__clang__"),
        "arm-none-eabi-gcc" -> Set("__GNUC__", "__arm__"),
        "ccache"            -> Set("__GNUC__")
      )(name)

      /** Drivers a database never runs for its macros: their table stands in, so no compiler
        * process is started however the PATH is set.
        */
      def tableOnlyDrivers: Set[String] =
          Set(
            "nvcc",
            "icx",
            "icpx",
            "emcc",
            "empp",
            "tcc",
            "iccarm",
            "armcl",
            "cl430",
            "clang-cl-mode"
          )

      "define each compiler's identifying macros, from its table" in {
          assume(!scala.util.Properties.isWin)
          Seq(
            "nvcc",
            "icx",
            "icpx",
            "emcc",
            "empp",
            "zig-cc",
            "zig-cpp",
            "tcc",
            "armclang",
            "iccarm",
            "armcl",
            "cl430",
            "clang-cl-mode",
            "arm-none-eabi-gcc",
            "ccache"
          ).foreach { name =>
              withClue(s"$name: ") {
                  val (_, settings) = settingsFor(name)
                  (settings.definedSymbols.keySet should contain).allElementsOf(
                    identifyingMacros(name)
                  )
              }
          }
      }

      "never run a compiler for the drivers only their table can describe" in {
          assume(!scala.util.Properties.isWin)
          PredefinedMacros.clearProcessCache()
          val before = PredefinedMacros.compilerRuns.get()
          tableOnlyDrivers.foreach { name =>
              withClue(s"$name: ") {
                  val (_, settings) = settingsFor(name)
                  settings.compiler shouldBe None
              }
          }
          PredefinedMacros.compilerRuns.get() shouldBe before
      }

      "preprocess without reaching their #error, as CDT reads them" in {
          assume(!scala.util.Properties.isWin)
          Seq(
            "nvcc",
            "icx",
            "icpx",
            "emcc",
            "empp",
            "zig-cc",
            "zig-cpp",
            "tcc",
            "armclang",
            "iccarm",
            "armcl",
            "cl430",
            "clang-cl-mode",
            "arm-none-eabi-gcc",
            "ccache"
          ).foreach { name =>
              withClue(s"$name: ") {
                  val dir    = fixtureDir(name)
                  val path   = dir.resolve(fixtureSource(name))
                  val db     = dir.resolve(CompileDatabase.FileName)
                  val config = Config().withInputPath(dir.toString).withCompileCommands(db.toString)
                  val parser = new CdtParser(config, new HeaderFileFinder(dir.toString))
                  val unit   = parser.parse(path).get
                  val problems = unit.getPreprocessorProblems
                  problems.map(_.getMessage) shouldBe empty
              }
          }
      }
  }

  "a driver the table does not know" should {
      "keep the host-family fallback and carry the fact that it is unknown" in {
          val dir   = Paths.get("/work/proj/build")
          val flags = CompileCommand.parseArguments(Seq("mycustomcc", "-c", "a.c"), dir)
          // the fact the parse report will read: the table has no entry for this driver
          flags.family shouldBe CompilerFamily.Unknown
          val settings = ProjectSources.settings(Config(), SourceLanguage.C, Some(flags), None)
          // today's host fallback stands in, not a toolchain table
          settings.compiler shouldBe None
          (settings.definedSymbols should contain).key("__STDC_VERSION__")
          settings.definedSymbols should not contain key("__CUDACC__")
          settings.definedSymbols should not contain key("__INTEL_LLVM_COMPILER")
      }
  }
end PredefinedMacrosTests

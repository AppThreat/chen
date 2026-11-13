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
end PredefinedMacrosTests

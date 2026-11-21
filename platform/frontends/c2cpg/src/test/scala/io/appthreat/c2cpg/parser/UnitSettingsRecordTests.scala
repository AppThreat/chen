package io.appthreat.c2cpg.parser

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.x2cpg.parse.{DatabaseCommand, ParseReporter, UnitSettingsReporter}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The records the parse report's `units` section keeps for the units the C/C++ frontend parses:
  * how a unit of a compilation database was set up, what an unknown driver is reported as, and what
  * a file the database names twice reports about its commands. A run without the parse report
  * collects nothing.
  */
class UnitSettingsRecordTests extends AnyWordSpec with Matchers:

  /** A project with source files and a compilation database naming units by their arguments. */
  private def projectOf(
    dir: File,
    sources: Seq[(String, String)],
    commands: Seq[(String, Seq[String])]
  ): File =
    sources.foreach((name, text) => (dir / name).writeText(text))
    val entries = commands.map { (file, arguments) =>
      val args = arguments.map(a => ujson.Str(a))
      s"""{"directory": ".", "file": "$file", "arguments": ${ujson.write(ujson.Arr(args*))}}"""
    }.mkString("[", ",", "]")
    (dir / CompileDatabase.FileName).writeText(entries)
    dir

  private def settingsOf(dir: File, unit: String): UnitSettings =
    val config = Config()
        .withInputPath(dir.toString)
        .withCompileCommands((dir / CompileDatabase.FileName).pathAsString)
    new ProjectSources(config).settingsFor(dir.path.resolve(unit))

  /** The parse report on, from an empty collector: what one run of these tests collects stays
    * theirs.
    */
  private def withReportEnabled[T](body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    UnitSettingsReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      UnitSettingsReporter.reset()
      ParseReporter.reset()

  "the units the frontend parses" should {

      "record the settings a known database gives the unit" in withReportEnabled {
          // the fixture's command names `cc`, and the record reads `probed` only when the host
          // can run it and answer for the macros
          assume(canRun("cc"))
          File.usingTemporaryDirectory("unit-settings-record") { dir =>
            (dir / "inc").createDirectory()
            (dir / "inc" / "extra.h").writeText("#define EXTRA 1\n")
            val project = projectOf(
              dir,
              sources = Seq(
                "main.c"  -> "#include \"local.h\"\nint main(void) { return count; }\n",
                "local.h" -> "#ifndef LOCAL_H\n#define LOCAL_H\nextern int count;\n#endif\n",
                "pre.h"   -> "#define PREPENDED 1\n",
                "defs.h"  -> "#define FROM_MACROS 1\n"
              ),
              commands = Seq(
                (
                  "main.c",
                  Seq(
                    "cc",
                    "-Iinc",
                    "-include",
                    "pre.h",
                    "-imacros",
                    "defs.h",
                    "-std=gnu11",
                    "-c",
                    "main.c"
                  )
                )
              )
            )
            settingsOf(project, "main.c")
            val records = UnitSettingsReporter.records
            records should have size 1
            val record = records.head
            record.frontend shouldBe ParseReporter.Frontend.C
            record.file shouldBe "main.c"
            record.driver shouldBe "cc"
            record.entry shouldBe "GCC"
            // the host answers for the compiler the command names, so the macros are its own
            record.macroSource shouldBe UnitSettingsReporter.MacroSource.Probed
            record.language shouldBe UnitSettingsReporter.Language.C
            record.standard shouldBe "gnu11"
            record.macroFingerprint should have size 32
            record.includeDirectories.head shouldBe project.path.resolve("inc").toString
            record.forcedIncludes shouldBe Seq(
              project.path.resolve("pre.h").toString,
              project.path.resolve("defs.h").toString
            )
            record.ownedHeaders shouldBe Seq("local.h")
            record.databaseCommands shouldBe empty
            record.usedDatabaseCommand shouldBe None
            UnitSettingsReporter.reset()
          }
      }

      "record a driver the table does not know as unknown" in withReportEnabled {
          File.usingTemporaryDirectory("unit-settings-record") { dir =>
            projectOf(
              dir,
              sources = Seq("main.c" -> "int main(void) { return 0; }\n"),
              commands = Seq(("main.c", Seq("mycc", "-c", "main.c")))
            )
            settingsOf(dir, "main.c")
            val record = UnitSettingsReporter.records.head
            record.driver shouldBe "mycc"
            record.entry shouldBe UnitSettingsReporter.MacroSource.Unknown
            // an unknown driver's macros are the host family's stand-in, and the record says so
            record.macroSource shouldBe UnitSettingsReporter.MacroSource.Unknown
            UnitSettingsReporter.reset()
          }
      }

      "record every command of a file the database names twice, and the one used" in withReportEnabled {
          File.usingTemporaryDirectory("unit-settings-record") { dir =>
            val first  = Seq("cc", "-DFIRST=1", "-c", "dup.c")
            val second = Seq("cc", "-DSECOND=1", "-Ilib", "-c", "dup.c")
            projectOf(
              dir,
              sources = Seq(
                "dup.c"   -> "int first(void) { return 1; }\n",
                "other.c" -> "int other(void) { return 2; }\n"
              ),
              commands = Seq(("dup.c", first), ("dup.c", second))
            )
            settingsOf(dir, "dup.c")
            val record = UnitSettingsReporter.records.find(_.file == "dup.c").get
            record.databaseCommands shouldBe Seq(
              DatabaseCommand(dir.path.toString, first),
              DatabaseCommand(dir.path.toString, second)
            )
            record.usedDatabaseCommand shouldBe Some(0)
            // the command reported as used is the one the database itself hands out
            CompileDatabase.load((dir / CompileDatabase.FileName).path)
                .commandFor(dir.path.resolve("dup.c"))
                .get
                .arguments shouldBe first
            record.entry shouldBe "GCC"
            // a file named once carries no commands of its own in the section
            settingsOf(dir, "other.c")
            val single = UnitSettingsReporter.records.find(_.file == "other.c").get
            single.databaseCommands shouldBe empty
            single.usedDatabaseCommand shouldBe None
            UnitSettingsReporter.reset()
          }
      }

      "collect nothing when the parse report is off" in {
          System.clearProperty("chen.parse.report")
          UnitSettingsReporter.reset()
          ParseReporter.reset()
          File.usingTemporaryDirectory("unit-settings-record") { dir =>
            projectOf(
              dir,
              sources = Seq("main.c" -> "int main(void) { return 0; }\n"),
              commands = Seq(("main.c", Seq("cc", "-c", "main.c")))
            )
            settingsOf(dir, "main.c")
            UnitSettingsReporter.isEnabled shouldBe false
            UnitSettingsReporter.records shouldBe empty
            ParseReporter.records shouldBe empty
          }
      }
  }

  /** Whether the host can run `command` and get an answer, the way the frontend's macro probe does:
    * a host without the driver cannot produce a `probed` record, and the case says so instead of
    * failing.
    */
  private def canRun(command: String): Boolean =
      try
        new ProcessBuilder(command, "--version").start().waitFor() == 0
      catch
        case _: Exception => false
end UnitSettingsRecordTests

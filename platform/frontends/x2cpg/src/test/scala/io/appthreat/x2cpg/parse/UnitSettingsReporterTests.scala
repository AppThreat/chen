package io.appthreat.x2cpg.parse

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

/** The collector behind the parse report's `units` section: what it keeps per translation unit, and
  * that it keeps nothing at all when the report is off.
  */
class UnitSettingsReporterTests extends AnyWordSpec with Matchers:

  private def recordOf(file: String, frontend: String = ParseReporter.Frontend.C): ParseUnitRecord =
      ParseUnitRecord(
        frontend = frontend,
        file = file,
        driver = "cc",
        entry = "GCC",
        macroSource = UnitSettingsReporter.MacroSource.Probed,
        language = UnitSettingsReporter.Language.C,
        standard = "gnu11",
        macroFingerprint = "6f1c0d9e1c4a2b7d8e5f3a2b1c0d9e8f",
        includeDirectories = Seq("/usr/include"),
        forcedIncludes = Seq("pre.h"),
        ownedHeaders = Seq("local.h")
      )

  "UnitSettingsReporter when disabled" should {

      "keep nothing, whatever a frontend records" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          UnitSettingsReporter.reset()
          UnitSettingsReporter.isEnabled shouldBe false
          UnitSettingsReporter.record(recordOf("main.c"))
          UnitSettingsReporter.recordCommandLine("main.c", Seq("edga", "main.c"))
          UnitSettingsReporter.recordDatabaseDuplicates(
            "dup.c",
            Seq(
              DatabaseCommand(".", Seq("cc", "-c", "dup.c")),
              DatabaseCommand(".", Seq("cc", "-O2", "-c", "dup.c"))
            ),
            0
          )
          UnitSettingsReporter.drop(ParseReporter.Frontend.C, "main.c")
          UnitSettingsReporter.records shouldBe empty
      }
  }

  "UnitSettingsReporter when enabled" should {

      "keep one record per unit and frontend, sorted by file" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            UnitSettingsReporter.isEnabled shouldBe true
            UnitSettingsReporter.record(recordOf("b.c"))
            UnitSettingsReporter.record(recordOf("a.c"))
            UnitSettingsReporter.record(recordOf("a.c", ParseReporter.Frontend.Edg))
            // a second record of the same unit and frontend replaces the first
            UnitSettingsReporter.record(recordOf("b.c").copy(standard = "gnu17"))
            UnitSettingsReporter.records shouldBe List(
              recordOf("a.c"),
              recordOf("a.c", ParseReporter.Frontend.Edg),
              recordOf("b.c").copy(standard = "gnu17")
            )
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }

      "normalize the separators of the file it records" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            UnitSettingsReporter.record(recordOf("lib\\pkg\\unit.c"))
            UnitSettingsReporter.records.head.file shouldBe "lib/pkg/unit.c"
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }

      "add the duplicate commands of the compilation database to the unit's record" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            val commands = Seq(
              DatabaseCommand("/work/proj", Seq("cc", "-DFIRST=1", "-c", "dup.c")),
              DatabaseCommand("/work/proj", Seq("cc", "-DSECOND=1", "-c", "dup.c"))
            )
            UnitSettingsReporter.recordDatabaseDuplicates("dup.c", commands, 0)
            UnitSettingsReporter.record(recordOf("dup.c"))
            UnitSettingsReporter.record(recordOf("plain.c"))
            val dup   = UnitSettingsReporter.records.find(_.file == "dup.c").get
            val plain = UnitSettingsReporter.records.find(_.file == "plain.c").get
            dup.databaseCommands shouldBe commands
            dup.usedDatabaseCommand shouldBe Some(0)
            plain.databaseCommands shouldBe empty
            plain.usedDatabaseCommand shouldBe None
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }

      "add the command line the edg frontend ran to its record" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            val command = Seq("/opt/edga", "--c11", "--edga-out", "/tmp/edga-1.json", "main.c")
            UnitSettingsReporter.record(recordOf("main.c", ParseReporter.Frontend.Edg))
            UnitSettingsReporter.recordCommandLine("main.c", command)
            UnitSettingsReporter.records.head.edgaCommandLine shouldBe command
            // a command line with no settings record behind it is kept on its own
            UnitSettingsReporter.recordCommandLine("other.c", Seq("edga", "other.c"))
            val other = UnitSettingsReporter.records.find(_.file == "other.c").get
            other.frontend shouldBe ParseReporter.Frontend.Edg
            other.edgaCommandLine shouldBe Seq("edga", "other.c")
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }

      "drop the record of a frontend for one unit" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            UnitSettingsReporter.record(recordOf("main.c"))
            UnitSettingsReporter.record(recordOf("main.c", ParseReporter.Frontend.Edg))
            UnitSettingsReporter.drop(ParseReporter.Frontend.C, "main.c")
            UnitSettingsReporter.records.map(_.frontend) shouldBe List(ParseReporter.Frontend.Edg)
            // dropping a unit nobody recorded is not an error
            UnitSettingsReporter.drop(ParseReporter.Frontend.C, "never-seen.c")
            UnitSettingsReporter.records should have size 1
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }

      "fingerprint the macros a unit is parsed with" in {
          UnitSettingsReporter.macroFingerprint(
            Map("__GNUC__" -> "4", "__x86_64__" -> "1")
          ) shouldBe
              UnitSettingsReporter.macroFingerprint(Map("__x86_64__" -> "1", "__GNUC__" -> "4"))
          UnitSettingsReporter.macroFingerprint(Map("__GNUC__" -> "4")) should not be
              UnitSettingsReporter.macroFingerprint(Map("__GNUC__" -> "13"))
          UnitSettingsReporter.macroFingerprint(Map("__GNUC__" -> "4")) should have size 32
      }

      "start from empty after a reset" in {
          val tmp = Files.createTempDirectory("unit-settings-reporter")
          System.setProperty("chen.parse.report", tmp.resolve("unused.json").toString)
          try
            UnitSettingsReporter.reset()
            UnitSettingsReporter.record(recordOf("main.c"))
            UnitSettingsReporter.recordDatabaseDuplicates(
              "main.c",
              Seq(DatabaseCommand(".", Seq("cc", "-c", "main.c"))),
              0
            )
            UnitSettingsReporter.records should have size 1
            UnitSettingsReporter.reset()
            UnitSettingsReporter.records shouldBe empty
            UnitSettingsReporter.record(recordOf("later.c"))
            UnitSettingsReporter.records.head.databaseCommands shouldBe empty
          finally
            System.clearProperty("chen.parse.report")
            UnitSettingsReporter.reset()
      }
  }
end UnitSettingsReporterTests

package io.appthreat.edg2atom.parser

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.CompileDatabase
import io.appthreat.c2cpg.parser.ProjectSources
import io.appthreat.x2cpg.parse.{ParseReporter, UnitSettingsReporter}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The records the parse report's `units` section keeps for the units edg2atom exports: the command
  * line that ran, the settings the unit was parsed with, and the settings record of the C frontend,
  * which stands only for units the export did not read.
  */
class EdgaUnitRecordTests extends AnyWordSpec with Matchers:

  /** The stub front end writes nothing but a unit document naming the file it was given. */
  private def exportingEdga: String =
      """#!/bin/sh
      |out=""
      |previous=""
      |for argument in "$@"; do
      |  if [ "$previous" = "--edga-out" ]; then out="$argument"; fi
      |  previous="$argument"
      |done
      |printf '{"tu": {"path": "%s", "status": "ok", "language": "c"}}' "$out" > "$out"
      |""".stripMargin

  private def failingEdga: String = "#!/bin/sh\nexit 1\n"

  private def withReporterEnabled[T](script: String)(body: => T): T =
    val stub = File.newTemporaryDirectory("edga-unit-record-bin") / "edga"
    stub.writeText(script)
    stub.toJava.setExecutable(true)
    System.setProperty("chen.parse.report", "unused")
    System.setProperty("edga.path", stub.toString)
    UnitSettingsReporter.reset()
    ParseReporter.reset()
    try body
    finally
      System.clearProperty("chen.parse.report")
      System.clearProperty("edga.path")
      UnitSettingsReporter.reset()
      ParseReporter.reset()

  /** A project whose one unit a compilation database compiles with the host's cc. */
  private def projectOf: File =
    val dir = File.newTemporaryDirectory("edga-unit-record")
    (dir / "single.c").writeText("int add(int a, int b) {\n  return a + b;\n}\n")
    (dir / CompileDatabase.FileName).writeText(
      """[{"directory": ".", "file": "single.c", "arguments": ["cc", "-c", "single.c"]}]"""
    )
    dir

  "the units edg2atom exports" should {

      "record the unit with the exact command line, and the C frontend's record goes" in
          withReporterEnabled(exportingEdga) {
              val dir = projectOf
              val config = Config()
                  .withInputPath(dir.toString)
                  .withCompileCommands((dir / CompileDatabase.FileName).pathAsString)
              val runner = new EdgaRunner(config, new ProjectSources(config))
              runner.exportUnit(dir.path.resolve("single.c"), 60).isDefined shouldBe true

              val records = UnitSettingsReporter.records
              records should have size 1
              val record = records.head
              record.frontend shouldBe ParseReporter.Frontend.Edg
              record.file shouldBe "single.c"
              record.driver shouldBe "cc"
              record.entry shouldBe "GCC"
              // the compiler the command names is asked for its macros, as the C frontend does
              record.macroSource shouldBe UnitSettingsReporter.MacroSource.Probed
              record.language shouldBe UnitSettingsReporter.Language.C
              val command = record.edgaCommandLine
              command should not be empty
              command.head should endWith("edga")
              command should contain("--edga-root")
              command.last should endWith("single.c")
              // the unit is the edg frontend's: no settings record under the C frontend stays
              records.map(_.frontend) should not contain ParseReporter.Frontend.C
          }

      "keep the C frontend's settings record when the export cannot read the unit" in
          withReporterEnabled(failingEdga) {
              val dir    = projectOf
              val config = Config().withInputPath(dir.toString)
              val runner = new EdgaRunner(config, new ProjectSources(config))
              runner.exportUnit(dir.path.resolve("single.c"), 60) shouldBe None

              val records = UnitSettingsReporter.records
              records.map(_.frontend).toSet shouldBe
                  Set(ParseReporter.Frontend.Edg, ParseReporter.Frontend.C)
              // the command that failed is part of the record: it is what a reader would rerun
              records.find(_.frontend == ParseReporter.Frontend.Edg).get.edgaCommandLine should not be empty
              // without a compiler to ask, the unit is parsed with the built-in macros, and the
              // record names them
              val cRecord = records.find(_.frontend == ParseReporter.Frontend.C).get
              cRecord.file shouldBe "single.c"
              cRecord.macroSource shouldBe UnitSettingsReporter.MacroSource.Table
          }
  }
end EdgaUnitRecordTests

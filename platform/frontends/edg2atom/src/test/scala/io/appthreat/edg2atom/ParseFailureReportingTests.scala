package io.appthreat.edg2atom

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** chen#255: a translation unit edga cannot export is lost with one warn line, and when the CDT
  * fallback reads it nothing says which frontend finally did. The failures are forced with a stub
  * edga that exports nothing, because the real front end is not installed here; the CDT fallback
  * that rescues the files is the real one.
  */
class ParseFailureReportingTests extends AnyWordSpec with Matchers:

  private def withReporterEnabled[T](edgaPath: Option[String])(body: => T): T =
    System.setProperty("chen.parse.report", "unused")
    ParseReporter.reset()
    edgaPath.foreach(System.setProperty("edga.path", _))
    try body
    finally
      System.clearProperty("chen.parse.report")
      System.clearProperty("edga.path")
      ParseReporter.reset()

  private def buildProject(): File =
    val dir = File.newTemporaryDirectory("edg-parse-report")
    (dir / "good.c").writeText("int add(int a, int b) {\n  return a + b;\n}\n")
    dir

  /** A stub front end that fails every unit: the real edga is not required to see what happens when
    * it cannot export.
    */
  private def failingEdga(): String =
    val stub = File.newTemporaryDirectory("edg-parse-report-bin") / "edga"
    stub.writeText("#!/bin/sh\nexit 1\n")
    stub.toJava.setExecutable(true)
    stub.toString

  private def buildCpg(input: File, fallback: Boolean): Cpg =
    val config = Config().withInputPath(input.toString).withOutputPath(
      File.newTemporaryDirectory("edg-parse-report-out").toString
    )
    new Edg2Atom(fallbackToCdt = fallback).createCpg(config).get

  "edg2atom parse failure reporting" should {

      "record the unit edga lost and the frontend that finally read it" in withReporterEnabled(
        Some(failingEdga())
      ) {
          val cpg = buildCpg(buildProject(), fallback = true)
          try
            // one record: edga failed on the unit, and the CDT fallback read it into the graph
            ParseReporter.records shouldBe List(
              io.appthreat.x2cpg.parse.ParseFailureRecord(
                "edg",
                "good.c",
                "partial",
                "parse",
                "edga exported no unit and reported no diagnostic; the c frontend read it instead"
              )
            )

            // the fallback really wrote the graph
            cpg.method.name("add").l should have size 1
          finally cpg.close()
      }

      "record the unit as lost when there is no fallback" in withReporterEnabled(
        Some(failingEdga())
      ) {
          val cpg = buildCpg(buildProject(), fallback = false)
          try
            ParseReporter.records shouldBe List(
              io.appthreat.x2cpg.parse.ParseFailureRecord(
                "edg",
                "good.c",
                "unparsed",
                "parse",
                "edga exported no unit and reported no diagnostic"
              )
            )
            cpg.method.name("add").l shouldBe empty
          finally cpg.close()
      }

      "record nothing when the reporter is disabled" in {
          System.clearProperty("chen.parse.report")
          ParseReporter.reset()
          System.setProperty("edga.path", failingEdga())
          try
            val cpg = buildCpg(buildProject(), fallback = true)
            try ParseReporter.records shouldBe empty
            finally cpg.close()
          finally System.clearProperty("edga.path")
      }
  }
end ParseFailureReportingTests

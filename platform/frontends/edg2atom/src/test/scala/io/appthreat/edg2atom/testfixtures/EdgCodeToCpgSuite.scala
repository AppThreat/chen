package io.appthreat.edg2atom.testfixtures

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.parser.EdgaRunner
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, DefaultTestCpg, LanguageFrontend}
import io.shiftleft.codepropertygraph.Cpg

trait EdgFrontend extends LanguageFrontend:
  def execute(sourceCodePath: java.io.File): Cpg =
    val cpgOutFile = File.newTemporaryFile("edg2atom.bin")
    cpgOutFile.deleteOnExit()
    val config = getConfig()
        .map(_.asInstanceOf[Config])
        .getOrElse(Config())
        .withInputPath(sourceCodePath.getAbsolutePath)
        .withOutputPath(cpgOutFile.pathAsString)
        .withFunctionBodies(true)
        .withAstCache(false)
    new Edg2Atom().createCpg(config).get

class DefaultTestCpgWithEdg(val fileSuffix: String) extends DefaultTestCpg with EdgFrontend

/** Code to graph through edga. The tests of a suite are cancelled when edga is not installed (set
  * EDGA_PATH, the edga.path system property, or put it on the PATH).
  */
class EdgCodeToCpgSuite(fileSuffix: String = ".cpp")
    extends Code2CpgFixture(() => new DefaultTestCpgWithEdg(fileSuffix)):

  protected val edgaAvailable: Boolean = EdgaRunner.locate().isDefined

  /** Cancels the running test when edga is not installed. */
  protected def requireEdga(): Unit = assume(edgaAvailable, "edga is not installed")

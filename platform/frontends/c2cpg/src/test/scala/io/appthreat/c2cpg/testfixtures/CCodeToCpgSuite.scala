package io.appthreat.c2cpg.testfixtures

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, DefaultTestCpg, LanguageFrontend}
import io.shiftleft.codepropertygraph.Cpg
import org.scalatest.Inside

trait C2CpgFrontend extends LanguageFrontend {
  def execute(sourceCodePath: java.io.File): Cpg = {
    val cpgOutFile = File.newTemporaryFile("c2cpg.bin")
    cpgOutFile.deleteOnExit()
    val c2cpg = new C2Cpg()

    val config = getConfig()
      .map(_.asInstanceOf[Config])
      .getOrElse(Config(includeComments = true))
      .withInputPath(sourceCodePath.getAbsolutePath)
      .withOutputPath(cpgOutFile.pathAsString)

    c2cpg.createCpg(config).get
  }
}

class DefaultTestCpgWithC(val fileSuffix: String) extends DefaultTestCpg with C2CpgFrontend

class CCodeToCpgSuite(fileSuffix: String = FileDefaults.C_EXT)
    extends Code2CpgFixture(() => new DefaultTestCpgWithC(fileSuffix))
    with Inside

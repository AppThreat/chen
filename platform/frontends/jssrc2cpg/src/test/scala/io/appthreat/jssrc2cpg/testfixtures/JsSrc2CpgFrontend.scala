package io.appthreat.jssrc2cpg.testfixtures

import better.files.File
import io.appthreat.jssrc2cpg.{Config, JsSrc2Cpg}
import io.shiftleft.codepropertygraph.Cpg
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, DefaultTestCpg, LanguageFrontend}
import org.scalatest.Inside

trait JsSrc2CpgFrontend extends LanguageFrontend {
  def execute(sourceCodePath: java.io.File): Cpg = {
    val cpgOutFile = File.newTemporaryFile(suffix = "cpg.bin")
    cpgOutFile.deleteOnExit()
    val jssrc2cpg = new JsSrc2Cpg()
    val config = getConfig()
      .map(_.asInstanceOf[Config])
      .getOrElse(Config(tsTypes = false))
      .withInputPath(sourceCodePath.getAbsolutePath)
      .withOutputPath(cpgOutFile.pathAsString)
    jssrc2cpg.createCpg(config).get
  }
}

class DefaultTestCpgWithJsSrc(val fileSuffix: String) extends DefaultTestCpg with JsSrc2CpgFrontend

class JsSrc2CpgSuite(fileSuffix: String = ".js")
    extends Code2CpgFixture(() => new DefaultTestCpgWithJsSrc(fileSuffix))
    with Inside

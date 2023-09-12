package io.appthreat.jssrc2cpg.testfixtures

import io.appthreat.x2cpg.testfixtures.CfgTestCpg

class JsCfgTestCpg extends CfgTestCpg with JsSrc2CpgFrontend {
  override val fileSuffix: String = ".js"
}

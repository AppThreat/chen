package io.appthreat.c2cpg.testfixtures

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.passes.AstCreationPass
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatest.Inside

abstract class AbstractPassTest extends AnyWordSpec with Matchers with Inside {

  protected abstract class Fixture

  protected object AstFixture extends Fixture {
    def apply(code: String, fileName: String = "file.c")(f: Cpg => Unit): Unit = {
      File.usingTemporaryDirectory("c2cpgtest") { dir =>
        val cpg  = newEmptyCpg()
        val file = dir / fileName
        file.write(code)
        val config = Config().withInputPath(dir.toString()).withOutputPath(dir.toString())
        new AstCreationPass(cpg, config).createAndApply()
        f(cpg)
        file.delete()
      }
    }

    def createCpg(code: String): Cpg = {
      val cpg = newEmptyCpg()
      File.usingTemporaryDirectory("c2cpgtest") { dir =>
        val file = dir / "file.c"
        file.write(code)
        val config = Config().withInputPath(dir.toString()).withOutputPath(dir.toString())
        new AstCreationPass(cpg, config).createAndApply()
      }
      cpg
    }
  }

}

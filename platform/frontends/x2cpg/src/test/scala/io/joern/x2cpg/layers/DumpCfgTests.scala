package io.appthreat.x2cpg.layers

import better.files.File
import io.shiftleft.semanticcpg.testing.MockCpg
import io.shiftleft.semanticcpg.layers.LayerCreatorContext
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Files

class DumpCfgTests extends AnyWordSpec with Matchers {

  "DumpCfg" should {

    "create two dot files for a CPG containing two methods" in {
      val cpg = MockCpg()
        .withMetaData()
        .withMethod("foo")
        .withMethod("bar")
        .cpg

      val context = new LayerCreatorContext(cpg)
      new Base().run(context)
      new ControlFlow().run(context)
      File.usingTemporaryDirectory("dumpcfg") { tmpDir =>
        val opts = CfgDumpOptions(tmpDir.path.toString)
        new DumpCfg(opts).run(context)
        (tmpDir / "0-cfg.dot").exists shouldBe true
        (tmpDir / "1-cfg.dot").exists shouldBe true
        Files.size((tmpDir / "0-cfg.dot").path) should not be 0
        Files.size((tmpDir / "1-cfg.dot").path) should not be 0
      }
    }

  }

}

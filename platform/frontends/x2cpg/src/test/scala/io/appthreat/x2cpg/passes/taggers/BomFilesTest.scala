package io.appthreat.x2cpg.passes.taggers

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class BomFilesTest extends AnyWordSpec with Matchers:

  "BomFiles" should {
      "recognise cdxgen's and depscan's BOM and VDR file names" in {
          Seq(
            "bom.json",
            "app/bom.json",
            "/tmp/reports/sbom-postbuild-js.cdx.json",
            "C:\\reports\\sbom-js.json",
            "reports/depscan-bom.vdr.json",
            "x-cdx.json"
          ).filterNot(BomFiles.isBom) shouldBe empty
      }
      "not take other JSON, or a package's own BOM under node_modules, for one" in {
          Seq(
            "package.json",
            "tsconfig.json",
            "bom.json.map",
            "node_modules/some-pkg/bom.json",
            "reports/depscan-risk-js.json"
          ).filter(BomFiles.isBom) shouldBe empty
      }
  }
end BomFilesTest

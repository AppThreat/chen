package io.appthreat.x2cpg.passes.taggers

import better.files.File
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The component locations a BOM gives (decision 0001, P5). `cdxgen-13.7.0-vendored.json` is a real
  * BOM: cdxgen 13.7.0 run with `-t c` on its own `test/data/brotli-exposure/vendored` project.
  */
class BomComponentLocationsTests extends AnyWordSpec with Matchers:

  private def realBom: String =
      scala.io.Source.fromResource("bom/cdxgen-13.7.0-vendored.json").mkString

  private def withRoot[T](dirs: String*)(f: File => T): T =
    val root = File.newTemporaryDirectory("bomloc")
    try
      dirs.foreach(d => (root / d).createDirectories())
      f(root)
    finally root.delete(swallowIOExceptions = true)

  private def bomOf(components: String*): String =
      s"""{"bomFormat":"CycloneDX","components":[${components.mkString(",")}]}"""

  private def component(name: String, purl: String, props: (String, String)*): String =
    val ps = props.map((n, v) => s"""{"name":"$n","value":"${v.replace("\\", "\\\\")}"}""")
    s"""{"type":"library","name":"$name","purl":"$purl","properties":[${ps.mkString(",")}]}"""

  "a real cdxgen BOM" should {
      "locate the vendored library by cdx:vendored:path, with the component's name" in withRoot(
        "third_party/brotli"
      ) { root =>
          BomComponentLocations.read(Seq(realBom), root.path) shouldBe Seq(
            BomLocatedComponent(
              "third_party/brotli",
              "pkg:generic/brotli@1.2.0#third_party/brotli",
              "brotli"
            )
          )
      }
      "locate nothing when the directory is not in the input" in withRoot("src") { root =>
          BomComponentLocations.read(Seq(realBom), root.path) shouldBe empty
      }
  }

  "a location" should {
      "be read from cdx:cmake:sourceDir too" in withRoot("deps/zlib") { root =>
        val bom = bomOf(component(
          "zlib",
          "pkg:github/madler/zlib@v1.3",
          "cdx:cmake:sourceDir" -> "deps/zlib"
        ))
        BomComponentLocations.read(Seq(bom), root.path) shouldBe Seq(
          BomLocatedComponent("deps/zlib", "pkg:github/madler/zlib@v1.3", "madler/zlib")
        )
      }
      "accept an absolute path inside the root and a backslash path" in withRoot(
        "third_party/a",
        "third_party/b"
      ) { root =>
        val bom = bomOf(
          component(
            "a",
            "pkg:generic/a@1",
            "cdx:vendored:path" -> (root / "third_party" / "a").pathAsString
          ),
          component("b", "pkg:generic/b@1", "cdx:vendored:path" -> "third_party\\b")
        )
        BomComponentLocations.read(Seq(bom), root.path).map(_.path) shouldBe
            Seq("third_party/a", "third_party/b")
      }
      "be ignored when it lies outside the root, is the root, or does not exist" in withRoot(
        "inside"
      ) { root =>
        val bom = bomOf(
          component("up", "pkg:generic/up@1", "cdx:vendored:path"       -> "../elsewhere"),
          component("abs", "pkg:generic/abs@1", "cdx:vendored:path"     -> "/usr/lib"),
          component("self", "pkg:generic/self@1", "cdx:vendored:path"   -> "."),
          component("gone", "pkg:generic/gone@1", "cdx:vendored:path"   -> "missing/dir"),
          component("empty", "pkg:generic/empty@1", "cdx:vendored:path" -> "")
        )
        BomComponentLocations.read(Seq(bom), root.path) shouldBe empty
      }
      "be left unmarked when two components claim the path" in withRoot(
        "third_party/x",
        "third_party/y"
      ) { root =>
        val bom = bomOf(
          component("x1", "pkg:generic/x1@1", "cdx:vendored:path" -> "third_party/x"),
          component("x2", "pkg:generic/x2@1", "cdx:vendored:path" -> "third_party/x"),
          component("y", "pkg:generic/y@1", "cdx:vendored:path"   -> "third_party/y")
        )
        BomComponentLocations.read(Seq(bom), root.path).map(_.path) shouldBe
            Seq("third_party/y")
      }
      "not be taken from evidence occurrences or the SrcFile property" in withRoot(
        "src",
        "third_party/x"
      ) { root =>
        val bom = bomOf(
          """{"type":"library","name":"express","purl":"pkg:npm/express@4.19.2",
              |"evidence":{"occurrences":[{"location":"src"}]},
              |"properties":[{"name":"internal:SrcFile","value":"third_party/x"}]}""".stripMargin
        )
        BomComponentLocations.read(Seq(bom), root.path) shouldBe empty
      }
  }

  "a component's module" should {
      "be spelled as its ecosystem spells it" in {
          BomComponentLocations.moduleOf(
            "pkg:npm/%40babel/parser@7.24.0",
            "parser",
            "@babel"
          ) shouldBe
              "@babel/parser"
          BomComponentLocations.moduleOf(
            "pkg:maven/org.apache.commons/commons-lang3@3.14",
            "commons-lang3",
            "org.apache.commons"
          ) shouldBe
              "org.apache.commons:commons-lang3"
          BomComponentLocations.moduleOf("pkg:pypi/pyyaml@6.0.1", "PyYAML", "") shouldBe "pyyaml"
          BomComponentLocations.moduleOf(
            "pkg:generic/brotli@1.2.0#third_party/brotli",
            "brotli",
            ""
          ) shouldBe
              "brotli"
      }
  }
end BomComponentLocationsTests

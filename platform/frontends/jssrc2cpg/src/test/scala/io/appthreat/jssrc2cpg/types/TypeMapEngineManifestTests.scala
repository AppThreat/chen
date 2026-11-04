package io.appthreat.jssrc2cpg.types

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.astcreation.AstCreator
import io.appthreat.jssrc2cpg.parser.BabelJsonParser
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.x2cpg.ValidationMode
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.Paths
import java.util.concurrent.ConcurrentHashMap

/** jssrc2cpg decides whether a type map is native from the types record of astgen_manifest.jsonl in
  * the astgen output, and only when astgen wrote no record (atom-parsetools 1.x, or a user-supplied
  * output directory without one) from the request. The record is what ran; the request is what was
  * asked for, and astgen 2.x falls back to TypeScript 6 under its default when the native binary is
  * missing. Which of the two decided is not a graph-observable difference by design (that is what
  * NativeTypeMapTests pins: both engines' strings lead to the same names), so these tests read the
  * decision where it is made.
  */
class TypeMapEngineManifestTests extends AnyWordSpec with Matchers:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  private val nativeRecord =
      """{"kind":"types","engine":"native","requested":"native","requestedBy":"default","astgen_version":"4.7.0"}"""
  private val ts6FallbackRecord =
      """{"kind":"types","engine":"ts6","requested":"native","requestedBy":"default","fallback_reason":"parsa was not found (ASTGEN_NATIVE_BIN, next to astgen.js, PATH); using TypeScript 6 for types.","astgen_version":"4.7.0"}"""

  /** The fixture parse, typed as the given engine record and configuration say. */
  private def readsAsNative(engine: Option[String], configure: Config => Config): Boolean =
    val root   = Paths.get(getClass.getResource("/native-typemap").toURI)
    val parsed = BabelJsonParser.readFile(root, root.resolve("native-types.ts.json"))
    val dir    = File.newTemporaryDirectory("jssrc2cpgEngine").toJava.toString
    val config = configure(
      Config(tsTypes = true).withInputPath(dir).withOutputPath(dir)
    )
    new AstCreator(config, parsed, new ConcurrentHashMap[(String, String), Boolean](), engine)
        .nativeTypeMap

  "the type map engine" should {
      "be native for a native record with nothing configured, and TypeScript 6 for a fallback record" in {
          readsAsNative(Some("native"), identity) shouldBe true
          readsAsNative(Some("ts6"), identity) shouldBe false
      }

      "come from the manifest even against a contradicting request" in {
          // astgen was asked for native and fell back: the record says what ran
          readsAsNative(Some("ts6"), _.withAstGenTypes("native")) shouldBe false
          // a manifest from the run that wrote the type maps, whoever asks now
          readsAsNative(Some("native"), _.withAstGenTypes("ts6")) shouldBe true
      }

      "fall back to the request when astgen wrote no record" in {
          readsAsNative(None, identity) shouldBe false
          readsAsNative(None, _.withAstGenTypes("native")) shouldBe true
      }
  }

  "the manifest reader" should {
      "take the engine of the last types record and skip what is not one" in {
          File.usingTemporaryDirectory("jssrc2cpgManifest") { dir =>
            val manifest = dir / "astgen_manifest.jsonl"
            AstGenRunner.typeMapEngineOf(manifest) shouldBe None

            manifest.write(
              s"""not json at all
                   |{"kind":"other","engine":"native"}
                   |$nativeRecord
                   |{"kind":"types","engine":"wasm"}
                   |""".stripMargin
            )
            AstGenRunner.typeMapEngineOf(manifest) shouldBe Some("native")

            manifest.append(s"$ts6FallbackRecord\n")
            AstGenRunner.typeMapEngineOf(manifest) shouldBe Some("ts6")
          }
      }
  }

  "the runner" should {
      "report the manifest's engine in its result" in {
          val root = File(getClass.getResource("/native-typemap").toURI)
          File.usingTemporaryDirectory("jssrc2cpgEngineRun") { dir =>
            def runWith(record: Option[String]) =
              Seq("native-types.ts", "native-types.ts.json", "native-types.ts.typemap").foreach {
                  n =>
                    val dest = dir / n
                    dest.delete(swallowIOExceptions = true)
                    (root / n).copyTo(dest)
              }
              (dir / "astgen_manifest.jsonl").delete(swallowIOExceptions = true)
              record.foreach(r => (dir / "astgen_manifest.jsonl").write(r + "\n"))
              // the .json output is already there, so no astgen is started: the directory is
              // reused the way a user-supplied output directory is
              val config = Config(tsTypes = true)
                  .withInputPath(dir.toString).withOutputPath(dir.toString)
                  .withAstGenOutDir(dir.toString)
              new AstGenRunner(config).execute(dir).typeMapEngine

            runWith(Some(nativeRecord)) shouldBe Some("native")
            runWith(Some(ts6FallbackRecord)) shouldBe Some("ts6")
            runWith(None) shouldBe None
          }
      }
  }
end TypeMapEngineManifestTests

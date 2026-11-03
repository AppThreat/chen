package io.appthreat.jssrc2cpg.types

import better.files.File
import io.appthreat.jssrc2cpg.passes.{
    AbstractPassTest,
    AstCreationPass,
    BuiltinTypesPass,
    Defines,
    TypeNodePass
}
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.jssrc2cpg.Config
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** jssrc2cpg reading a type map written by the native binary (TypeScript 7's checker): the member
  * order and quote style differ from TypeScript 6's, and the type names chen derives must not.
  */
class NativeTypeMapTests extends AbstractPassTest:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  /** Builds the CPG from the committed astgen output (no astgen involved); `engine` is what the
    * configuration says wrote the type map.
    */
  private def withFixture(engine: Option[String])(f: Cpg => Unit): Unit =
    val root = File(getClass.getResource("/native-typemap").toURI)
    File.usingTemporaryDirectory("jssrc2cpgNativeTypeMap") { dir =>
      Seq("native-types.ts", "native-types.ts.json", "native-types.ts.typemap").foreach { n =>
          (root / n).copyToDirectory(dir)
      }
      val base   = Config(tsTypes = true).withInputPath(dir.toString).withOutputPath(dir.toString)
      val config = engine.fold(base)(base.withAstGenTypes).withAstGenOutDir(dir.toString)
      val cpg    = newEmptyCpg()
      val result = new AstGenRunner(config).execute(dir)
      val pass   = new AstCreationPass(cpg, result, config)
      pass.createAndApply()
      new TypeNodePass(pass.allUsedTypes(), cpg).createAndApply()
      new BuiltinTypesPass(cpg).createAndApply()
      f(cpg)
    }

  /** The type chen derives for the first identifier named `name` that has a type other than ANY. */
  private def typeOf(cpg: Cpg, name: String): String =
      cpg.identifier(name).typeFullName.filterNot(_ == Defines.Any).headOption.getOrElse(
        Defines.Any
      )

  "a native type map" should {
      "name an object type `object`, whatever quote the checker kept for its members" in withFixture(
        Some("native")
      ) { cpg =>
          // the map says  { mode: 'strict'; ... }  (TypeScript 7 keeps the quote of `'strict' as const`)
          typeOf(cpg, "config") shouldBe Defines.Object
      }

      "name the object types alike whatever the order TypeScript 7 gives their members" in withFixture(
        Some("native")
      ) { cpg =>
          typeOf(cpg, "holder") shouldBe Defines.Object
      }

      "name a union of string literals by their type, so that the name does not depend on the checker" in withFixture(
        Some("native")
      ) { cpg =>
          // the map says  (flag: boolean) => 'left' | "right"; the arrow returns a string either way
          cpg.method.methodReturn.typeFullName.toSet should contain(Defines.String)
      }

      "give the same names when the setting does not say native" in withFixture(None) { cpg =>
        typeOf(cpg, "config") shouldBe Defines.Object
        typeOf(cpg, "holder") shouldBe Defines.Object
        cpg.method.methodReturn.typeFullName.toSet should contain(Defines.String)
      }
  }

end NativeTypeMapTests

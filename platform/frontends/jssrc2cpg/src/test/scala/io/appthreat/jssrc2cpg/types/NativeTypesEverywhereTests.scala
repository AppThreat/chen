package io.appthreat.jssrc2cpg.types

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.appthreat.jssrc2cpg.passes.{
    AbstractPassTest,
    AstCreationPass,
    BuiltinTypesPass,
    Defines,
    TypeNodePass
}
import io.appthreat.jssrc2cpg.utils.AstGenRunner
import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.newEmptyCpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The types of the native type map reach the graph for every kind of node, not only for the
  * declarations that start at an offset of their own. The fixture (`native-kinds`) was written by
  * the native binary, which also writes the type of each node by its extent (`.typespans`): the
  * type map keeps one type for all the nodes that start at one offset (`svc`, `svc.load` and
  * `svc.load(user)`).
  */
class NativeTypesEverywhereTests extends AbstractPassTest:

  private implicit val schemaValidationMode: ValidationMode = ValidationMode.Enabled

  private def withFixture(spans: Boolean)(f: Cpg => Unit): Unit =
    val root = File(getClass.getResource("/native-kinds").toURI)
    File.usingTemporaryDirectory("jssrc2cpgNativeKinds") { dir =>
      root.children.filter(c => spans || !c.name.endsWith(".typespans")).foreach(
        _.copyToDirectory(dir)
      )
      val config = Config(tsTypes = true).withInputPath(dir.toString)
          .withOutputPath(dir.toString).withAstGenOutDir(dir.toString)
      val cpg    = newEmptyCpg()
      val result = new AstGenRunner(config).execute(dir)
      val pass   = new AstCreationPass(cpg, result, config)
      pass.createAndApply()
      new TypeNodePass(pass.allUsedTypes(), cpg).createAndApply()
      new BuiltinTypesPass(cpg).createAndApply()
      f(cpg)
    }

  private def inFile(cpg: Cpg) = cpg.call.filter(_.file.name.exists(_.endsWith("native-kinds.ts")))

  "with the type of each node by its extent" should {
      "type an await expression with the awaited type" in withFixture(true) { cpg =>
          inFile(cpg).name("<operator>.await").typeFullName.l shouldBe List("User", "__ecma.Array")
      }

      "type a call with its return type and its callee with the function type" in withFixture(
        true
      ) { cpg =>
        inFile(cpg).nameExact("makeUser").lineNumber(18).typeFullName.l shouldBe List("User")
        inFile(cpg).nameExact("load").typeFullName.l shouldBe List("User")
        inFile(cpg).nameExact("fetchUser").typeFullName.l shouldBe List("Promise")
        // the callee is a function, which no class names, and has not the type of the call it starts
        cpg.identifier("fetchUser").typeFullName.toSet shouldBe Set(Defines.Any)
      }

      "not give an identifier the type of the longer expression that starts where it does" in withFixture(
        true
      ) { cpg =>
        // `svc.load(user)` on line 13 and `loaded.name + ...` on line 19
        cpg.identifier("svc").lineNumber(13).typeFullName.toSet shouldBe Set("Svc")
        cpg.identifier("loaded").lineNumber(19).typeFullName.toSet shouldBe Set("User")
        cpg.identifier("first").lineNumber(19).typeFullName.toSet shouldBe Set("User")
      }

      "leave an identifier without a type of its own untyped, whatever starts at its offset" in withFixture(
        true
      ) { cpg =>
          // `anyVal as User`: the type map has User at the offset of `anyVal`, the span map has nothing
          // for the identifier, which is `any`
          cpg.identifier("anyVal").lineNumber(26).typeFullName.toSet shouldBe Set(Defines.Any)
      }

      "type the temporary of a call on an expression with the type of that expression" in withFixture(
        true
      ) { cpg =>
          // `base.name.trim()`: the receiver `base.name` is held in a temporary
          cpg.identifier.name("_tmp_.*").lineNumber(28).typeFullName.toSet shouldBe Set(
            Defines.String
          )
      }

      "type a member access with the type of the member" in withFixture(true) { cpg =>
        inFile(cpg).name("<operator>.fieldAccess").code("svc.items").typeFullName.l shouldBe List(
          "__ecma.Array"
        )
        inFile(cpg).name("<operator>.fieldAccess").code("cfg.owner").typeFullName.l shouldBe List(
          "User"
        )
        inFile(cpg).name("<operator>.fieldAccess").code("made.id").typeFullName.l shouldBe List(
          Defines.Number
        )
      }

      "type the operators of an expression" in withFixture(true) { cpg =>
          inFile(cpg).name("<operator>.addition").typeFullName.toSet shouldBe Set(Defines.String)
      }

      "type the declarations of a destructuring" in withFixture(true) { cpg =>
        cpg.local("first").typeFullName.l shouldBe List("User")
        cpg.local("renamed").typeFullName.l shouldBe List(Defines.String)
        // the temporaries hold the destructured value, and so do the references to them
        cpg.local("_tmp_0").typeFullName.l should contain("__ecma.Array")
        cpg.identifier("_tmp_0").lineNumber(14).typeFullName.toSet shouldBe Set("__ecma.Array")
        cpg.identifier("_tmp_1").lineNumber(15).typeFullName.toSet shouldBe Set("User")
      }

      "type the temporaries of object and array literals" in withFixture(true) { cpg =>
        cpg.local("_tmp_2").typeFullName.l shouldBe List(Defines.Object)
        cpg.identifier("_tmp_2").typeFullName.toSet shouldBe Set(
          Defines.Object
        )
        cpg.local("_tmp_3").typeFullName.l should contain("__ecma.Array")
        cpg.identifier("_tmp_3").typeFullName.toSet shouldBe Set("__ecma.Array")
      }

      "type the locals of an import specifier" in withFixture(true) { cpg =>
        (cpg.local("makeUser").typeFullName.toSet should not).contain("() => User")
        cpg.local("defaultUser").typeFullName.toSet should contain("User")
        cpg.identifier("defaultUser").lineNumber(1).typeFullName.toSet shouldBe Set("User")
      }

      "type a new expression and its allocation" in withFixture(true) { cpg =>
        inFile(cpg).name("<operator>.new").lineNumber(22).typeFullName.l shouldBe List("Svc")
        inFile(cpg).name("<operator>.alloc").lineNumber(22).typeFullName.l shouldBe List("Svc")
        cpg.local("_tmp_4").typeFullName.l should contain("Svc")
        cpg.identifier("_tmp_4").typeFullName.toSet shouldBe Set("Svc")
      }

      "type the value of a default export" in withFixture(true) { cpg =>
        inFile(cpg).name("<operator>.assignment").code("exports\\[\"default\"\\] = instance")
            .typeFullName.l shouldBe List("Svc")
        inFile(cpg).name("<operator>.indexAccess").code("exports\\[\"default\"\\]")
            .typeFullName.l shouldBe List("Svc")
        cpg.identifier("instance").lineNumber(23).typeFullName.toSet shouldBe Set("Svc")
      }

      "type the assignment of a declaration with the declared type" in withFixture(true) { cpg =>
        inFile(cpg).name("<operator>.assignment").code("const user = await fetchUser\\(\\)")
            .typeFullName.l shouldBe List("User")
        inFile(cpg).name("<operator>.assignment").code("const instance = new Svc\\(\\)")
            .typeFullName.l shouldBe List("Svc")
      }

      "type the return of a function without an annotation" in withFixture(true) { cpg =>
          cpg.method.fullName(".*:run").methodReturn.typeFullName.l shouldBe List("Promise")
      }

      "give a method the return type as its return and keep the signature for its member" in withFixture(
        true
      ) { cpg =>
        cpg.method.fullName(".*:Svc:load").methodReturn.typeFullName.l shouldBe List("User")
        cpg.member("load").typeFullName.l shouldBe List(Defines.Any)
      }
  }

  "without the type of each node by its extent" should {
      "leave the calls as they were, with the type map alone" in withFixture(false) { cpg =>
        inFile(cpg).name("<operator>.await").typeFullName.toSet shouldBe Set(Defines.Any)
        inFile(cpg).nameExact("load").typeFullName.l shouldBe List(Defines.Any)
        inFile(cpg).name("<operator>.new").lineNumber(22).typeFullName.l shouldBe List(
          Defines.Any
        )
        inFile(cpg).name("<operator>.fieldAccess").code("svc.items").typeFullName.l shouldBe List(
          Defines.Any
        )
        cpg.local("first").typeFullName.l shouldBe List(Defines.Any)
        cpg.method.fullName(".*:Svc:load").methodReturn.typeFullName.l shouldBe List("User")
      }
  }
end NativeTypesEverywhereTests

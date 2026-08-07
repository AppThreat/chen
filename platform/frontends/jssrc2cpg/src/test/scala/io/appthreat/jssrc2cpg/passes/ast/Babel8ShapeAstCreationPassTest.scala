package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.codepropertygraph.generated.DispatchTypes
import io.shiftleft.semanticcpg.language.*

/** Regression coverage for AST-shape changes introduced by Babel 8
  * (@babel/parser 8.x), which astgen now emits. Snippets are drawn from / modeled
  * on the real cdxgen (v13) codebase so the frontend keeps building a correct CPG
  * regardless of whether the astgen on PATH emits Babel 7 or Babel 8 node shapes.
  *
  * Babel 8 changes exercised here:
  *   - dynamic import() -> ImportExpression (source/options) instead of a
  *     CallExpression whose callee is an `Import` node
  *   - TSEnumDeclaration members are wrapped in a TSEnumBody node (body.members)
  *   - template literal types -> TSTemplateLiteralType
  *   - TSInstantiationExpression uses `typeArguments` (was `typeParameters`)
  */
class Babel8ShapeAstCreationPassTest extends AbstractPassTest {

  "AST generation for Babel 8 dynamic imports (real cdxgen usage)" should {

    // lib/core/parallel.js: `const { Worker } = await import("node:worker_threads");`
    "build a dynamic import call for a destructured await import()" in AstFixture(
      """const { Worker } = await import("node:worker_threads");"""
    ) { cpg =>
      val List(call) = cpg.call("import").l
      call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
      call.argument.isLiteral.code.l shouldBe List("\"node:worker_threads\"")
    }

    // lib/validator/precompiled-parity.poku.js:
    //   `const mod = await import(`./generated/validate-${specVersion}.mjs`);`
    "build a dynamic import call for a templated specifier" in AstFixture(
      """const specVersion = "1.6";
        |const mod = await import(`./generated/validate-${specVersion}.mjs`);
        |""".stripMargin
    ) { cpg =>
      val List(call) = cpg.call("import").l
      call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
      call.argument.size shouldBe 1
    }
  }

  "AST generation for Babel 8 TypeScript node shapes" should {

    // Babel 8 nests enum members in a TSEnumBody node (body.members); the
    // members must still surface as TYPE_DECL members.
    "expose enum members that Babel 8 wraps in TSEnumBody" in TsAstFixture(
      """export enum HashAlgorithm {
        |  SHA256 = "sha256",
        |  SHA512 = "sha512",
        |  BLAKE2b = "blake2b"
        |}
        |""".stripMargin
    ) { cpg =>
      cpg.typeDecl("HashAlgorithm").member.name.l.toSet shouldBe Set("SHA256", "SHA512", "BLAKE2b")
    }

    // Template literal types become a dedicated TSTemplateLiteralType node in
    // Babel 8; the frontend must parse the file without falling over.
    "handle template literal types without breaking the file" in TsAstFixture(
      """type SemVer = `${number}.${number}.${number}`;
        |const version: SemVer = "1.6.0";
        |console.log(version);
        |""".stripMargin
    ) { cpg =>
      cpg.identifier.name("version").size should be >= 1
      cpg.call.name("log").size shouldBe 1
    }

    // TSInstantiationExpression uses `typeArguments` in Babel 8 (was
    // `typeParameters`); the underlying expression must still be created.
    "handle a TS instantiation expression (typeArguments)" in TsAstFixture(
      """function identity<T>(x: T): T { return x; }
        |const makeString = identity<string>;
        |makeString("ok");
        |""".stripMargin
    ) { cpg =>
      cpg.identifier.name("makeString").size should be >= 1
      cpg.call.name("makeString").size shouldBe 1
    }
  }
}

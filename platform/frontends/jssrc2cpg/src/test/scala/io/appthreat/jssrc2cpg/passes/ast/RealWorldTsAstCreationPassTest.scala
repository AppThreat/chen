package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.AbstractPassTest
import io.shiftleft.codepropertygraph.generated.nodes.Annotation
import io.shiftleft.semanticcpg.language.*

/** End-to-end AST-creation coverage on unmodified real-world TypeScript files vendored from
  * upstream GitHub projects, pinned to their Babel 8 astgen output (see the `README.md` in each
  * `src/test/resources/babel8-ts-*` fixture dir for provenance/licensing). These guard the
  * TypeScript-specific node shapes on genuine code rather than hand-written snippets.
  */
class RealWorldTsAstCreationPassTest extends AbstractPassTest {

  // nestjs/nest sample/01-cats-app/src/cats/cats.controller.ts (MIT) - decorator-heavy NestJS style.
  "AST generation for a real NestJS decorated controller (Babel 8)" should {

    "create the controller type with its methods" in AstJsonFixture("babel8-ts-decorators") { cpg =>
      cpg.typeDecl.nameExact("CatsController").size shouldBe 1
      cpg.typeDecl("CatsController").method.name.l should contain allOf ("create", "findAll", "findOne")
    }

    "attach the class-level decorators" in AstJsonFixture("babel8-ts-decorators") { cpg =>
      cpg.typeDecl("CatsController").astChildren.collectAll[Annotation].name.toSet should contain allOf (
        "Controller",
        "UseGuards"
      )
    }

    "attach method-level decorators to the right methods" in AstJsonFixture("babel8-ts-decorators") { cpg =>
      cpg.method.nameExact("create").annotation.name.toSet shouldBe Set("Post", "Roles")
      cpg.method.nameExact("findAll").annotation.name.l shouldBe List("Get")
      cpg.method.nameExact("findOne").annotation.name.l shouldBe List("Get")
    }

    "model parameter decorators" in AstJsonFixture("babel8-ts-decorators") { cpg =>
      cpg.all.collectAll[Annotation].name.toSet should contain allOf ("Body", "Param")
    }

    "model the injected constructor parameter" in AstJsonFixture("babel8-ts-decorators") { cpg =>
      cpg.typeDecl("CatsController").method.isConstructor.parameter.name.l should contain("catsService")
    }
  }

  // microsoft/TypeScript src/compiler/performance.ts @ v4.4.4 (Apache-2.0) - `namespace ts.performance`.
  "AST generation for a real qualified-namespace file (Babel 8)" should {

    "expand the qualified namespace path into nested namespace blocks" in AstJsonFixture(
      "babel8-ts-namespace"
    ) { cpg =>
      cpg.namespaceBlock.name.l should contain allOf ("ts", "performance")
      cpg.namespaceBlock.nameExact("ts").fullName.l shouldBe List("performance.ts::program:ts")
      cpg.namespaceBlock.nameExact("performance").fullName.l shouldBe List(
        "performance.ts::program:ts:performance"
      )
      cpg.namespaceBlock("ts").astChildren.isNamespaceBlock.name.l shouldBe List("performance")
    }

    "place the namespace's functions and interface under the qualified path" in AstJsonFixture(
      "babel8-ts-namespace"
    ) { cpg =>
      cpg.method.nameExact("createTimer").fullName.l shouldBe List(
        "performance.ts::program:ts:performance:createTimer"
      )
      cpg.method.name.l should contain allOf ("mark", "measure", "enable", "disable")
      cpg.typeDecl.nameExact("Timer").fullName.l shouldBe List(
        "performance.ts::program:ts:performance:Timer"
      )
    }
  }
}

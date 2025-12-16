package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.{AbstractPassTest, Defines}
import io.shiftleft.semanticcpg.language.*

class FlowTypeParsingTest extends AbstractPassTest {

    "AST generation for Flow Type Definitions" should {

        "handle Flow 'TypeAlias' with 'right' property" in AstFixture(
            """
              |// @flow
              |
              |// Mimicking the structure causing the crash: TypeAlias -> right -> ObjectTypeAnnotation
              |type Options = {
              |  environmentName?: string | (() => string),
              |  identifierPrefix?: string,
              |  onError?: (error: mixed) => void
              |};
              |
              |type TemporaryReferenceSet = {
              |  [string]: any
              |};
              |""".stripMargin) { cpg =>
            val List(optionsDecl) = cpg.typeDecl.name("Options").l
            optionsDecl.fullName should endWith(":program:Options")
            val memberNames = optionsDecl.member.name.l
            memberNames should contain allElementsOf List("environmentName", "identifierPrefix", "onError")
            val List(prefix) = optionsDecl.member.name("identifierPrefix").l
            prefix.typeFullName shouldBe Defines.String
            val List(tempRefSet) = cpg.typeDecl.name("TemporaryReferenceSet").l
            tempRefSet.fullName should endWith(":program:TemporaryReferenceSet")
        }

        "handle nested Flow types inside declarations" in AstFixture(
            """
              |// @flow
              |type Response = {
              |  _chunks: Map<string, SomeChunk>,
              |  _formData: FormData
              |};
              |""".stripMargin) { cpg =>
            val List(responseDecl) = cpg.typeDecl.name("Response").l
            responseDecl.member.name("_chunks").size shouldBe 1
            responseDecl.member.name("_formData").size shouldBe 1
        }
    }
}

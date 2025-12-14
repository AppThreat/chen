package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.{AbstractPassTest, Defines}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, ModifierTypes}
import io.shiftleft.semanticcpg.language.*

class NewNodesAstCreationPassTest extends AbstractPassTest {

    "AST generation for Dynamic Imports" should {

        "have correct structure for simple import()" in AstFixture("import('foo')") { cpg =>
            val List(call) = cpg.call("import").l
            call.code shouldBe "import('foo')"
            call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH

            val List(arg) = call.argument.isLiteral.l
            arg.code shouldBe "\"foo\""
            arg.order shouldBe 3
        }

        "have correct structure for import() with options" in AstFixture("import('foo', { with: { type: 'json' } })") { cpg =>
            val List(call) = cpg.call("import").l
            call.code shouldBe "import('foo', { with: { type: 'json' } })"
            call.argument.size shouldBe 3

            val List(arg1) = call.argument.isLiteral.l
            arg1.code shouldBe "\"foo\""

            val List(arg2) = call.argument.isBlock.l
            arg2.order shouldBe 4
        }
    }

    "AST generation for TS Instantiation Expressions" should {

        "handle generic function calls correctly" in TsAstFixture("""
                                                                    |function foo<T>(x: T) { return x; }
                                                                    |foo<string>("test");
                                                                    |""".stripMargin) { cpg =>
            val List(call) = cpg.call.name("foo").l
            call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH
            val List(arg) = call.argument.isLiteral.l
            arg.code shouldBe "\"test\""
        }

        "handle generic calls in assignment" in TsAstFixture("""
                                                               |const x = foo<number>(1);
                                                               |""".stripMargin) { cpg =>
            val List(assignment) = cpg.assignment.l
            val List(rhs)        = assignment.argument.isCall.l
            rhs.name shouldBe "foo"
            val List(arg) = rhs.argument.isLiteral.l
            arg.code shouldBe "1"
        }
    }

    "AST generation for Flow Declarations" should {

        "handle declare interface" in AstFixture("""
                                                   |// @flow
                                                   |declare interface FlowInterface {
                                                   |  prop: string;
                                                   |}
                                                   |""".stripMargin) { cpg =>
            val List(typeDecl) = cpg.typeDecl.name("FlowInterface").l
            typeDecl.fullName should endWith(":program:FlowInterface")
            typeDecl.isExternal shouldBe false

            val List(member) = typeDecl.member.l
            member.name shouldBe "prop"
            member.typeFullName shouldBe Defines.String
        }

        "handle simple type alias" in AstFixture("""
                                                   |// @flow
                                                   |type MyString = string;
                                                   |""".stripMargin) { cpg =>
            val List(typeDecl) = cpg.typeDecl.name("MyString").l
            typeDecl.fullName should endWith(":program:MyString")
        }

        "handle object type alias" in AstFixture("""
                                                   |// @flow
                                                   |type Point = {
                                                   |  x: number,
                                                   |  y: number
                                                   |};
                                                   |""".stripMargin) { cpg =>
            val List(typeDecl) = cpg.typeDecl.name("Point").l
            typeDecl.fullName should endWith(":program:Point")

            val List(x, y) = typeDecl.member.l
            x.name shouldBe "x"
            x.typeFullName shouldBe Defines.Number
            y.name shouldBe "y"
            y.typeFullName shouldBe Defines.Number
        }

        "handle declare class with static members" in AstFixture("""
                                                                   |// @flow
                                                                   |declare class MyFlowClass {
                                                                   |  static prop: number;
                                                                   |  method(): void;
                                                                   |}
                                                                   |""".stripMargin) { cpg =>
            val List(typeDecl) = cpg.typeDecl.name("MyFlowClass").l
            typeDecl.fullName should endWith(":program:MyFlowClass")

            val List(prop) = typeDecl.member.name("prop").l
            prop.typeFullName shouldBe Defines.Number
            prop.modifier.modifierType.l should contain(ModifierTypes.STATIC)

            val List(method) = typeDecl.method.name("method").l
            method.fullName should endWith(":MyFlowClass:method")
        }

        "handle standard interface syntax in flow" in AstFixture("""
                                                                   |// @flow
                                                                   |interface IBase {
                                                                   |  id: string;
                                                                   |}
                                                                   |""".stripMargin) { cpg =>
            val List(typeDecl) = cpg.typeDecl.name("IBase").l
            typeDecl.fullName should endWith(":program:IBase")
            val List(member) = typeDecl.member.l
            member.name shouldBe "id"
            member.typeFullName shouldBe Defines.String
        }

        "handle class implementing interface" in AstFixture("""
                                                              |// @flow
                                                              |interface I { method(): void; }
                                                              |class C implements I {
                                                              |  method() {}
                                                              |}
                                                              |""".stripMargin) { cpg =>
            val List(cDecl) = cpg.typeDecl.name("C").l
            cDecl.inheritsFromTypeFullName.l should contain only "I"
        }
    }
}
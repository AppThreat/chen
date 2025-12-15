package io.appthreat.jssrc2cpg.passes.ast

import io.appthreat.jssrc2cpg.passes.{AbstractPassTest, Defines}
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators, ModifierTypes}
import io.shiftleft.semanticcpg.language.*

class NewNodesAstCreationPassTest extends AbstractPassTest {

    "AST generation for Dynamic Imports" should {

        "have correct structure for simple import()" in AstFixture("import('foo')") { cpg =>
            val List(call) = cpg.call("import").l
            call.code shouldBe "import(\"foo\")"
            call.dispatchType shouldBe DispatchTypes.DYNAMIC_DISPATCH

            val List(arg) = call.argument.isLiteral.l
            arg.code shouldBe "\"foo\""
            arg.order shouldBe 1
        }

        "have correct structure for import() with options" in AstFixture("import('foo', { with: { type: 'json' } })") { cpg =>
            val List(call) = cpg.call("import").l
            call.code shouldBe "import(\"foo\", { with: { type: 'json' } })"
            call.argument.size shouldBe 2

            val List(arg1) = call.argument.isLiteral.l
            arg1.code shouldBe "\"foo\""
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
        "AST generation for Flow Type Casting" should {

          "handle standard flow type casting (x: type)" in AstFixture("""
                                                                          |// @flow
                                                                          |function test(y: any) {
                                                                          |  var x = (y: string);
                                                                          |}
                                                                          |""".stripMargin) { cpg =>
            val List(cast) = cpg.call.name(Operators.cast).l
            cast.argument(1).code shouldBe "string"
            cast.argument(2).code shouldBe "y"
            cast.dynamicTypeHintFullName should contain(Defines.String)
          }

          "handle casting to custom types" in AstFixture("""
                                                             |// @flow
                                                             |class User {}
                                                             |var u = (data: User);
                                                             |""".stripMargin) { cpg =>
            val List(cast) = cpg.call.name(Operators.cast).l
            cast.argument(1).code shouldBe "User"
            cast.dynamicTypeHintFullName.head should endWith("User")
          }
      }

          "AST generation for Flow Type Definitions" should {

          "handle type aliases" in AstFixture("""
                                                  |// @flow
                                                  |type UserID = string;
                                                  |type User = {
                                                  |  id: UserID;
                                                  |  name: string;
                                                  |};
                                                  |""".stripMargin) { cpg =>
            val List(idDecl) = cpg.typeDecl.name("UserID").l
            idDecl.aliasTypeFullName shouldBe Some(Defines.String)
            val List(userDecl) = cpg.typeDecl.name("User").l
            val List(idMember) = userDecl.member.name("id").l
            idMember.typeFullName should endWith("UserID")
          }

          "handle opaque types" in AstFixture("""
                                                  |// @flow
                                                  |opaque type AccountNumber = number;
                                                  |""".stripMargin) { cpg =>
            val List(opaque) = cpg.typeDecl.name("AccountNumber").l
            opaque.aliasTypeFullName shouldBe Some(Defines.Number)
          }

          "handle generic type aliases" in AstFixture("""
                                                          |// @flow
                                                          |type Container<T> = { value: T };
                                                          |""".stripMargin) { cpg =>
            val List(container)   = cpg.typeDecl.name("Container").l
            val List(valueMember) = container.member.name("value").l
            valueMember.order shouldBe 1
          }
      }

          "AST generation for Ambient Declarations" should {

          "handle declare variable" in AstFixture("""
                                                      |// @flow
                                                      |declare var config: { version: string };
                                                      |""".stripMargin) { cpg =>
            val List(local) = cpg.local.name("config").l
            local.typeFullName should endWith(
              "config"
            )
          }

          "handle declare function" in AstFixture("""
                                                      |// @flow
                                                      |declare function fetch(url: string): any;
                                                      |""".stripMargin) { cpg =>
            val List(method) = cpg.method.name("fetch").l
            method.isExternal shouldBe false

            val List(param) = method.parameter.name("url").l
            param.typeFullName shouldBe Defines.String
          }

          "handle declare module" in AstFixture("""
                                                    |// @flow
                                                    |declare module "my-lib" {
                                                    |  declare function init(): void;
                                                    |}
                                                    |""".stripMargin) { cpg =>
            val List(ns) = cpg.namespaceBlock.name("my-lib").l
            val List(method) = cpg.method.name("init").l
            method.fullName should include("my-lib")
          }
      }
    }
}
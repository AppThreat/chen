package io.appthreat.jssrc2cpg.types

import io.appthreat.jssrc2cpg.passes.{AbstractPassTest, Defines}
import io.appthreat.jssrc2cpg.utils.TypeNames
import io.shiftleft.semanticcpg.language.*

/** The name of a type written as a type expression: one name or ANY, never its display text. */
class TypeNamesTests extends AbstractPassTest:

  private def name(t: String) = TypeNames.clean(t, _ => "the-module")

  "a type expression" should {
      "be its class when it is a generic reference" in {
          name("Promise<User>") shouldBe "Promise"
          name("Map<string, Array<never> | Array<string>>") shouldBe "Map"
          name("Box<User | null>") shouldBe "Box"
          name("express.Response<any>") shouldBe "express.Response"
      }

      "be package:Class for a class named by an import type of a package" in {
          name("import(\"@angular/core\").InputSignal<string>") shouldBe "@angular/core:InputSignal"
          name("import(\"rxjs\").Subscription") shouldBe "rxjs:Subscription"
      }

      "be the class alone for a class named by an import type of a file of the project" in {
          name("import(\"../../types\").Action") shouldBe "Action"
          name("import(\"./a\").B<C>") shouldBe "B"
      }

      "be the module for typeof import" in {
          name("typeof import(\"./m\")") shouldBe "the-module"
          name("import(\"./m\")") shouldBe "the-module"
      }

      "be the built-in array for an array, a tuple and a readonly array" in {
          name("Array<User>") shouldBe "__ecma.Array"
          name("User[]") shouldBe "__ecma.Array"
          name("[number, string]") shouldBe "__ecma.Array"
          name("readonly string[]") shouldBe "__ecma.Array"
          name("ReadonlyArray<User>") shouldBe "__ecma.Array"
      }

      "be object for an object literal type, and ANY for one with a call signature" in {
          name("{ user: ANY; }") shouldBe Defines.Object
          name("{}") shouldBe Defines.Object
          name("{ a: { b: string; }; }") shouldBe Defines.Object
          name("{ (x: number): string; }") shouldBe Defines.Any
      }

      "be ANY for a function or constructor type" in {
          name("(a: string, b: number) => void") shouldBe Defines.Any
          name("<T>(a: T) => T") shouldBe Defines.Any
          name("new () => Foo") shouldBe Defines.Any
          name("(cb: (x: number) => void) => Promise<void>") shouldBe Defines.Any
      }

      "be the return of a function where a value is expected of it" in {
          TypeNames.cleanReturn("(u: User) => User", _ => "") shouldBe "User"
          TypeNames.cleanReturn("() => Promise<void>", _ => "") shouldBe "Promise"
          TypeNames.cleanReturn("(cb: (x: number) => void) => string", _ => "") shouldBe Defines.String
          TypeNames.cleanReturn("Promise<User>", _ => "") shouldBe "Promise"
      }

      "be its only member for a union with null or undefined, and ANY for any other union" in {
          name("User | null") shouldBe "User"
          name("User | undefined") shouldBe "User"
          name("Box<User> | null | undefined") shouldBe "Box"
          name("string | number") shouldBe Defines.Any
          name("User | Other") shouldBe Defines.Any
          name("\"a\" | \"b\"") shouldBe Defines.String
          name("(User | null)") shouldBe "User"
      }

      "be ANY for an intersection and for the types that are no class" in {
          name("A & B") shouldBe Defines.Any
          name("keyof User") shouldBe Defines.Any
          name("typeof user") shouldBe "user"
          name("typeof models.User") shouldBe "models.User"
          name("typeof user[0]") shouldBe Defines.Any
          name("User[\"id\"]") shouldBe Defines.Any
          name("T extends string ? A : B") shouldBe Defines.Any
          name("`a${string}`") shouldBe Defines.String
      }

      "keep the names it already is" in {
          name("User") shouldBe "User"
          name("__ecma.Number") shouldBe "__ecma.Number"
          name("a.ts::program:Foo") shouldBe "a.ts::program:Foo"
          name("@angular/core:Foo") shouldBe "@angular/core:Foo"
          name("ANY") shouldBe Defines.Any
      }

      "name the primitives and the literal types" in {
          name("string") shouldBe Defines.String
          name("number") shouldBe Defines.Number
          name("42") shouldBe Defines.Number
          name("true") shouldBe Defines.Boolean
          name("1n") shouldBe Defines.BigInt
          name("unknown") shouldBe Defines.Unknown
          name("void") shouldBe Defines.Void
      }
  }

  "the type of a parameter written as a type annotation" should {
      "be a name in both modes" in TsAstFixture(
        """
        |import { User } from "./u";
        |export function f(a: Promise<User>, b: { x: number }, c: User[], d: Array<User>, e: (x: number) => void, f: string[], g: Map<string, User>) {}
        |""".stripMargin,
        tsTypes = true
      ) { cpg =>
        def t(p: String) = cpg.parameter.name(p).typeFullName.l
        t("a") shouldBe List("Promise")
        t("b").head should endWith("_anon_cdecl")
        t("c") shouldBe List("__ecma.Array")
        t("d") shouldBe List("__ecma.Array")
        t("e") shouldBe List(Defines.Any)
        t("f") shouldBe List("__ecma.Array")
        t("g") shouldBe List("Map")
      }
  }
end TypeNamesTests

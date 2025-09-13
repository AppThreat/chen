package io.appthreat.jimple2cpg.querying

import io.appthreat.jimple2cpg.testfixtures.JimpleCode2CpgFixture
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.{Call, FieldIdentifier, Identifier}
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}

class FieldAccessTests extends JimpleCode2CpgFixture {

  implicit val resolver: ICallResolver = NoResolve

  val cpg: Cpg = code("""
      |class Foo {
      |  public static int MAX_VALUE = 12;
      |  public int value;
      |
      |  public Foo(int value) {
      |    if (value <= MAX_VALUE) {
      |      this.value = value;
      |    } else {
      |      this.value = MAX_VALUE;
      |    }
      |  }
      |
      |  public void setValue(int value) {
      |    if (value <= MAX_VALUE) {
      |      this.value = value;
      |    }
      |  }
      |}
      |
      |class Test {
      |public void foo() {
      |  int x = Foo.MAX_VALUE;
      |}
      |
      |public void bar() {
      |  Foo f = new Foo(5);
      |  int y = f.value;
      |}
      |
      |public void baz() {
      |  Foo g = new Foo(5);
      |  g.value = 66;
      |}
      |}
      |""".stripMargin).cpg

  "should handle static member accesses" in {
    val List(assign: Call) = cpg.method(".*foo.*").call(".*assignment").l
    assign.code shouldBe "x = Foo.MAX_VALUE"
    val List(access: Call) = cpg.method(".*foo.*").call(".*fieldAccess").l
    access.code shouldBe "Foo.MAX_VALUE"
    val List(identifier: Identifier, fieldIdentifier: FieldIdentifier) = access.argument.l: @unchecked
    identifier.code shouldBe "Foo"
    identifier.name shouldBe "Foo"
    identifier.typeFullName shouldBe "Foo"
    fieldIdentifier.canonicalName shouldBe "MAX_VALUE"
    fieldIdentifier.code shouldBe "MAX_VALUE"
  }

  "should handle object field accesses on RHS of assignments" in {
    val List(_: Call, _: Call, assign: Call) = cpg.method(".*bar.*").call(".*assignment").l
    assign.code shouldBe "y = f.value"
    val List(access: Call)                                             = cpg.method(".*bar.*").call(".*fieldAccess").l
    val List(identifier: Identifier, fieldIdentifier: FieldIdentifier) = access.argument.l: @unchecked
    identifier.name shouldBe "f"
    identifier.typeFullName shouldBe "Foo"
    fieldIdentifier.canonicalName shouldBe "value"
  }

  "should handle object field accesses on LHS of assignments" in {
    val List(_: Call, _: Call, assign: Call) = cpg.method(".*baz.*").call(".*assignment").l
    assign.code shouldBe "g.value = 66"
    val List(access: Call)                                             = cpg.method(".*baz.*").call(".*fieldAccess").l
    val List(identifier: Identifier, fieldIdentifier: FieldIdentifier) = access.argument.l: @unchecked
    identifier.name shouldBe "g"
    identifier.typeFullName shouldBe "Foo"
    fieldIdentifier.canonicalName shouldBe "value"
  }

    "it should demonstrate precise field access code generation" in {
        val staticAccess = cpg.method("foo").call.name("<operator>.fieldAccess").head
        staticAccess.code shouldBe "Foo.MAX_VALUE"
        val staticArgs = staticAccess.argument.l
        staticArgs.size shouldBe 2
        val staticBaseArg = staticArgs(0).asInstanceOf[Identifier]
        val staticFieldArg = staticArgs(1).asInstanceOf[FieldIdentifier]
        staticBaseArg.code shouldBe "Foo"
        staticFieldArg.code shouldBe "MAX_VALUE"

        val instanceRhsAccess = cpg.method("bar").call.name("<operator>.fieldAccess").head
        instanceRhsAccess.code shouldBe "f.value"
        val rhsArgs = instanceRhsAccess.argument.l
        rhsArgs.size shouldBe 2
        val rhsBaseArg = rhsArgs(0).asInstanceOf[Identifier]
        val rhsFieldArg = rhsArgs(1).asInstanceOf[FieldIdentifier]
        rhsBaseArg.code shouldBe "f"
        rhsFieldArg.code shouldBe "value"

        val instanceLhsAccess = cpg.method("baz").call.name("<operator>.fieldAccess").head
        instanceLhsAccess.code shouldBe "g.value"
        val lhsArgs = instanceLhsAccess.argument.l
        lhsArgs.size shouldBe 2
        val lhsBaseArg = lhsArgs(0).asInstanceOf[Identifier]
        val lhsFieldArg = lhsArgs(1).asInstanceOf[FieldIdentifier]
        lhsBaseArg.code shouldBe "g"
        lhsFieldArg.code shouldBe "value"
    }

    "it should correctly structure field access ASTs with argument edges" in {
        val staticAccess = cpg.method("foo").call.name("<operator>.fieldAccess").head
        staticAccess.argument.size shouldBe 2
        val staticBaseArg = staticAccess.argument.order(1).head
        val staticFieldArg = staticAccess.argument.order(2).head
        staticBaseArg.isInstanceOf[Identifier] shouldBe true
        staticFieldArg.isInstanceOf[FieldIdentifier] shouldBe true

        val instanceRhsAccess = cpg.method("bar").call.name("<operator>.fieldAccess").head
        instanceRhsAccess.argument.size shouldBe 2
        val rhsBaseArg = instanceRhsAccess.argument.order(1).head
        val rhsFieldArg = instanceRhsAccess.argument.order(2).head
        rhsBaseArg.isInstanceOf[Identifier] shouldBe true
        rhsBaseArg.asInstanceOf[Identifier].name shouldBe "f"
        rhsFieldArg.isInstanceOf[FieldIdentifier] shouldBe true
        rhsFieldArg.asInstanceOf[FieldIdentifier].canonicalName shouldBe "value"

        val instanceLhsAccess = cpg.method("baz").call.name("<operator>.fieldAccess").head
        instanceLhsAccess.argument.size shouldBe 2
        val lhsBaseArg = instanceLhsAccess.argument.order(1).head
        val lhsFieldArg = instanceLhsAccess.argument.order(2).head
        lhsBaseArg.isInstanceOf[Identifier] shouldBe true
        lhsBaseArg.asInstanceOf[Identifier].name shouldBe "g"
        lhsFieldArg.isInstanceOf[FieldIdentifier] shouldBe true
        lhsFieldArg.asInstanceOf[FieldIdentifier].canonicalName shouldBe "value"
    }

    "it should reflect field access within constructor logic correctly" in {
        val constructorMethod = cpg.method.fullNameExact("Foo.<init>:void(int)").head
        val instanceFieldAccesses = constructorMethod.call.name("<operator>.fieldAccess").filter { fa =>
            fa.argument.order(1).headOption.exists(_.code == "this")
        }.l

        instanceFieldAccesses.size shouldBe 2
        val firstInstanceAccess = instanceFieldAccesses.head
        firstInstanceAccess.code shouldBe "this.value"

        val staticFieldAccesses = constructorMethod.call.name("<operator>.fieldAccess").filter { fa =>
            fa.argument.order(1).headOption.exists(_.code == "Foo")
        }.l

        staticFieldAccesses should not be empty
        val firstStaticAccess = staticFieldAccesses.head
        firstStaticAccess.code shouldBe "Foo.MAX_VALUE"

        val setValueMethod = cpg.method.name("setValue").head
        val setValueThisAccesses = setValueMethod.call.name("<operator>.fieldAccess").filter { fa =>
            fa.argument.order(1).headOption.exists(_.code == "this")
        }.l
        setValueThisAccesses should not be empty
        val setValueThisAccess = setValueThisAccesses.head
        setValueThisAccess.code shouldBe "this.value"

        val maxValueAccessesInSetValue = setValueMethod.call.name("<operator>.fieldAccess").filter { fa =>
            fa.argument.order(1).headOption.exists(_.code == "Foo")
        }.l
        maxValueAccessesInSetValue should not be empty
        val firstMaxValueInSetValue = maxValueAccessesInSetValue.head
        firstMaxValueInSetValue.code shouldBe "Foo.MAX_VALUE"
    }
}

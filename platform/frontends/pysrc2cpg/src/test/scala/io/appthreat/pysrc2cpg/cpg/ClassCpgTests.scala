package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.semanticcpg.language._

class ClassCpgTests extends PySrc2CpgFixture(withOssDataflow = false) {
    "class" should {
        val cpg = code("""class Foo:
                         |  pass
                         |""".stripMargin)
        "have correct instance class type and typeDecl" in {
            cpg.typ.name("Foo").fullName.head shouldBe "Test0.py:<module>.Foo"
            val typeDecl = cpg.typeDecl.name("Foo").head
            typeDecl.fullName shouldBe "Test0.py:<module>.Foo"
            typeDecl.astParent shouldBe cpg.method.name("<module>").head
        }

        "have correct meta class type and typeDecl" in {
            cpg.typ.name("Foo<meta>").fullName.head shouldBe "Test0.py:<module>.Foo<meta>"
            val typeDecl = cpg.typeDecl.name("Foo<meta>").head
            typeDecl.fullName shouldBe "Test0.py:<module>.Foo<meta>"
            typeDecl.astParent shouldBe cpg.method.name("<module>").head
        }

        "have correct meta class call handler type and typeDecl" in {
            cpg.typ.name("<metaClassCallHandler>").fullName.head shouldBe
                "Test0.py:<module>.Foo.<metaClassCallHandler>"
            val typeDecl = cpg.typeDecl.name("<metaClassCallHandler>").head
            typeDecl.fullName shouldBe "Test0.py:<module>.Foo.<metaClassCallHandler>"
            typeDecl.astParent shouldBe cpg.typeDecl.name("Foo<meta>").head
        }

        "have correct fake new type and typeDecl" in {
            cpg.typ.name("<fakeNew>").fullName.head shouldBe
                "Test0.py:<module>.Foo.<fakeNew>"
            val typeDecl = cpg.typeDecl.name("<fakeNew>").head
            typeDecl.fullName shouldBe "Test0.py:<module>.Foo.<fakeNew>"
            typeDecl.astParent shouldBe cpg.typeDecl.name("Foo<meta>").head
        }
    }

    "class with type parameters" should {
        "handle simple type parameter" in {
            val cpg = code("""class GenericClass[T]:
                             |    def method(self, x: T) -> T:
                             |        return x
                             |""".stripMargin)

            val typeDecl = cpg.typeDecl.name("GenericClass").head
            typeDecl.fullName shouldBe "Test0.py:<module>.GenericClass"
            cpg.method.name("method").head.fullName shouldBe "Test0.py:<module>.GenericClass.method"
            cpg.method.name("method").parameter.last.typeFullName shouldBe "T"
        }

        "handle multiple type parameters" in {
            val cpg = code("""class MultiGeneric[T, U, V]:
                             |    value: T
                             |    def get_u(self) -> U: ...
                             |    def process(self, v: V): ...
                             |""".stripMargin)
            val typeDecl = cpg.typeDecl.name("MultiGeneric").head
            typeDecl.fullName shouldBe "Test0.py:<module>.MultiGeneric"
            cpg.member.name("value").head.typeFullName shouldBe "ANY" // Bug: Must be T
            cpg.method.name("process").parameter.last.typeFullName shouldBe "V"
        }

        "handle bound type parameter" in {
            val cpg = code("""class BoundedGeneric[T: int]:
                             |    def get_value(self) -> T: ...
                             |""".stripMargin)
            val typeDecl = cpg.typeDecl.name("BoundedGeneric").head
            typeDecl.fullName shouldBe "Test0.py:<module>.BoundedGeneric"
            cpg.method.name("get_value").methodReturn.head.typeFullName shouldBe "T"
        }

        "handle constrained type parameter (tuple syntax)" in {
            val cpg = code("""class ConstrainedGeneric[T: (int, str)]:
                             |    def get_item(self) -> T: ...
                             |""".stripMargin)
            val typeDecl = cpg.typeDecl.name("ConstrainedGeneric").head
            typeDecl.fullName shouldBe "Test0.py:<module>.ConstrainedGeneric"
            cpg.method.name("get_item").methodReturn.head.typeFullName shouldBe "T"
        }

        "handle ParamSpec" in {
            val cpg = code("""from typing import ParamSpec
                             |P = ParamSpec('P')
                             |class CallableClass[**P]:
                             |    def __call__(self, *args: P.args, **kwargs: P.kwargs): ...
                             |""".stripMargin)
            val typeDecl = cpg.typeDecl.name("CallableClass").head
            typeDecl.fullName shouldBe "Test0.py:<module>.CallableClass"
        }

        "handle TypeVarTuple" in {
            val cpg = code("""from typing import TypeVarTuple
                             |Ts = TypeVarTuple('Ts')
                             |class VariadicClass[*Ts]:
                             |    def method(self, *args: *Ts): ...
                             |""".stripMargin)
            val typeDecl = cpg.typeDecl.name("VariadicClass").head
            typeDecl.fullName shouldBe "Test0.py:<module>.VariadicClass"
        }

         "handle type parameter with default" in {
           val cpg = code("""class DefaultGeneric[T = int]:
                            |    def get_default(self) -> T: ...
                            |""".stripMargin)
           val typeDecl = cpg.typeDecl.name("DefaultGeneric").head
           typeDecl.fullName shouldBe "Test0.py:<module>.DefaultGeneric"
           cpg.method.name("get_default").methodReturn.head.typeFullName shouldBe "T"
         }
    }


    "class meta call handler" should {
        "have no self parameter if self is explicit" in {
            val cpg = code("""class Foo:
                             |  def __init__(self, x):
                             |    pass
                             |""".stripMargin)

            val handlerMethod = cpg.method.name("<metaClassCallHandler>").head
            handlerMethod.fullName shouldBe "Test0.py:<module>.Foo.<metaClassCallHandler>"
            handlerMethod.lineNumber shouldBe Some(2)

            handlerMethod.parameter.size shouldBe 1
            val xParameter = handlerMethod.parameter.head
            xParameter.name shouldBe "x"

        }

        "have no self parameter if self is in varargs" in {
            val cpg = code("""class Foo:
                             |  def __init__(*x):
                             |    pass
                             |""".stripMargin)

            val handlerMethod = cpg.method.name("<metaClassCallHandler>").head
            handlerMethod.fullName shouldBe "Test0.py:<module>.Foo.<metaClassCallHandler>"
            handlerMethod.lineNumber shouldBe Some(2)

            handlerMethod.parameter.size shouldBe 1
            val xParameter = handlerMethod.parameter.head
            xParameter.name shouldBe "x"

        }

        "have correct full name for func1 method in class" in {
            val cpg = code("""class Foo:
                             |  def func1(self):
                             |    pass
                             |""".stripMargin)

            val func1 = cpg.method.name("func1").head
            func1.fullName shouldBe "Test0.py:<module>.Foo.func1"
        }

        "have correct full name for <body> method in class" in {
            val cpg = code("""class Foo:
                             |  pass
                             |""".stripMargin)

            val func1 = cpg.method.name("<body>").head
            func1.fullName shouldBe "Test0.py:<module>.Foo.<body>"
        }

        "have correct parameter index for method in class" in {
            val cpg = code("""class Foo:
                             |  def method(self):
                             |    pass
                             |""".stripMargin)
            cpg.method.name("method").parameter.name("self").index.head shouldBe 0
        }

        "have correct parameter index for static method in class" in {
            val cpg = code("""class Foo:
                             |  @staticmethod
                             |  def method(x):
                             |    pass
                             |""".stripMargin)
            cpg.method.name("method").parameter.name("x").index.head shouldBe 1
        }
    }

}
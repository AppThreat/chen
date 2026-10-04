package io.appthreat.c2cpg.querying

import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** A call to a compiler builtin the parser does not declare (the FORTIFY builtins, and the C
  * library's `__memcpy_chk` family without its header) carries the builtin's signature and return
  * type, and in C++ is named as in C: builtins have C linkage.
  */
class BuiltinSignatureTests extends CCodeToCpgSuite:

  private val body = """
      |void f(char *d, const char *s, unsigned n) {
      |  __builtin___memcpy_chk(d, s, n, __builtin_object_size(d, 0));
      |  __memcpy_chk(d, s, n, 8);
      |  __builtin_memcpy(d, s, n);
      |  undeclared(n);
      |}
      |""".stripMargin

  "builtin calls in C" should {
      val cpg = code(body, "f.c")

      "carry the builtin's signature and return type" in {
          val List(chk) = cpg.call.nameExact("__builtin___memcpy_chk").l
          chk.signature shouldBe "void*(void*,void*,unsigned long int,unsigned long int)"
          chk.typeFullName shouldBe "void*"
          cpg.call.nameExact("__memcpy_chk").typeFullName.l shouldBe List("void*")
      }

      "leave a call to an unknown function untyped" in {
          cpg.call.nameExact("undeclared").typeFullName.l shouldBe List("ANY")
      }
  }

  "builtin calls in C++" should {
      val cpg = code(body, "f.cpp")

      "be named as in C, with the builtin's signature" in {
          val List(chk) = cpg.call.nameExact("__builtin___memcpy_chk").l
          chk.methodFullName shouldBe "__builtin___memcpy_chk"
          chk.signature shouldBe "void*(void*,void*,unsigned long int,unsigned long int)"
          chk.typeFullName shouldBe "void*"
          cpg.call.nameExact("__builtin_memcpy").methodFullName.l shouldBe List("__builtin_memcpy")
          cpg.call.nameExact("__builtin_object_size").methodFullName.l shouldBe List(
            "__builtin_object_size"
          )
      }

      "leave a call to an unknown function unresolved" in {
          cpg.call.nameExact("undeclared").methodFullName.l shouldBe List(
            "<unresolvedNamespace>.undeclared:<unresolvedSignature>(1)"
          )
      }
  }
end BuiltinSignatureTests

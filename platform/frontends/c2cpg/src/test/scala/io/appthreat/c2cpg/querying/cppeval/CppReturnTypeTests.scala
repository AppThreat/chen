package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** Regression tests for namespace-qualified return types on function definitions.
  *
  * A function definition returning a named type (`std::string foo() {...}`) used to lose its
  * namespace qualifier in `methodReturn.typeFullName`/`signature` (`std::string` -> `string`),
  * because the named-type return-type path fell through to an unqualified `getSimpleName`, while
  * parameters of the same type were qualified correctly.
  */
class CppReturnTypeTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private val cpg = code("""
      |#include <string>
      |#include <vector>
      |
      |namespace ns {
      |    struct Widget {};
      |}
      |
      |std::string free_fn(std::string_view name) { return std::string(name); }
      |std::vector<int> make_vec() { std::vector<int> v; return v; }
      |ns::Widget make_widget() { return ns::Widget(); }
      |
      |struct Holder {
      |    std::string label() { return "x"; }
      |};
      |""".stripMargin)

  "return types of function definitions are fully qualified" in {
      val free = cpg.method.nameExact("free_fn").head
      free.methodReturn.typeFullName shouldBe "std.string"
      free.signature shouldBe "std.string (std.string_view)"

      cpg.method.nameExact("make_vec").methodReturn.typeFullName.head shouldBe "std.vector<int>"
      cpg.method.nameExact("make_widget").methodReturn.typeFullName.head shouldBe "ns.Widget"
      cpg.method.nameExact("label").methodReturn.typeFullName.head shouldBe "std.string"
  }
end CppReturnTypeTests

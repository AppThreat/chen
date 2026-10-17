package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.NoResolve

/** A subscript with a comma-separated argument list is a call to the type's multi-parameter
  * `operator[]` (C++23's multidimensional subscript): it links to the operator's METHOD, with the
  * object as argument 0 and every index in its written order.
  */
class MultidimSubscriptTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private implicit val resolver: NoResolve.type = NoResolve

  private val cpg = code("""
      |struct grid {
      |  char cells[4][8];
      |  char &operator[](unsigned long row, unsigned long col) { return cells[row][col]; }
      |};
      |
      |void writer(const char *user) {
      |  grid g;
      |  int row = atoi(user);
      |  g[row, 0] = 'x';
      |}
      |""".stripMargin)

  "a multidimensional subscript" should {
      "link to the operator the type declares" in {
          val call = cpg.method.nameExact("writer").call.codeExact("g[row, 0]").head
          call.name shouldBe "operator []"
          call.methodFullName shouldBe "grid.operator []:char &(unsigned long int,unsigned long int)"
          call.callee(using NoResolve).fullName.l shouldBe List(
            "grid.operator []:char &(unsigned long int,unsigned long int)"
          )
      }

      "carry the object as argument 0 and each index in order" in {
          val call = cpg.method.nameExact("writer").call.codeExact("g[row, 0]").head
          call.argument.code.l shouldBe List("g", "row", "0")
      }

      "keep a plain subscript on an array a plain index access" in {
          val operator = cpg.method.nameExact("operator []").l.head
          val access   = operator.call.nameExact("<operator>.indirectIndexAccess").head
          access.methodFullName shouldBe "<operator>.indirectIndexAccess"
      }
  }
end MultidimSubscriptTests

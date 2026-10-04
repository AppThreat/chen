package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.appthreat.x2cpg.passes.taggers.*
import io.shiftleft.codepropertygraph.generated.nodes.StoredNode
import io.shiftleft.semanticcpg.language.*

/** A C API that reports failure through an error out-parameter returns NULL exactly when it sets
  * it: a guard on the error is a guard on the result.
  */
class ErrorChannelNullTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
    |#include <stdlib.h>
    |struct db { int count; };
    |
    |struct db *db_open(const char *name, char **errptr)
    |{
    |    if (!name) { *errptr = "bad name"; return NULL; }
    |    return (struct db *)malloc(sizeof(struct db));
    |}
    |
    |#define CHECK_NO_ERROR(err) if ((err) != NULL) { abort(); }
    |
    |void good_error_checked(const char *name)
    |{
    |    char *err = NULL;
    |    struct db *db = db_open(name, &err);
    |    CHECK_NO_ERROR(err);
    |    db->count = 1;
    |}
    |
    |void good_direct_check(const char *name)
    |{
    |    char *err = NULL;
    |    struct db *db = db_open(name, &err);
    |    if (!db) abort();
    |    db->count = 1;
    |}
    |
    |void good_error_if(const char *name)
    |{
    |    char *err = NULL;
    |    struct db *db = db_open(name, &err);
    |    if (err != NULL) return;
    |    db->count = 1;
    |}
    |
    |void bad_unchecked(const char *name)
    |{
    |    char *err = NULL;
    |    struct db *db = db_open(name, &err);
    |    db->count = 1;
    |}
    |""".stripMargin,
    "errchan.c"
  )

  new MemorySemanticsPass(cpg).createAndApply()
  new MemoryApiPass(cpg).createAndApply()
  new ExtentPass(cpg).createAndApply()
  new GuardPass(cpg).createAndApply()
  new ValueOriginPass(cpg).createAndApply()
  new AllocationStatePass(cpg).createAndApply()
  new MemorySafetyFindingPass(cpg).createAndApply()

  private def nullFindings(method: String): List[String] =
      cpg.method.nameExact(method).ast.collectAll[StoredNode]
          .flatMap(_.tag.name("ms-finding").value.l).filter(_ == "MS-NULL-001").l

  "a result whose error out-parameter is checked" should {
      "not be reported as an unchecked nullable result" in {
          nullFindings("good_error_checked") shouldBe empty
      }
      "not be reported after a guard that returns, or one that aborts" in {
          nullFindings("good_error_if") shouldBe empty
          nullFindings("good_direct_check") shouldBe empty
      }
      "still be reported when nothing checks either" in {
          nullFindings("bad_unchecked") should not be empty
      }
  }
end ErrorChannelNullTests

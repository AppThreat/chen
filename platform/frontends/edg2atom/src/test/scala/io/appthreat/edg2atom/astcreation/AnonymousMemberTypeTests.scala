package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** An anonymous struct or union member's TYPE_DECL is named after its owner and its position among
  * the owner's anonymous members - `frame.anonymous_composite_type_0` - the name the CDT frontend
  * gives it, where the front end's own name for every unnamed type is the same `<unnamed>`.
  */
class AnonymousMemberTypeTests extends EdgCodeToCpgSuite(".c"):

  "an anonymous union member" should {
      val cpg = code(
        """#include <string.h>
        |struct frame {
        |    int kind;
        |    union {
        |        char small[8];
        |        long aligned;
        |    };
        |};
        |void copy_small(struct frame *f, const char *user) {
        |    strcpy(f->small, user);
        |}
        |""".stripMargin
      )

      "carry the owner-qualified name" in {
          requireEdga()
          val anon = cpg.typeDecl.name(".*anonymous_composite_type.*").l
          anon.map(_.name).distinct shouldBe List("frame.anonymous_composite_type_0")
          anon.flatMap(_.member.nameExact("small").l).map(_.typeFullName) shouldBe List("char[8]")
      }

      "resolve through the owner for a member read" in {
          requireEdga()
          val frame = cpg.typeDecl.nameExact("frame").l.head
          frame.astChildren.isTypeDecl.l.map(_.name) shouldBe List(
            "frame.anonymous_composite_type_0"
          )
      }
  }

  "two anonymous members of one record" should {
      val cpg = code(
        """struct pair {
        |    struct { int lo; };
        |    struct { int hi; };
        |};
        |int both(struct pair *p) {
        |    return p->lo + p->hi;
        |}
        |""".stripMargin
      )

      "be numbered apart" in {
          requireEdga()
          cpg.typeDecl.name(".*anonymous_composite_type.*").name.l.sorted shouldBe List(
            "pair.anonymous_composite_type_0",
            "pair.anonymous_composite_type_1"
          )
      }
  }
end AnonymousMemberTypeTests

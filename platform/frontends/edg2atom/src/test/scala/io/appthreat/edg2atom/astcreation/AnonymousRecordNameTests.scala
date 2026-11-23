package io.appthreat.edg2atom.astcreation

import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.shiftleft.semanticcpg.language.*

/** A record without a tag is named after the first declarator of the declaration that holds it, as
  * the CDT frontend names it, where the front end calls every one of them `<unnamed>` and a typedef
  * of one aliased the same `<unnamed>` as all the others.
  */
class AnonymousRecordNameTests extends EdgCodeToCpgSuite(".c"):

  "typedef'd anonymous structs" should {
      val cpg = code(
        """typedef struct { float lo, hi; } range;
        |typedef struct { int nHsync; range hsync[8]; void *Modes; } MonRec, *MonPtr;
        |void f(MonPtr m) { m->hsync[m->nHsync].lo = 1; }
        |""".stripMargin
      )

      "get the typedef name, each with its own members" in {
          requireEdga()
          cpg.typeDecl.nameExact("range").astChildren.isMember.name.l.sorted shouldBe List(
            "hi",
            "lo"
          )
          cpg.typeDecl.nameExact("MonRec").astChildren.isMember.name.l shouldBe List(
            "nHsync",
            "hsync",
            "Modes"
          )
      }

      "type the array member by the named element type" in {
          requireEdga()
          cpg.typeDecl.nameExact("MonRec").astChildren.isMember.nameExact("hsync").typeFullName.l shouldBe
              List("range[8]")
      }

      "alias the record from a pointer typedef" in {
          requireEdga()
          cpg.typeDecl.nameExact("MonPtr").aliasTypeFullName.l shouldBe List("MonRec*")
          cpg.method.nameExact("f").parameter.typeFullName.l shouldBe List("MonPtr")
      }

      "leave no unnamed record behind" in {
          requireEdga()
          cpg.typeDecl.name(".*unnamed.*").l shouldBe empty
          cpg.typ.fullName(".*unnamed.*").l shouldBe empty
          cpg.typeDecl.aliasTypeFullName(".*unnamed.*").l shouldBe empty
      }

      "keep the field access resolved" in {
          requireEdga()
          val access = cpg.method.nameExact("f").call.nameExact("<operator>.indirectFieldAccess").l
          access.map(_.code).distinct should contain("m->hsync")
          access.map(_.typeFullName).distinct should contain("range[8]")
      }
  }

  "two anonymous typedef structs of one file" should {
      val cpg = code(
        """typedef struct { int a; } first_t;
        |typedef struct { char b; } second_t;
        |first_t x; second_t y;
        |""".stripMargin
      )

      "stay distinct" in {
          requireEdga()
          cpg.typeDecl.nameExact("first_t").astChildren.isMember.name.l shouldBe List("a")
          cpg.typeDecl.nameExact("second_t").astChildren.isMember.name.l shouldBe List("b")
          cpg.local.nameExact("x").typeFullName.l shouldBe List("first_t")
          cpg.local.nameExact("y").typeFullName.l shouldBe List("second_t")
      }
  }

  "an anonymous struct only a pointer typedef names" should {
      val cpg = code(
        """typedef struct { int q; } *handle_t;
        |int read_q(handle_t h) { return h->q; }
        |""".stripMargin
      )

      "get a name of its own that the typedef aliases" in {
          requireEdga()
          val alias = cpg.typeDecl.nameExact("handle_t").aliasTypeFullName.l
          alias shouldBe List("anonymous_composite_type_0*")
          cpg.typeDecl.nameExact("anonymous_composite_type_0").member.name.l shouldBe List("q")
      }
  }

  "a typedef'd anonymous struct with an attribute, a comment and a declarator on a later line" should {
      val cpg = code(
        """typedef struct {
        |    int a;
        |} __attribute__((packed)) /* the wire form */
        |    wire_t, *wire_ptr;
        |wire_t w; wire_ptr p;
        |""".stripMargin
      )

      "be named after the first declarator" in {
          requireEdga()
          cpg.typeDecl.nameExact("wire_t").astChildren.isMember.name.l shouldBe List("a")
          cpg.typeDecl.nameExact("wire_ptr").aliasTypeFullName.l shouldBe List("wire_t*")
      }
  }

  "an anonymous struct declared with a variable" should {
      val cpg = code(
        """struct { int a; } global_v;
        |int use(void) {
        |    struct { int b; } local_v;
        |    local_v.b = 1;
        |    return local_v.b + global_v.a;
        |}
        |int other(void) {
        |    struct { char c; } local_v;
        |    return local_v.c;
        |}
        |""".stripMargin
      )

      "be named after the variable, a local's record after its function too" in {
          requireEdga()
          cpg.typeDecl.nameExact("global_v").member.name.l shouldBe List("a")
          cpg.typeDecl.fullNameExact("use.local_v").member.name.l shouldBe List("b")
          cpg.typeDecl.fullNameExact("other.local_v").member.name.l shouldBe List("c")
          cpg.typeDecl.name(".*unnamed.*").l shouldBe empty
          cpg.local.nameExact("global_v").typeFullName.l shouldBe List("global_v")
      }
  }

  "anonymous members" should {
      val cpg = code(
        """struct outer {
        |    struct { int q; } named;
        |    union { int u; float w; };
        |    struct { int s; };
        |};
        |int get(struct outer *o) { return o->u + o->s + o->named.q; }
        |""".stripMargin
      )

      "keep the numbered names of the owner" in {
          requireEdga()
          cpg.typeDecl.name(".*anonymous_composite_type.*").name.l.sorted shouldBe List(
            "outer.anonymous_composite_type_0",
            "outer.anonymous_composite_type_1"
          )
          cpg.typeDecl.nameExact("outer").member.nameExact("named").typeFullName.l shouldBe
              List("outer.named")
          cpg.typeDecl.name(".*unnamed.*").l shouldBe empty
      }
  }
  "typedef'd enumerations without a tag" should {
      val cpg = code(
        """typedef enum { CLR_RED, CLR_BLUE } colour_t;
        |typedef enum { SZ_SMALL, SZ_LARGE } size_class_t;
        |colour_t paint(colour_t c, size_class_t s) { return s == SZ_SMALL ? c : CLR_BLUE; }
        |""".stripMargin
      )

      "each take the typedef name and keep their own enumerators" in {
          requireEdga()
          cpg.typeDecl.nameExact("colour_t").member.name.l shouldBe List("CLR_RED", "CLR_BLUE")
          cpg.typeDecl.nameExact("size_class_t").member.name.l shouldBe List("SZ_SMALL", "SZ_LARGE")
          cpg.method.nameExact("paint").parameter.typeFullName.l shouldBe List(
            "colour_t",
            "size_class_t"
          )
          cpg.typeDecl.aliasTypeFullName(".*unnamed.*").l shouldBe empty
          cpg.typ.fullName(".*unnamed.*").l shouldBe empty
      }
  }
end AnonymousRecordNameTests

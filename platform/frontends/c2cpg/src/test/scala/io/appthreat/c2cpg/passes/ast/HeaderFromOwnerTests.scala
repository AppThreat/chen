package io.appthreat.c2cpg.passes.ast

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.x2cpg.X2Cpg
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

import java.nio.file.Paths

/** The CPG of a fixture directory under the test resources: the same pipeline the inline
  * `code(...)` fixtures run, over files that stay on disk for every run.
  */
private object FixtureCpgs:
  def of(resource: String): Cpg =
    val dir = Paths.get(classOf[FixtureCpgs.type].getResource(resource).toURI)
    val out = File.newTemporaryFile("c2cpg-fixture.bin")
    out.deleteOnExit()
    val config = Config(includeComments = true)
        .withInputPath(dir.toString)
        .withOutputPath(out.pathAsString)
        .withFunctionBodies(true)
        .withAstCache(false)
    val cpg = new C2Cpg().createCpg(config).get
    X2Cpg.applyDefaultOverlays(cpg)
    cpg

/** A header whose code only makes sense inside the unit that includes it: one that uses a typedef
  * the unit declares before the `#include`, and an X-macro list spelled in a header extension that
  * the unit expands inside an `enum` and inside a `switch`. The types and members such a header
  * contributes come from the unit's parse, as they do from a front end that writes a header as part
  * of its owner, and the header's own file and line numbers are kept. A header that stands on its
  * own - self-contained, or spelled in an extension nothing includes mid-declaration - is parsed as
  * a unit of its own, exactly as before.
  */
class HeaderFromOwnerTests extends org.scalatest.wordspec.AnyWordSpec
    with org.scalatest.matchers.should.Matchers:

  "A header using a typedef its includer declares first" should {

      val cpg = FixtureCpgs.of("/contexts/typedef-before-include")

      "have the field accesses resolved from the unit's parse, under the header's name and lines" in {
          val get_n = cpg.method.nameExact("get_n").l
          get_n.map(m => (m.filename, m.lineNumber, m.lineNumberEnd)) shouldBe Seq((
            "impl.h",
            Some(1),
            Some(1)
          ))

          val calls  = get_n.head.call.l
          val byCode = calls.map(c => c.code -> c.typeFullName).toMap
          byCode("c->n") shouldBe "int"
          byCode("c->buf") shouldBe "char*"
          byCode("c->buf[0]") shouldBe "char"
          byCode("(int)c->buf[0]") shouldBe "int"
          byCode("c->n + (int)c->buf[0]") shouldBe "int"
      }

      "spell the parameter and its identifiers the way the resolved typedef does" in {
          val get_n = cpg.method.nameExact("get_n").l
          get_n.head.parameter.nameExact("c").l.map(_.typeFullName) shouldBe Seq("ctx_t*")
          get_n.head.ast.isIdentifier.nameExact("c").l.map(_.typeFullName) shouldBe Seq(
            "ctx_t*",
            "ctx_t*"
          )
      }

      "leave the unit's own declarations untouched" in {
          val main = cpg.method.nameExact("main").l
          main.map(_.filename) shouldBe Seq("unit.c")
          val ctx_t = cpg.typeDecl.nameExact("ctx_t").l
          ctx_t.map(_.filename) shouldBe Seq("unit.c")
          ctx_t.head.member.l.map(m => (m.name, m.typeFullName)) should contain theSameElementsAs
              Seq(("n", "int"), ("buf", "char*"))
          val call = cpg.call.nameExact("get_n").l
          call.map(c => (c.method.name, c.typeFullName)) shouldBe Seq(("main", "int"))
      }
  }

  "A unit declaring the missing name after its include" should {

      val cpg = FixtureCpgs.of("/contexts/typedef-declared-after-include")

      "keep the header's own parse with the types it can find there" in {
          val widget_len = cpg.method.nameExact("widget_len").l
          widget_len.map(m => (m.filename, m.lineNumber)) shouldBe Seq(("widget.h", Some(1)))
          val field = widget_len.head.call.nameExact("<operator>.indirectFieldAccess").l
          field.map(_.typeFullName) shouldBe Seq("ANY")
          widget_len.head.ast.isIdentifier.nameExact("w").l.map(_.typeFullName) shouldBe Seq(
            "widget_t*"
          )
      }
  }

  "A self-contained header and a header included at file scope" should {

      val cpg = FixtureCpgs.of("/contexts/self-contained-header")

      "keep the graph their own parses give, exactly as before" in {
          val sample_len = cpg.method.nameExact("sample_len").l
          sample_len.map(m => (m.filename, m.lineNumber, m.lineNumberEnd)) shouldBe
              Seq(("lib.h", Some(6), Some(6)))
          sample_len.head.parameter.nameExact("s").l.map(_.typeFullName) shouldBe Seq("sample_t*")
          val len = sample_len.head.call.nameExact("<operator>.indirectFieldAccess").l
          len.map(c => (c.code, c.typeFullName)) shouldBe Seq(("s->len", "int"))

          val plain_tag = cpg.method.nameExact("plain_tag").l
          plain_tag.map(m => (m.filename, m.lineNumber, m.lineNumberEnd)) shouldBe
              Seq(("plain.h", Some(3), Some(3)))
          plain_tag.head.parameter.nameExact("p").l.map(_.typeFullName) shouldBe Seq("plain*")
          val tag = plain_tag.head.call.nameExact("<operator>.indirectFieldAccess").l
          tag.map(c => (c.code, c.typeFullName)) shouldBe Seq(("p->tag", "int"))
      }

      "keep the unit's graph and the types the headers declared" in {
          val run = cpg.method.nameExact("run").l
          run.map(m => (m.filename, m.lineNumber)) shouldBe Seq(("unit.c", Some(4)))
          run.head.local.l.map(l =>
              (l.name, l.typeFullName, l.lineNumber)
          ) should contain theSameElementsAs
              Seq(("s", "sample_t", Some(6)), ("p", "plain", Some(7)))
          val calls = run.head.call.l.map(c => (c.code, c.typeFullName)).toMap
          calls("sample_len(&s)") shouldBe "int"
          calls("plain_tag(&p)") shouldBe "int"
          calls("sample_len(&s) + plain_tag(&p)") shouldBe "int"

          val members = cpg.typeDecl.nameExact("sample").l
              .flatMap(_.member.l.map(m => (m.name, m.typeFullName, m.lineNumber)))
          members should contain theSameElementsAs
              Seq(("len", "int", Some(4)), ("data", "char*", Some(4)))
      }
  }

  "An X-macro list file included inside an enum and inside a switch" should {

      val cpg = FixtureCpgs.of("/contexts/x-macro-def")

      "carry the enumerators as members with the types the expansion gives them" in {
          val op_code = cpg.typeDecl.nameExact("op_code").l
          op_code.map(_.filename) shouldBe Seq("ops.c")
          op_code.head.member.l.map(m =>
              (m.name, m.typeFullName, m.lineNumber)
          ) should contain theSameElementsAs
              Seq(
                ("OP_ADD", "op_code", Some(1)),
                ("OP_SUB", "op_code", Some(2)),
                ("OP_COUNT", "op_code", Some(4))
              )
      }

      "build the switch from the expansion inside the method that holds it" in {
          val op_dispatch = cpg.method.nameExact("op_dispatch").l
          op_dispatch.map(m => (m.filename, m.lineNumber)) shouldBe Seq(("ops.c", Some(7)))
          op_dispatch.head.ast
              .collectAll[io.shiftleft.codepropertygraph.generated.nodes.JumpTarget].l
              .map(j => (j.code, j.lineNumber)) shouldBe
              Seq(("X(ADD)", Some(1)), ("X(SUB)", Some(2)), ("default:", Some(13)))
      }

      "give the same member types as the same list written out inline" in {
          val inline      = FixtureCpgs.of("/contexts/x-macro-inline")
          val defMembers  = membersOf(cpg, "op_code")
          val sameMembers = membersOf(inline, "op_code")
          defMembers.map(_._1) shouldBe sameMembers.map(_._1)
          defMembers.map(_._2) shouldBe sameMembers.map(_._2)
      }

      "write no declarations of its own for the list file" in {
          cpg.method.filename("ops.def").nameNot("<global>").l shouldBe empty
      }
  }

  "An X-macro list spelled in a header extension" should {

      val cpg = FixtureCpgs.of("/contexts/x-macro-header")

      "be taken from the unit's parse instead of being parsed as a unit of its own" in {
          cpg.method.filename("ops.h").nameNot("<global>").l shouldBe empty
      }

      "keep the file in the graph with the types and members the expansion gives" in {
          cpg.file.name.l should contain("ops.h")
          val op_code = cpg.typeDecl.nameExact("op_code").l
          op_code.head.member.l.map(m =>
              (m.name, m.typeFullName, m.lineNumber)
          ) should contain theSameElementsAs
              Seq(
                ("OP_ADD", "op_code", Some(1)),
                ("OP_SUB", "op_code", Some(2)),
                ("OP_COUNT", "op_code", Some(4))
              )
          val op_dispatch = cpg.method.nameExact("op_dispatch").l
          op_dispatch.map(m => (m.filename, m.lineNumber)) shouldBe Seq(("ops.c", Some(7)))
          op_dispatch.head.ast
              .collectAll[io.shiftleft.codepropertygraph.generated.nodes.JumpTarget].l
              .map(j => (j.code, j.lineNumber)) shouldBe
              Seq(("X(ADD)", Some(1)), ("X(SUB)", Some(2)), ("default:", Some(13)))
      }
  }

  private def membersOf(cpg: Cpg, typeName: String): Seq[(String, String, Option[Integer])] =
      cpg.typeDecl.nameExact(typeName).l
          .flatMap(_.member.l.map(m => (m.name, m.typeFullName, m.lineNumber)))
          .sortBy(_._1)

  "The same fixture reached through a symbolic link" should {

      val cpg = SymbolicLinkCpgs.typedefThroughLink

      "give the header the same resolved fragment as the direct spelling" in {
          val get_n = cpg.method.nameExact("get_n").l
          get_n.map(m => (m.filename, m.lineNumber, m.lineNumberEnd)) shouldBe
              Seq(("impl.h", Some(1), Some(1)))
          val byCode = get_n.head.call.l.map(c => c.code -> c.typeFullName).toMap
          byCode("c->n") shouldBe "int"
          byCode("c->buf") shouldBe "char*"
          byCode("c->buf[0]") shouldBe "char"
      }
  }
end HeaderFromOwnerTests

/** The typedef fixture built in a directory the run reaches only through a symbolic link: the
  * preprocessor registers included content under the link's real path, so the input path given to
  * the frontend is spelled differently from every file name the parse reports.
  */
private object SymbolicLinkCpgs:
  lazy val typedefThroughLink: Cpg =
    val source =
        Paths.get(classOf[FixtureCpgs.type].getResource("/contexts/typedef-before-include").toURI)
    val target = java.nio.file.Files.createTempDirectory("c2cpg-linked-fixture")
    java.nio.file.Files.writeString(
      target.resolve("impl.h"),
      java.nio.file.Files.readString(source.resolve("impl.h"))
    )
    java.nio.file.Files.writeString(
      target.resolve("unit.c"),
      java.nio.file.Files.readString(source.resolve("unit.c"))
    )
    val link = target.resolveSibling(s"${target.getFileName}-link")
    java.nio.file.Files.deleteIfExists(link)
    val linked =
        try java.nio.file.Files.createSymbolicLink(link, target)
        catch
          case _: Throwable =>
              assume(false, "symbolic links are unavailable on this filesystem"); target
    val out = File.newTemporaryFile("c2cpg-linked.bin")
    out.deleteOnExit()
    val config = Config(includeComments = true)
        .withInputPath(linked.toString)
        .withOutputPath(out.pathAsString)
        .withFunctionBodies(true)
        .withAstCache(false)
    val cpg = new C2Cpg().createCpg(config).get
    X2Cpg.applyDefaultOverlays(cpg)
    cpg
  end typedefThroughLink
end SymbolicLinkCpgs

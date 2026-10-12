package io.appthreat.edg2atom

import better.files.File
import io.appthreat.c2cpg.{C2Cpg, Config}
import io.appthreat.edg2atom.parser.EdgaRunner
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The graphs of both C/C++ frontends side by side on the fixtures in `golden/`: every difference
  * in names, signatures, types and shapes is one `<fixture>.differences` lists, each with the
  * reason it is expected (a `#` comment above it). A difference the file does not list, or one it
  * lists that is gone, fails the test.
  *
  * To rewrite the files after a change, run with `-Dedg2atom.golden.update=true` and review the
  * result: comments of lines that remain are kept, new lines need one.
  */
class GoldenComparisonTests extends AnyWordSpec with Matchers:

  private val fixtures = Seq("basics.c", "classes.cpp", "templates.cpp")
  private val update   = sys.props.get("edg2atom.golden.update").contains("true")
  // the source tree when the tests run from the project (to rewrite it), else the class path
  private val resources =
    val source = File("src/test/resources/golden")
    if source.exists then source
    else File(getClass.getClassLoader.getResource("golden/basics.c").toURI).parent

  "the two frontends" should {
      fixtures.foreach { fixture =>
          s"differ on $fixture only as reviewed" in {
              assume(EdgaRunner.locate().isDefined, "edga is not installed")
              val cdt      = dump(fixture, edg = false)
              val edg      = dump(fixture, edg = true)
              val actual   = differences(cdt, edg)
              val expected = resources / s"$fixture.differences"
              if update then write(expected, actual)
              val reviewed = if expected.exists then expected.lines.toSeq else Seq.empty
              reviewed.filterNot(l => l.startsWith("#") || l.isBlank) shouldBe actual
          }
      }
  }

  /** `- ` lines only the CDT frontend's graph has, `+ ` lines only edga's has, sorted. */
  private def differences(cdt: Seq[String], edg: Seq[String]): Seq[String] =
    val onlyCdt = cdt.diff(edg).map("- " + _)
    val onlyEdg = edg.diff(cdt).map("+ " + _)
    (onlyCdt ++ onlyEdg).sortBy(l => (l.drop(2), l.head))

  /** The comments of the lines that remain are kept above the first of them. */
  private def write(file: File, lines: Seq[String]): Unit =
    val comments = scala.collection.mutable.Map.empty[String, Seq[String]]
    if file.exists then
      var pending = Seq.empty[String]
      file.lines.foreach { l =>
          if l.startsWith("#") then pending :+= l
          else if !l.isBlank then
            if pending.nonEmpty then comments(l) = comments.getOrElse(l, Seq.empty) ++ pending
            pending = Seq.empty
      }
    val seen = scala.collection.mutable.Set.empty[String]
    val text =
        lines.flatMap(l => (if seen.add(l) then comments.getOrElse(l, Seq.empty) else Nil) :+ l)
    file.writeText(text.mkString("", "\n", "\n"))

  private def dump(fixture: String, edg: Boolean): Seq[String] =
    val dir = File.newTemporaryDirectory("golden")
    val out = File.newTemporaryFile("golden", ".atom")
    try
      (resources / fixture).copyToDirectory(dir)
      val config = Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
          .withFunctionBodies(true).withAstCache(false)
      val cpg = (if edg then new Edg2Atom() else new C2Cpg()).createCpg(config).get
      try lines(cpg)
      finally cpg.close()
    finally
      dir.delete(swallowIOExceptions = true)
      out.delete(swallowIOExceptions = true)

  /** What both frontends promise: each method's full name and signature, its parameters, locals,
    * calls, identifiers, literals and control structures, in the order written; each type's
    * members. Positions are left out.
    */
  private def lines(cpg: Cpg): Seq[String] =
    val methods = cpg.method.isExternal(false).filterNot(m =>
        m.name.startsWith("<") || m.block.astChildren.isEmpty
    ).sortBy(_.fullName).l
    val types =
        cpg.typeDecl.isExternal(false).filterNot(_.name.startsWith("<")).sortBy(_.fullName).l
    methods.flatMap { m =>
        s"METHOD ${m.fullName} | ${m.signature} | returns ${m.methodReturn.typeFullName}" +:
            (m.parameter.sortBy(_.index).map(p => s"  ${m.name} PARAM ${p.name}: ${p.typeFullName}")
                .l ++
                m.block.ast.collect(node(m.name)).l)
    } ++ types.map { t =>
      val members = t.member.sortBy(_.order).map(mb => s"${mb.name}: ${mb.typeFullName}").l
      s"TYPE_DECL ${t.fullName} members=${members.mkString(", ")}"
    }

  private def node(method: String): PartialFunction[AstNode, String] =
    case l: Local => s"  $method LOCAL ${l.name}: ${l.typeFullName}"
    case c: Call =>
        s"  $method CALL ${c.name} -> ${c.methodFullName} [${c.dispatchType}] args=${c.argument.size}"
    case i: Identifier        => s"  $method IDENTIFIER ${i.name}: ${i.typeFullName}"
    case l: Literal           => s"  $method LITERAL ${l.code}: ${l.typeFullName}"
    case cs: ControlStructure => s"  $method CONTROL ${cs.controlStructureType}"
    case _: Return            => s"  $method RETURN"
    case r: MethodRef         => s"  $method METHOD_REF ${r.methodFullName}"
end GoldenComparisonTests

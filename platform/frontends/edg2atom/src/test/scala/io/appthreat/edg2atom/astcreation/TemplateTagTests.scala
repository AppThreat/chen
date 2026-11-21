package io.appthreat.edg2atom.astcreation

import better.files.File
import io.appthreat.c2cpg.Config
import io.appthreat.edg2atom.Edg2Atom
import io.appthreat.edg2atom.testfixtures.EdgCodeToCpgSuite
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Method
import io.shiftleft.semanticcpg.language.*

/** The template identity edga exports, read into the graph: an instance METHOD names the template
  * it came from and the arguments it was written with, the prototype of a template nothing
  * instantiated is the template's pattern, one unit is kept per template definition, and a call
  * written in a pattern whose callee the unit resolves only per instance lists the METHODs it
  * reaches in the unit's instances.
  */
class TemplateTagTests extends EdgCodeToCpgSuite(".cpp"):

  private def tagsOf(method: Method, name: String): List[String] =
      method.tag.nameExact(name).value.l

  private def templateTags(method: Method): List[String] =
      tagsOf(method, X2CpgDefines.TemplateTag)

  private def templateArgs(method: Method): List[String] =
      tagsOf(method, X2CpgDefines.TemplateArgsTag)

  private def templatePattern(method: Method): List[String] =
      tagsOf(method, X2CpgDefines.TemplatePatternTag)

  /** A class template whose members are used with two argument types, a function template used with
    * two types, and two templates nothing instantiates: one whose body calls a member of its own
    * class (resolved per instance in the units that use the class), one a free function whose
    * callee is a member of its parameter's type. Every instance is written with a known type.
    */
  private val cpg = code(
    """
      |template <typename T> struct Box {
      |  T v;
      |  T get() const { return v; }
      |  void put(const T &x) { v = x; }
      |  T trans() const { return get() + T(); }
      |};
      |template <typename T> int twice(T x) { return x.get() + x.get(); }
      |template <typename T> int tally(const T &x) { return x.size() + 1; }
      |struct A { int get() const { return 1; } };
      |struct B { int get() const { return 2; } };
      |int main() {
      |  A a; B b;
      |  Box<int> bi; bi.put(3);
      |  Box<long> bl; bl.put(4L);
      |  return twice(a) + twice(b) + bi.get() + bl.get();
      |}
      |""".stripMargin
  )

  "an instance METHOD" should {

      "carry the tag of the template it came from" in {
          requireEdga()
          val twices = cpg.method.nameExact("twice").l
          twices should have size 2
          // both instances name the same template; the front end spells its name without
          // arguments for a free function template
          twices.map(templateTags).l shouldBe List(List("twice"), List("twice"))
          val boxGets = cpg.method.nameExact("get").filter(templateTags(_).nonEmpty).l
              .sortBy(_.fullName)
          boxGets.map(_.fullName).l shouldBe List(
            "Box<int>.get:int()",
            "Box<long>.get:long int()"
          )
          boxGets.map(templateTags).l shouldBe List(List("Box<T>.get"), List("Box<T>.get"))
      }

      "carry the arguments it was written with" in {
          requireEdga()
          val twices = cpg.method.nameExact("twice").sortBy(_.fullName).l
          twices.map(templateArgs).l shouldBe List(List("A"), List("B"))
          val boxGets = cpg.method.nameExact("get").filter(templateTags(_).nonEmpty).l
              .sortBy(_.fullName)
          boxGets.map(templateArgs).l shouldBe List(List("int"), List("long"))
          val puts = cpg.method.nameExact("put").filter(templateTags(_).nonEmpty).l
              .sortBy(_.fullName)
          puts.map(templateArgs).l shouldBe List(List("int"), List("long"))
          // the plain members of A and B came from no template
          cpg.method.fullNameExact("A.get:int()", "B.get:int()").l.foreach { plain =>
            templateTags(plain) shouldBe empty
            templateArgs(plain) shouldBe empty
            templatePattern(plain) shouldBe empty
          }
      }
  }

  "the METHOD of a template nothing instantiated" should {

      "carry the template-pattern tag and no instance tags" in {
          requireEdga()
          val tallyMethod = cpg.method.nameExact("tally").l
          tallyMethod should have size 1
          templatePattern(tallyMethod.head) shouldBe List("true")
          templateTags(tallyMethod.head) shouldBe empty
          templateArgs(tallyMethod.head) shouldBe empty
      }

      "carry the pattern tag for a member of an instantiated class template" in {
          requireEdga()
          // trans is called by no instance; its pattern is the method's body with the
          // parameters in place
          val transPatterns = cpg.method.nameExact("trans").filter(templatePattern(_).nonEmpty).l
          transPatterns should have size 1
          transPatterns.head.fullName shouldBe "Box<T>.trans:T()"
          transPatterns.head.filename.endsWith(".cpp") shouldBe true
      }
  }

  "a call written in a pattern" should {

      "keep today's unresolved shape and list the instance METHODs it reaches" in {
          requireEdga()
          val get = cpg.method.nameExact("trans").filter(templatePattern(_).nonEmpty).head.ast
              .isCall.nameExact("<operator>.pointerCall").l
          get should have size 1
          // the full name and dispatch are today's; only the callee list is new
          get.head.methodFullName shouldBe "<operator>.pointerCall"
          get.head.dispatchType shouldBe "DYNAMIC_DISPATCH"
          get.head.dynamicTypeHintFullName.l shouldBe List(
            "Box<int>.get:int()",
            "Box<long>.get:long int()"
          )
      }

      "list nothing for a pattern whose template the unit did not instantiate" in {
          requireEdga()
          val size = cpg.method.nameExact("tally").head.ast.isCall
              .nameExact("<operator>.pointerCall").l
          size should have size 1
          size.head.methodFullName shouldBe "<operator>.pointerCall"
          size.head.dynamicTypeHintFullName.l shouldBe empty
      }

      "leave the resolved calls of the instances alone" in {
          requireEdga()
          val resolved = cpg.method.nameExact("main").ast.isCall.l
          val twices   = resolved.nameExact("twice").l
          twices.map(_.methodFullName).sorted.l shouldBe List("twice:int(A)", "twice:int(B)")
          twices.flatMap(_.dynamicTypeHintFullName).l shouldBe empty
          val memberGets = resolved.filter(_.name == "get").l
          memberGets.map(_.methodFullName).sorted.l shouldBe List(
            "Box<int>.get:int()",
            "Box<long>.get:long int()"
          )
          memberGets.flatMap(_.dynamicTypeHintFullName).l shouldBe empty
      }

      "rename no method the graph already holds" in {
          requireEdga()
          // every METHOD of the fixture keeps today's full name; the instance and pattern tags
          // are the only thing the template identity adds
          cpg.method.isExternal(false).filterNot(_.name == "<global>").fullName.l.toSet shouldBe
              Set(
                "A.get:int()",
                "B.get:int()",
                "Box<T>.trans:T()",
                "Box<int>.get:int()",
                "Box<int>.put:void(int &)",
                "Box<int>.trans:int()",
                "Box<long>.get:long int()",
                "Box<long>.put:void(long int &)",
                "Box<long>.trans:long int()",
                "tally:int(T &)",
                "twice:int(A)",
                "twice:int(B)",
                "main:int()"
              )
      }
  }

  /** A project of two units sharing a header that defines the templates: a class template both
    * units use with their own argument type, and a function template nothing instantiates.
    */
  private def withTwoUnitProject(run: Cpg => Unit): Unit =
    requireEdga()
    val header =
        """#ifndef TMPLMATH_HPP
          |#define TMPLMATH_HPP
          |template <typename T> struct Slot {
          |  T v;
          |  T read() const { return v; }
          |  void store(const T &x) { v = x; }
          |  T echo() const { return read(); }
          |};
          |template <typename T> T weigh(const T &x) { return x.weight() + 1; }
          |struct Load { int weight() const { return 1; } };
          |#endif
          |""".stripMargin
    val first =
        """#include "tmplmath.hpp"
          |int first() {
          |  Slot<int> s; s.store(1);
          |  return s.read();
          |}
          |""".stripMargin
    val second =
        """#include "tmplmath.hpp"
          |int second() {
          |  Slot<unsigned> s; s.store(2U);
          |  return s.read();
          |}
          |""".stripMargin
    val root = File.newTemporaryDirectory("tmpltags")
    val out  = File.newTemporaryFile("tmpltags", ".atom")
    (root / "tmplmath.hpp").write(header)
    (root / "first_use.cpp").write(first)
    (root / "second_use.cpp").write(second)
    out.deleteOnExit()
    val cpg = new Edg2Atom().createCpg(
      Config().withInputPath(root.pathAsString).withOutputPath(out.pathAsString)
          .withFunctionBodies(true).withAstCache(false)
    ).get
    try run(cpg)
    finally
      cpg.close()
      root.delete(swallowIOExceptions = true)
      out.delete(swallowIOExceptions = true)
  end withTwoUnitProject

  "a project of units sharing a header" should {

      "write one copy of each template definition and each instance" in {
          withTwoUnitProject { cpg =>
            // the function template nothing instantiates: its pattern, written once
            val weighs = cpg.method.nameExact("weigh").l
            weighs should have size 1
            templatePattern(weighs.head) shouldBe List("true")
            weighs.head.fullName shouldBe "weigh:T(T &)"
            // the class template's pattern member, also written once
            val echoes = cpg.method.nameExact("echo").filter(templatePattern(_).nonEmpty).l
            echoes should have size 1
            echoes.head.fullName shouldBe "Slot<T>.echo:T()"
            // one instance of the class per argument type, its member once per instance
            val reads = cpg.method.nameExact("read").filter(templateTags(_).nonEmpty).l
                .sortBy(_.fullName)
            reads.map(_.fullName).l shouldBe List(
              "Slot<int>.read:int()",
              "Slot<unsigned int>.read:unsigned int()"
            )
            reads.map(templateTags).l shouldBe List(List("Slot<T>.read"), List("Slot<T>.read"))
            reads.map(templateArgs).l shouldBe List(List("int"), List("unsigned int"))
          }
      }
  }

  "ordinary code without templates" should {

      /** A project with no template in it, the shape every template-free project has. */
      val plain = code("""
        |struct Gauge {
        |  int level;
        |  int read() const { return level; }
        |};
        |int check(Gauge *g, int limit) {
        |  int level = g->read();
        |  return level > limit ? limit : level;
        |}
        |""".stripMargin)

      "carry no template tag on any node and no callee hint on any call" in {
          requireEdga()
          plain.method.tag
              .nameExact(
                X2CpgDefines.TemplateTag,
                X2CpgDefines.TemplateArgsTag,
                X2CpgDefines.TemplatePatternTag
              ).l shouldBe empty
          plain.call.flatMap(_.dynamicTypeHintFullName).l shouldBe empty
          // and nothing else about the graph moved: the methods keep their names and shapes
          plain.method.nameExact("read").head.fullName shouldBe "Gauge.read:int()"
          plain.method.nameExact("check").head.fullName shouldBe "check:int(Gauge*,int)"
          plain.call.nameExact("read").head.methodFullName shouldBe "Gauge.read:int()"
      }
  }
end TemplateTagTests

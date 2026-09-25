package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.testfixtures.DataFlowCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.nodes.{Identifier, Local}
import io.shiftleft.semanticcpg.language.*

/** A declaration in a `for` init (and in a C++ `if` condition) is in scope for the whole statement:
  * every later occurrence of the counter must resolve to its LOCAL - a REF edge and the declared
  * type - exactly as when the counter is declared before the loop. The init's scope used to close
  * before the condition, the update and the body were built, and 517 of libavformat's 586 such
  * loops lost their counter's type and definitions.
  */
class ForInitScopeTests extends DataFlowCodeToCpgSuite:

  private val cpg = code(
    """
      |void use(int v);
      |int a[4];
      |void f_decl(int n) { for (int i = 0; i < n; i++) use(a[i]); }
      |void f_before(int n) { int i; for (i = 0; i < n; i++) use(a[i]); }
      |void f_unsigned(void) { for (unsigned i = 0; i < 4; i++) use(a[i]); }
      |void f_two(int n) { for (int i = 0, j = 1; i < n; i++, j++) use(a[i] + j); }
      |void f_shadow(void) {
      |    int i = 3;
      |    for (int i = 0; i < 2; i++) use(a[i]);
      |    use(a[i]);
      |}
      |""".stripMargin,
    "loops.c"
  ).moreCode(
    """
      |int g(void);
      |void use(int v);
      |void f_if(void) { if (int x = g()) use(x); else use(x + 1); }
      |""".stripMargin,
    "cond.cpp"
  )

  private def ids(method: String, name: String): List[Identifier] =
      cpg.method.nameExact(method).ast.isIdentifier.nameExact(name).l

  private def locals(i: Identifier): List[Local] = i._refOut.collectAll[Local].l

  "a counter declared in the for init" should:
    "resolve every occurrence to its LOCAL, with its declared type" in {
        for m <- List("f_decl", "f_before") do
          val occurrences = ids(m, "i")
          occurrences.size shouldBe 4
          occurrences.map(_.typeFullName).distinct shouldBe List("int")
          occurrences.flatMap(locals).distinct.size shouldBe 1
    }
    "keep an unsigned counter's type in the condition and the body" in {
        ids("f_unsigned", "i").map(_.typeFullName).distinct.map(_.stripSuffix(" int")) shouldBe
            List("unsigned")
    }
    "resolve both of two declarators" in {
        for name <- List("i", "j") do
          val occurrences = ids("f_two", name)
          occurrences.filter(locals(_).isEmpty) shouldBe empty
          occurrences.flatMap(locals).distinct.size shouldBe 1
    }
    "connect the body's use to the condition that tests it" in {
        val bodyUse = cpg.method.nameExact("f_decl").call.name("<operator>.*ndexAccess")
            .argument(2).isIdentifier.head
        bodyUse._reachingDefIn.collectAll[Identifier].map(_._astIn.collectAll[
          io.shiftleft.codepropertygraph.generated.nodes.Call
        ].name.l).l.flatten should contain("<operator>.lessThan")
    }
    "go out of scope after the loop: a later `i` is the outer one" in {
        val all      = ids("f_shadow", "i")
        val outer    = locals(all.head).head
        val afterUse = all.maxBy(_.lineNumber.map(_.toInt).getOrElse(0))
        locals(afterUse) shouldBe List(outer)
        all.filter(locals(_).isEmpty) shouldBe empty
        all.flatMap(locals).distinct.size shouldBe 2
    }

  "a C++ if-condition declaration" should:
    "be in scope in both branches" in {
        val xs = ids("f_if", "x")
        xs.size shouldBe 3
        xs.filter(locals(_).isEmpty) shouldBe empty
        xs.flatMap(locals).distinct.size shouldBe 1
    }
end ForInitScopeTests

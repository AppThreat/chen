package io.appthreat.c2cpg.querying.cppeval

import io.appthreat.c2cpg.astcreation.CppScopeExits
import io.appthreat.c2cpg.parser.FileDefaults
import io.appthreat.c2cpg.testfixtures.CCodeToCpgSuite
import io.shiftleft.codepropertygraph.generated.nodes.{Call, CfgNode}
import io.shiftleft.codepropertygraph.generated.{ControlStructureTypes, Operators}
import io.shiftleft.semanticcpg.language.*

/** Objects with automatic storage are destroyed where control leaves their scope: at its end, and
  * at every `return`, `break`, `continue` and `goto` that leaves it early.
  */
class CppScopeExitTests extends CCodeToCpgSuite(fileSuffix = FileDefaults.CPP_EXT):

  private val guard = """
      |struct Guard { Guard(); explicit Guard(int n); ~Guard(); operator bool() const; int v; };
      |int poll();
      |""".stripMargin

  /** The destructor calls of `method` in CFG order from its entry, by code. */
  private def destructorsOn(cpg: io.shiftleft.codepropertygraph.Cpg, method: String) =
      cpg.method.nameExact(method).call.nameExact("~Guard").code.l

  /** The destructor calls that run right before the jump statement with `code` in `method`, in the
    * order they run.
    */
  private def destructorsBefore(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    method: String,
    code: String
  ): List[String] =
    val target   = cpg.method.nameExact(method).ast.isCfgNode.codeExact(code).head
    val inTarget = target.ast.isCfgNode.l.toSet[CfgNode]
    Iterator.iterate(target.cfgPrev.headOption)(_.flatMap(_.cfgPrev.headOption))
        .takeWhile(_.isDefined).flatten
        .dropWhile(inTarget.contains)
        .takeWhile { case c: Call => c.name == "~Guard"; case _ => false }
        .map(_.code).toList.reverse

  "a return" should {
      val cpg = code(s"""$guard
          |int early(int n) {
          |  Guard outer;
          |  if (n > 0) {
          |    Guard inner;
          |    if (n > 5) return 1;
          |    Guard later;
          |    return outer.v + n;
          |  }
          |  return 0;
          |}
          |void noValue(int n) {
          |  Guard g;
          |  if (n) return;
          |  poll();
          |}
          |""".stripMargin)

      "destroy every object constructed so far, innermost first, before a constant value" in {
          destructorsBefore(cpg, "early", "return 1;") shouldBe List(
            "inner.~Guard()",
            "outer.~Guard()"
          )
      }

      "compute a value that reads a destroyed object before destroying it" in {
          val ret = cpg.method.nameExact("early").ast.isReturn.codeExact("return outer.v + n;").head
          ret.astChildren.isIdentifier.name.l shouldBe List(CppScopeExits.ReturnValueName)
          val store = cpg.method.nameExact("early").call.nameExact(Operators.assignment)
              .filter(_.argument(1).code == CppScopeExits.ReturnValueName).head
          store.argument(2).code shouldBe "outer.v + n"
          store.typeFullName shouldBe "int"
          destructorsBefore(cpg, "early", "return outer.v + n;") shouldBe List(
            "later.~Guard()",
            "inner.~Guard()",
            "outer.~Guard()"
          )
          cpg.method.nameExact("early").local.nameExact(CppScopeExits.ReturnValueName)
              .typeFullName.l shouldBe List("int")
      }

      "not destroy an object twice where control cannot fall out of the block" in {
          destructorsOn(cpg, "early").count(_ == "later.~Guard()") shouldBe 1
          destructorsOn(cpg, "early").count(_ == "inner.~Guard()") shouldBe 2
          destructorsOn(cpg, "early").count(_ == "outer.~Guard()") shouldBe 3
      }

      "destroy before a return without a value, and at the end of the body" in {
          destructorsBefore(cpg, "noValue", "return;") shouldBe List("g.~Guard()")
          destructorsOn(cpg, "noValue") shouldBe List("g.~Guard()", "g.~Guard()")
      }
  }

  "break and continue" should {
      val cpg = code(s"""$guard
          |void loops(int n) {
          |  for (int i = 0; i < n; i++) {
          |    Guard step;
          |    if (i == 2) continue;
          |    if (i == 3) break;
          |    poll();
          |  }
          |  while (n--) {
          |    Guard a;
          |    switch (n) {
          |      case 1: { Guard b; break; }
          |      default: break;
          |    }
          |  }
          |}
          |""".stripMargin)

      "destroy the iteration's objects before continuing or breaking" in {
          destructorsBefore(cpg, "loops", "continue;") shouldBe List("step.~Guard()")
          destructorsBefore(cpg, "loops", "break;") shouldBe List("step.~Guard()")
      }

      "destroy only the scopes inside the switch a break leaves" in {
          val breaks = cpg.method.nameExact("loops").ast.isControlStructure
              .controlStructureTypeExact(ControlStructureTypes.BREAK).l
          val inCase = breaks.filter(b =>
              b.cfgPrev.collect { case c: Call => c.code }.l == List("b.~Guard()")
          )
          inCase should have size 1
      }
  }

  "condition and loop variables" should {
      val cpg = code(s"""$guard
          |struct Item { Item(int); ~Item(); };
          |void conditions(int *xs, int n) {
          |  if (Guard g = Guard(n)) { poll(); }
          |  while (Guard w = Guard(poll())) {
          |    if (n) continue;
          |    poll();
          |  }
          |  for (int x : {1, 2, 3}) { Item it(x); if (x) break; }
          |  switch (Guard s = Guard(n); n) { case 0: break; }
          |}
          |void ranged() {
          |  Guard arr[2];
          |  for (Guard r : arr) { if (poll()) break; poll(); }
          |  poll();
          |}
          |""".stripMargin)

      "destroy an if's condition variable after the statement" in {
          val List(dtor) = cpg.method.nameExact("conditions").call.codeExact("g.~Guard()").l
          dtor.cfgPrev.code.l should contain("poll()")
      }

      "destroy a while's condition variable at the end of each iteration, at continue and on exit" in {
          destructorsOn(cpg, "conditions").count(_ == "w.~Guard()") shouldBe 3
          destructorsBefore(cpg, "conditions", "continue;") shouldBe List("w.~Guard()")
      }

      "destroy a range-based for's loop variable in every iteration, not after the loop" in {
          val dtors = cpg.method.nameExact("ranged").call.codeExact("r.~Guard()").l
          dtors should have size 2
          dtors.foreach { d =>
              d.inAstMinusLeaf.isControlStructure
                  .controlStructureTypeExact(ControlStructureTypes.FOR).l should have size 1
          }
          destructorsBefore(cpg, "ranged", "break;") shouldBe List("r.~Guard()")
      }

      "destroy a switch's init-statement variable after the switch" in {
          destructorsOn(cpg, "conditions").count(_ == "s.~Guard()") shouldBe 1
          cpg.method.nameExact("conditions").local.nameExact("s").l should have size 1
      }

      "build the declarations of conditions and init statements" in {
          (cpg.method.nameExact("conditions").local.name.toSetMutable should contain).allOf(
            "g",
            "w",
            "s"
          )
      }
  }

  "a goto" should {
      val cpg = code(s"""$guard
          |void retry(int n) {
          |again:
          |  Guard attempt;
          |  {
          |    Guard nested;
          |    if (poll()) goto again;
          |    if (n) goto done;
          |  }
          |done:
          |  poll();
          |}
          |""".stripMargin)

      "destroy the objects a jump back passes, and those of the scopes it leaves" in {
          destructorsBefore(cpg, "retry", "goto again;") shouldBe List(
            "nested.~Guard()",
            "attempt.~Guard()"
          )
          destructorsBefore(cpg, "retry", "goto done;") shouldBe List("nested.~Guard()")
      }
  }
end CppScopeExitTests

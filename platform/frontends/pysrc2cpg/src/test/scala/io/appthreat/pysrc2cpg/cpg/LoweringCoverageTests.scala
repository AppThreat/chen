package io.appthreat.pysrc2cpg.cpg

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.shiftleft.codepropertygraph.generated.ControlStructureTypes
import io.shiftleft.semanticcpg.language.*

/** Regression tests for the lowering coverage work: real FOR control structures, operator lowerings
  * for slice/yield/starred/global/nonlocal, and decorator annotation parameters. Each of these used
  * to be an UNKNOWN node or missing entirely.
  */
class LoweringCoverageTests extends PySrc2CpgFixture():

  "for loops" should {
      "lower to a CONTROL_STRUCTURE(FOR) with conventional children and keep the iteration protocol" in {
          val cpg = code("""def f(xs):
          |    for x in xs:
          |        sink(x)""".stripMargin)
          val forCs = cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.FOR).l
          forCs.size shouldBe 1
          // no WHILE left behind for the same statement
          cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.WHILE).isEmpty shouldBe true

          val children = forCs.head.astChildren.l
          children.size shouldBe 3 // init, condition, body (no loop expression)
          // init (order 1): tmp = xs.__iter__()
          val init = children.head
          init.order shouldBe 1
          init.code should include("__iter__")
          // condition (order 2): <operator>.iteratorNonEmpty over the iterator tmp
          val condition = forCs.head.condition.head
          condition.order shouldBe 2
          condition.code shouldBe "<operator>.iteratorNonEmpty(tmp0)"
          // body (order 4) starts with the __next__ assignment
          val body = children(2)
          body.order shouldBe 4
          body.ast.isCall.name("__next__").size shouldBe 1
          body.ast.isCall.nameExact("sink").size shouldBe 1
      }

      "lower async for to a FOR carrying async in its code" in {
          val cpg = code("""async def f(xs):
          |    async for x in xs:
          |        sink(x)""".stripMargin)
          val forCs = cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.FOR).l
          forCs.size shouldBe 1
          forCs.head.code shouldBe "async for ... : ..."
      }

      "lower comprehensions to FOR control structures" in {
          val cpg = code("""def f(xs):
          |    return [x for x in xs]""".stripMargin)
          cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.FOR).size shouldBe 1
          cpg.controlStructure.controlStructureTypeExact(ControlStructureTypes.WHILE).isEmpty shouldBe true
      }
  }

  "slices" should {
      "lower to indexAccess over a <operator>.slice call whose bounds carry taint" in {
          val cpg = code("""def f(m):
          |    return m[1:2]""".stripMargin)
          val sliceCall = cpg.call.nameExact("<operator>.slice").l
          sliceCall.size shouldBe 1
          sliceCall.head.code shouldBe "1:2"
          sliceCall.head.argument.size shouldBe 2

          val indexAccess = cpg.call.nameExact("<operator>.indexAccess").l
          indexAccess.size shouldBe 1
          indexAccess.head.argument.code("1:2").size shouldBe 1
      }

      "support step-only and multi-dimensional slices" in {
          val cpg = code("""def f(m):
          |    return m[::2, 1:9:3]""".stripMargin)
          val slices = cpg.call.nameExact("<operator>.slice").map(_.code).l.sorted
          slices shouldBe List("1:9:3", "::2")
      }
  }

  "yield" should {
      "lower to a <operator>.yield call wired to the method return" in {
          val cpg = code("""def gen(x):
          |    yield x""".stripMargin)
          val yieldCall = cpg.call.nameExact("<operator>.yield").l
          yieldCall.size shouldBe 1
          yieldCall.head.code shouldBe "yield x"
          yieldCall.head.argument.size shouldBe 1
          // the yield is a return point: CFG edge into the enclosing METHOD_RETURN
          yieldCall.head._cfgOut.l.map(_.label) should contain("METHOD_RETURN")
      }

      "lower yield from to a <operator>.yieldFrom call" in {
          val cpg = code("""def gen(it):
          |    yield from it""".stripMargin)
          val yieldFromCall = cpg.call.nameExact("<operator>.yieldFrom").l
          yieldFromCall.size shouldBe 1
          yieldFromCall.head.code shouldBe "yield from it"
          yieldFromCall.head._cfgOut.l.map(_.label) should contain("METHOD_RETURN")
      }
  }

  "starred assignment targets" should {
      "bind the tail via starredUnpack over a slice" in {
          val cpg = code("""def f(v):
          |    a, (b, *rest) = v""".stripMargin)
          val starred = cpg.call.nameExact("<operator>.starredUnpack").l
          starred.size shouldBe 1
          starred.head.code should startWith("*tmp")
          starred.head.ast.isCall.nameExact("<operator>.slice").size shouldBe 1

          // rest is a real identifier resolving to a local
          val restIdents = cpg.identifier.nameExact("rest").l
          restIdents.size shouldBe 1
          restIdents.head.refsTo.l.map(_.label) shouldBe List("LOCAL")
          cpg.local.nameExact("rest").size shouldBe 1
      }
  }

  "global and nonlocal" should {
      "lower to operator calls carrying the names instead of UNKNOWN nodes" in {
          val cpg = code("""x = 1
          |def outer():
          |    global x
          |    def inner():
          |        nonlocal y
          |        y = 2
          |    inner()
          |outer()""".stripMargin)
          cpg.all.filter(_.label == "UNKNOWN").size shouldBe 0
          val globalCall = cpg.call.nameExact("<operator>.global").l
          globalCall.size shouldBe 1
          globalCall.head.code shouldBe "global x"
          globalCall.head.argument.isLiteral.code("x").size shouldBe 1
          val nonlocalCall = cpg.call.nameExact("<operator>.nonlocal").l
          nonlocalCall.size shouldBe 1
          nonlocalCall.head.code shouldBe "nonlocal y"
      }
  }

  "decorator annotations" should {
      "expose arguments as ANNOTATION_PARAMETER_ASSIGN children with literal values" in {
          val cpg = code("""import flask
          |app = flask.Flask(__name__)
          |@app.route("/users", methods=["GET"])
          |def users(): pass""".stripMargin)
          val annotation = cpg.annotation.nameExact("app.route").l
          annotation.size shouldBe 1
          annotation.head.code shouldBe """@app.route("/users", methods=["GET"])"""
          val params = annotation.head.astChildren.l.collect {
              case p: io.shiftleft.codepropertygraph.generated.nodes.AnnotationParameterAssign => p
          }
          params.size shouldBe 2
          params.head.code shouldBe "\"/users\""
          params.head.astChildren.isLiteral.code("\"/users\"").size shouldBe 1
          params.toList(1).code shouldBe "methods = [\"GET\"]"
          params.toList(1).astChildren.isCall.name("<operator>.listLiteral").size shouldBe 1
      }

      "surface class decorators on the instance type decl" in {
          val cpg = code("""def deco(c): return c
          |@deco
          |class C: pass""".stripMargin)
          val annotation = cpg.typeDecl.nameExact("C").annotation.l
          annotation.size shouldBe 1
          annotation.head.name shouldBe "deco"
      }
  }
end LoweringCoverageTests

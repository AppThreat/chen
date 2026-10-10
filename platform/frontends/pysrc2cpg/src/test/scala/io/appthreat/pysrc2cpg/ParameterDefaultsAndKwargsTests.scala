package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.language.toExtendedCfgNode
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*

/** Parameter defaults and keyword/unpacked arguments in the CPG and in data flow.
  *
  *   - A default is evaluated once, where the `def` or `lambda` is (CPython 3.15 evaluates `def
  *     f(x=x)` against the enclosing `x`), into a hidden variable `<default>f.x`; the function
  *     captures it and its first statement is `x = x if x passed else <default>f.x`.
  *   - A named argument binds the parameter of that name, `f(**opts)` any parameter a keyword can,
  *     extra positionals the `*args` collector and unknown names the `**kwargs` one.
  */
class ParameterDefaultsAndKwargsTests extends PySrc2CpgFixture(withOssDataflow = true):

  "parameter defaults" should {

      "be evaluated where the def is, before the function is bound" in {
          val cpg = code(
            """x = 1
              |def f(a, b=2, *, c=x):
              |    return a + b + c
              |""".stripMargin
          )
          val module = cpg.method.nameExact("<module>").head
          (module.ast.isCall.nameExact(Operators.assignment).code.l should contain).allOf(
            "<default>f.b = 2",
            "<default>f.c = x"
          )
          // `x` in the default is the module's x, not anything inside f
          cpg.identifier.nameExact("x").method.name.toSet shouldBe Set("<module>")
          // f's body starts with one prologue statement per defaulted parameter
          val f = cpg.method.nameExact("f").head
          f.block.astChildren.isCall.code.l.take(2) shouldBe List(
            "b = b if b passed else <default>f.b",
            "c = c if c passed else <default>f.c"
          )
          // the prologue assigns the parameters themselves, not new locals
          f.local.name.l should not contain "b"
      }

      "carry a literal default to a sink" in {
          val cpg = code(
            """import hashlib
              |def digest(data, alg="md5"):
              |    return hashlib.new(alg, data)
              |""".stripMargin
          )
          val source = cpg.literal.codeExact("\"md5\"")
          val sink   = cpg.call.nameExact("new").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "reach methods of a class, whose body Python functions cannot see" in {
          val cpg = code(
            """import hashlib
              |class Hasher:
              |    ALG = "sha1"
              |    def run(self, data, alg=ALG):
              |        return hashlib.new(alg, data)
              |""".stripMargin
          )
          // ALG is read in the class body, where the default is evaluated
          cpg.identifier.nameExact("ALG").method.name.l.distinct shouldBe List("<body>")
          val source = cpg.literal.codeExact("\"sha1\"")
          val sink   = cpg.call.nameExact("new").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "carry an enclosing function's value into a nested function's default" in {
          val cpg = code(
            """import helpers
              |def outer(source):
              |    def inner(v=source):
              |        helpers.sink(v)
              |    return inner
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "apply to lambdas" in {
          val cpg = code(
            """import helpers
              |def handle(source):
              |    run = lambda v=source: helpers.sink(v)
              |    return run()
              |""".stripMargin
          )
          cpg.method.nameExact("<lambda>").block.astChildren.isCall.code.headOption shouldBe
              Some("v = v if v passed else <default><lambda>.v")
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "keep the caller's argument flowing into the parameter" in {
          val cpg = code(
            """import helpers
              |def run(cmd="ls"):
              |    helpers.sink(cmd)
              |def handle(source):
              |    run(source)
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "stay distinct for two functions with the same name in one scope" in {
          val cpg = code(
            """def f(a=1):
              |    return a
              |def f(a=2):
              |    return a
              |""".stripMargin
          )
          (cpg.call.nameExact(Operators.assignment).code.l should contain).allOf(
            "<default>f.a = 1",
            "<default>f.a#1 = 2"
          )
      }
  }

  "keyword arguments" should {

      "bind the parameter of that name" in {
          val cpg = code(
            """import helpers
              |def run(cmd, *, shell=False):
              |    helpers.sink(cmd)
              |def handle(source):
              |    run(shell=True, cmd=source)
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "not bind a keyword-only parameter of another name" in {
          val cpg = code(
            """import helpers
              |def run(cmd="", *, shell=False):
              |    helpers.sink(shell)
              |def handle(source):
              |    run(cmd=source)
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size shouldBe 0
      }

      "land in **kwargs when no parameter has the name" in {
          val cpg = code(
            """import helpers
              |def run(**opts):
              |    helpers.sink(opts["cmd"])
              |def handle(source):
              |    run(cmd=source)
              |""".stripMargin
          )
          cpg.parameter.nameExact("opts").isVariadic.l shouldBe List(true)
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }
  }

  "unpacked arguments" should {

      "lower f(**opts) to a ** argument" in {
          val cpg = code(
            """import requests
              |def fetch(url, opts):
              |    return requests.get(url, timeout=3, **opts)
              |""".stripMargin
          )
          val get = cpg.call.nameExact("get").head
          get.code shouldBe "requests.get(url, timeout = 3, **opts)"
          val unpack = get.argument.isCall.nameExact("<operator>.dictUnpack").l
          unpack.argumentName.l shouldBe List("**")
          unpack.argument.isIdentifier.name.l shouldBe List("opts")
      }

      "carry a mapping's values into the parameters it can bind" in {
          val cpg = code(
            """import helpers
              |def run(cmd="ls", **rest):
              |    helpers.sink(cmd)
              |def handle(source):
              |    opts = {"cmd": source}
              |    run(**opts)
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "carry extra positionals into *args and an unpacked iterable into the positionals" in {
          val cpg = code(
            """import helpers
              |def collect(first, *rest):
              |    helpers.sink(rest)
              |def pair(a, b):
              |    helpers.sink2(b)
              |def handle(source):
              |    collect(1, 2, source)
              |    pair(*[1, source])
              |""".stripMargin
          )
          def source = cpg.parameter.nameExact("source")
          cpg.call.nameExact("sink").argument(1).reachableByFlows(source).size should be >= 1
          cpg.call.nameExact("sink2").argument(1).reachableByFlows(source).size should be >= 1
      }

      "reach __init__'s **kwargs through the class call" in {
          val cpg = code(
            """import helpers
              |class Job:
              |    def __init__(self, **opts):
              |        helpers.sink(opts)
              |def handle(source):
              |    Job(cmd=source)
              |""".stripMargin
          )
          val source = cpg.parameter.nameExact("source")
          val sink   = cpg.call.nameExact("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }
  }
end ParameterDefaultsAndKwargsTests

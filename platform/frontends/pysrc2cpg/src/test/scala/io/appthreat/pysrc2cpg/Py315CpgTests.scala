package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.language.toExtendedCfgNode
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

/** Python 3.15 in the CPG.
  *
  *   - PEP 810 lazy imports: every import call (and the IMPORT node derived from it) that binds a
  *     lazily loaded name carries the `lazy-import` TAG, valued `keyword` for `lazy import ...` and
  *     `__lazy_modules__` for the compatibility list. The `__lazy_modules__` semantics asserted
  *     here were measured against CPython 3.15.0 at runtime (which modules land in `sys.modules`).
  *   - PEP 798 unpacking comprehensions lower like the nested comprehension they abbreviate: `[*L
  *     for L in ls]` adds every item of `L` (`tmp.extend(L)`), `{*s for s in ss}` and `{**d for d
  *     in ds}` merge (`tmp.update(...)`) - no unpack operator, no UNKNOWN.
  *   - New builtins (`frozendict`, `sentinel`, `ImportCycleError`) resolve like the others.
  */
class Py315CpgTests extends PySrc2CpgFixture(withOssDataflow = true):

  private def lazyTagValues(call: Call): List[String] =
      call.tag.nameExact(PythonLazyImports.Tag).value.l

  /** The import call that binds `name`, and its lazy-import tag values. */
  private def importOf(cpg: io.shiftleft.codepropertygraph.Cpg, name: String): List[String] =
    val calls = cpg.call.nameExact("import").filter(_.inAssignment.target.code.l == List(name)).l
    calls should have size 1
    lazyTagValues(calls.head)

  "PEP 810 lazy imports" should {

      "tag every name a lazy import binds, and nothing else" in {
          val cpg = code(
            """lazy import json
              |lazy import xml.etree.ElementTree as ET, csv
              |lazy from pathlib import Path, PurePath
              |import os
              |from sys import argv
              |""".stripMargin
          )
          for name <- Seq("json", "ET", "csv", "Path", "PurePath") do
            importOf(cpg, name) shouldBe List(PythonLazyImports.Keyword)
          importOf(cpg, "os") shouldBe empty
          importOf(cpg, "argv") shouldBe empty
          // one TAG node per (name, value) per file, shared by all lazy imports
          cpg.tag.nameExact(PythonLazyImports.Tag).size shouldBe 1
      }

      "pass the tag on to the IMPORT nodes" in {
          val cpg = code("lazy import json\nlazy from os import path\nimport sys\n")
          cpg.imports.importedEntity("json").tag.nameExact(PythonLazyImports.Tag).value.l shouldBe
              List(PythonLazyImports.Keyword)
          cpg.imports.importedEntity("os.path").tag.nameExact(PythonLazyImports.Tag).size shouldBe 1
          cpg.imports.importedEntity("sys").tag.nameExact(PythonLazyImports.Tag).size shouldBe 0
      }

      "keep the import lowering itself unchanged" in {
          val cpg              = code("lazy from os import path as p\n")
          val List(importCall) = cpg.call.nameExact("import").l
          importCall.code shouldBe "import(os, path, p)"
          importCall.inAssignment.target.code.l shouldBe List("p")
          val List(importNode) = cpg.imports.l
          importNode.importedEntity shouldBe Some("os.path")
          importNode.importedAs shouldBe Some("p")
      }

      "tag lazy imports wherever the parser accepts them, as ast.parse does" in {
          // compile() rejects these; the AST (and a static analyser) still sees is_lazy=1
          val cpg = code("def f():\n    lazy import json\n    return json\n")
          importOf(cpg, "json") shouldBe List(PythonLazyImports.Keyword)
      }
  }

  "__lazy_modules__" should {

      "make the listed modules' imports after the assignment lazy" in {
          val cpg = code(
            """import before
              |__lazy_modules__ = ["before", "after", "dotted.child", "fromed"]
              |import after
              |import dotted.child
              |import other
              |from fromed import name
              |""".stripMargin
          )
          importOf(cpg, "before") shouldBe empty // executed before the assignment: eager
          importOf(cpg, "after") shouldBe List(PythonLazyImports.LazyModules)
          // `import dotted.child` binds `dotted`; the list names the full dotted module
          cpg.call.nameExact("import").filter(_.argument.code.l == List("", "dotted.child")).flatMap(
            lazyTagValues
          ).l shouldBe List(PythonLazyImports.LazyModules)
          importOf(cpg, "other") shouldBe empty
          // for `from M import x` the looked-up name is M, not x
          importOf(cpg, "name") shouldBe List(PythonLazyImports.LazyModules)
      }

      "apply at module scope only - not in functions, class bodies, try bodies or handlers" in {
          val cpg = code(
            """__lazy_modules__ = ("m_if", "m_func", "m_cls", "m_try", "m_exc", "m_else", "m_fin", "m_with", "m_for", "m_match")
              |if True:
              |    import m_if
              |def f():
              |    import m_func
              |class C:
              |    import m_cls
              |try:
              |    import m_try
              |except ImportError:
              |    import m_exc
              |else:
              |    import m_else
              |finally:
              |    import m_fin
              |with open("x"):
              |    import m_with
              |for _ in ():
              |    import m_for
              |match 1:
              |    case 1:
              |        import m_match
              |""".stripMargin
          )
          for lazyName <- Seq("m_if", "m_else", "m_fin", "m_with", "m_for", "m_match") do
            withClue(lazyName) {
                importOf(cpg, lazyName) shouldBe List(PythonLazyImports.LazyModules)
            }
          for eagerName <- Seq("m_func", "m_cls", "m_try", "m_exc") do
            withClue(eagerName) { importOf(cpg, eagerName) shouldBe empty }
      }

      "follow additions and stop claiming once the list is unknown" in {
          val cpg = code(
            """__lazy_modules__ = ["a"]
              |__lazy_modules__ += ["b"]
              |__lazy_modules__.append("c")
              |import a, b, c
              |__lazy_modules__ = compute()
              |import d
              |""".stripMargin
          )
          for name <- Seq("a", "b", "c") do
            withClue(name) { importOf(cpg, name) shouldBe List(PythonLazyImports.LazyModules) }
          importOf(cpg, "d") shouldBe empty
      }

      "never make star or __future__ imports lazy" in {
          val cpg = code(
            """__lazy_modules__ = ["os", "__future__"]
              |from __future__ import annotations
              |from os import *
              |""".stripMargin
          )
          cpg.call.nameExact("import").flatMap(lazyTagValues).l shouldBe empty
      }

      "resolve relative imports against the package" in {
          val cpg = code("", "pkg/__init__.py")
              .moreCode(
                """__lazy_modules__ = ["pkg", "pkg.sub.utils"]
                  |from . import helper
                  |from .sub.utils import func
                  |from .other import thing
                  |""".stripMargin,
                "pkg/mod.py"
              )
              .moreCode("", "pkg/sub/__init__.py")
          importOf(cpg, "helper") shouldBe List(PythonLazyImports.LazyModules)
          importOf(cpg, "func") shouldBe List(PythonLazyImports.LazyModules)
          importOf(cpg, "thing") shouldBe empty
      }
  }

  "PEP 798 unpacking in comprehensions" should {

      "lower a starred list-comprehension element to extend" in {
          val cpg = code("lists = [[1], [2]]\nflat = [*L for L in lists]\n")
          cpg.call.nameExact("extend").argument(1).code.l shouldBe List("L")
          cpg.call.nameExact("append").size shouldBe 0
          cpg.call.nameExact("<operator>.starredUnpack").size shouldBe 0
          cpg.all.label("UNKNOWN").size shouldBe 0
      }

      "lower a starred generator element to extend and keep plain elements on append" in {
          val cpg = code("g = (*L for L in ls)\nh = (x for x in xs)\nt = sum(*L for L in ls)\n")
          cpg.call.nameExact("extend").size shouldBe 2
          cpg.call.nameExact("append").argument(1).code.l shouldBe List("x")
      }

      "lower starred set elements and dict unpacking to update" in {
          val cpg = code("u = {*s for s in ss}\nm = {**d for d in ds if d}\n")
          cpg.call.nameExact("update").argument(1).code.l.sorted shouldBe List("d", "s")
          cpg.call.nameExact("add").size shouldBe 0
          // no dict element assignment for a value-less DictComp
          cpg.call.nameExact("<operator>.indexAccess").size shouldBe 0
          cpg.all.label("UNKNOWN").size shouldBe 0
      }

      "keep carrying taint from the unpacked iterable to the comprehension result" in {
          // Already true before 3.15 support (through an append of the unpack operator); the
          // extend lowering must not lose it.
          val cpg = code(
            """import helpers
              |def handle(source):
              |    lists = [source]
              |    flat = [*L for L in lists]
              |    helpers.sink(flat)
              |""".stripMargin
          )
          val source = cpg.parameter.name("source")
          val sink   = cpg.call.name("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "carry taint through a dict-unpacking comprehension" in {
          // `{**d for d in ...}` did not parse before, so this flow did not exist at all.
          val cpg = code(
            """import helpers
              |def handle(source):
              |    merged = {**d for d in [source]}
              |    helpers.sink(merged)
              |""".stripMargin
          )
          val source = cpg.parameter.name("source")
          val sink   = cpg.call.name("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }
  }

  "Python 3.15 builtins" should {

      "resolve frozendict, sentinel and ImportCycleError like other builtin classes" in {
          val cpg = code(
            """fd = frozendict(a=1)
              |MISSING = sentinel("MISSING")
              |try:
              |    pass
              |except ImportCycleError:
              |    pass
              |""".stripMargin
          )
          for name <- Seq("frozendict", "sentinel", "ImportCycleError") do
            withClue(name) {
                cpg.call.code(s"$name = __builtins__.$name").size shouldBe 1
            }
      }
  }

  "pre-3.15 forms that used to lose code" should {

      "keep the body of a with statement over a parenthesised expression" in {
          val cpg = code(
            """def read(p):
              |    with (p / "f").open() as fh:
              |        return fh.read()
              |""".stripMargin
          )
          cpg.call.nameExact("read").size shouldBe 1
          cpg.all.label("UNKNOWN").size shouldBe 0
      }

      "keep a file that deletes through a list target" in {
          // Delete(targets=[Tuple([Name('a'), List([Name('b'), Name('c')])])]) - CPython 3.15
          val cpg = code("a = b = c = 1\ndel a, [b, c]\ndel [a]\ndef after():\n    return 1\n")
          cpg.method.nameExact("after").size shouldBe 1
          cpg.call.nameExact("<operator>.listLiteral").size shouldBe 2
      }

      "keep a class whose __init__ binds nothing positionally" in {
          val cpg = code(
            """class A:
              |    def __init__():
              |        pass
              |class B:
              |    def __init__(*, key):
              |        self.key = key
              |def after():
              |    return B(key=1)
              |""".stripMargin
          )
          cpg.method.nameExact("after").size shouldBe 1
          cpg.method.nameExact("<metaClassCallHandler>").size shouldBe 2
      }

      "lower nested format-spec fields as a second formattedValue argument" in {
          // CPython evaluates `source` too: f"{value:>{source}}" pads with its value
          val cpg = code(
            """import helpers
              |def handle(source, value):
              |    text = f"{value:>{source}}"
              |    plain = f"{value:>10}"
              |    helpers.sink(text)
              |""".stripMargin
          )
          val nested =
              cpg.call.nameExact("<operator>.formattedValue").code("\\{value:>\\{source\\}\\}").l
          nested should have size 1
          nested.head.argument.argumentIndex.l shouldBe List(1, 2)
          val spec = nested.argument.argumentIndex(2).isCall.l
          spec.name.l shouldBe List("<operator>.formatString")
          spec.head.code shouldBe ">{source}"
          spec.ast.isIdentifier.name.l shouldBe List("source")
          // a spec of literal text only evaluates nothing and adds no argument
          val plain = cpg.call.nameExact("<operator>.formattedValue").code("\\{value:>10\\}").l
          plain.argument.argumentIndex.l shouldBe List(1)
          // and the spec's names take part in data flow
          val source = cpg.parameter.name("source")
          val sink   = cpg.call.name("sink").argument(1)
          sink.reachableByFlows(source).size should be >= 1
      }

      "tag names the file spells with characters NFKC folds away" in {
          // CPython runs eval, os.system and verify=False here; a reader or a grep does not see them
          val cpg = code(
            "import requests\n" +
                "from \uff4f\uff53 import \uff53\uff59\uff53\uff54\uff45\uff4d\n" +
                "def \ud835\udc1f(\ud835\udc31):\n" +
                "    \uff45\uff56\uff41\uff4c(\ud835\udc31)\n" +
                "    requests.\uff47\uff45\uff54(\ud835\udc31, \uff56\uff45\uff52\uff49\uff46\uff59=False)\n" +
                "class \uff23:\n" +
                "    pass\n" +
                "plain = eval\n"
          )
          val confusable = io.appthreat.x2cpg.Defines.UnicodeConfusableTag
          def spellings(
            nodes: Iterator[? <: io.shiftleft.codepropertygraph.generated.nodes.StoredNode]
          ) =
              nodes.flatMap(_.tag.nameExact(confusable).value).toSet
          // the names are the normalised ones Python resolves
          cpg.call.nameExact("eval").size shouldBe 1
          cpg.method.nameExact("f").size shouldBe 1
          // each node keeps the file's spelling in its tag
          spellings(cpg.identifier.nameExact("eval")) shouldBe Set("\uff45\uff56\uff41\uff4c")
          spellings(cpg.identifier.nameExact("system")) shouldBe Set(
            "\uff4f\uff53,\uff53\uff59\uff53\uff54\uff45\uff4d"
          )
          spellings(cpg.identifier.nameExact("x")) shouldBe Set("\ud835\udc31")
          spellings(cpg.parameter.nameExact("x")) shouldBe Set("\ud835\udc31")
          spellings(cpg.method.nameExact("f")) shouldBe Set("\ud835\udc1f")
          spellings(cpg.fieldAccess.fieldIdentifier.canonicalNameExact("get")) shouldBe Set(
            "\uff47\uff45\uff54"
          )
          // a TYPE_DECL cannot carry a tag: the name the class statement binds does
          spellings(cpg.identifier.nameExact("C")) shouldBe Set("\uff23")
          spellings(cpg.literal.codeExact("False")) shouldBe Set(
            "\uff56\uff45\uff52\uff49\uff46\uff59"
          )
          // names written in ASCII are left alone
          cpg.identifier.nameExact("plain").tag.nameExact(confusable).size shouldBe 0
          cpg.identifier.nameExact("requests").tag.nameExact(confusable).size shouldBe 0
      }

      "keep every statement after an identifier with a combining mark" in {
          // used to be a lexical error that dropped the whole file
          val cpg = code("cafe\u0301 = 1\ndef after():\n    return cafe\u0301\n")
          cpg.method.nameExact("after").size shouldBe 1
          cpg.identifier.nameExact("caf\u00e9").size should be >= 2 // NFKC-normalised
      }
  }
end Py315CpgTests

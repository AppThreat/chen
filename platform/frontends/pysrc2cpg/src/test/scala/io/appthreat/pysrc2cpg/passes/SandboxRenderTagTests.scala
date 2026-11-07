package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.shiftleft.semanticcpg.language.*

/** The `sandbox-render` sink: in-process template and expression rendering. Every positive case
  * also carries `code-execution` (the sandbox is not a security boundary), and every literal
  * template stands the tag down.
  */
class SandboxRenderTagTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOn(cpg: io.shiftleft.codepropertygraph.Cpg, callName: String): Set[String] =
      cpg.call.nameExact(callName).tag.name.toSet

  private def tagsOnCallContaining(
    cpg: io.shiftleft.codepropertygraph.Cpg,
    snippet: String
  ): Set[String] =
      cpg.call.code(s".*${java.util.regex.Pattern.quote(snippet)}.*").tag.name.toSet

  "EasyTagsPass sandbox-render (Jinja sandbox environments)" should:

    "tag from_string and the render of the template it returned" in:
      val cpg = code("""
            |from jinja2.sandbox import ImmutableSandboxEnvironment
            |def render_chat(src, messages):
            |    env = ImmutableSandboxEnvironment(trim_blocks=True)
            |    tpl = env.from_string(src)
            |    return tpl.render(messages=messages)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should contain("sandbox-render")
      tagsOn(cpg, "from_string") should contain("code-execution")
      tagsOn(cpg, "render") should contain("sandbox-render")

    "tag from_string on a SandboxedEnvironment with a source read from a dict" in:
      val cpg = code("""
            |import json
            |from jinja2.sandbox import SandboxedEnvironment
            |def config_template(path):
            |    cfg = json.load(open(path))
            |    env = SandboxedEnvironment()
            |    return env.from_string(cfg["chat_template"]).render()
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should contain("sandbox-render")
      tagsOn(cpg, "render") should contain("sandbox-render")

    "tag a Template constructor called with a non-literal source" in:
      val cpg = code("""
            |from jinja2 import Template
            |def build(src):
            |    return Template(src).render()
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "render") should contain("sandbox-render")

    "tag compile_expression and template_class on a sandbox environment" in:
      val cpg = code("""
            |from jinja2.sandbox import SandboxedEnvironment
            |def compile_parts(src, cls_src):
            |    env = SandboxedEnvironment()
            |    expr = env.compile_expression(src)
            |    tpl = env.template_class(cls_src)
            |    return expr, tpl
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "compile_expression") should contain("sandbox-render")
      tagsOn(cpg, "template_class") should contain("sandbox-render")

    "tag a user class whose full name ends in Environment under jinja2" in:
      val cpg = code(
        """from jinja2.custom import FastEnvironment
          |
          |def render_user(src):
          |    env = FastEnvironment()
          |    return env.from_string(src).render()
          |""".stripMargin,
        "app.py"
      ).moreCode(
        """from jinja2.sandbox import SandboxedEnvironment
          |
          |class FastEnvironment(SandboxedEnvironment):
          |    pass
          |""".stripMargin,
        "jinja2/custom.py"
      )
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should contain("sandbox-render")

    "not tag a render whose template source is a string literal" in:
      val cpg = code("""
            |from jinja2.sandbox import SandboxedEnvironment
            |def greeting(n):
            |    env = SandboxedEnvironment()
            |    return env.from_string("Hello {{ name }}").render(name=n)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should not contain "sandbox-render"
      tagsOn(cpg, "render") should not contain "sandbox-render"

    "not tag a Template constructor called with a literal source" in:
      val cpg = code("""
            |from jinja2 import Template
            |def greeting(n):
            |    return Template("Hello {{ name }}").render(name=n)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "render") should not contain "sandbox-render"

    "not tag a from_string in a project that imports no jinja2 and defines its own" in:
      val cpg = code("""
            |class MyEnv:
            |    def from_string(self, src):
            |        return src
            |def render_local(src):
            |    env = MyEnv()
            |    return env.from_string(src).render()
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should not contain "sandbox-render"
      tagsOn(cpg, "render") should not contain "sandbox-render"

    "not tag a local variable that borrowed the jinja2 name" in:
      val cpg = code("""
            |def shadowed(src):
            |    jinja2 = object()
            |    return jinja2.Template(src)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "Template") should not contain "sandbox-render"

    "not tag a local variable that borrowed the pandas name" in:
      val cpg = code("""
            |def shadowed(expr):
            |    pandas = object()
            |    return pandas.eval(expr)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "eval") should not contain "sandbox-render"

  "EasyTagsPass sandbox-render (restricted evaluators)" should:

    "tag RestrictedPython compile_restricted and its variants" in:
      val cpg = code("""
            |from RestrictedPython import compile_restricted, compile_restricted_exec
            |def compile_policy(src):
            |    return compile_restricted(src), compile_restricted_exec(src)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "compile_restricted") should contain("sandbox-render")
      tagsOn(cpg, "compile_restricted_exec") should contain("sandbox-render")

    "tag asteval's eval method and the instance call, not the construction" in:
      val cpg = code("""
            |import asteval
            |from asteval import Interpreter
            |def evaluate(expr):
            |    ae = asteval.Interpreter()
            |    ae2 = Interpreter()
            |    return ae.eval(expr), ae2(expr)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "Interpreter") should not contain "sandbox-render"
      tagsOn(cpg, "eval") should contain("sandbox-render")
      tagsOn(cpg, "ae2") should contain("sandbox-render")

    "tag simpleeval helper and evaluator class methods" in:
      val cpg = code("""
            |from simpleeval import simple_eval, SimpleEval, EvalWithCompoundTypes
            |def evaluate(expr):
            |    return simple_eval(expr), SimpleEval().eval(expr), EvalWithCompoundTypes().eval(expr)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "simple_eval") should contain("sandbox-render")
      cpg.call.nameExact("eval").tag.name.toSet should contain("sandbox-render")

    "tag numexpr.evaluate and pandas.eval" in:
      val cpg = code("""
            |import numexpr
            |import pandas as pd
            |def evaluate(expr):
            |    return numexpr.evaluate(expr), pd.eval(expr)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "evaluate") should contain("sandbox-render")
      tagsOn(cpg, "eval") should contain("sandbox-render")

    "tag DataFrame.eval and DataFrame.query only for a non-literal expression" in:
      val cpg = code("""
            |import pandas as pd
            |def dynamic(path, expr):
            |    df = pd.read_csv(path)
            |    return df.query(expr), df.eval(expr)
            |def literal(path):
            |    df = pd.DataFrame({"a": [1]})
            |    return df.query("a > 1")
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOnCallContaining(cpg, "df.query(expr)") should contain("sandbox-render")
      tagsOnCallContaining(cpg, "df.eval(expr)") should contain("sandbox-render")
      tagsOnCallContaining(cpg, "df.query(\"a > 1\")") should not contain "sandbox-render"

    "not tag a from_string of an unrelated library in a project without the gate packages" in:
      val cpg = code("""
            |import templatekit
            |def build(src):
            |    env = templatekit.Environment()
            |    return env.from_string(src)
            |""".stripMargin)
      new EasyTagsPass(cpg).createAndApply()
      tagsOn(cpg, "from_string") should not contain "sandbox-render"
end SandboxRenderTagTests

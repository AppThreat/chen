package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.EasyTagsPass
import io.appthreat.x2cpg.passes.taggers.python.PythonFrameworkRecognizersPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.*

/** The calls that look like a sandbox render or a model load by name but are not one: a method of
  * the same name on an unrelated object, a flag spelled as a literal `False`, and the write of a
  * chat template rather than its read.
  */
class SandboxRenderPrecisionTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOnCode(cpg: Cpg, snippet: String): Set[String] =
      cpg.call.code(java.util.regex.Pattern.quote(snippet)).tag.name.toSet

  private def tagged(cpg: Cpg): Cpg =
    new EasyTagsPass(cpg).createAndApply()
    new PythonFrameworkRecognizersPass(cpg).createAndApply()
    cpg

  "sandbox-render precision" should:

    "not tag an ORM query or a model's eval() in a file that imports pandas" in:
      val cpg = tagged(code("""
            |import pandas as pd
            |from sqlalchemy.orm import Session
            |def rows(session, User, model):
            |    model.eval()
            |    return session.query(User).all()
            |""".stripMargin))
      tagsOnCode(cpg, "session.query(User)") should not contain "sandbox-render"
      tagsOnCode(cpg, "model.eval()") should not contain "sandbox-render"
      tagsOnCode(cpg, "model.eval()") should not contain "code-execution"

    "tag DataFrame.query with a non-literal expression on a frame pandas built" in:
      val cpg = tagged(code("""
            |import pandas as pd
            |def filtered(path, expr):
            |    df = pd.read_csv(path)
            |    return df.query(expr)
            |""".stripMargin))
      tagsOnCode(cpg, "df.query(expr)") should contain("sandbox-render")

    "keep the builtin eval as code-execution and leave a method named eval alone" in:
      val cpg = tagged(code("""
            |import torch
            |def run(src, model):
            |    model.eval()
            |    return eval(src)
            |""".stripMargin))
      tagsOnCode(cpg, "eval(src)") should contain("code-execution")
      tagsOnCode(cpg, "model.eval()") should not contain "code-execution"

  "ai-model-artifact precision" should:

    "not treat trust_remote_code=False as code execution" in:
      val cpg = tagged(code("""
            |from transformers import AutoTokenizer
            |def load(repo_id):
            |    return AutoTokenizer.from_pretrained(repo_id, trust_remote_code=False)
            |""".stripMargin))
      val tags = cpg.call.nameExact("from_pretrained").tag.name.toSet
      tags should contain("ai-model-artifact")
      tags should not contain "code-execution"

    "not tag a chat_template=None keyword as a render" in:
      val cpg = tagged(code("""
            |from transformers import AutoTokenizer
            |def build(tok, messages):
            |    return tok.render_prompt(messages, chat_template=None)
            |""".stripMargin))
      cpg.call.nameExact("render_prompt").tag.name.toSet should not contain "sandbox-render"

    "tag a render helper given a chat template but not an object that only carries one" in:
      val cpg = tagged(code("""
            |from transformers import AutoTokenizer
            |def build(tok, messages, template, ChatParams):
            |    params = ChatParams(chat_template=template)
            |    kwargs = dict(chat_template=template)
            |    return render_jinja_template(conversations=messages, chat_template=template)
            |""".stripMargin))
      cpg.call.nameExact("ChatParams").tag.name.toSet should not contain "sandbox-render"
      cpg.call.nameExact("dict").tag.name.toSet should not contain "sandbox-render"
      cpg.call.nameExact("render_jinja_template").tag.name.toSet should contain("sandbox-render")

    "tag the read of a chat template but not the write of one" in:
      val cpg = tagged(code("""
            |from transformers import AutoTokenizer
            |class Server:
            |    def __init__(self, tok, override):
            |        self.chat_template = override
            |        self.fallback = tok.chat_template
            |""".stripMargin))
      cpg.call.nameExact("<operator>.fieldAccess").code("self.chat_template").tag.name.toSet should
          not contain "ai-model-artifact"
      cpg.call.nameExact("<operator>.fieldAccess").code("tok.chat_template").tag.name.toSet should
          contain("ai-model-artifact")
end SandboxRenderPrecisionTests

package io.appthreat.pysrc2cpg.passes

import io.appthreat.pysrc2cpg.PySrc2CpgFixture
import io.appthreat.x2cpg.passes.taggers.python.PythonFrameworkRecognizersPass
import io.shiftleft.semanticcpg.language.*

/** The model-repository arms of the AI/LLM recognizer: downloads, loads and file reads are
  * `ai-model-artifact` sources, `trust_remote_code=True` is `code-execution`, and the chat
  * templates the inference libraries render internally are `sandbox-render` sinks.
  */
class AiModelArtifactTests extends PySrc2CpgFixture(withOssDataflow = false):

  private def tagsOn(cpg: io.shiftleft.codepropertygraph.Cpg, callName: String): Set[String] =
      cpg.call.nameExact(callName).tag.name.toSet

  private def withRecognizers(cpg: io.shiftleft.codepropertygraph.Cpg)(
    body: => Unit
  ): Unit =
    new PythonFrameworkRecognizersPass(cpg).createAndApply()
    body

  "AiLlmRecognizer model artefact sources" should:

    "tag hub downloads, from_pretrained and pipeline as ai-model-artifact" in:
      val cpg = code("""
            |from huggingface_hub import hf_hub_download, snapshot_download, HfApi
            |from transformers import AutoTokenizer, pipeline
            |def load(repo_id):
            |    path = hf_hub_download(repo_id, "chat_template.jinja")
            |    snap = snapshot_download(repo_id)
            |    api = HfApi()
            |    via_api = api.hf_hub_download(repo_id, "tokenizer_config.json")
            |    tok = AutoTokenizer.from_pretrained(repo_id)
            |    pipe = pipeline("text-generation")
            |    return path, snap, via_api, tok, pipe
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "hf_hub_download") should contain("ai-model-artifact")
          tagsOn(cpg, "snapshot_download") should contain("ai-model-artifact")
          tagsOn(cpg, "from_pretrained") should contain("ai-model-artifact")
          tagsOn(cpg, "pipeline") should contain("ai-model-artifact")
      }

    "tag from_pretrained with a literal trust_remote_code=True as code-execution too" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |def load(repo_id):
            |    return AutoTokenizer.from_pretrained(repo_id, trust_remote_code=True)
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "from_pretrained") should contain("ai-model-artifact")
          tagsOn(cpg, "from_pretrained") should contain("code-execution")
      }

    "not tag from_pretrained without the flag as code-execution" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |def load(repo_id):
            |    return AutoTokenizer.from_pretrained(repo_id)
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "from_pretrained") should contain("ai-model-artifact")
          tagsOn(cpg, "from_pretrained") should not contain "code-execution"
      }

    "tag chat_template reads on a tokenizer and out of a config dict" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |def template_of(repo_id):
            |    tok = AutoTokenizer.from_pretrained(repo_id)
            |    return tok.chat_template
            |def from_config(path):
            |    import json
            |    cfg = json.load(open(path))
            |    return cfg["chat_template"]
            |""".stripMargin)
      withRecognizers(cpg) {
          val attrRead = cpg.call
              .nameExact("<operator>.fieldAccess")
              .code("tok.chat_template")
              .tag
              .name
              .toSet
          attrRead should contain("ai-model-artifact")
          cpg.call.nameExact("<operator>.indexAccess").tag.name.toSet should contain(
            "ai-model-artifact"
          )
      }

    "tag open, json.load and Path.read_text pointed at a chat-template file by a literal path" in:
      val cpg = code("""
            |import json
            |from pathlib import Path
            |from transformers import AutoTokenizer
            |def read_artifacts():
            |    a = open("model/chat_template.jinja")
            |    b = json.load(open("model/tokenizer_config.json"))
            |    c = Path("model/chat_template.json").read_text()
            |    return a, b, c
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "open") should contain("ai-model-artifact")
          tagsOn(cpg, "load") should contain("ai-model-artifact")
          tagsOn(cpg, "read_text") should contain("ai-model-artifact")
      }

    "not tag an open with a path that names no artefact" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |def read_weights():
            |    return open("model/model.safetensors")
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "open") should not contain "ai-model-artifact"
      }

  "AiLlmRecognizer chat-template renders" should:

    "tag apply_chat_template and a non-literal chat_template keyword as sandbox-render" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |from vllm import LLM
            |def render(tok, llm, messages, tpl_name):
            |    a = tok.apply_chat_template(messages, tokenize=False)
            |    b = llm.chat(messages, chat_template=tpl_name)
            |    return a, b
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "apply_chat_template") should contain("sandbox-render")
          tagsOn(cpg, "apply_chat_template") should contain("code-execution")
          tagsOn(cpg, "chat") should contain("sandbox-render")
      }

    "not tag a literal chat_template keyword as sandbox-render" in:
      val cpg = code("""
            |from transformers import AutoTokenizer
            |def render(tok, messages):
            |    return tok.apply_chat_template(messages, chat_template="builtin")
            |""".stripMargin)
      withRecognizers(cpg) {
          tagsOn(cpg, "apply_chat_template") should contain("sandbox-render")
          cpg.tag.nameExact("sandbox-render").size shouldBe 1
      }

  "AiLlmRecognizer gate" should:

    "not tag a project that imports none of the gate packages" in:
      val cpg = code("""
            |def load(path):
            |    return open(path).read()
            |class MyTokenizer:
            |    def from_pretrained(self, repo_id):
            |        return repo_id
            |""".stripMargin)
      withRecognizers(cpg) {
          cpg.tag.nameExact("ai-model-artifact").size shouldBe 0
          cpg.tag.nameExact("sandbox-render").size shouldBe 0
      }
end AiModelArtifactTests

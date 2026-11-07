package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.{Call, Expression, Identifier, Literal}
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** AI/LLM frameworks (LangChain, LlamaIndex, OpenAI, Anthropic, litellm) and the inference stacks
  * that load model repositories (transformers, huggingface_hub, vllm, sglang, llama_cpp,
  * tokenizers, modelscope).
  *
  * Tags:
  *   - `ai-prompt` on prompt-construction calls (`PromptTemplate.from_template(...)`,
  *     `ChatPromptTemplate.from_messages(...)`, message constructors, an LLM call whose
  *     `messages=...` argument is being populated),
  *   - `ai-invoke` on model/chain invocations (`chain.invoke(...)`, `client.chat.completions
  *     .create(...)`, `litellm.completion(...)`, LlamaIndex `query_engine.query(...)`),
  *   - `ai-compose` on LangChain's `|` composition (`tpl | ChatOpenAI(...)`), lowered as
  *     `<operator>.or`,
  *   - `ai-model-artifact` on the calls that bring a model repository's files into the process: hub
  *     downloads (`hf_hub_download`, `snapshot_download`, the `HfApi` methods), `*.from_pretrained`
  *     on transformers classes, `pipeline(...)`, reads of a tokenizer's or processor's
  *     `chat_template`, and `open`/`json.load`/`Path.read_text` pointed at a chat-template file by
  *     a literal path. `from_pretrained(..., trust_remote_code=True)` also carries
  *     `code-execution`: that flag runs repository code by design and needs no sandbox escape,
  *   - `sandbox-render` on the calls that render a chat template inside an inference library, where
  *     no jinja2 call is visible in user code: `apply_chat_template`, `vllm.LLM.chat`, and a render
  *     helper passed a non-literal `chat_template=` keyword.
  *
  * The first-class flows: framework-input -> `ai-prompt` (prompt injection), `ai-invoke` result ->
  * `code-execution` (agent escape), and `ai-model-artifact` -> `sandbox-render` (a downloaded chat
  * template is rendered in-process). All run through atom's reachables once the tags are registered
  * as source/sink tags.
  *
  * NB: receiver type inference would let `invoke` be scoped to actual runnables - the gate is
  * project-wide (any `invoke` in an AI-gated project is treated as chain-related), and the runnable
  * side of `|` composition is matched structurally (either operand is a call), not by type.
  */
object AiLlmRecognizer extends PythonFrameworkRecognizer:

  override val name: String = "ai-llm"

  private val GateRoots = Set(
    "langchain",
    "langchain_core",
    "langchain_community",
    "langchain_openai",
    "langgraph",
    "llama_index",
    "llama_index_core",
    "openai",
    "anthropic",
    "litellm",
    // the inference stacks: their gate is shared with the prompt/chain recognizers below,
    // because a project can load model artefacts without building a chain
    "transformers",
    "huggingface_hub",
    "vllm",
    "sglang",
    "llama_cpp",
    "tokenizers",
    "modelscope"
  )

  /** The model-repository roots whose calls the artefact arms are scoped to. */
  private val ModelRepoRoots = Set(
    "transformers",
    "huggingface_hub",
    "vllm",
    "sglang",
    "llama_cpp",
    "tokenizers",
    "modelscope"
  )

  /** Prompt-template factories; the literal argument is the prompt template. */
  private val PromptFactoryCalls =
      Set("from_template", "from_messages", "from_examples", "format_prompt")

  /** Message/constructor names that carry prompt content. */
  private val MessageConstructors =
      Set(
        "PromptTemplate",
        "ChatPromptTemplate",
        "FewShotPromptTemplate",
        "HumanMessage",
        "SystemMessage",
        "AIMessage",
        "ChatMessage",
        "ToolMessage"
      )

  private val ChainInvocations = Set("invoke", "ainvoke", "batch", "abatch")

  private val CompletionInvocations = Set("completion", "acompletion")

  private val LlamaInvocations = Set("query", "aquery", "chat", "achat")

  /** The hub download calls, on the module spelling and on an `HfApi` instance alike. */
  private val HubDownloadFullNames =
      "(huggingface_hub|modelscope)(\\.\\w+)*\\.(hf_hub_download|snapshot_download)"

  /** The model files whose content reaches a template engine. */
  private val ArtifactFileNames =
      Seq("chat_template.jinja", "tokenizer_config.json", "chat_template.json")

  override def applies(cpg: Cpg): Boolean = importsAnyOf(cpg, GateRoots)

  override def run(cpg: Cpg, diff: DiffGraphBuilder): Unit =
    given DiffGraphBuilder = diff

    cpg.call.name(PromptFactoryCalls.map(java.util.regex.Pattern.quote).mkString("|")).foreach(c =>
        tag(c, AI_PROMPT_TAG)
    )
    cpg.call.name(MessageConstructors.mkString("|")).foreach(c => tag(c, AI_PROMPT_TAG))

    cpg.call.name(ChainInvocations.mkString("|")).foreach { c =>
        if !c.methodFullName.startsWith("<operator") then tag(c, AI_INVOKE_TAG)
    }

    // OpenAI/Anthropic `client.chat.completions.create(messages=...)` and litellm
    // `completion(messages=...)`: the call is an invocation whose messages argument is a prompt.
    val sdkRoots = importedRoots(cpg)
    if sdkRoots.exists(r => Set("openai", "anthropic", "litellm").contains(r)) then
      cpg.call
          .name((CompletionInvocations ++ Set("create")).mkString("|"))
          .filter(c => c.code.contains("messages") || c.code.contains("completion"))
          .foreach { c =>
            tag(c, AI_INVOKE_TAG)
            tag(c, AI_PROMPT_TAG)
          }

    if sdkRoots.contains("llama_index") || sdkRoots.contains("llama_index_core") then
      cpg.call.name(LlamaInvocations.mkString("|")).foreach { c =>
          if !c.methodFullName.startsWith("<operator") then tag(c, AI_INVOKE_TAG)
      }

    // LangChain `|` composition: `tpl | ChatOpenAI(model=...)` lowers to `<operator>.or`.
    // Treated as composition when either operand is a call (a constructor/chain expression);
    // typing the operands to runnables would need receiver type inference.
    cpg.call
        .nameExact(Operators.or)
        .filter(_.code.contains("|"))
        .filter(_.argument.isCall.nonEmpty)
        .foreach(c => tag(c, AI_COMPOSE_TAG))

    if sdkRoots.exists(ModelRepoRoots.contains) then
      val importsByFile = importedEntitiesByFile(cpg)
      modelArtifactArms(cpg, sdkRoots, importsByFile)
      chatTemplateRenderArms(cpg)
  end run

  /** The model-repository arms: downloads, loads and file reads are `ai-model-artifact` sources;
    * `trust_remote_code=True` is `code-execution` on its own account.
    */
  private def modelArtifactArms(
    cpg: Cpg,
    sdkRoots: Set[String],
    importsByFile: Map[String, Set[String]]
  )(using DiffGraphBuilder): Unit =
    // hub downloads, on the module spelling and on an HfApi instance
    cpg.call.methodFullName(HubDownloadFullNames).foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))
    cpg.call
        .name("hf_hub_download|snapshot_download")
        .filter(c => fileImportsAny(c, sdkRoots, importsByFile))
        .foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))

    // `*.from_pretrained` on the transformers classes, and `pipeline(...)`. The flag that
    // runs repository code by design is its own execution risk, on top of the artefact it
    // brings in.
    cpg.call
        .name("from_pretrained")
        .filter(c =>
            c.methodFullName.matches("transformers(\\.\\w+)*\\.from_pretrained") ||
                fileImportsAny(c, sdkRoots, importsByFile)
        )
        .foreach { c =>
          tag(c, AI_MODEL_ARTIFACT_TAG)
          if hasTrueFlag(c, "trust_remote_code") then tag(c, "code-execution")
        }
    cpg.call
        .name("pipeline")
        .filter(c =>
            c.methodFullName.matches("transformers(\\.\\w+)*\\.pipeline") ||
                fileImportsAny(c, sdkRoots, importsByFile)
        )
        .foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))

    // a tokenizer's or processor's chat template, read as an attribute or out of a config
    // dict the model repo supplied (the target of an assignment is a write, not a read)
    cpg.call
        .name(
          s"${Operators.fieldAccess}|${Operators.indirectFieldAccess}|${Operators.indexAccess}|${Operators.indirectIndexAccess}"
        )
        .filter { c =>
            c.argumentOption(2).exists(a => unquote(a.code) == "chat_template") &&
            !isAssignmentTarget(c)
        }
        .filter { c =>
          val baseType = c.argumentOption(1).collect { case i: Identifier => i.typeFullName }
          baseType.exists(t => t.matches("(?i).*(tokenizer|processor).*")) ||
          fileImportsAny(c, sdkRoots, importsByFile)
        }
        .foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))

    // a model file opened, loaded or read by a literal path that names one of the artefacts
    cpg.call
        .name("open")
        .filter(c => literalArtifactPath(c.argumentOption(1)))
        .foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))
    cpg.call
        .methodFullName("json\\.load")
        .filter { c =>
            c.argumentOption(1).exists {
                case l: Literal => isArtifactPath(unquote(l.code))
                case nested: Call =>
                    nested.name == "open" && literalArtifactPath(nested.argumentOption(1))
                case _ => false
            }
        }
        .foreach(c => tag(c, AI_MODEL_ARTIFACT_TAG))
    pathReadTextArms(cpg, artifactPath = isArtifactPath)
  end modelArtifactArms

  /** The literal path a call was spelled with, when it names one of the artefact files. */
  private def literalArtifactPath(arg: Option[Expression]): Boolean =
      arg.collect { case l: Literal => unquote(l.code) }.exists(isArtifactPath)

  private def isArtifactPath(p: String): Boolean =
      ArtifactFileNames.exists(e => p == e || p.endsWith("/" + e))

  /** `Path("model/chat_template.jinja").read_text()`: the literal sits on the Path constructor the
    * read's receiver was assigned from.
    */
  private def pathReadTextArms(cpg: Cpg, artifactPath: String => Boolean)(using
    DiffGraphBuilder
  ): Unit =
    val pathLiterals = scala.collection.mutable.LinkedHashMap.empty[(Long, String), String]
    cpg.call.name("Path").foreach { c =>
        c.argumentOption(1).collect { case l: Literal => unquote(l.code) }.foreach { p =>
          val loweredInto = c._astIn
              .collectFirst { case a: Call if a.name == Operators.assignment => a }
              .flatMap(_.argumentOption(1))
              .collect { case i: Identifier => i.name }
              .getOrElse("")
          pathLiterals((c.method.id, loweredInto)) = p
        }
    }
    cpg.call
        .name("read_text")
        .filter(c => c.methodFullName.matches("pathlib\\.Path\\.read_text"))
        .foreach { c =>
          val receiver = c.argumentOption(0).collect { case i: Identifier => i.name }
          receiver.flatMap(r => pathLiterals.get((c.method.id, r))).foreach { p =>
              if artifactPath(p) then tag(c, AI_MODEL_ARTIFACT_TAG)
          }
        }
  end pathReadTextArms

  /** The `chat_template` render the inference libraries perform internally. A call tagged
    * sandbox-render carries code-execution with it, as everywhere else the tag is written.
    */
  private def chatTemplateRenderArms(cpg: Cpg)(using DiffGraphBuilder): Unit =
    def renderSink(c: Call): Unit =
      tag(c, SANDBOX_RENDER_TAG)
      tag(c, "code-execution")
    cpg.call
        .name("apply_chat_template")
        .foreach(renderSink)
    cpg.call
        .name("chat")
        .filter(c =>
            c.methodFullName.matches("vllm(\\.\\w+)*\\.LLM\\.chat") ||
                c.argumentOption(0).exists {
                    case i: Identifier => i.typeFullName.startsWith("vllm.")
                    case _             => false
                }
        )
        .foreach(renderSink)
    // a chat or render call handed a chat template by keyword (`llm.chat(chat_template=t)`,
    // `render_jinja_template(chat_template=t)`). Constructors, `dict(...)` and settings objects
    // that only carry the template onward are not renders, so the name has to be `chat` or a
    // lower-case function or method that says it renders.
    cpg.call
        .filter(c =>
            c.name == "chat" || (c.name.headOption.exists(_.isLower) && c.name.contains("render"))
        )
        .filter(c => hasNonLiteralFlag(c, "chat_template"))
        .foreach(renderSink)
  end chatTemplateRenderArms

  /** A keyword argument spelled `name=True`. */
  private def hasTrueFlag(c: Call, name: String): Boolean =
      c.argument.exists(a =>
          a.argumentName.contains(name) && a.isInstanceOf[Literal] && a.code == "True"
      )

  private def isAssignmentTarget(c: Call): Boolean =
      c._astIn.collectFirst { case a: Call if a.name == Operators.assignment => a }
          .exists(_.argumentOption(1).exists(_.id == c.id))

  /** A keyword argument `name=...` whose value is not a literal. */
  private def hasNonLiteralFlag(c: Call, name: String): Boolean =
      c.argument.exists(a => a.argumentName.contains(name) && !a.isInstanceOf[Literal])

  private def fileImportsAny(
    c: Call,
    roots: Set[String],
    importsByFile: Map[String, Set[String]]
  ): Boolean = fileImports(importsByFile, c.method.filename, roots)
end AiLlmRecognizer

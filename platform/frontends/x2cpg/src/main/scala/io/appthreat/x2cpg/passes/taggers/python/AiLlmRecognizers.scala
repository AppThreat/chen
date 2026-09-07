package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import PythonRecognizerUtil.*

/** B5 - AI/LLM frameworks (LangChain, LlamaIndex, OpenAI, Anthropic, litellm).
  *
  * Tags:
  *   - `ai-prompt` on prompt-construction calls (`PromptTemplate.from_template(...)`,
  *     `ChatPromptTemplate.from_messages(...)`, message constructors, an LLM call whose
  *     `messages=...` argument is being populated),
  *   - `ai-invoke` on model/chain invocations (`chain.invoke(...)`, `client.chat.completions
  *     .create(...)`, `litellm.completion(...)`, LlamaIndex `query_engine.query(...)`),
  *   - `ai-compose` on LangChain's `|` composition (`tpl | ChatOpenAI(...)`), lowered as
  *     `<operator>.or`.
  *
  * The two first-class flows: framework-input -> `ai-prompt` (prompt injection) and `ai-invoke`
  * result -> `code-execution` (agent escape). Both run through atom's reachables once
  * `ai-prompt`/`ai-invoke` are registered as sink tags.
  *
  * NB (Task 5 input): receiver typing would let `invoke` be scoped to actual runnables - today the
  * gate is project-wide (any `invoke` in an AI-gated project is treated as chain-related), and the
  * runnable side of `|` composition is matched structurally (either operand is a call), not by
  * type.
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
    "litellm"
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
    // typing the operands to runnables needs Task 5.
    cpg.call
        .nameExact(Operators.or)
        .filter(_.code.contains("|"))
        .filter(_.argument.isCall.nonEmpty)
        .foreach(c => tag(c, AI_COMPOSE_TAG))
  end run
end AiLlmRecognizer

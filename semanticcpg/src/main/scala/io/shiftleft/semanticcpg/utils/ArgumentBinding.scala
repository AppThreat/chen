package io.shiftleft.semanticcpg.utils

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.codepropertygraph.generated.nodes.{
    Call,
    Expression,
    Identifier,
    Method,
    MethodParameterIn,
    StoredNode,
    Tag
}
import io.shiftleft.semanticcpg.language.*

/** Which formal parameters an actual argument of a call can bind.
  *
  * Positional arguments bind by index. A named argument (`ARGUMENT_NAME`, e.g. Python's
  * `run(cmd=x)`, PHP's `run(cmd: $x)`, Ruby's `run(cmd: x)`) binds the parameter of that name,
  * whatever its index - the CPG spec ignores the index of a named argument. A name no parameter
  * takes is collected by a keyword-variadic parameter (`**kwargs`). Beyond that:
  *   - extra positional arguments are collected by a positional variadic parameter (`*args`,
  *     `...$args`, Java's `String...`, a C++ parameter pack);
  *   - an iterable unpacked into the positionals (`f(*xs)`, `f(...xs)`) can supply any positional
  *     parameter from its own index on;
  *   - a mapping unpacked into the keywords (`f(**opts)`, named [[MappingUnpackName]]) can supply
  *     any parameter a keyword can bind.
  *
  * A variadic parameter written with `**` (Python's `**kwargs`, Ruby's `**opts`) collects keywords
  * only; one written with `...` (PHP's `...$args`, Ruby's `...`, JavaScript's `...args`) collects
  * both; any other collects positionals only. Parameter indices cannot tell them apart: a parameter
  * without a positional index takes its AST order as index.
  *
  * What a frontend knows of a parameter's kind and the schema cannot hold is a
  * [[ParameterKindTag]]: Python's positional-only parameters (before `/`) and keyword-only ones
  * (after `*` or `*args`). Ruby's are told by language: its positional parameters cannot be named
  * by a keyword, its keyword parameters (`a:`, `a: 1`) cannot be passed by position, and the
  * keywords of a call to a method that takes none are passed as one trailing Hash.
  */
object ArgumentBinding:

  /** `ARGUMENT_NAME` of an argument that unpacks a mapping into the keywords (`f(**opts)`). */
  val MappingUnpackName = "**"

  /** The calls that unpack an iterable into the positional arguments: Python's `f(*xs)`,
    * JavaScript's `f(...xs)`, PHP's `f(...$xs)`, Ruby's `f(*xs)` (whose `f(**h)` is named
    * [[MappingUnpackName]]).
    */
  val IterableUnpackCalls: Set[String] =
      Set("<operator>.starredUnpack", "<operator>.spread", "<operator>.unpack", "<operator>.splat")

  /** Tag on a parameter whose kind its CODE and IS_VARIADIC do not tell, valued [[PositionalOnly]]
    * or [[KeywordOnly]].
    */
  val ParameterKindTag = "parameter-kind"
  val PositionalOnly   = "positional-only"
  val KeywordOnly      = "keyword-only"

  def isKeywordVariadic(param: MethodParameterIn): Boolean =
      param.isVariadic && (param.code.startsWith("**") || param.code.startsWith("..."))

  /** c2cpg marks a C function's last named parameter (`const char *fmt...`) as variadic: the
    * arguments after it reach the callee's `va_list`, not that parameter, so it collects none.
    */
  def isPositionalVariadic(param: MethodParameterIn): Boolean =
      param.isVariadic && !param.code.startsWith("**") &&
          !(param.code.length > 3 && param.code.endsWith("..."))

  /** A `**kwargs`: no positional argument binds it. */
  private def collectsKeywordsOnly(param: MethodParameterIn): Boolean =
      param.isVariadic && param.code.startsWith("**")

  def isPositionalOnly(param: MethodParameterIn): Boolean =
      hasKind(param, PositionalOnly) ||
          isRuby(param) && param.index > 0 && !param.isVariadic && !isRubyKeyword(param)

  def isKeywordOnly(param: MethodParameterIn): Boolean =
      hasKind(param, KeywordOnly) || isRuby(param) && isRubyKeyword(param)

  /** What a call's keywords can bind in the method of `params`. */
  final class Signature(params: Seq[MethodParameterIn]):

    /** A stub's parameters are made from a call's argument count (`p0`, `p1`, ...): a keyword can
      * be any of them but the receiver.
      */
    lazy val namesUnknown: Boolean =
        params.nonEmpty && params.forall(p => p.name == p.code && StubParameterName.matches(p.name))

    /** The names a keyword can bind: not the receiver, a variadic or a positional-only parameter.
      */
    lazy val keywordNames: Set[String] =
        params.filter(p => p.index != 0 && !p.isVariadic && !isPositionalOnly(p)).map(_.name).toSet
    lazy val keywordVariadic: Boolean = params.exists(isKeywordVariadic)

    /** Ruby: the parameter the keywords of a call are passed to as a trailing Hash, when the method
      * takes no keywords - the last positional one, or the `*rest` collecting it.
      */
    lazy val trailingHash: Option[MethodParameterIn] =
        params.headOption.filter(isRuby) match
          case Some(_) if !keywordVariadic && !params.exists(isKeywordOnly) =>
              params.filter(p => p.index > 0 && !p.code.startsWith("&")).maxByOption(_.index)
          case _ => None
  end Signature

  object Signature:
    def of(method: Method): Signature = new Signature(method.parameter.l)

  /** Whether `arg` binds `param`. `signature` describes all parameters of `param`'s method, and is
    * consulted only for a named or unpacked argument.
    */
  def binds(arg: Expression, param: MethodParameterIn, signature: => Signature): Boolean =
      arg.argumentName match
        case Some(MappingUnpackName) =>
            // any parameter a keyword can bind - not the receiver, not the `*args` collector - that
            // the call does not bind already: `f(x, **opts)` passing `x` in opts is a TypeError
            param.index != 0 && !isPositionalVariadic(param) && !isPositionalOnly(param) &&
            !boundByOtherArguments(arg, param) ||
            isKeywordVariadic(param) || signature.trailingHash.contains(param)
        case Some(_) if signature.namesUnknown => param.index > 0
        case Some(name) =>
            if signature.keywordNames.contains(name) then
              name == param.name && !isPositionalOnly(param)
            else if signature.keywordVariadic then isKeywordVariadic(param)
            else signature.trailingHash.contains(param)
        case None =>
            val index = arg.argumentIndex
            (index == param.index && !collectsKeywordsOnly(param) && !isKeywordOnly(param)) ||
            (isPositionalVariadic(param) && index > param.index && param.index > 0) ||
            (isIterableUnpack(arg) && index > 0 && param.index > index &&
                !collectsKeywordsOnly(param) && !isKeywordOnly(param)) ||
            (isForwardAll(arg) && index > 0 && param.index >= index)

  /** The arguments of `call` that bind `param`. */
  def argumentsBinding(call: Call, param: MethodParameterIn): Iterator[Expression] =
    lazy val signature = Signature.of(param.method)
    call._argumentOut.collect { case arg: Expression if binds(arg, param, signature) => arg }

  /** The parameters of the callee `params` that `arg` binds. */
  def parametersBound(arg: Expression, params: Seq[MethodParameterIn]): Seq[MethodParameterIn] =
    lazy val signature = new Signature(params)
    params.filter(binds(arg, _, signature))

  private val StubParameterName = "p\\d+".r

  /** Whether a positional or named argument of `arg`'s call binds `param`. */
  private def boundByOtherArguments(arg: Expression, param: MethodParameterIn): Boolean =
      arg._argumentIn.collectFirst { case call: Call => call }.exists(
        _._argumentOut.exists {
            case other: Expression if other != arg =>
                other.argumentName match
                  case Some(MappingUnpackName) => false
                  case Some(name)              => name == param.name
                  case None => other.argumentIndex == param.index && !isIterableUnpack(other)
            case _ => false
        }
      )

  /** The literal key a parameter's value is read by, on a data-flow path that continues through the
    * value read (`first`, then `next`): `kwargs["cmd"]`, `kwargs.get("cmd")`, `kwargs.pop("cmd",
    * None)`, `kwargs.setdefault("cmd", x)`, Ruby's `opts[:cmd]`. None when the path goes on through
    * the mapping itself, which still holds every other key (`kwargs.pop("cmd")` then
    * `forward(**kwargs)`).
    */
  def keyRead(first: StoredNode, next: Option[StoredNode]): Option[String] =
      first match
        case call: Call if isKeyRead(call) =>
            val mapping = mappingOf(call)
            if next.exists {
                  case id: Identifier => mapping.exists(_.name == id.name)
                  case _              => false
              }
            then None
            else literalKey(call)
        case id: Identifier =>
            readOf(id).filter(read => next.contains(read)).flatMap(literalKey)
        case _ => None

  private def isKeyRead(call: Call): Boolean =
      call.name == "<operator>.indexAccess" || KeyReads.contains(call.name)

  /** The mapping a key read reads: the indexed value, or the receiver of `get`/`pop`. */
  private def mappingOf(call: Call): Option[Identifier] =
    val index = if call.name == "<operator>.indexAccess" then 1 else 0
    call._argumentOut.collectFirst { case id: Identifier if id.argumentIndex == index => id }

  /** The key read `id` is the mapping of: `id[...]`, `id.get(...)` or, through the receiver's field
    * access, `id.pop(...)`.
    */
  private def readOf(id: Identifier): Option[Call] =
      id._argumentIn.collectFirst { case call: Call => call }.flatMap { call =>
          if call.name == "<operator>.indexAccess" && id.argumentIndex == 1 then Some(call)
          else if KeyReads.contains(call.name) && id.argumentIndex == 0 then Some(call)
          else if call.name == "<operator>.fieldAccess" && id.argumentIndex == 1 then
            call._receiverIn.collectFirst {
                case read: Call if KeyReads.contains(read.name) => read
            }
          else None
      }

  private def literalKey(call: Call): Option[String] =
      literalKey(call, if call.name == "<operator>.indexAccess" then 2 else 1)

  // Python's dict and Ruby's Hash (`opts.fetch(:cmd)`, `opts.delete(:cmd)`)
  private val KeyReads = Set("get", "pop", "setdefault", "fetch", "delete")

  private def literalKey(call: Call, index: Int): Option[String] =
      call._argumentOut.collectFirst {
          case literal: io.shiftleft.codepropertygraph.generated.nodes.Literal
              if literal.argumentIndex == index => literal.code
      }.collect {
          case code if code.length >= 2 && "\"'".contains(code.head) && code.last == code.head =>
              code.substring(1, code.length - 1)
          // a Ruby symbol
          case code
              if code.length >= 2 && code.head == ':' && code.drop(1).forall(c =>
                  Character.isLetterOrDigit(c) || c == '_'
              ) => code.drop(1)
      }

  private def isIterableUnpack(arg: Expression): Boolean =
      arg match
        case call: Call => IterableUnpackCalls.contains(call.name)
        case _          => false

  /** Ruby's `bar(...)`: everything the enclosing `def foo(...)` was passed, block included. */
  private def isForwardAll(arg: Expression): Boolean =
      arg match
        case id: Identifier => id.name == "..." && isRuby(id)
        case _              => false

  private def hasKind(param: MethodParameterIn, kind: String): Boolean =
      param._taggedByOut.exists {
          case tag: Tag => tag.name == ParameterKindTag && tag.value == kind
          case _        => false
      }

  private def isRubyKeyword(param: MethodParameterIn): Boolean =
      !param.isVariadic && param.code.startsWith(s"${param.name}:")

  private def isRuby(node: StoredNode): Boolean = languageOf(node) == Languages.RUBYSRC

  private val languages =
      java.util.Collections.synchronizedMap(new java.util.WeakHashMap[overflowdb.Graph, String]())

  private def languageOf(node: StoredNode): String =
      languages.computeIfAbsent(
        node.graph,
        graph => new Cpg(graph).metaData.language.headOption.getOrElse("")
      )
end ArgumentBinding

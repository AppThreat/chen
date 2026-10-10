package io.shiftleft.semanticcpg.utils

import io.shiftleft.codepropertygraph.generated.nodes.{Call, Expression, MethodParameterIn}
import io.shiftleft.semanticcpg.language.*

/** Which formal parameters an actual argument of a call can bind.
  *
  * Positional arguments bind by index. A named argument (`ARGUMENT_NAME`, e.g. Python's
  * `run(cmd=x)`) binds the parameter of that name, whatever its index - the CPG spec ignores the
  * index of a named argument, and frontends set it to -1. A name no parameter has is collected by a
  * keyword-variadic parameter (`**kwargs`). Beyond that:
  *   - extra positional arguments are collected by a positional variadic parameter (`*args`, Java's
  *     `String...`, C's `...`);
  *   - an iterable unpacked into the positionals (`f(*xs)`) can supply any positional parameter
  *     from its own index on;
  *   - a mapping unpacked into the keywords (`f(**opts)`, named [[MappingUnpackName]]) can supply
  *     any parameter a keyword can bind.
  *
  * A variadic parameter is keyword-variadic when its code is written with `**` (Python's
  * `**kwargs`, Ruby's `**opts`), positional-variadic otherwise. Parameter indices cannot tell them
  * apart: a parameter without a positional index takes its AST order as index.
  */
object ArgumentBinding:

  /** `ARGUMENT_NAME` of an argument that unpacks a mapping into the keywords (`f(**opts)`). */
  val MappingUnpackName = "**"

  /** Name of the call that unpacks an iterable into the positional arguments (`f(*xs)`). */
  val IterableUnpackCall = "<operator>.starredUnpack"

  def isKeywordVariadic(param: MethodParameterIn): Boolean =
      param.isVariadic && param.code.startsWith(MappingUnpackName)

  def isPositionalVariadic(param: MethodParameterIn): Boolean =
      param.isVariadic && !isKeywordVariadic(param)

  /** Whether `arg` binds `param`. `parameterNames` are the names of all parameters of `param`'s
    * method, consulted only for a named argument and a keyword-variadic parameter.
    */
  def binds(arg: Expression, param: MethodParameterIn, parameterNames: => Set[String]): Boolean =
      arg.argumentName match
        case Some(MappingUnpackName) =>
            // any parameter a keyword can bind: not the receiver, not the `*args` collector
            param.index != 0 && !isPositionalVariadic(param)
        case Some(name) =>
            name == param.name || (isKeywordVariadic(param) && !parameterNames.contains(name))
        case None =>
            val index = arg.argumentIndex
            (index == param.index && !isKeywordVariadic(param)) ||
            (isPositionalVariadic(param) && index > param.index && param.index > 0) ||
            (isIterableUnpack(arg) && index > 0 && param.index > index && !isKeywordVariadic(param))

  /** The arguments of `call` that bind `param`. */
  def argumentsBinding(call: Call, param: MethodParameterIn): Iterator[Expression] =
    lazy val names = param.method.parameter.map(_.name).toSet
    call._argumentOut.collect { case arg: Expression if binds(arg, param, names) => arg }

  /** The parameters of the callee `params` that `arg` binds. */
  def parametersBound(arg: Expression, params: Seq[MethodParameterIn]): Seq[MethodParameterIn] =
    lazy val names = params.map(_.name).toSet
    params.filter(binds(arg, _, names))

  private def isIterableUnpack(arg: Expression): Boolean =
      arg match
        case call: Call => call.name == IterableUnpackCall
        case _          => false
end ArgumentBinding

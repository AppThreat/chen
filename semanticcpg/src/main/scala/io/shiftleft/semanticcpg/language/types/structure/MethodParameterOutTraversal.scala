package io.shiftleft.semanticcpg.language.types.structure

import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.utils.ArgumentBinding

import scala.jdk.CollectionConverters.*

class MethodParameterOutTraversal(val traversal: Iterator[MethodParameterOut]) extends AnyVal:

  def paramIn: Iterator[MethodParameterIn] = traversal.flatMap(_.parameterLinkIn.headOption)

  /* method parameter indexes are  based, i.e. first parameter has index  (that's how java2cpg generates it) */
  def index(num: Int): Iterator[MethodParameterOut] =
      traversal.filter { _.index == num }

  /* get all parameters from (and including)
   * method parameter indexes are  based, i.e. first parameter has index  (that's how java2cpg generates it) */
  def indexFrom(num: Int): Iterator[MethodParameterOut] =
      traversal.filter(_.index >= num)

  /* get all parameters up to (and including)
   * method parameter indexes are  based, i.e. first parameter has index  (that's how java2cpg generates it) */
  def indexTo(num: Int): Iterator[MethodParameterOut] =
      traversal.filter(_.index <= num)

  /** The arguments bound to the parameter, by index or by name (see [[ArgumentBinding]]). */
  def argument: Iterator[Expression] =
      for
        paramOut <- traversal
        paramIn  <- paramOut.parameterLinkIn.headOption.iterator
        call     <- paramOut.method.callIn
        arg      <- ArgumentBinding.argumentsBinding(call, paramIn)
      yield arg
end MethodParameterOutTraversal

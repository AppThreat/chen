package io.shiftleft.semanticcpg.language

import io.shiftleft.codepropertygraph.generated.nodes.*

import scala.reflect.ClassTag

class TagTraversal(val traversal: Iterator[Tag]) extends AnyVal:

  def member: Iterator[Member]                   = tagged[Member]
  def method: Iterator[Method]                   = tagged[Method]
  def methodReturn: Iterator[MethodReturn]       = tagged[MethodReturn]
  def parameter: Iterator[MethodParameterIn]     = tagged[MethodParameterIn]
  def parameterOut: Iterator[MethodParameterOut] = tagged[MethodParameterOut]
  def call: Iterator[Call]                       = tagged[Call]
  def identifier: Iterator[Identifier]           = tagged[Identifier]
  def literal: Iterator[Literal]                 = tagged[Literal]
  def local: Iterator[Local]                     = tagged[Local]
  def file: Iterator[File]                       = tagged[File]

  /** The tagged nodes as generic expressions - Identifier, Call, Literal, Block and every other
    * argument kind. The overlay tags arguments of memory-API calls, and those arguments are a mix
    * of node kinds (on FFmpeg's libavformat the `mem-len` tags alone land on identifiers, calls and
    * literals), so a detector reading a tagged argument back needs this step rather than a union of
    * the kind-specific ones - which would silently miss whichever kind it forgot.
    */
  def expression: Iterator[Expression] = tagged[Expression]

  /** The tagged nodes without narrowing the kind: for diagnostics and renderers that must not drop
    * a node just because it is not an Expression.
    */
  def taggedNode: Iterator[StoredNode] = tagged[StoredNode]

  private def tagged[A <: StoredNode: ClassTag]: Iterator[A] =
      traversal._taggedByIn.collectAll[A].sortBy(_.id).iterator
end TagTraversal

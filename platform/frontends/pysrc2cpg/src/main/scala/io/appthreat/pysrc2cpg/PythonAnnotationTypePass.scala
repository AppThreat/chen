package io.appthreat.pysrc2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder
import PythonAstVisitor.builtinPrefix

/** Seeds type information derived from PEP 484/526 annotations into the graph before
  * [[PythonTypeRecoveryPass]] runs, so the recovery's symbol table starts from author declarations
  * rather than heuristics alone.
  *
  * The frontend already writes annotation types onto the declaring node (parameter `typeFullName`
  * from `Arg.annotation`, `METHOD_RETURN` from `FunctionDef.returns`, and the assignment-target
  * identifier/field-access call from `AnnAssign`). What is missing - and what this pass fills in -
  * is the rest of the storage the recovery reads:
  *
  *   1. `LOCAL` nodes shadowed by an annotated parameter or an annotated assignment target. 2.
  *      `MEMBER` nodes declared by annotated assignments (`self.attr: T`, module-level `X: T`).
  *
  * An annotation is a declaration by the author: where a heuristic later disagrees, the declaration
  * must win (enforced in `PythonTypeRecovery`).
  */
class PythonAnnotationTypePass(cpg: Cpg) extends ForkJoinParallelCpgPass[Method](cpg):

  /** Builtin *classes* only. A reference to a builtin class is a reference to a type, so
    * `__builtin.str` is the honest type of the name `str`. Builtin *functions* are not: typing the
    * name `len` as `__builtin.len` invents a type that denotes nothing, and it deflates the ANY
    * metric with exactly the kind of fake precision the operator leak was.
    */
  private val builtinNames: Set[String] = PythonAstVisitor.allBuiltinClasses

  override def generateParts(): Array[Method] = cpg.method.internal.toArray

  override def runOnPart(builder: DiffGraphBuilder, method: Method): Unit =
    val paramTypes = method.parameter
        .filter(p => p.typeFullName != Constants.ANY && p.name != "self" && p.name != "cls")
        .map(p => p.name -> p.typeFullName)
        .toMap

    // 0. `self`/`cls` typing is intentionally left to PythonTypeRecovery (frontend receiver
    //    typing + the recovery's final flush): typing receiver identifiers here would collapse
    //    the speculative callee candidates the recovery deliberately keeps open.

    // 0b. references to builtin classes/functions (`isinstance`, `str`, ...) are
    // language-defined bindings, not guesses. Only applied when the method does not shadow
    // the name with a parameter or an assignment.
    val shadowed = paramTypes.keySet ++
        method.ast.isCall
            .nameExact(io.shiftleft.codepropertygraph.generated.Operators.assignment)
            .argument
            .argumentIndex(1)
            .isIdentifier
            .map(_.name)
            .toSet
    val builtinRefs =
        method.ast.isIdentifier
            .filter(i =>
                i.typeFullName == Constants.ANY && builtinNames.contains(i.name)
                    && !shadowed.contains(i.name)
            )
    builtinRefs.foreach { i =>
      builder.setNodeProperty(i, PropertyNames.TYPE_FULL_NAME, builtinPrefix + i.name)
      method.local.nameExact(i.name).foreach { l =>
          if l.typeFullName == Constants.ANY then
            builder.setNodeProperty(l, PropertyNames.TYPE_FULL_NAME, builtinPrefix + i.name)
      }
    }

    // 1a. locals that shadow an annotated parameter inherit the declared type
    method.local.foreach { local =>
        if local.typeFullName == Constants.ANY then
          paramTypes.get(local.name).foreach(t =>
              builder.setNodeProperty(local, PropertyNames.TYPE_FULL_NAME, t)
          )
    }

    // 1b. locals that shadow an annotated assignment target (`x: T = ...` / `x: T`)
    method.ast.isIdentifier
        .filter(i => i.typeFullName != Constants.ANY && !paramTypes.contains(i.name))
        .groupBy(_.name)
        .foreach { case (name, occurrences) =>
            val declared = occurrences.map(_.typeFullName).distinct
            if declared.size == 1 then
              method.local.nameExact(name).foreach { local =>
                  if local.typeFullName == Constants.ANY then
                    builder.setNodeProperty(local, PropertyNames.TYPE_FULL_NAME, declared.head)
              }
        }

    // 2. annotated attribute declarations on `self`/`cls` (`self.attr: T`) and module-level
    //    names (`X: T`) are members of their TYPE_DECL
    val typeDecl = method.typeDecl.headOption
    method.ast.isCall
        .nameExact(io.shiftleft.codepropertygraph.generated.Operators.fieldAccess)
        .filter(_.typeFullName != Constants.ANY)
        .foreach { fieldAccess =>
            fieldAccess.astChildren.l match
              case List(base: Identifier, fi: FieldIdentifier)
                  if (base.name == "self" || base.name == "cls") && typeDecl.isDefined =>
                  typeDecl.get.member.nameExact(fi.canonicalName).foreach { member =>
                      if member.typeFullName == Constants.ANY then
                        builder.setNodeProperty(
                          member,
                          PropertyNames.TYPE_FULL_NAME,
                          fieldAccess.typeFullName
                        )
                  }
              case _ =>
        }
    if method.name == "<module>" then
      method.ast.isIdentifier
          .filter(i => i.typeFullName != Constants.ANY)
          .groupBy(_.name)
          .foreach { case (name, occurrences) =>
              val declared = occurrences.map(_.typeFullName).distinct
              if declared.size == 1 then
                typeDecl.foreach { td =>
                    td.member.nameExact(name).foreach { member =>
                        if member.typeFullName == Constants.ANY then
                          builder.setNodeProperty(
                            member,
                            PropertyNames.TYPE_FULL_NAME,
                            declared.head
                          )
                    }
                }
          }
  end runOnPart
end PythonAnnotationTypePass

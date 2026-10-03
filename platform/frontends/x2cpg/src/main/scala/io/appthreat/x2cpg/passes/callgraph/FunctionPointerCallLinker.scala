package io.appthreat.x2cpg.passes.callgraph

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, Operators}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

import scala.collection.mutable

/** Links a C/C++ call through a function pointer (`fp(x)`, `(*fp)(x)`, `ops->read(x)`) to the
  * functions the program stores into that pointer:
  *
  *   - a variable (local, parameter or global): every function assigned to it, its initialiser
  *     included, and for a parameter every function a caller passes to it (a callback);
  *   - a struct member: every function stored into that member of that struct type anywhere, by an
  *     assignment (`ops.read = f`, also a designated initialiser) or a positional initialiser
  *     (`struct ops o = { f, g }`).
  *
  * A function is a reference to it, also through `&` or a cast. Like a virtual call's overrides,
  * the targets are every function the pointer may hold, not the one a given execution holds.
  */
class FunctionPointerCallLinker(cpg: Cpg) extends CpgPass(cpg):

  import FunctionPointerCallLinker.*

  override def run(dstGraph: DiffGraphBuilder): Unit =
    val pointerCalls = cpg.call.nameExact(PointerCall).l
    if pointerCalls.isEmpty then return

    val byVariable = mutable.HashMap.empty[StoredNode, mutable.LinkedHashSet[Method]]
    val byMember   = mutable.HashMap.empty[(String, String), mutable.LinkedHashSet[Method]]
    lazy val membersByType: Map[String, List[String]] =
        cpg.typeDecl.map(td => typeKey(td.fullName) -> td.member.sortBy(_.order).name.l).toMap

    cpg.call.nameExact(Operators.assignment).foreach { assignment =>
        (assignment.argumentOption(1), assignment.argumentOption(2)) match
          case (Some(target), Some(value)) =>
              val functions = functionsIn(value)
              if functions.nonEmpty then
                variableOf(target).foreach(v =>
                    byVariable.getOrElseUpdate(v, mutable.LinkedHashSet.empty) ++= functions
                )
                memberOf(target).foreach(k =>
                    byMember.getOrElseUpdate(k, mutable.LinkedHashSet.empty) ++= functions
                )
              // `struct ops o = { f, g }`: the initialiser's elements fill the members in order
              value match
                case init: Call if init.name == Operators.arrayInitializer =>
                    variableOf(target).flatMap(typeOfVariable).foreach { owner =>
                        membersByType.get(owner).foreach { members =>
                            members.zip(init.argument.sortBy(_.argumentIndex).l).foreach {
                                (member, element) =>
                                  val fs = functionsIn(element)
                                  if fs.nonEmpty then
                                    byMember.getOrElseUpdate(
                                      (owner, member),
                                      mutable.LinkedHashSet.empty
                                    ) ++= fs
                            }
                        }
                    }
                case _ =>
          case _ =>
    }

    // a callback: a function passed to a parameter of a function the call links to
    cpg.call.filterNot(_.name.startsWith("<operator")).foreach { call =>
      val passed = call.argument.l.filter(_.argumentIndex >= 1).flatMap(a =>
          functionsIn(a) match
            case Nil => None
            case fs  => Some(a.argumentIndex -> fs)
      )
      if passed.nonEmpty then
        call._callOut.collectAll[Method].foreach { callee =>
            passed.foreach { (index, fs) =>
                callee.parameter.filter(_.index == index).foreach(p =>
                    byVariable.getOrElseUpdate(p, mutable.LinkedHashSet.empty) ++= fs
                )
            }
        }
    }

    pointerCalls.foreach { call =>
      val linked  = call._callOut.collectAll[Method].toSet
      val pointer = call.receiver.headOption.orElse(call.argumentOption(0)).map(withoutDeref)
      val targets = pointer.toList.flatMap { p =>
          variableOf(p).toList.flatMap(byVariable.get).flatten ++
              memberOf(p).toList.flatMap(byMember.get).flatten
      }.distinct
      targets.filterNot(linked.contains).foreach(dstGraph.addEdge(call, _, EdgeTypes.CALL))
    }
  end run

  /** The functions an expression refers to: `f`, `&f`, `(handler)f`. */
  private def functionsIn(e: Expression): List[Method] =
      e match
        case ref: MethodRef => ref._refOut.collectAll[Method].l
        case c: Call if c.name == Operators.addressOf || c.name == Operators.cast =>
            c.argument.l.lastOption.toList.flatMap(functionsIn)
        case _ => Nil

  /** `(*fp)` calls the function `fp` holds. */
  private def withoutDeref(e: Expression): Expression =
      e match
        case c: Call if c.name == Operators.indirection =>
            c.argument.l.headOption.map(withoutDeref).getOrElse(c)
        case other => other

  /** The variable an identifier refers to. */
  private def variableOf(e: Expression): Option[StoredNode] =
      e match
        case id: Identifier =>
            id._refOut.collectFirst { case d @ (_: Local | _: MethodParameterIn) => d }
        case _ => None

  private def typeOfVariable(v: StoredNode): Option[String] =
      v match
        case l: Local             => Some(typeKey(l.typeFullName))
        case p: MethodParameterIn => Some(typeKey(p.typeFullName))
        case _                    => None

  private def typeOfExpression(e: Expression): Option[String] =
    val t = e match
      case id: Identifier => id.typeFullName
      case c: Call        => c.typeFullName
      case _              => ""
    Option(t).filter(t => t.nonEmpty && t != "ANY").map(typeKey)

  /** (struct type, member) for `s.member` and `p->member`. */
  private def memberOf(e: Expression): Option[(String, String)] =
      e match
        case c: Call
            if c.name == Operators.fieldAccess || c.name == Operators.indirectFieldAccess =>
            for
              base  <- c.argumentOption(1)
              field <- c.argument.collectAll[FieldIdentifier].headOption
              owner <- typeOfExpression(base)
            yield (owner, field.canonicalName)
        case _ => None
end FunctionPointerCallLinker

object FunctionPointerCallLinker:
  /** The call the C/C++ frontend writes for a call through a pointer to function. */
  val PointerCall = "<operator>.pointerCall"

  /** A struct type by name, whatever its spelling at a use: `struct ops *`, `const ops`, `ops`. */
  def typeKey(typeFullName: String): String =
      typeFullName.replace("*", "").replace("&", "").split("\\s+").filterNot(w =>
          w.isEmpty || w == "const" || w == "volatile" || w == "struct" || w == "union"
      ).mkString(" ")

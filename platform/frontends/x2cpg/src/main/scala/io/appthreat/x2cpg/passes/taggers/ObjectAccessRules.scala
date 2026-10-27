package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** An access whose size the pointer's type sets, against an object the pointer's provenance sets -
  * CBMC's `pointer outside object bounds`, read off a conversion. `int x; char c; *(int *)&c` reads
  * four bytes of a one-byte object; `print_pair((struct pair *)&x)` hands a reader of eight bytes a
  * four-byte int. The frontends give both sizes: the bytes the object occupies (`object-size` on
  * its LOCAL) and the bytes an access through the converted pointer touches (`pointee-size` on the
  * cast).
  *
  * A read reports under MS-BOUND-003 (CWE-125), a write under MS-BOUND-004 (CWE-787). The object
  * must be one the method itself names - a local, through its address or as an array - on every
  * definition of the pointer that is not NULL; a parameter's pointee is the caller's, of any size.
  */
object ObjectAccessRules:

  import MemorySafetyFindingPass.*

  def accessThroughWiderType(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
    atom.call.nameExact(Operators.cast).foreach { cast =>
        for
          pointee <- cast.tag.nameExact(X2CpgDefines.PointeeSizeTag).value.headOption
              .flatMap(_.toLongOption)
          operand <- cast.argument.l.collect { case e: Expression => e }.lastOption
          bytes   <- objectBytes(operand)
          if pointee > bytes
          (node, rule) <- accessOf(cast).toList ++ accessesThroughVariable(cast)
        do record(node, rule)
    }
    // the same question without the frontend's pointee size: the access's own width (the
    // member read or written, the element) against the constant-size allocation the pointer
    // was stored from
    atom.call.nameExact(Operators.cast).filter(_.tag.nameExact(X2CpgDefines.PointeeSizeTag).isEmpty)
        .foreach { cast =>
            for
              operand <- cast.argument.l.collect { case e: Expression => e }.lastOption
              bytes   <- objectBytes(operand).filter(_ => isAllocationCall(operand))
              case (access: Call, rule) <- accessesThroughVariable(cast)
              width <- accessWidth(atom, access)
              if width > bytes
            do record(access, rule)
        }
  end accessThroughWiderType

  private def isAllocationCall(e: Expression): Boolean = e match
    case c: Call if c.name == Operators.cast =>
        c.argument.l.collect { case x: Expression => x }.lastOption.exists(isAllocationCall)
    case c: Call => c.tag.nameExact(MemoryApiPass.TagAlloc).nonEmpty
    case _       => false

  /** The bytes one access touches, from the type it reads or writes. */
  private def accessWidth(atom: Cpg, access: Call): Option[Long] =
    val typeName = access.name match
      case Operators.indirectFieldAccess =>
          OverlayFacts.memberRefOf(atom, access).map(_.typeFullName)
              .orElse(Some(access.typeFullName))
      case _ => Some(access.typeFullName)
    typeName.flatMap(t => OverlayFacts.integralWidth(t)).map(_.toLong / 8).filter(_ > 0)

  /** The accesses through a variable the converted pointer was stored into: `p = (S *)malloc(1);
    * p->i = x;` writes four bytes of a one-byte object at the member access.
    */
  private def accessesThroughVariable(cast: Call): List[(StoredNode, String)] =
      cast._astIn.collectFirst { case a: Call => a }
          .filter(a =>
              a.name == Operators.assignment && a.argumentOption(2).exists(_.id == cast.id)
          )
          .flatMap(_.argumentOption(1).collect { case i: Identifier => i }).toList
          .flatMap { lhs =>
              lhs.method.ast.isCall
                  .name(
                    s"${Operators.indirection}|${Operators.indirectFieldAccess}|" +
                        s"${Operators.indirectIndexAccess}"
                  ).l
                  .filter(access =>
                      access.argumentOption(1).exists {
                          case i: Identifier =>
                              i.name == lhs.name &&
                              assignmentsOf(i).exists(_.argumentOption(1).exists(_.id == lhs.id))
                          case _ => false
                      }
                  )
                  .map(access =>
                      (access, if isWritten(access) then RuleIndexWrite else RuleIndexRead)
                  )
          }

  /** The bytes of the object a pointer expression points to, at its start. */
  private def objectBytes(e: Expression, depth: Int = 0): Option[Long] =
    if depth > 4 then return None
    e match
      case c: Call if c.name == Operators.cast =>
          c.argument.l.collect { case x: Expression => x }.lastOption.flatMap(objectBytes(
            _,
            depth + 1
          ))
      case c: Call if c.name == Operators.addressOf =>
          c.argumentOption(1).collect { case i: Identifier => i }.flatMap(localOf).flatMap(sizeOf)
      // a parameter points where its callers say: the object every resolved call site hands it,
      // when they agree on its size (a caller the graph does not resolve leaves it unknown)
      // an allocation of a constant size holds exactly that many bytes
      case c: Call
          if c.tag.nameExact(MemoryApiPass.TagAlloc).nonEmpty ||
              c.tag.nameExact(MemoryApiPass.TagRealloc).nonEmpty =>
          val sizes  = c.argument.l.filter(_.tag.nameExact(MemoryApiPass.TagLen).nonEmpty)
          val values = sizes.flatMap(IndexRange.literal)
          Option.when(sizes.nonEmpty && values.size == sizes.size)(values.product)
              .filter(_.isValidLong).map(_.toLong)
      case i: Identifier if localOf(i).isEmpty =>
          i.method.parameter.nameExact(i.name).headOption.flatMap { p =>
            val sites = p.method.callIn.l
            val sizes = sites.map(site =>
                site.argumentOption(p.index).collect { case a: Expression => a }
                    .flatMap(objectBytes(_, depth + 1))
            )
            Option.when(
              sites.nonEmpty && sizes.forall(_.isDefined) && sizes.flatten.distinct.size == 1
            )(
              sizes.head
            ).flatten
          }
      case i: Identifier =>
          localOf(i).flatMap { local =>
              if OverlayFacts.arrayExtent(local.typeFullName).isDefined then sizeOf(local)
              else
                // a pointer local: the object every non-NULL assignment points to
                val values = assignmentsOf(i).flatMap(_.argumentOption(2).collect {
                    case x: Expression => x
                })
                    .filterNot(isNull)
                val sizes = values.map(objectBytes(_, depth + 1))
                Option.when(values.nonEmpty && sizes.forall(_.isDefined) &&
                    sizes.flatten.distinct.size == 1)(sizes.head).flatten
          }
      case _ => None
    end match
  end objectBytes

  /** Where the converted pointer is used to access memory, and whether it writes: a dereference, a
    * member or element access through it, or a call that reads through the argument (a callee whose
    * body dereferences that parameter on every path, or a function with no body here, given a
    * pointer converted for it).
    */
  private def accessOf(cast: Call): Option[(StoredNode, String)] =
      cast._astIn.collectFirst { case p: Call => p }.flatMap { parent =>
        val first = parent.argumentOption(1).exists(_.id == cast.id)
        parent.name match
          case Operators.indirection | Operators.indirectFieldAccess | Operators.indirectIndexAccess
              if first =>
              Some((parent, if isWritten(parent) then RuleIndexWrite else RuleIndexRead))
          case n if !n.startsWith("<operator") =>
              val index   = cast.argumentIndex
              val callees = parent._callOut.collectAll[Method].l
              val reads =
                  if callees.isEmpty || callees.forall(m =>
                        m.isExternal || m.block.astChildren.isEmpty
                    )
                  then true
                  else
                    callees.exists(m =>
                        m.tag.nameExact(AllocationStatePass.TagEffect).value.l
                            .contains(s"effect:derefs-param:$index") ||
                            m.tag.nameExact(AllocationStatePass.TagEffect).value.l
                                .contains(s"effect:reads-param:$index")
                    )
              Option.when(reads)((cast, RuleIndexRead))
          case _ => None
        end match
      }

  private def isWritten(access: Call): Boolean =
      access._astIn.collectFirst { case c: Call => c }.exists(c =>
          OverlayFacts.isAssignmentOperator(c.name) && c.argumentOption(1).exists(_.id == access.id)
      )

  private def localOf(i: Identifier): Option[Local] =
      i.refsTo.collectFirst { case l: Local => l }.orElse(
        i.method.local.nameExact(i.name).headOption
      )

  private def sizeOf(local: Local): Option[Long] =
      local.tag.nameExact(X2CpgDefines.ObjectSizeTag).value.headOption.flatMap(_.toLongOption)

  private def assignmentsOf(i: Identifier): List[Call] =
      OverlayFacts.reachingDefsIn(i).collect { case d: Identifier if d.name == i.name => d }
          .flatMap(d =>
              d._astIn.collectFirst {
                  case a: Call
                      if a.name == Operators.assignment && a.argumentOption(1).exists(
                        _.id == d.id
                      ) =>
                      a
              }
          ).distinct

  private def isNull(e: Expression): Boolean = e match
    case c: Call if c.name == Operators.cast =>
        c.argument.l.collect { case x: Expression => x }.lastOption.exists(isNull)
    case c: Call if c.name == "NULL" => true
    case l: Literal    => IndexRange.literal(l).contains(BigInt(0)) || l.code.trim == "nullptr"
    case i: Identifier => i.name == "NULL" || i.name == "nullptr"
    case _             => false
end ObjectAccessRules

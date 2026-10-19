package io.appthreat.x2cpg.passes.taggers

import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** Objects whose lifetime ends where the language ends it, read after it ended.
  *
  * CBMC marks every address-taken local dead at each exit from its block (`DEAD`, instrumented for
  * the `dirty` set only) and asserts at each dereference that the pointer is not into a dead
  * object. The graph already says which block declares a local, and a pointer's definitions say
  * which object it points into: a pointer whose every non-NULL definition points into an object of
  * a block, read or written through where that block has been left, reads a dead object (C11
  * 6.2.4p2: "the value of a pointer becomes indeterminate when the object it points to reaches the
  * end of its lifetime"). The objects are an inner block's automatic locals, through their address
  * or as a decayed array, and a compound literal written in an inner block (C11 6.5.2.5p5: it has
  * the enclosing block's automatic storage). A `static` local lives to the program's end. The
  * method's own outermost block ends where the frame does - leaving the frame is MS-ESC-001's
  * question.
  *
  * Reported under MS-ALLOC-002 (CWE-416) at the access.
  */
object LifetimeRules:

  import MemorySafetyFindingPass.*

  def useAfterScope(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.method.filterNot(_.isExternal).foreach { method =>
        val top = Option(method.block).map(_.id())
        accessesThroughPointers(method).foreach { case (pointer, access) =>
            val stores = assignmentsOf(pointer)
            val objects = stores.map(_.argumentOption(2).collect { case e: Expression => e })
                .flatMap {
                    case Some(rhs) if isNull(rhs) => None
                    case other                    => Some(other.flatMap(scopedObject(_, top)))
                }
            if objects.nonEmpty && objects.forall(_.isDefined) then
              val blocks = objects.flatten
              if blocks.forall(b => !contains(b, access)) then record(access, RuleUseAfterFree)
        }
      }

  /** A pointer or view assigned something borrowed from a temporary the end of its full-expression
    * destroys ([class.temporary]p4): `const char *p = make().c_str();`, `std::string_view v = a +
    * "x";`. Every read of the variable after that statement reads a destroyed object. The frontends
    * mark the temporaries (`lifetime-end=full-expression`, EDG's object lifetimes and CDT's
    * implicit destructor names); one a reference binding extends is not marked. Borrowed means: the
    * temporary itself bound to a view, or a member call on it - or a conversion of it - whose
    * result is a pointer, a reference or a view.
    */
  def useOfDeadTemporary(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.call.nameExact(Operators.assignment).foreach { a =>
          for
            lhs <- a.argumentOption(1).collect { case i: Identifier => i }
            rhs <- a.argumentOption(2).collect { case e: Expression => e }
            if isBorrowingType(lhs.typeFullName) && borrowsTemporary(rhs, lhs.typeFullName)
          do
            val statement = statementOf(a)
            lhs._reachingDefOut.collect { case use: Identifier if use.name == lhs.name => use }
                .filterNot(use => statementOf(use).id() == statement.id())
                .foreach { use =>
                  // returned, the dangling storage leaves the frame (CWE-562); read here, it is
                  // a use of a destroyed object (CWE-416)
                  val returned = use._astIn.nextOption().exists(_.isInstanceOf[Return])
                  record(use, if returned then RuleStackEscape else RuleUseAfterFree)
                }
      }

  private def borrowsTemporary(e: Expression, targetType: String): Boolean =
      withoutWrappers(e) match
        case c: Call if isTemporary(c) => isViewType(targetType)
        // a view bound directly to a call's by-value result: the result is a temporary whatever
        // the frontend could resolve of its class (CDT types an unresolved library return `ANY`;
        // the resolved callee still declares what it returns)
        case c: Call if isViewType(targetType) && returnsValue(c) => true
        // a member call on the temporary, or a conversion of it: `make().c_str()`. Only the
        // object (argument 0) or a cast's operand - what a free function returns from a temporary
        // argument is not the argument's storage (`New(std::move(state))` builds a new object)
        case c: Call if !c.name.startsWith("<operator>.") || c.name == Operators.cast =>
            val result = Option(c.typeFullName).getOrElse("")
            (isBorrowingType(result) || isViewType(targetType)) &&
            c.argument.l.collect { case x: Expression => x }
                .filter(arg => c.name == Operators.cast || arg.argumentIndex == 0)
                .exists(arg =>
                    withoutWrappers(arg) match
                      case t: Call => isTemporary(t)
                      case _       => false
                )
        case _ => false

  /** A call whose resolved callee returns an object by value - not a pointer, a reference, a view
    * or nothing.
    */
  private def returnsValue(c: Call): Boolean =
      !c.name.startsWith("<operator>") && {
          val callees = c._callOut.collectAll[Method].l
          callees.nonEmpty && callees.forall { m =>
            val t = Option(m.methodReturn.typeFullName).map(_.trim).getOrElse("")
            !isBorrowingType(t) && isOwnerType(t)
          }
      }

  /** A type that owns the storage a view of it reads: a string or a contiguous container. Named,
    * because an alias can hide a reference (an iterator's `reference operator*()` returns `const
    * T&` under a member typedef) and an iterator's referent outlives the iterator.
    */
  private def isOwnerType(t: String): Boolean =
    val bare = t.replaceAll("<.*>", "").replace("const ", "").trim
    OwnerTypeNames.contains(bare.split("[.:]+").lastOption.getOrElse(""))

  private val OwnerTypeNames =
      Set(
        "basic_string",
        "string",
        "wstring",
        "u8string",
        "u16string",
        "u32string",
        "vector",
        "array"
      )

  private def isTemporary(c: Call): Boolean =
      c.tag.nameExact(X2CpgDefines.LifetimeEndTag).valueExact(X2CpgDefines.TemporaryLifetime).nonEmpty

  /** A pointer, a reference, or a view: types whose value is another object's storage. */
  private def isBorrowingType(t: String): Boolean =
    val x = Option(t).getOrElse("").trim
    x.endsWith("*") || x.endsWith("&") || isViewType(x)

  private val ViewTypeName = """(^|[.:])(basic_)?(string_view|span)\b""".r

  private def isViewType(t: String): Boolean = ViewTypeName.findFirstIn(t.trim).isDefined

  private def withoutWrappers(e: Expression): Expression = e match
    case c: Call if c.name == Operators.cast || c.name == "<operator>.classRvalueAdjust" =>
        c.argument.l.collect { case x: Expression => x }.lastOption.map(withoutWrappers).getOrElse(
          e
        )
    case other => other

  /** The statement an expression belongs to: its ancestor whose parent is a block or a control
    * structure.
    */
  private def statementOf(node: AstNode): AstNode =
    var cursor: AstNode = node
    var walking         = true
    while walking do
      cursor._astIn.nextOption() match
        case Some(_: Block | _: ControlStructure | _: Method) => walking = false
        case Some(parent: AstNode)                            => cursor = parent
        case _                                                => walking = false
    cursor

  /** A closure that holds a local by reference, stored where it outlives the local's frame - a
    * global, a `static`, a member through `this` or a pointer, or returned - refers to storage that
    * is gone once the function returns ([expr.prim.lambda.capture]p13: a reference capture does not
    * extend the referent's lifetime). The frontends tag each lambda with what it captures; a
    * capture default by reference captures every local of the enclosing function its body names.
    * Reported under MS-ESC-001 (CWE-562) where the closure leaves.
    */
  def closureEscape(atom: Cpg, record: (StoredNode, String) => Unit): Unit =
      atom.method.filterNot(_.isExternal).foreach { m =>
        val closures = m.ast.collectAll[MethodRef].l.filter(r => capturesLocalByReference(r, m))
        if closures.nonEmpty then
          val ids = closures.map(_.id()).toSet
          def carries(e: Expression, depth: Int = 0): Boolean =
              depth < 4 && (e match
                case r: MethodRef => ids.contains(r.id())
                case i: Identifier =>
                    localOf(i).exists(l => l.astParent.isInstanceOf[Block]) &&
                    assignmentsOf(i).exists(a =>
                        a.argumentOption(2).collect { case x: Expression => x }.exists(carries(
                          _,
                          depth + 1
                        ))
                    )
                // a wrapper built from the closure (`std::function<...>(g)`, a conversion)
                case c: Call if !OverlayFacts.isAssignmentOperator(c.name) =>
                    c.argument.l.collect { case x: Expression => x }.exists(carries(_, depth + 1))
                case _ => false
              )
          m.ast.isCall.l.foreach { c =>
            val (lhs, rhs) =
                if c.name == Operators.assignment then (c.argumentOption(1), c.argumentOption(2))
                else if c.name == "operator=" || c.methodFullName.contains(".operator=") then
                  val args = c.argument.l.sortBy(_.argumentIndex)
                  (args.headOption, args.lift(1))
                else (None, None)
            for
              target <- lhs.collect { case e: Expression => e }
              value  <- rhs.collect { case e: Expression => e }
              if outlivesFrame(target, m) && carries(value)
            do record(c, RuleStackEscape)
          }
          m.ast.collectAll[Return].foreach { r =>
              r.astChildren.collectFirst { case e: Expression => e }.filter(carries(_)).foreach(_ =>
                  record(r, RuleStackEscape)
              )
          }
        end if
      }

  private def capturesLocalByReference(ref: MethodRef, m: Method): Boolean =
    val captures   = ref.tag.nameExact(X2CpgDefines.CaptureTag).value.l
    val frameNames = (m.local.l.filterNot(isStatic).map(_.name) ++ m.parameter.name.l).toSet
    captures.exists(c => c.startsWith("ref:") && frameNames.contains(c.stripPrefix("ref:"))) ||
    captures.contains("default:ref") && ref._refOut.collectAll[Method].ast.isIdentifier.exists(i =>
        i.refsTo.collectFirst { case l: Local => l }.exists(l =>
            m.local.exists(_.id == l.id) && !isStatic(l)
        )
    )

  private def isStatic(l: Local): Boolean =
      l.tag.nameExact(X2CpgDefines.StorageClassTag).value.l.contains(
        X2CpgDefines.StorageClassStatic
      )

  /** Storage that outlives the frame: a global or `static` variable, or a member reached through
    * `this` or a pointer. A function's own automatic local does not, whichever copy of the function
    * (a header's inline member, emitted by every unit) its reference resolves to.
    */
  private def outlivesFrame(target: Expression, m: Method): Boolean = target match
    case i: Identifier =>
        val own = m.local.nameExact(i.name).l
        if own.nonEmpty then own.forall(isStatic)
        else
          m.parameter.nameExact(i.name).isEmpty &&
          i.refsTo.collectFirst { case l: Local => l }.exists(isProgramStorage)
    case c: Call if c.name == Operators.indirectFieldAccess => true
    case c: Call if c.name == Operators.indirection         => true
    case c: Call if c.name == Operators.fieldAccess =>
        c.argumentOption(1).collect { case e: Expression => e }.exists(outlivesFrame(_, m))
    case _ => false

  /** The accesses through a pointer variable in a method: `*p`, `p[i]`, `p->f`, and a pointer
    * handed to a memory API's source or destination - each with the identifier it reads.
    */
  private def accessesThroughPointers(method: Method): List[(Identifier, StoredNode)] =
    val derefs = method.ast.isCall.l.flatMap { c =>
        c.name match
          case Operators.indirection | Operators.indirectFieldAccess | Operators.indirectIndexAccess |
              Operators.indexAccess =>
              c.argumentOption(1).collect {
                  case i: Identifier if isPointerLocal(i) => (i, c: StoredNode)
              }
          case _ => None
    }
    val apiArgs =
        method.ast.isIdentifier.l.filter(i =>
            isPointerLocal(i) &&
                (i.tag.nameExact(MemoryApiPass.TagDst).nonEmpty || i.tag.nameExact(
                  MemoryApiPass.TagSrc
                ).nonEmpty)
        ).map(i => (i, i: StoredNode))
    derefs ++ apiArgs

  /** A pointer local - not an array: an array is its own object, never a view of another. */
  private def isPointerLocal(i: Identifier): Boolean =
      localOf(i).exists(l => !l.typeFullName.trim.endsWith("]"))

  /** The block whose end ends the object an address expression points into, when that block is an
    * inner one: an address-taken local's, an array local's, or a compound literal's.
    */
  private def scopedObject(e: Expression, top: Option[Long]): Option[Block] =
      e match
        case c: Call if c.name == Operators.cast && isCompoundLiteral(c) =>
            innerBlockOf(c, top)
        case c: Call if c.name == Operators.cast =>
            c.argument.l.collect { case x: Expression => x }.lastOption.flatMap(scopedObject(
              _,
              top
            ))
        case c: Call if c.name == Operators.addressOf =>
            c.argumentOption(1).collect { case x: Expression => x }.flatMap(objectRoot).flatMap(
              declaringBlock(_, top)
            )
        case c: Call if c.name == Operators.addition =>
            c.argument.l.collect { case x: Expression => x }.find(isArrayValued)
                .flatMap(scopedObject(_, top))
        case i: Identifier if isArrayValued(i) =>
            localOf(i).flatMap(declaringBlock(_, top))
        case _ => None

  /** The local an lvalue names: `x`, `x[i]`, `x.f`. */
  private def objectRoot(e: Expression): Option[Local] = e match
    case i: Identifier => localOf(i)
    case c: Call if c.name == Operators.indexAccess || c.name == Operators.fieldAccess =>
        c.argumentOption(1).collect { case x: Expression => x }.flatMap(objectRoot)
    case c: Call if c.name == Operators.indirectIndexAccess =>
        c.argumentOption(1).collect { case i: Identifier if isArrayValued(i) => i }.flatMap(localOf)
    case _ => None

  /** The inner block a local is declared in; None for the method's own block, for a `static` local,
    * which lives as long as the program, and for an object another method declares - a global is a
    * local of the file's `<global>`, and its block never ends while this one runs.
    */
  private def declaringBlock(local: Local, top: Option[Long]): Option[Block] =
      if isStatic(local) then None
      else
        local._astIn.collectFirst { case b: Block => b }
            .filterNot(b => top.contains(b.id()))
            .filter(b =>
                enclosingMethod(b).flatMap(m => Option(m.block)).exists(mb => top.contains(mb.id()))
            )

  private def enclosingMethod(node: StoredNode): Option[Method] =
    var cursor: Option[StoredNode] = Some(node)
    var found: Option[Method]      = None
    while found.isEmpty && cursor.isDefined do
      cursor.get match
        case m: Method => found = Some(m)
        case other     => cursor = other._astIn.nextOption()
    found

  /** A local of the file's `<global>`, or a `static` one: storage the program keeps. */
  private def isProgramStorage(l: Local): Boolean =
      isStatic(l) || enclosingMethod(l).exists(_.name == "<global>")

  /** The innermost block enclosing a node, unless it is the method's own. */
  private def innerBlockOf(node: AstNode, top: Option[Long]): Option[Block] =
    var cursor: Option[StoredNode] = node._astIn.nextOption()
    var found: Option[Block]       = None
    while found.isEmpty && cursor.isDefined do
      cursor.get match
        case b: Block if !isExpressionBlock(b) => found = Some(b)
        case _: Method                         => cursor = None
        case other                             => cursor = other._astIn.nextOption()
    found.filterNot(b => top.contains(b.id()))

  /** A block that is an expression's own (a macro expansion, a statement expression) is not a scope
    * a compound literal's lifetime is tied to.
    */
  private def isExpressionBlock(b: Block): Boolean =
      b._astIn.nextOption().exists {
          case _: Block | _: Method | _: ControlStructure => false
          case _                                          => true
      }

  private def isCompoundLiteral(c: Call): Boolean =
      c.argument.l.exists {
          case init: Call => init.name == Operators.arrayInitializer
          case _          => false
      }

  private def isArrayValued(e: Expression): Boolean = e match
    case i: Identifier => localOf(i).exists(_.typeFullName.trim.endsWith("]"))
    case _             => false

  private def contains(block: Block, node: StoredNode): Boolean =
    var cursor: Option[StoredNode] = Some(node)
    var inside                     = false
    while !inside && cursor.isDefined do
      cursor.get match
        case b: Block if b.id() == block.id() => inside = true
        case _: Method                        => cursor = None
        case other                            => cursor = other._astIn.nextOption()
    inside

  private def localOf(i: Identifier): Option[Local] =
      i.refsTo.collectFirst { case l: Local => l }.orElse(
        i.method.local.nameExact(i.name).headOption
      )

  /** The assignments that define the pointer a use reads, when those are its only writes. */
  private def assignmentsOf(i: Identifier): List[Call] =
    val defs =
        OverlayFacts.reachingDefsIn(i).collect { case d: Identifier if d.name == i.name => d }
    val writes = defs.flatMap(d =>
        d._astIn.collectFirst { case c: Call => c }.filter(c =>
            OverlayFacts.isAssignmentOperator(c.name) && c.argumentOption(1).exists(_.id == d.id)
        )
    ).distinct
    if writes.exists(_.name != Operators.assignment) then Nil else writes

  private def isNull(e: Expression): Boolean = e match
    case c: Call if c.name == Operators.cast =>
        c.argument.l.collect { case x: Expression => x }.lastOption.exists(isNull)
    // `NULL` as a macro invocation: what it expands to
    case c: Call
        if c.name == "NULL" || c
            .dispatchType == io.shiftleft.codepropertygraph.generated.DispatchTypes.INLINED =>
        c.name == "NULL" || c.astChildren.collect { case x: Expression => x }.toList.lastOption
            .exists(isNull)
    case l: Literal    => IndexRange.literal(l).contains(BigInt(0)) || l.code.trim == "nullptr"
    case i: Identifier => i.name == "NULL" || i.name == "nullptr"
    case _             => false
end LifetimeRules

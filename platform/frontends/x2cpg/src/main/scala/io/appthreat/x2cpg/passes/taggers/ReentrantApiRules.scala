package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{DispatchTypes, Operators}
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

/** MS-INVAL-002 (CWE-416): a borrowed item or a length read from a mutable Python container is used
  * after a call that can run arbitrary Python code.
  *
  * In the CPython C API a borrowed reference (`PyList_GET_ITEM`, `PyDict_GetItem*`) stays valid
  * only while the container keeps the item, and a size (`PyList_GET_SIZE`) stays true only while
  * nothing resizes the container. Any call that can run Python code in between (a `__eq__` behind
  * `PyObject_RichCompare`, a `__del__` behind `Py_DECREF`, a callback behind `PyObject_Call*`) can
  * mutate the container, so the borrowed item may be freed and the size may be past the end. This
  * is the shape behind most of the interpreter's own use-after-free fixes, and the reason the API
  * documentation asks for a strong reference (`Py_INCREF`, `Py_NewRef`) before calling out.
  *
  * The rule reports:
  *   - a borrowed item used after a re-entrant call, unless a strong reference to it was taken
  *     between the read and the call;
  *   - a size used after a re-entrant call when the same container is indexed again after the call
  *     (the stale size then bounds a read of the changed container).
  *
  * Only mutable containers count: a tuple cannot change size or drop an item while it is alive, so
  * its readers are not tracked. Only containers the callback can reach count: a parameter, a field,
  * or a local copied from either. A list the method built itself and never handed out is out of the
  * callback's reach.
  *
  * The re-entrant calls are the C API entry points that can execute Python code, the reference
  * decrements, and calls to defined functions whose bodies make one of the entry-point calls (a
  * bounded walk up the call graph). Every such call is tagged `py-reentrant`. A decrement of an
  * object the method itself created as a str, int, float or bytes runs no Python code and is not
  * counted. A finding reports at `medium` when the call in between is an entry point or a defined
  * function reaching one, and at the rule's `low` when it is only a decrement.
  */
object ReentrantApiRules:

  final val TagReentrant = "py-reentrant"

  private val EntryPointExact =
      Set(
        "PyObject_Hash",
        "PyObject_Str",
        "PyObject_Repr",
        "PyObject_IsTrue",
        "PyIter_Next",
        "PyObject_GetItem",
        "PyObject_SetItem",
        "PyObject_DelItem"
      )
  private val EntryPointPrefixes = Seq(
    "PyObject_Call",
    "PyObject_Vectorcall",
    "_PyObject_Call",
    "_PyObject_Vectorcall",
    "PyObject_GetAttr",
    "PyObject_SetAttr",
    "PyObject_RichCompare",
    "PyNumber_"
  )
  private val Decrements =
      Set(
        "Py_DECREF",
        "Py_XDECREF",
        "Py_CLEAR",
        "Py_SETREF",
        "Py_XSETREF",
        "Py_DecRef",
        "Py_XDecRef"
      )

  /** The reference-count and assertion machinery a header defines inline. With the headers
    * available these expand into calls of their own (`_Py_Dealloc`, `_PyObject_AssertFailed`);
    * those calls are the decrement or the debug-only check they expand, never an entry point, and
    * the walk up the call graph does not pass through them.
    */
  private val RefcountMachinery = Decrements ++ Set(
    "_Py_DECREF",
    "_Py_XDECREF",
    "_Py_Dealloc",
    "_Py_DecRef",
    "Py_INCREF",
    "Py_XINCREF",
    "_Py_INCREF",
    "Py_NewRef",
    "Py_XNewRef",
    "_PyObject_AssertFailed",
    "_PyObject_AssertFailedMsg"
  )

  /** Constructors of objects whose deallocation runs no Python code. */
  private val InertConstructorPrefixes =
      Seq("PyUnicode_", "PyLong_", "PyFloat_", "PyBytes_", "PyBool_")

  private val BorrowedItemReaders = Set(
    "PyList_GET_ITEM",
    "PyList_GetItem",
    "PyDict_GetItem",
    "PyDict_GetItemWithError",
    "PyDict_GetItemString",
    "_PyDict_GetItem_KnownHash",
    "PySequence_Fast_GET_ITEM"
  )
  private val SizeReaders = Set(
    "PyList_GET_SIZE",
    "PyList_Size",
    "PyDict_GET_SIZE",
    "PyDict_Size",
    "PyByteArray_GET_SIZE",
    "PyByteArray_Size",
    "PySequence_Fast_GET_SIZE"
  )

  /** The accesses that index a container again: a stale size bounding one of these reads past the
    * container's current end.
    */
  private val ItemAccessors =
      BorrowedItemReaders ++ Set("PyList_SET_ITEM", "PyList_SetItem", "PySequence_Fast_ITEMS")

  private val StrongReference = Set("Py_INCREF", "Py_XINCREF", "Py_NewRef", "Py_XNewRef")

  def isEntryPoint(name: String): Boolean =
      EntryPointExact.contains(name) || EntryPointPrefixes.exists(name.startsWith)

  def isReentrantApiName(name: String): Boolean = isEntryPoint(name) || Decrements.contains(name)

  /** How far the closure walks up the call graph from the functions that call an entry point. */
  private val ClosureDepth = 4

  /** The call sites that can run Python code: the API calls themselves, and the calls into defined
    * functions whose bodies call an entry point (directly or within the closure).
    */
  def reentrantSites(atom: Cpg): List[Call] =
    val viaEntryPoint = entryPointClosure(atom)
    atom.method.isExternal(false).ast.isCall
        .filter(c =>
            !c.name.startsWith("<operator") && !insideExpansion(c) &&
                (isReentrantApiName(c.name) || reachesClosure(c, viaEntryPoint))
        )
        .l

  /** A call inside the expansion of a macro whose own call stands for it: the refcount macros, the
    * re-entrant API macros, and the assert family (a debug-only check runs nothing in a release
    * build).
    */
  private def insideExpansion(c: Call): Boolean =
      c.inAst.collectAll[Call].exists(m =>
          m.id() != c.id() && m.dispatchType == DispatchTypes.INLINED &&
              (isReentrantApiName(m.name) || RefcountMachinery.contains(m.name) ||
                  GuardPass.isAssertFamilyCall(m))
      )

  private def entryPointClosure(atom: Cpg): Set[Long] =
    val direct = atom.method.isExternal(false)
        .filterNot(m => RefcountMachinery.contains(m.name))
        .filter(_.ast.isCall.exists(c => isEntryPoint(c.name) && !insideExpansion(c)))
        .l
    val closure  = mutable.HashSet.empty[Long] ++ direct.map(_.id())
    var frontier = direct
    var depth    = 0
    while frontier.nonEmpty && depth < ClosureDepth do
      depth += 1
      frontier = frontier
          .flatMap(_._callIn.collectAll[Call].map(_.method).l)
          .filter(m =>
              !m.isExternal && !RefcountMachinery.contains(m.name) && closure.add(m.id())
          )
    closure.toSet

  private def reachesClosure(c: Call, closure: Set[Long]): Boolean =
      c._callOut.collectAll[Method].exists(m => closure.contains(m.id()))

  private enum ReadKind:
    case Borrowed, Size

  /** One read: the assignment holding it, its target, the container and what was read. */
  private final case class Read(
    assignment: Call,
    target: Identifier,
    container: Expression,
    kind: ReadKind
  )

  /** One finding: the use, the call in between, and whether it reports at `medium`. */
  final case class Finding(use: Identifier, between: Call, medium: Boolean)

  /** The rule's findings; each is recorded, and the medium ones report above the rule's `low`. */
  def reentrantInvalidation(
    atom: Cpg,
    sites: List[Call],
    record: (StoredNode, String) => Unit
  ): List[Finding] =
    val found    = mutable.LinkedHashMap.empty[Long, Finding]
    val byMethod = sites.groupBy(_.method.id())
    atom.method.isExternal(false).filter(m => byMethod.contains(m.id())).foreach { m =>
      val calls = byMethod(m.id()).filterNot(inertDecrement(m, _))
      readsIn(m).filter(r => reachableContainer(m, r.container)).foreach { read =>
          usesOf(read).foreach { use =>
              calls.find(r => between(read, r, use) && !strongRefBefore(read, r)).foreach { r =>
                  if (read.kind == ReadKind.Borrowed || indexedAfter(m, read.container, r)) &&
                    !found.contains(use.id())
                  then
                    record(use, MemorySafetyFindingPass.RuleReentrantInvalidation)
                    found(use.id()) = Finding(use, r, !Decrements.contains(r.name))
              }
          }
      }
    }
    found.values.toList
  end reentrantInvalidation

  /** `x = <reader>(container, ...)`, for the borrowed-item and size readers. */
  private def readsIn(m: Method): List[Read] =
      m.ast.isCall.nameExact(Operators.assignment).l.flatMap { a =>
          for
            lhs <- a.argumentOption(1).collect { case i: Identifier => i }
            rhs <- a.argumentOption(2).collect { case c: Call => c }
            kind <-
                if BorrowedItemReaders.contains(rhs.name) then Some(ReadKind.Borrowed)
                else if SizeReaders.contains(rhs.name) then Some(ReadKind.Size)
                else None
            container <- rhs.argumentOption(1)
          yield Read(a, lhs, container, kind)
      }

  /** The uses the read's definition reaches. */
  private def usesOf(read: Read): List[Identifier] =
      read.target.method.ast.isIdentifier.nameExact(read.target.name)
          .filter(i => i.id() != read.target.id())
          .filter(i => OverlayFacts.reachingDefsIn(i, 1).exists(_.id() == read.target.id()))
          .l

  /** Does a CFG path run from the completed read through `r` to the use, without the read running
    * again in between (a loop that re-reads the item each iteration uses a fresh one)? The walk
    * starts after the assignment, so the reader call itself is never the call in between.
    */
  private def between(read: Read, r: Call, use: Identifier): Boolean =
    val reread = Set(read.assignment.id())
    GuardPass.cfgReachesAvoiding(read.assignment._cfgOut.collectAll[CfgNode].l, r.id(), reread) &&
    GuardPass.cfgReachesAvoiding(r._cfgOut.collectAll[CfgNode].l, use.id(), reread)

  /** A strong reference to the borrowed item taken after the read and before `r`. */
  private def strongRefBefore(read: Read, r: Call): Boolean =
      read.kind == ReadKind.Borrowed &&
          read.target.method.ast.isCall.filter(c => StrongReference.contains(c.name))
              .filter(_.argument.isIdentifier.nameExact(read.target.name).nonEmpty)
              .exists(inc =>
                  GuardPass.cfgReachesAvoiding(
                    read.assignment._cfgOut.collectAll[CfgNode].l,
                    inc.id(),
                    Set.empty
                  ) &&
                      GuardPass.cfgReachesAvoiding(
                        inc._cfgOut.collectAll[CfgNode].l,
                        r.id(),
                        Set.empty
                      )
              )

  /** The container is indexed again after `r`: the stale size then bounds a read of it. */
  private def indexedAfter(m: Method, container: Expression, r: Call): Boolean =
      OverlayFacts.variableKey(container).exists { key =>
          m.ast.isCall.filter(c => ItemAccessors.contains(c.name))
              .filter(_.argumentOption(1).flatMap(OverlayFacts.variableKey).contains(key))
              .exists(acc =>
                  GuardPass.cfgReachesAvoiding(r._cfgOut.collectAll[CfgNode].l, acc.id(), Set.empty)
              )
      }

  /** A container the callback can reach: a parameter, a field, or a local whose every definition
    * copies one of those. A local built in the method is out of the callback's reach.
    */
  private def reachableContainer(m: Method, container: Expression): Boolean = container match
    case c: Call => c.name == Operators.indirectFieldAccess || c.name == Operators.fieldAccess
    case i: Identifier =>
        m.parameter.nameExact(i.name).nonEmpty || {
            val defs = assignmentsTo(m, i.name)
            defs.nonEmpty && defs.forall {
                case f: Call =>
                    f.name == Operators.indirectFieldAccess || f.name == Operators.fieldAccess
                case p: Identifier => m.parameter.nameExact(p.name).nonEmpty
                case _             => false
            }
        }
    case _ => false

  /** A decrement of a local the method assigned from a str/int/float/bytes constructor. */
  private def inertDecrement(m: Method, r: Call): Boolean =
      Decrements.contains(r.name) && r.argumentOption(1).collect { case i: Identifier => i }.exists {
          target =>
            val defs = assignmentsTo(m, target.name)
            defs.nonEmpty && defs.forall {
                case c: Call => InertConstructorPrefixes.exists(c.name.startsWith)
                case _       => false
            }
      }

  /** The right sides of the assignments to a local in the method. */
  private def assignmentsTo(m: Method, name: String): List[Expression] =
      m.ast.isCall.nameExact(Operators.assignment).l.flatMap { a =>
          a.argumentOption(1).collect { case t: Identifier if t.name == name => t }
              .flatMap(_ => a.argumentOption(2).collect { case e: Expression => e })
      }
end ReentrantApiRules

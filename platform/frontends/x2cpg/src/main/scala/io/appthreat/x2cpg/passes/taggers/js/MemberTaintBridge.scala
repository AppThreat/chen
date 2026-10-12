package io.appthreat.x2cpg.passes.taggers.js

import io.shiftleft.codepropertygraph.generated.Operators
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

import scala.collection.mutable

import JsShapes.*
import JsTags.*

/** Carries a source across the methods of a class through the class's fields.
  *
  * Component code keeps what it read in a field and uses it later: `ngOnInit` stores `this.orderId
  * \= params.get('id')` and a click handler builds `window.open(...this.orderId...)`; a Vue
  * `created()` hook keeps `this.q = this.$route.query.q` for a method to render. The dataflow
  * engine follows a value through a field only within one method, so the read in the handler starts
  * a new, untainted value and the flow is lost.
  *
  * The bridge closes that gap from the field's side: a field that some method of the class assigns
  * from a source - checked along the reaching definitions inside that method - makes every read
  * `this.<field>` in the class's other methods a source of the same kind. Writes through a signal
  * or subject (`this.q.set(v)`, `this.q$.next(v)`) count as assignments.
  *
  * Runs after every recognizer, over the tags they emitted, and repeats until no new field is found
  * (a field computed from another tainted field).
  */
object MemberTaintBridge:

  private val SourceTags = Seq(INPUT, INGRESS)

  /** Methods of a signal/subject that store their argument. */
  private val StoringMethods = Set("set", "next")

  private val MaxRounds = 4

  /** Visits at most this many nodes per write when looking for a source. */
  private val MaxVisits = 400

  /** How far the search goes on after the first source, and how many more it names. */
  private val MaxVisitsAfterFound = 120
  private val MaxOtherSources     = 6

  def run(ctx: JsContext): Unit =
    val classWrites = memberWrites(ctx)
    val localWrites = localRefWrites(ctx)
    if classWrites.isEmpty && localWrites.isEmpty then return
    // an Angular component's template reads its members by bare name
    val templateOf =
        AngularRecognizer.componentTemplates(ctx).map((td, html) => td.id() -> html).toMap
    val done  = mutable.HashSet.empty[(String, String)]
    var round = 0
    var grew  = true
    while grew && round < MaxRounds do
      grew = false
      round += 1
      val withSources = ctx.methodsWithSources
      classWrites.foreach { case (td, member, value) =>
          if !done.contains((td.fullName, member)) && withSources.contains(value.method.id()) then
            sourceOf(ctx, value).foreach { found =>
              done += ((td.fullName, member))
              grew = true
              val reads = classMethods(td).iterator
                  .flatMap(_.ast.isCall)
                  .nameExact(Operators.fieldAccess)
                  .codeExact(s"this.$member")
                  .filterNot(isAssignmentTarget)
                  .filterNot(isStoreReceiver)
              ctx.tagger.tagVia(readChains(reads), found.tag, found.places(value)*)
              templateOf.get(td.id()).foreach(html =>
                  ctx.tagger.tagVia(
                    AngularRecognizer.templateReads(ctx, html, member),
                    found.tag,
                    found.places(value)*
                  )
              )
            }
      }
      localWrites.foreach { case (declMethod, local, member, value) =>
          val key = (declMethod.fullName + "|" + local, member)
          if !done.contains(key) then
            sourceOf(ctx, value).foreach { found =>
              done += key
              grew = true
              val reads = JsIndexes
                  .methodsUnder(ctx.cpg.graph, declMethod.fullName + ":")
                  .iterator
                  .flatMap(_.ast.isCall.nameExact(Operators.fieldAccess))
                  .filter(c =>
                      fieldName(c).contains(member) && fieldBase(c).exists {
                          case id: Identifier => id.name == local
                          case _              => false
                      } && !isAssignmentTarget(c)
                  )
              ctx.tagger.tagVia(readChains(reads), found.tag, found.places(value)*)
            }
      }
    end while
  end run

  /** Writes through a CAPTURED LOCAL that holds a reactive container - `term.value = v` on a ref,
    * `q.set(v)` / `q.next(v)` on a signal or subject - in a method that closes over the local. Like
    * a class field, the container's value crosses methods only through this bridge. The owner is
    * the innermost method that binds the local (assigns it, takes it as a parameter, or the module
    * top level); the reads tagged are `<local>.<member>` in it and the methods nested under it.
    */
  private def localRefWrites(ctx: JsContext): List[(Method, String, String, Expression)] =
    def declaringMethod(name: String, m: Method): Method =
      def binds(mid: Method): Boolean =
          mid.parameter.nameExact(name).nonEmpty || JsIndexes.assignedValues(mid, name).nonEmpty
      val segments = m.fullName.split(':')
      // innermost binding first, so a shadowing declaration wins; the write's method included
      (segments.length to 1 by -1).iterator
          .map(n => JsIndexes.methodByFullName(m.graph, segments.take(n).mkString(":")))
          .collectFirst { case Some(mid) if binds(mid) => mid }
          .getOrElse(m)
    val assignments = ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          // x.value = v, x.<member> = v on a local of an enclosing scope
          case (Some(fa: Call), Some(v)) if fa.name == Operators.fieldAccess =>
              (fieldBase(fa), fieldName(fa)) match
                case (Some(id: Identifier), Some(field))
                    if id.name != "this" && !id.name.startsWith("_tmp_") =>
                    Some((declaringMethod(id.name, a.method), id.name, field, v))
                case _ => None
          case _ => None
    }
    val stores = ctx.cpg.call.filter(c => StoringMethods.contains(c.name)).l.flatMap { c =>
        receiverOf(c) match
          case Some(id: Identifier)
              if id.name != "this" && !id.name.startsWith("_tmp_") =>
              c.argument.filter(_.argumentIndex == 1).headOption.map(v =>
                  (declaringMethod(id.name, c.method), id.name, "value", v)
              )
          case _ => None
    }
    assignments ++ stores
  end localRefWrites

  /** (class, field, value written) for every field write in a class. */
  private[js] def memberWrites(ctx: JsContext): List[(TypeDecl, String, Expression)] =
    val assignments = ctx.cpg.call.nameExact(Operators.assignment).l.flatMap { a =>
        (a.argumentOption(1), a.argumentOption(2)) match
          // this.x = v
          case (Some(fa: Call), Some(v)) if fa.name == Operators.fieldAccess =>
              (fieldBase(fa), fieldName(fa)) match
                case (Some(b: Identifier), Some(field)) if b.name == "this" =>
                    enclosingTypeDecl(a.method).map(td => (td, field, v))
                case _ => None
          // `x = v` in a constructor: a field initialiser, lowered with the member's code
          case (Some(id: Identifier), Some(v)) if a.method.name == "<init>" =>
              a.method.typeDecl.flatMap(td =>
                  td.member.nameExact(id.name).codeExact(a.code).headOption.map(_ =>
                      (td, id.name, v)
                  )
              )
          case _ => None
    }
    val stores = ctx.cpg.call.filter(c => StoringMethods.contains(c.name)).l.flatMap { c =>
        receiverOf(c) match
          case Some(fa: Call) if fa.name == Operators.fieldAccess && fa.code.startsWith("this.") =>
              (fieldName(fa), c.argument.filter(_.argumentIndex == 1).headOption) match
                case (Some(field), Some(v)) =>
                    enclosingTypeDecl(c.method).map(td => (td, field, v))
                case _ => None
          case _ => None
    }
    assignments ++ stores
  end memberWrites

  /** `this.q` in `this.q.set(v)`: written through, not read. */
  private def isStoreReceiver(fa: Call): Boolean =
      fa.astParent match
        case a: Call if a.name == Operators.assignment =>
            // lowered through a temporary: `(_tmp = this.q).set(v)`
            a.astParent match
              case callee: Call if callee.name == Operators.fieldAccess =>
                  fieldName(callee).exists(StoringMethods.contains)
              case _ => false
        case callee: Call if callee.name == Operators.fieldAccess =>
            fieldName(callee).exists(StoringMethods.contains)
        case _ => false

  /** The source tag that reaches `value` inside its method, if any: a tagged node in the value
    * itself, or in what the variables it reads were last assigned.
    *
    * A variable is followed only to its assignments - and then into what they assign - and to
    * parameters, never into other calls that merely took it as an argument: the reaching
    * definitions count a call's identifier arguments as possibly redefined, and following those
    * wanders off into whatever else that call touched. An import binding (`require(...)`) carries
    * nothing.
    */
  private[js] def sourceTagOf(ctx: JsContext, value: Expression): Option[String] =
      sourceTagThrough(ctx, value)._1

  /** A source found behind a value: its kind, and the node that carries it. */
  /** A source found behind a value: its kind, the node that carries it, and the call-site arguments
    * the value crossed on the way (`setTerm(route.query.term)`).
    */
  final case class Found(
    tag: String,
    at: StoredNode,
    hops: List[StoredNode] = Nil,
    others: List[StoredNode] = Nil
  ):
    /** Where the value came from, for provenance: the source, the crossings, the other sources an
      * object built from several carries (`{ props: { id, notice } }`), and `value`.
      */
    def places(value: StoredNode): Seq[StoredNode] = ((at :: hops) ++ others) :+ value

  /** [[sourceTagOf]], with the node the source was found at, for provenance. */
  private[js] def sourceOf(ctx: JsContext, value: Expression): Option[Found] =
    val (tag, _, at, hops, others) = search(ctx, value)
    tag.zip(at).map((t, a) => Found(t, a, hops, others))

  /** [[sourceTagOf]], and whether the source was found behind a reactive derivation - a wrapper
    * holding what its callback returns (`useActionState(fn)`, `computed(() => ...)`), which no
    * dataflow edge connects to its result.
    */
  private[js] def sourceTagThrough(ctx: JsContext, value: Expression): (Option[String], Boolean) =
    val (tag, derived, _, _, _) = search(ctx, value)
    (tag, derived)

  private def search(
    ctx: JsContext,
    value: Expression
  ): (Option[String], Boolean, Option[StoredNode], List[StoredNode], List[StoredNode]) =
    var derived                = false
    var at: Option[StoredNode] = None
    // how each node was reached, and the call-site arguments a parameter was followed to: the
    // places the value crossed into a callee, for provenance
    val prev    = mutable.HashMap.empty[Long, AstNode]
    val crossed = mutable.HashSet.empty[Long]
    def tagOf(n: StoredNode): Option[String] =
        SourceTags.find(t => ctx.tagger.has(n.id(), t)).orElse(
          n.tag.name.find(SourceTags.contains)
        )
    def isImport(e: AstNode): Boolean = e match
      case c: Call => c.code.startsWith("require(")
      case _       => false
    val seen  = mutable.HashSet.empty[Long]
    val queue = mutable.Queue.empty[AstNode]
    queue.enqueue(value)
    var current: AstNode = value
    def push(n: AstNode): Unit =
      if !prev.contains(n.id()) && n.id() != value.id() then prev.update(n.id(), current)
      queue.enqueue(n)
    var found: Option[String] = None
    // after the first source, the search goes on a little to name the others an object carries
    val others = mutable.ListBuffer.empty[StoredNode]
    while queue.nonEmpty && seen.size < MaxVisits && others.size < MaxOtherSources &&
      (found.isEmpty || seen.size < MaxVisitsAfterFound)
    do
      val node = queue.dequeue()
      current = node
      if seen.add(node.id()) && !isImport(node) then
        val here = tagOf(node)
        if here.isDefined && found.isDefined then others += node
        else if here.isDefined then
          found = here
          at = Some(node)
          // a tag on a derivation call is the derivation's own doing (ReactiveBridge tags the
          // wrapper): the value behind this one is still a derivation's result
          node match
            case c: Call if ReactiveBridge.isDerivationCall(c) => derived = true
            case _                                             =>
        if here.isEmpty && !JsTags.neutralises(ctx.tagger, node) then
          node match
            // a definition reached through another read's definitions: what it was assigned
            case id: Identifier if isAssignmentTarget(id) =>
                id.astParent match
                  case a: Call => a.argumentOption(2).foreach(push(_))
                  case _       =>
            case id: Identifier =>
                id._reachingDefIn.foreach {
                    case p: MethodParameterIn => push(p)
                    case a: Call
                        if a.name.startsWith("<operator>.assignment") &&
                            a.argumentOption(1).exists(_.code == id.name) =>
                        a.argumentOption(2).foreach(push(_))
                    // `x` assigned as `x = v` is the definition node `x` itself in some lowerings
                    case d: Identifier if d.name == id.name =>
                        d.astParent match
                          case a: Call if a.name.startsWith("<operator>.assignment") =>
                              a.argumentOption(2).foreach(push(_))
                          // a same-named identifier whose reaching definitions are the def chain
                          case _ =>
                              d._reachingDefIn.collect { case n: AstNode => n }.foreach(
                                push(_)
                              )
                    case _ =>
                }
            case p: MethodParameterIn =>
                // a parameter of a resolved callee is as tainted as the argument a caller passes:
                // `store.setTerm(route.query.term)` makes setTerm's `value` carry what the caller
                // had. The CALL edges this run added are not in the graph yet - the tagger's own
                // record of them is.
                (p.method._callIn.l.collect {
                    case c: io.shiftleft.codepropertygraph.generated.nodes.Call => c
                } ++ ctx.tagger.callSitesOf(p.method)).foreach { call =>
                    call.argument.collectFirst { case a if a.argumentIndex == p.index => a }
                        .foreach { arg =>
                          crossed += arg.id()
                          push(arg)
                        }
                }
            case c: Call if c.name.startsWith("<operator>.assignment") =>
                c.argumentOption(2).foreach(push(_))
            // a derivation holds what its callback returns
            case c: Call if ReactiveBridge.isDerivationCall(c) =>
                ReactiveBridge.derivationCallback(c).foreach { cb =>
                  // only on the way to the first source: what `derived` reports
                  if found.isEmpty then derived = true
                  cb.ast.isReturn.astChildren.foreach {
                      case e: Expression if e.method.id() == cb.id() => push(e)
                      case _                                         =>
                  }
                }
            case c: Call  => c.astChildren.foreach(push(_))
            case b: Block => b.astChildren.foreach(push(_))
            case _        =>
        end if
      end if
    end while
    val hops = at.toList.flatMap { a =>
        Iterator.iterate(prev.get(a.id()))(_.flatMap(n => prev.get(n.id()))).takeWhile(_.nonEmpty)
            .flatten.filter(n => crossed.contains(n.id())).toList
    }
    (found, derived && found.nonEmpty, at, hops, others.toList)
  end search
end MemberTaintBridge

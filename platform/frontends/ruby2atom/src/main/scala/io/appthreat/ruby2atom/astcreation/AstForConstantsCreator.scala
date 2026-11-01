package io.appthreat.ruby2atom.astcreation

import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.*
import io.appthreat.ruby2atom.passes.Defines
import io.appthreat.x2cpg.{Ast, ValidationMode}
import io.shiftleft.codepropertygraph.generated.nodes.NewTypeRef

import scala.collection.mutable

/** Constant references that resolve outside the project.
  *
  * Ruby looks a constant up in the lexical scopes (innermost first, each class or module on its
  * own), then in the ancestors of the innermost one, then in `Object`. The frontend knows the
  * constants the project defines (see [[io.appthreat.ruby2atom.datastructures.RubyProgramSummary]])
  * but not what gems define, so it decides one thing: whether a reference reaches a project
  * constant. A reference that does not is a use of a dependency (a gem or Ruby itself), and gets a
  * `TYPE_REF` at the start of the written constant:
  *
  *   - `typeFullName` is the written path with `.` as separator (`Faraday.Utils` for
  *     `Faraday::Utils`), without the leading `::` of an absolute path.
  *   - `dynamicTypeHintFullName` lists the other names Ruby would try first when the reference sits
  *     inside classes or modules, innermost first (`Outer.Faraday.Utils` inside `module Outer`). A
  *     consumer that knows what the gems define can pick the one that exists. Absolute paths
  *     (`::Faraday`) have none.
  *
  * References to project constants keep their earlier lowering: `ImplicitRequirePass` reads the
  * `self.Name` field accesses to make autoloaded files visible, and call resolution reads the
  * receiver's shape.
  */
trait AstForConstantsCreator(implicit withSchemaValidation: ValidationMode):
  this: AstCreator =>

  /** The dotted paths of the classes and modules around the code being lowered, innermost first.
    */
  protected var lexicalCrefs: List[String] = Nil

  /** The mixins found so far in the class or module bodies being lowered, innermost last: whether
    * each is a singleton one (`extend`) and the dotted name of the module.
    */
  private var mixinFrames: List[mutable.ArrayBuffer[(Boolean, String)]] = Nil

  /** Runs `body`, a class or module body, and returns what it mixes in besides its result. */
  protected def collectingMixins[T](body: => T): (T, List[(Boolean, String)]) =
    val frame      = mutable.ArrayBuffer.empty[(Boolean, String)]
    val savedInDef = insideDef
    mixinFrames = frame :: mixinFrames
    insideDef = false
    try (body, frame.toList)
    finally
      mixinFrames = mixinFrames.tail
      insideDef = savedInDef

  /** Whether the code being lowered is inside a `def`: there, `include` is not a mixin of the
    * class.
    */
  private var insideDef = false

  /** Records `include X`, `prepend X` and `extend X` written directly in a class or module body as
    * ancestors of the class (or of its singleton class, for `extend`). Called for receiver-less
    * calls; a call inside a method is not a mixin of the enclosing class.
    */
  protected def noteMixin(call: SimpleCall): Unit =
    val name = call.target.text
    if (name == "include" || name == "prepend" || name == "extend") && !insideDef then
      mixinFrames.headOption.foreach { frame =>
          call.arguments.foreach { argument =>
              constantPath(argument).foreach { case (_, segments) =>
                  frame += (name == "extend") -> segments.mkString(".")
              }
          }
      }

  protected case class ExternalConstant(fullName: String, candidates: List[String])

  /** Matches an expression that is a constant reference reaching outside the project. */
  protected object ExternalConstantRef:
    def unapply(node: RubyExpression): Option[ExternalConstant] = externalConstant(node)

  /** Runs `body` with `declared` (a class or module path as written in the declaration) pushed as
    * the innermost lexical scope.
    */
  protected def withLexicalCref[T](declared: String, absolute: Boolean)(body: => T): T =
    val saved = lexicalCrefs
    val full = lexicalCrefs.headOption match
      case Some(outer) if !absolute => s"$outer.$declared"
      case _                        => declared
    lexicalCrefs = full :: lexicalCrefs
    try body
    finally lexicalCrefs = saved

  /** `(absolute, segments)` for an expression made only of constants: `Foo`, `Foo::Bar`, `::Foo`.
    */
  protected def constantPath(node: RubyExpression): Option[(Boolean, List[String])] = node match
    case MemberAccess(_: SelfIdentifier, "::", name) if isConstantName(name) =>
        // `::Foo` is lowered by the parser as a scope access on an implicit `self`
        Option.when(node.span.text.startsWith("::"))((true, List(name)))
    case MemberAccess(target, "::", name) if isConstantName(name) =>
        constantPath(target).map { case (absolute, segments) => (absolute, segments :+ name) }
    case x: SimpleIdentifier if isConstantName(x.text) && !x.text.contains("::") =>
        Option((false, List(x.text)))
    case _ => None

  private def isConstantName(name: String): Boolean = name.headOption.exists(_.isUpper)

  private def known(constant: String): Boolean = programSummary.definedConstants.contains(constant)

  /** Whether a project ancestor of `owner` (a class or module path) defines `name`. */
  private def ancestorDefines(owner: String, name: String, seen: Set[String] = Set.empty): Boolean =
      if seen.contains(owner) then false
      else
        val outer =
            owner.split('.').toList.inits.toList.drop(1).filter(_.nonEmpty).map(_.mkString("."))
        programSummary.ancestors.getOrElse(owner, Nil).exists { written =>
          val resolved = (outer.map(o => s"$o.$written") :+ written).find(known)
          resolved.exists(a => known(s"$a.$name") || ancestorDefines(a, name, seen + owner))
        }

  private def externalConstant(node: RubyExpression): Option[ExternalConstant] =
      node match
        case _: MemberAccess | _: SimpleIdentifier =>
            constantPath(node).flatMap { case (absolute, segments) =>
                val first   = segments.head
                val written = segments.mkString(".")
                val variable =
                    segments.size == 1 && (scope.lookupVariable(first).isDefined ||
                        isBundledClass(first))
                val lexical =
                    if absolute then None
                    else lexicalCrefs.view.map(c => s"$c.$first").find(known)
                val viaAncestors =
                    !absolute && lexical.isEmpty && lexicalCrefs.headOption.exists(
                      ancestorDefines(_, first)
                    )
                val project = lexical.isDefined || viaAncestors || known(first)
                if variable || project then None
                else
                  val candidates =
                      if absolute then Nil else lexicalCrefs.map(c => s"$c.$written")
                  Some(ExternalConstant(written, candidates))
            }
        case _ => None

  /** The references to dependency constants in a `rescue` list: `rescue A::Error, ::B => e`. */
  protected def externalConstantsIn(exceptionList: RubyExpression): List[Ast] =
      exceptionList match
        case ArrayLiteral(elements, _) => elements.flatMap(externalConstantsIn)
        case StatementList(statements) => statements.flatMap(externalConstantsIn)
        case ExternalConstantRef(constant) =>
            astForExternalConstant(exceptionList, constant) :: Nil
        // a bundled core class (`StandardError`) has its own reference node
        case x: SimpleIdentifier
            if isBundledClass(x.text) && scope.lookupVariable(x.text).isEmpty =>
            astForExpression(x) :: Nil
        case _ => Nil

  /** Locals of the `def` being lowered that hold an instance of a dependency class, as `x =
    * Foo::Bar.new(...)` binds them exactly once, mapped to the class. A local is listed from the
    * moment its assignment has been lowered, so uses written before it are not typed.
    */
  private var typedLocals: Map[String, ExternalConstant] = Map.empty

  /** The names `decl` binds exactly once, by `name = Const.new`, and nowhere else (no parameter,
    * block parameter, multiple assignment, operator assignment, `rescue => name`, `for` variable or
    * pattern variable of the same name, in the `def` or in its blocks; nested `def`s and classes
    * have their own locals).
    */
  private var singleNewBindings: Map[String, ExternalConstant] = Map.empty

  protected def withTypedLocals[T](decl: ProcedureDeclaration)(body: => T): T =
    val saved = (typedLocals, singleNewBindings, insideDef)
    typedLocals = Map.empty
    // a class body is lowered as a method too, but it is not a `def`
    val isDef = decl.methodName != Defines.TypeDeclBody
    singleNewBindings = if isDef then singleNewBindingsOf(decl) else Map.empty
    insideDef = isDef
    try body
    finally
      typedLocals = saved._1
      singleNewBindings = saved._2
      insideDef = saved._3

  /** To be called once `node` has been lowered. */
  protected def noteLocalAssignment(node: SingleAssignment): Unit = node match
    case SingleAssignment(lhs: SimpleIdentifier, "=", _) =>
        singleNewBindings.get(lhs.text).foreach(c => typedLocals += lhs.text -> c)
    case _ =>

  /** The dependency class of a local used as the receiver of a call, if it is typed. */
  protected def typedLocalOf(target: RubyExpression): Option[ExternalConstant] = target match
    case x: SimpleIdentifier => typedLocals.get(x.text)
    case _                   => None

  /** `get`, `get?`, `reset!`: operators and setters are not attributed to the receiver's class. */
  protected def isPlainMethodName(name: String): Boolean =
      name.headOption.exists(c => c.isLower || c == '_') &&
          name.dropRight(1).forall(c => c.isLetterOrDigit || c == '_') &&
          (name.last.isLetterOrDigit || name.last == '_' || name.last == '?' || name.last == '!')

  private def instantiatedConstant(rhs: RubyExpression): Option[ExternalConstant] = rhs match
    case SimpleObjectInstantiation(ExternalConstantRef(c), _)       => Some(c)
    case ObjectInstantiationWithBlock(ExternalConstantRef(c), _, _) => Some(c)
    case _                                                          => None

  private def singleNewBindingsOf(decl: ProcedureDeclaration): Map[String, ExternalConstant] =
    val counts     = mutable.Map.empty[String, Int].withDefaultValue(0)
    val candidates = mutable.Map.empty[String, ExternalConstant]

    def bind(name: String): Unit = counts(name) += 1

    def bindAll(node: Any): Unit = node match
      case x: SimpleIdentifier => bind(x.text)
      case p: MethodParameter  => bind(p.name)
      case x: MatchVariable    => bind(x.span.text)
      case p: Product          => p.productIterator.foreach(bindAll)
      case it: Iterable[?]     => it.foreach(bindAll)
      case _                   =>

    def walk(node: Any): Unit = node match
      case _: TypeDeclaration | _: ProcedureDeclaration => // their own locals
      case assignment @ SingleAssignment(lhs: SimpleIdentifier, op, rhs) =>
          bind(lhs.text)
          if op == "=" then instantiatedConstant(rhs).foreach(candidates(lhs.text) = _)
          walk(rhs)
      case multiple: MultipleAssignment => bindAll(multiple.assignments.map(_.lhs))
      case OperatorAssignment(lhs, _, rhs) =>
          bindAll(lhs)
          walk(rhs)
      case p: MethodParameter =>
          bind(p.name)
          p match
            case OptionalParameter(_, default) => walk(default)
            case _                             =>
      case RescueClause(classes, variables, body) =>
          classes.foreach(walk)
          variables.foreach(bindAll)
          walk(body)
      case ForExpression(variable, iterable, body) =>
          bindAll(variable)
          walk(iterable)
          walk(body)
      case x: MatchVariable => bind(x.span.text)
      case MatchAs(value, as) =>
          walk(value)
          bindAll(as)
      case p: Product      => p.productIterator.foreach(walk)
      case it: Iterable[?] => it.foreach(walk)
      case _               =>

    decl.parameters.foreach(walk)
    walk(decl.body)
    candidates.view.filterKeys(counts(_) == 1).toMap
  end singleNewBindingsOf

  protected def astForExternalConstant(node: RubyExpression, constant: ExternalConstant): Ast =
    val typeRef: NewTypeRef =
        typeRefNode(node, code(node), constant.fullName).dynamicTypeHintFullName(
          constant.candidates
        )
    Ast(typeRef)
end AstForConstantsCreator

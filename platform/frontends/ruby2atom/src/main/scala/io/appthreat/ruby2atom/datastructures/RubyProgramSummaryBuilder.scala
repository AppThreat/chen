package io.appthreat.ruby2atom.datastructures

import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.*
import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst
import io.appthreat.ruby2atom.parser.RubyJsonHelpers
import io.appthreat.ruby2atom.passes.Defines

import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/** Builds a [[RubyProgramSummary]] from the parsed ASTs of all files in one pass before AST
  * creation (the "two-phase parse"): a class/module/def inventory per file plus
  * `Data.define`/`Struct.new` assignments. During AST creation, `require` calls consult
  * `pathToType` (keyed by the require-style relative path, e.g. `models/user`) and pull the
  * required types into scope.
  */
object RubyProgramSummaryBuilder:

  /** @param programs
    *   the parsed files as (require-style relative path without .rb extension, parsed program).
    */
  def build(programs: List[(String, StatementList)]): RubyProgramSummary =
    val namespaceToType: NamespaceToTypeMap = mutable.Map.empty
    val pathToType: NamespaceToTypeMap      = mutable.Map.empty
    val constants                           = mutable.Set.empty[String]
    val solid                               = mutable.Set.empty[String]
    val ancestors                           = mutable.Map.empty[String, List[String]]
    val autoloaded                          = mutable.Set.empty[String]
    val autoloadedFiles                     = mutable.Set.empty[String]

    programs.foreach { case (relativePath, program) =>
        // Require calls look paths up without the .rb extension (see RubyScope.addRequire).
        val requirePath = relativePath.stripSuffix(".rb").replace('\\', '/')
        collectConstants(program, constants, solid, ancestors)
        autoloadConstants(requirePath).foreach { implied =>
          // the file defines the constant its path spells, and Zeitwerk makes a module of each
          // directory above it, which only nests
          val key = RubyProgramSummary.inflectionKey(implied)
          addWithPrefixes(autoloaded, key)
          autoloadedFiles += key
        }
        collectTypes(program).foreach { ty =>
          pathToType.updateWith(requirePath) {
              case Some(existing) => existing += ty; Some(existing)
              case None           => Some(mutable.Set(ty))
          }
          val namespace = ty.name.split('.').dropRight(1).mkString(".")
          namespaceToType.updateWith(namespace) {
              case Some(existing) => existing += ty; Some(existing)
              case None           => Some(mutable.Set(ty))
          }
        }
    }

    RubyProgramSummary(
      namespaceToType,
      pathToType,
      constants,
      ancestors,
      solid,
      autoloaded,
      autoloadedFiles
    )
  end build

  private def addWithPrefixes(into: mutable.Set[String], dotted: String): Unit =
    val parts = dotted.split('.')
    (1 to parts.length).foreach(i => into += parts.take(i).mkString("."))

  private def camelize(segment: String): String =
      segment.split('_').map(p => if p.isEmpty then p else p.head.toUpper +: p.tail).mkString

  /** The constant path Rails autoloading (Zeitwerk) implies for a file, from its location: `app/`
    * and `lib/` roots, with `concerns` directories and the first directory under `app/` (`models`,
    * `controllers`, ...) not part of the name. Files elsewhere imply nothing.
    */
  private[datastructures] def autoloadConstants(requirePath: String): Option[String] =
    val parts = requirePath.split('/').toList
    val rest = parts match
      case "app" :: tail if tail.size > 1 =>
          val afterRoot = tail.drop(1)
          if afterRoot.headOption.contains("concerns") && afterRoot.size > 1 then afterRoot.drop(1)
          else afterRoot
      case "lib" :: tail if tail.nonEmpty => tail
      case _                              => Nil
    Option.when(rest.nonEmpty)(rest.map(camelize).mkString("."))

  /** Constant assignments (`FOO = ...`, `Foo = Struct.new`) and the ancestors each class or module
    * declares, with the lexical nesting the declaration sits in.
    */
  private def collectConstants(
    program: StatementList,
    constants: mutable.Set[String],
    solid: mutable.Set[String],
    ancestors: mutable.Map[String, List[String]]
  ): Unit =
    def dotted(name: RubyExpression): String = name match
      case memberAccess: MemberAccess => RubyJsonHelpers.getParts(memberAccess).mkString(".")
      case other                      => other.text.split("::").mkString(".")

    def isConstantName(name: String): Boolean = name.headOption.exists(_.isUpper)

    def isConstantTarget(text: String): Boolean =
        text.stripPrefix("::").split("::").forall(isConstantName) && !text.exists(c =>
            c == '.' || c == '@' || c == '[' || c == ' '
        )

    def go(prefix: String, expr: RubyExpression): Unit = expr match
      case stmtList: StatementList => stmtList.statements.foreach(go(prefix, _))
      case decl: TypeDeclaration   =>
          // `class Api::BaseController` names its namespace beside the class name
          val namespace = decl match
            case x: NamespaceDeclaration => x.namespaceParts.getOrElse(Nil)
            case _                       => Nil
          val writtenName = (namespace :+ dotted(decl.name)).mkString(".")
          val name        = (if prefix.isEmpty then "" else s"$prefix.") + writtenName
          addWithPrefixes(constants, name)
          // A declaration nested in a module is also known by the name it is written with: a
          // bare reference from outside the module may still reach it (an `include` of the module,
          // `const_missing`), so it is not claimed for a dependency.
          addWithPrefixes(constants, writtenName)
          // the parser puts a class body's statements in a `<body>` method beside its declarations
          def flattened(stmts: List[RubyExpression]): List[RubyExpression] = stmts.flatMap {
              case m: MethodDeclaration if m.methodName == Defines.TypeDeclBody =>
                  m.body match
                    case inner: StatementList => flattened(inner.statements)
                    case other                => List(other)
              case other => List(other)
          }
          val body = flattened(decl.body match
            case stmtList: StatementList => stmtList.statements
            case other                   => List(other)
          )
          def written(e: RubyExpression): String = e.text.stripPrefix("::").replace("::", ".")
          val mixedIn = body.flatMap {
              case IncludeCall(_, argument) => List(written(argument))
              case SimpleCall(target, arguments)
                  if target.text == "prepend" || target.text == "include" =>
                  arguments.map(written)
              case _ => Nil
          }
          val ancestorNames = decl.baseClass.map(written).toList ++ mixedIn
          if ancestorNames.nonEmpty then
            ancestors.updateWith(name)(old => Some(old.getOrElse(Nil) ++ ancestorNames))
          // a class can be instantiated and a module with more than nested declarations has
          // content: both are the project's. A module that only nests others may be a gem's.
          val onlyNests = decl match
            case _: ClassDeclaration => false
            case _ =>
                body.forall {
                    case _: TypeDeclaration => true
                    case SimpleCall(target, _)
                        if target.text == "autoload" || target.text == "private_constant" =>
                        true
                    case _ => false
                }
          if !onlyNests then
            solid += name
            solid += writtenName
          body.foreach(go(name, _))
      case SingleAssignment(lhs, _, _) if isConstantTarget(lhs.text) =>
          // a constant is assigned through a plain name, a field of the class body or a path
          val name = lhs.text.stripPrefix("::").replace("::", ".")
          addWithPrefixes(constants, (if prefix.isEmpty then "" else s"$prefix.") + name)
          constants += name
          solid += (if prefix.isEmpty then "" else s"$prefix.") + name
          solid += name
      case _ =>

    program.statements.foreach(go("", _))
  end collectConstants

  /** Collects the types declared anywhere in the file, with dotted full names (e.g. `Models.User`)
    * so that `ProgramSummary.matchingTypes` can resolve partially qualified references.
    */
  private def collectTypes(program: StatementList): List[RubyType] =
    val types = ListBuffer.empty[RubyType]

    def qualifiedName(name: RubyExpression): String = name match
      case memberAccess: MemberAccess => RubyJsonHelpers.getParts(memberAccess).mkString(".")
      case other                      => other.text.split("::").mkString(".")

    def visitType(prefix: List[String], decl: TypeDeclaration): Unit =
      val typeName = (prefix :+ qualifiedName(decl.name)).mkString(".")
      val bodyStmts = decl.body match
        case stmtList: StatementList => stmtList.statements
        case expr                    => List(expr)
      // Sorbet types when the method carries a sig (ruby_ast_gen marks the attachment, the JSON
      // creator resolves the block), the untyped defaults otherwise.
      def summaryMethod(name: String, sig: Option[Sig]): RubyMethod =
          RubyMethod(
            name,
            sig.fold(List.empty[(String, String)])(_.parameterTypes),
            sig.fold(Defines.Any)(_.returnType),
            Option(typeName)
          )

      val methods = bodyStmts.collect {
          case m: MethodDeclaration          => summaryMethod(m.methodName, m.sig)
          case m: SingletonMethodDeclaration => summaryMethod(m.methodName, m.sig)
      }
      val fields = bodyStmts.flatMap {
          case SingleAssignment(lhs: RubyFieldIdentifier, _, _) =>
              RubyField(lhs.span.text, Defines.Any) :: Nil
          case fieldsDecl: FieldsDeclaration if fieldsDecl.hasGetter || fieldsDecl.hasSetter =>
              fieldsDecl.fieldNames.collect {
                  case sym: StaticLiteral if sym.isSymbol => RubyField(sym.innerText, Defines.Any)
              }
          case _ => Nil
      }
      types.addOne(RubyType(typeName, methods.toList, fields.toList))
      // Nested type declarations carry their own entries with the qualified name.
      bodyStmts.foreach {
          case nested: TypeDeclaration => visitType(typeName.split('.').toList, nested)
          case _                       =>
      }
    end visitType

    def go(expr: RubyExpression): Unit =
        expr match
          case stmtList: StatementList => stmtList.statements.foreach(go)
          case decl: TypeDeclaration   => visitType(Nil, decl)
          case SingleAssignment(lhs: SimpleIdentifier, "=", rhs) =>
              dataOrStructClass(lhs, rhs).foreach(types.addOne)
          case _ =>

    program.statements.foreach(go)
    types.toList
  end collectTypes

  /** `Point = Data.define(:x, :y)` / `Point = Struct.new(:x)` introduce a class with members. */
  private def dataOrStructClass(lhs: SimpleIdentifier, rhs: RubyExpression): Option[RubyType] =
      rhs match
        case MemberCall(base, _, "define" | "new", arguments)
            if base.text == "Data" || base.text == "Struct" =>
            val fields = arguments.collect {
                case sym: StaticLiteral if sym.isSymbol =>
                    RubyField(sym.innerText, Defines.Any)
            }
            Some(RubyType(lhs.span.text, List.empty, fields.toList))
        case _ => None
end RubyProgramSummaryBuilder

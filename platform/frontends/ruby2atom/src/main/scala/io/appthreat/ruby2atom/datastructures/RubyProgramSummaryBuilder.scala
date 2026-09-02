package io.appthreat.ruby2atom.datastructures

import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst.*
import io.appthreat.ruby2atom.astcreation.RubyIntermediateAst
import io.appthreat.ruby2atom.parser.RubyJsonHelpers
import io.appthreat.ruby2atom.passes.Defines

import scala.collection.mutable
import scala.collection.mutable.ListBuffer

/** Builds a [[RubyProgramSummary]] from the parsed ASTs of all files in one pass before AST
  * creation (plan 04 §6, the "two-phase parse"): a class/module/def inventory per file plus
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

    programs.foreach { case (relativePath, program) =>
        // Require calls look paths up without the .rb extension (see RubyScope.addRequire).
        val requirePath = relativePath.stripSuffix(".rb").replace('\\', '/')
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

    RubyProgramSummary(namespaceToType, pathToType)
  end build

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
      val methods = bodyStmts.collect {
          case m: MethodDeclaration =>
              RubyMethod(m.methodName, List.empty, Defines.Any, Option(typeName))
          case m: SingletonMethodDeclaration =>
              RubyMethod(m.methodName, List.empty, Defines.Any, Option(typeName))
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

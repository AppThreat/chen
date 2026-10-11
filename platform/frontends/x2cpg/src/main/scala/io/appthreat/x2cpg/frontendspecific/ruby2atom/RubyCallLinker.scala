package io.appthreat.x2cpg.frontendspecific.ruby2atom

import io.appthreat.x2cpg.Defines as XDefines
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.{AstNode, Call, Method, TypeDecl}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Names the callee of a Ruby call to a method of the project, which ruby2atom leaves
  * `<unknownFullName>`: without it no call reaches a body, and data flow stops at every call
  * between a controller and its models. A call is named when exactly one method of the project
  * fits:
  *   - the method the frontend found in scope (`POSSIBLE_TYPES`);
  *   - for a constant receiver (`Benefits.save(file)`, `Admin::User.find_by_token(t)`), the method
  *     of that name declared by the class or module of that name;
  *   - for an implicit `self` (`helper(x)`), the method of that name declared by the class, module
  *     or file the call is in, innermost first.
  *
  * The call keeps its dynamic dispatch: the call graph links it, and its overrides, by this name.
  */
class RubyCallLinker(cpg: Cpg) extends CpgPass(cpg):

  // `(<tmp-0> = Benefits).save(...)` and `Benefits.save(...)`
  private val ConstantReceiver =
      """^(?:\(<tmp-\d+> = )?(?:::)?([A-Z][\w]*(?:::[A-Z][\w]*)*)\)?\.""".r

  override def run(builder: DiffGraphBuilder): Unit =
    val internal = cpg.method.isExternal(false).l
    val byScopeAndName: Map[(String, String), List[Method]] =
        internal.groupBy(m => (m.astParentFullName, m.name))
    val fullNames = internal.map(_.fullName).toSet
    // a method's or type's enclosing scope, until AstLinkerPass links them
    val parentOf: Map[String, String] =
        (internal.map(m => m.fullName -> m.astParentFullName) ++
            cpg.typeDecl.isExternal(false).l.map(t => t.fullName -> t.astParentFullName))
            .filter((child, parent) => parent.nonEmpty && parent != "<empty>" && parent != child)
            .toMap
    lazy val typesByName: Map[String, List[TypeDecl]] =
        cpg.typeDecl.isExternal(false).l.groupBy(_.name)

    def declaredBy(scope: String, name: String): List[Method] =
        byScopeAndName.getOrElse((scope, name), Nil)

    def onConstant(call: Call): List[Method] =
        ConstantReceiver.findPrefixMatchOf(call.code).toList.flatMap { m =>
          val path = m.group(1).split("::").toList
          val types = typesByName.getOrElse(path.last, Nil).filter(t =>
              path.sizeIs == 1 || t.fullName.endsWith(path.mkString(".", ".", ""))
          )
          types.flatMap(t =>
              declaredBy(t.fullName, call.name) ++ declaredBy(s"${t.fullName}<class>", call.name)
          )
        }

    def onSelf(call: Call): List[Method] =
        if !call.code.startsWith(call.name) then Nil
        else
          scopesOf(call, parentOf).iterator.map(declaredBy(_, call.name)).find(_.nonEmpty)
              .getOrElse(Nil)

    cpg.call.methodFullNameExact(XDefines.DynamicCallUnknownFullName).foreach { call =>
      val hinted = call.possibleTypes.filter(fullNames.contains).distinct.toList
      val candidates =
          if hinted.nonEmpty then hinted
          else (onConstant(call) ++ onSelf(call)).map(_.fullName).distinct
      candidates match
        case single :: Nil =>
            builder.setNodeProperty(call, PropertyNames.METHOD_FULL_NAME, single)
        case _ =>
    }
  end run

  /** The full names of the scopes around `call`, innermost first: each enclosing method, class,
    * module and the file's `<main>`. This runs before AstLinkerPass hangs methods and types under
    * their parents, so past the call's own method the chain follows their AST_PARENT_FULL_NAME.
    */
  private def scopesOf(call: Call, parentOf: Map[String, String]): List[String] =
      Iterator
          .iterate(Option(call: AstNode))(_.flatMap(_._astIn.collectFirst { case p: AstNode => p }))
          .takeWhile(_.isDefined)
          .flatten
          .collectFirst { case m: Method => m.fullName }
          .toList
          .flatMap(own =>
              // bounded: a malformed parent chain could loop
              Iterator.iterate(Option(own))(_.flatMap(parentOf.get)).takeWhile(_.isDefined).take(64)
                  .flatten
          )
          .distinct
end RubyCallLinker

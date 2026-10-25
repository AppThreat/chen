package io.appthreat.jssrc2cpg.passes

import io.appthreat.x2cpg.passes.frontend.XInheritanceFullNamePass
import io.appthreat.x2cpg.passes.taggers.js.{JsModules, JsPathAliases}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.semanticcpg.language.*

/** Using some basic heuristics, will try to resolve type full names from types found within the
  * CPG. Requires ImportPass as a pre-requisite.
  *
  * A base class is what the class's file binds the base's name to: a class of the same file, the
  * class of that name in the project file a relative or path-alias import names, or - imported from
  * a package - an external type. The generic pass matches an imported name against every class of
  * the project, so `class Widget extends Component` with `Component` from react inherited from the
  * project's own `Component`.
  */
class JavaScriptInheritanceNamePass(cpg: Cpg) extends XInheritanceFullNamePass(cpg):

  override val pathSep: Char      = ':'
  override val moduleName: String = ":program"
  override val fileExt: String    = ".js"

  private lazy val aliases = JsPathAliases(cpg)

  // file -> local name -> imported module specifier
  private lazy val importsByFile: Map[String, Map[String, String]] =
      cpg.imports.l.flatMap { i =>
          for
            file   <- i.call.file.name.headOption
            local  <- i.importedAs
            module <- i.call.argument.isLiteral.code.headOption
          yield (
            file,
            local,
            module.stripPrefix("\"").stripSuffix("\"").stripPrefix("'").stripSuffix("'")
          )
      }.groupMap(_._1)(t => (t._2, t._3)).view.mapValues(_.toMap).toMap

  private val ScriptExtension = """\.(?:[cm]?[jt]sx?|vue|svelte|astro)$""".r

  private def projectFile(path: String): String => Boolean = candidate =>
    val stem = ScriptExtension.replaceFirstIn(candidate, "")
    stem == path || stem == s"$path/index"

  override protected def resolveInheritedTypeFullName(
    td: TypeDecl,
    builder: DiffGraphBuilder
  ): Seq[TypeDeclBase] =
    val file    = td.file.name.headOption.getOrElse("")
    val imports = importsByFile.getOrElse(file, Map.empty)
    // None: the file does not bind the name (a global, or a binding this pass cannot follow)
    def byBinding(base: String): Option[Seq[TypeDeclBase]] =
      // already resolved (the pass runs again on a graph it has seen): keep it
      val resolved = if base.contains(s"$fileModuleSep$moduleName") then
        cpg.typeDecl.fullNameExact(base).l
      else Nil
      if resolved.nonEmpty then return Some(resolved)
      val sameFile =
          td.file.typeDecl.isExternal(false).nameExact(base).filterNot(_.id() == td.id()).l
      if sameFile.nonEmpty then Some(sameFile)
      else
        imports.get(base.takeWhile(_ != '.')).flatMap { module =>
          val target =
              if module.startsWith(".") then Some(JsModules.resolveRelative(file, module))
              else aliases.resolve(file, module)
          target match
            case Some(path) =>
                // a default import may be named differently from the class: no match is no answer
                Some(cpg.typeDecl.isExternal(false).nameExact(base.split('.').last)
                    .filter(t => projectFile(path)(t.filename)).l).filter(_.nonEmpty)
            case None =>
                Some(externalTypeStubs(td, Seq(base), qualifiedNamesInScope(td), builder))
        }
    end byBinding
    val perBase = td.inheritsFromTypeFullName.map(base => base -> byBinding(base))
    val unbound = perBase.collect { case (base, None) => base }
    perBase.flatMap(_._2.toSeq.flatten) ++
        (if unbound.isEmpty then Nil
         else
           super.resolveInheritedTypeFullName(td, builder).filter(t =>
               unbound.exists(b => b.split('.').last == t.name)
           )
        )
  end resolveInheritedTypeFullName
end JavaScriptInheritanceNamePass

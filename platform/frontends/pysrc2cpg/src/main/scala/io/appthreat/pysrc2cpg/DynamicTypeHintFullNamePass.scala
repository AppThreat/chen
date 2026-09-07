package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.ImportStringHandling
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.PropertyNames
import io.shiftleft.codepropertygraph.generated.nodes.{
    TypeDecl,
    CfgNode,
    MethodParameterIn,
    MethodReturn,
    StoredNode
}
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate

/** The type hints we pick up via the parser are not full names. This pass fixes that by retrieving
  * the import for each dynamic type hint and adjusting the dynamic type hint full name field
  * accordingly.
  */
class DynamicTypeHintFullNamePass(
  cpg: Cpg
) extends ForkJoinParallelCpgPass[CfgNode](cpg):

  private case class ImportScope(entity: Option[String], alias: Option[String])

  /** Materialised once per run: every type decl as (fullName, decl) in graph order. The per-lookup
    * alternative - `cpg.typeDecl.fullName(".*<quoted name>")` - is a regex scan over the whole
    * typeDecl population FOR EVERY typed node, and on annotation-dense graphs (typeshed stubs) that
    * dominated this pass's wall (task 12 D.2: 128s of a 260s typeshed run). `.*<Pattern.quote(x)>`
    * is exactly `fullName.endsWith(x)`, so scanning this array preserves both the matched SET and
    * its order while dropping the per-node regex work.
    */
  private val allTypeDecls: Array[(String, TypeDecl)] =
      cpg.typeDecl.map(td => td.fullName -> td).toArray

  /** `typeHint` is `imported` or `imported` followed by at least one dotted segment - the exact
    * meaning of the regex this replaces (`Pattern.quote(imported) + "(\\..+)*"`), without compiling
    * a pattern per check.
    */
  private def isImportedPrefix(typeHint: String, imported: String): Boolean =
      typeHint == imported ||
          (typeHint.startsWith(imported + ".") && typeHint.length > imported.length + 1)

  private val fileToImports = cpg.imports.l
      .flatMap(imp => imp.call.file.l.map { f => f.name -> imp })
      .groupBy(_._1)
      .view
      .mapValues(_.map { case (_, imp) =>
          ImportScope(imp.importedEntity, imp.importedAs)
      })

  override def generateParts(): Array[CfgNode] =
      (cpg.methodReturn.filter(x => x.typeFullName != Constants.ANY) ++ cpg.parameter.filter(x =>
          x.typeFullName != Constants.ANY
      )).toArray

  override def runOnPart(builder: DiffGraphBuilder, part: CfgNode): Unit =
      part match
        case x: MethodReturn      => runOnMethodReturn(builder, x)
        case x: MethodParameterIn => runOnMethodParameter(builder, x)
        case _                    =>

  private def runOnMethodReturn(diffGraph: DiffGraphBuilder, methodReturn: MethodReturn): Unit =
      methodReturn.file.foreach { file =>
        val typeHint = methodReturn.typeFullName
        val imports =
            fileToImports.getOrElse(file.name, List.empty) ++ methodReturn.method.typeDecl
                .map(td =>
                    ImportScope(Option(td.fullName), Option(td.name))
                )
                .toList
        imports
            .filter { x =>
                // TODO: Handle * imports correctly
                x.alias.exists(imported => isImportedPrefix(typeHint, imported))
            }
            .flatMap(_.entity)
            .foreach { importedEntity =>
                setTypeHints(diffGraph, methodReturn, typeHint, importedEntity)
            }
      }

  private def runOnMethodParameter(diffGraph: DiffGraphBuilder, param: MethodParameterIn): Unit =
      param.file.foreach { file =>
        val typeHint = param.typeFullName
        val imports = fileToImports.getOrElse(file.name, List.empty) ++ param.method.typeDecl
            .map(td =>
                ImportScope(Option(td.fullName), Option(td.name))
            )
            .toList
        imports
            // TODO: Handle * imports correctly
            .filter(_.alias.exists(imported => isImportedPrefix(typeHint, imported)))
            .foreach {
                case ImportScope(Some(importedEntity), Some(_)) =>
                    setTypeHints(diffGraph, param, typeHint, importedEntity)
                case _ =>
            }
      }

  /** The combined import path already IS the full name (`foo.bar.Baz`) since task 09 made dotted
    * the only representation, so there is nothing to rewrite: the file form's alias-driven `a.b.C`
    * -> `a/b.py:<module>.C` translation is what the removed `alias` parameter existed for, and both
    * call sites now ask the same question.
    */
  private def setTypeHints(
    diffGraph: BatchedUpdate.DiffGraphBuilder,
    node: StoredNode,
    typeHint: String,
    importedEntity: String
  ) =
    val pythonicTypeFullName = ImportStringHandling.combinedPath(importedEntity, typeHint)
    allTypeDecls.collect {
        case (fullName, td) if fullName.endsWith(pythonicTypeFullName) => td
    } match
      case Array(single) =>
          diffGraph.setNodeProperty(node, PropertyNames.TYPE_FULL_NAME, single.fullName)
      case xs if xs.nonEmpty =>
          diffGraph.setNodeProperty(
            node,
            PropertyNames.DYNAMIC_TYPE_HINT_FULL_NAME,
            xs.map(_.fullName).toSeq
          )
      case _ =>
          diffGraph.setNodeProperty(node, PropertyNames.TYPE_FULL_NAME, pythonicTypeFullName)
  end setTypeHints
end DynamicTypeHintFullNamePass

package io.appthreat.x2cpg.frontendspecific.ruby2atom

import io.appthreat.x2cpg.Imports.createImportNodeAndLink
import io.appthreat.x2cpg.X2Cpg.stripQuotes
import io.shiftleft.codepropertygraph.generated.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.*
import io.shiftleft.passes.ForkJoinParallelCpgPass
import io.shiftleft.semanticcpg.language.*

class ImportsPass(cpg: Cpg) extends ForkJoinParallelCpgPass[Call](cpg):

  override def generateParts(): Array[Call] =
      cpg.call.nameExact(ImportsPass.ImportCallNames.toSeq*).isStatic.toArray

  override def runOnPart(diffGraph: DiffGraphBuilder, call: Call): Unit =
    val importedEntity = stripQuotes(call.argument.isLiteral.code.l match
      case s :: _ => s
      case _      => ""
    )
    val importNode = createImportNodeAndLink(importedEntity, importedEntity, Some(call), diffGraph)
    if call.name == "require_all" then importNode.isWildcard(true)

object ImportsPass:
  val ImportCallNames: Set[String] = Set("require", "load", "require_relative", "require_all")

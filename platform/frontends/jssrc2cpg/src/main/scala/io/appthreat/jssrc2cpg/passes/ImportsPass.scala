package io.appthreat.jssrc2cpg.passes

import io.appthreat.x2cpg.X2Cpg
import io.appthreat.x2cpg.passes.frontend.XImportsPass
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.semanticcpg.language.operatorextension.OpNodes.Assignment

/** This pass creates `IMPORT` nodes by looking for calls to `require`. `IMPORT` nodes are linked to
  * existing dependency nodes, or, if no suitable dependency node exists, a dependency node is
  * created.
  *
  * The `importedEntity` written here is the '''bare specifier''' (the unquoted `require(...)`
  * argument, e.g. `require('vue')` → `"vue"`, `require('./bar.js')` → `"./bar.js"`). This differs
  * from ESM imports, which `AstForDeclarationsCreator` records as `"<package>:<name>"`; consumers
  * (see `XImportResolverPass.optionalResolveImport`) must handle both shapes.
  *
  * Note: `importCallToPart` deliberately skips `var ...` assignments (those import nodes are
  * already created during AST creation), so a `require` bound with `var` yields one IMPORT node
  * while one bound with `const`/`let` yields two (AST-creation + this pass) for the same call.
  *
  * TODO Dependency node creation is still missing.
  */
class ImportsPass(cpg: Cpg) extends XImportsPass(cpg):

  override protected val importCallName: String = "require"

  override protected def importCallToPart(x: Call): Iterator[(Call, Assignment)] =
      x.inAssignment.codeNot("var .*").map(y => (x, y))

  override protected def importedEntityFromCall(call: Call): String =
      X2Cpg.stripQuotes(call.argument(1).code)

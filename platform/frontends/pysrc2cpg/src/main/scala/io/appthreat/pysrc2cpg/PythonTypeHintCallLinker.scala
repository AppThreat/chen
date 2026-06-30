package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.passes.frontend.XTypeHintCallLinker
import io.appthreat.x2cpg.passes.frontend.XTypeRecovery.isDummyType
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.semanticcpg.language.*

class PythonTypeHintCallLinker(cpg: Cpg) extends XTypeHintCallLinker(cpg):

  // Exclude only the synthetic `import(...)` pseudo-call, not user methods whose name merely
  // starts with "import" (e.g. `import_models`, `import_module`, common in Django).
  override def calls: Iterator[Call] = super.calls.nameNot("import")

  override def calleeNames(c: Call): Seq[String] = super.calleeNames(c).map {
      // Python call from  a type
      case typ if typ.split("\\.").lastOption.exists { lastPart =>
              lastPart.length > 0 && lastPart.charAt(0).isUpper
          } => s"$typ.__init__"
      // Python call from a function pointer
      case typ => typ
  }

  override def setCallees(call: Call, methodNames: Seq[String], builder: DiffGraphBuilder): Unit =
      if methodNames.sizeIs == 1 then
        super.setCallees(call, methodNames, builder)
      else if methodNames.sizeIs > 1 then
        val nonDummyMethodNames =
            methodNames.filterNot(x =>
                isDummyType(x) || x.startsWith(PythonAstVisitor.builtinPrefix + "None")
            )
        // Type recovery can attach unresolvable pseudo-type hints alongside the real one
        // (e.g. `tmp0.ready` next to `pkg.Cls.ready`, produced by a fallback in an early
        // iteration before the receiver was typed). When at least one candidate resolves to a
        // method actually present in the CPG, prefer those so a lone real callee still links.
        val resolvable = nonDummyMethodNames.filter(n => cpg.method.fullNameExact(n).nonEmpty)
        val chosen     = if resolvable.nonEmpty then resolvable.distinct else nonDummyMethodNames
        super.setCallees(call, chosen, builder)
end PythonTypeHintCallLinker

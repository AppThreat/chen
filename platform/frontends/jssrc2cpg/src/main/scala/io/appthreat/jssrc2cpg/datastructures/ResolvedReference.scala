package io.appthreat.jssrc2cpg.datastructures

import io.shiftleft.codepropertygraph.generated.nodes.NewNode

case class ResolvedReference(variableNodeId: NewNode, origin: PendingReference)

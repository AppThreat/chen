package io.appthreat.jssrc2cpg.datastructures

sealed trait ScopeType
object MethodScope extends ScopeType
object BlockScope  extends ScopeType

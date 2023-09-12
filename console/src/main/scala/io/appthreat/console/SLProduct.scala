package io.appthreat.console

sealed trait SLProduct { def name: String }
case object OcularProduct extends SLProduct { val name: String = "ocular" }
case object ChenProduct   extends SLProduct { val name: String = "chen"   }

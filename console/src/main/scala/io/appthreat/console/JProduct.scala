package io.appthreat.console

sealed trait JProduct:
  def name: String
case object ChenProduct extends JProduct:
  val name: String = "chen"

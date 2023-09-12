package io.appthreat.chencli.console

import io.appthreat.console.{BridgeBase, ChenProduct}

import java.io.PrintStream

object ReplBridge extends BridgeBase {

  override val slProduct = ChenProduct

  def main(args: Array[String]): Unit = {
    run(parseConfig(args))
  }

  /** Code that is executed when starting the shell
    */
  override def predefLines =
    Predefined.forInteractiveShell

  override def greeting = ChenConsole.banner()

  override def promptStr: String = "chen"

  override def onExitCode: String = "workspace.projects.foreach(_.close)"

}

package io.appthreat.chencli.console

import io.appthreat.console.{BridgeBase, ChenProduct, JProduct}

import java.io.PrintStream

object ReplBridge extends BridgeBase:

  override val jProduct: JProduct = ChenProduct

  def main(args: Array[String]): Unit =
      run(parseConfig(args))

  /** Code that is executed when starting the shell
    */
  override def predefLines: Seq[String] =
      Predefined.forInteractiveShell

  override def greeting: String = ChenConsole.banner()

  override def promptStr: String = "chennai"

  override def onExitCode: String = "workspace.projects.foreach(_.close)"

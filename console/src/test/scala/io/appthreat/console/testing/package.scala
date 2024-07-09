package io.appthreat.console

import better.files.Dsl.*
import better.files.*
import io.appthreat.console.workspacehandling.Project

import scala.util.Try

package object testing {

  object WithStandaloneCpg {
    def apply(console: Console[Project], codeDir: File)(fun: File => Unit): Unit = {
      val tmpProjectName = "standalonecpg"
      console.importCode(codeDir.toString, tmpProjectName)
      val project = console.workspace.project(tmpProjectName)
      val cpgPath = project.get.path.resolve("cpg.bin")
      File.usingTemporaryFile("console", suffix = "cpg.bin") { tmpCpg =>
        cp(cpgPath, tmpCpg)
        Try(console.workspace.reset)
        fun(tmpCpg)
      }
    }
  }

}

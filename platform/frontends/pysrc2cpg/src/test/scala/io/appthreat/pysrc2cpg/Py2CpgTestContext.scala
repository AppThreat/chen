package io.appthreat.pysrc2cpg

import io.appthreat.x2cpg.ValidationMode
import io.appthreat.x2cpg.X2Cpg.defaultOverlayCreators
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

import scala.collection.mutable

object Py2CpgTestContext:
  def buildCpg(code: String, file: String = "test.py"): Cpg =
    val context = new Py2CpgTestContext()
    context.addSource(code, file)
    context.buildCpg

class Py2CpgTestContext:

  private val codeAndFile = mutable.ArrayBuffer.empty[Py2Cpg.InputPair]
  private var buildResult = Option.empty[Cpg]
  private val absTestFilePath =
      java.nio.file.Files.createTempDirectory("pysrc2cpg-test").toString

  def addSource(code: String, file: String = "test.py"): Py2CpgTestContext =
    if buildResult.nonEmpty then
      throw new RuntimeException("Not allowed to add sources after buildCpg() was called.")
    if codeAndFile.exists(_.relFileName == file) then
      throw new RuntimeException(s"Add more than one source under file name $file.")
    codeAndFile.append(Py2Cpg.InputPair(code, file))
    this

  def buildCpg: Cpg =
    if buildResult.isEmpty then
      val cpg = new Cpg()
      // Dotted full names are derived from the whole ingested file set (the `__init__.py`
      // walk), exactly as Py2CpgOnFileSystem does for real runs.
      val moduleNames: Map[String, String] =
          codeAndFile.view.map(_.relFileName).flatMap { rel =>
              PythonModuleName.moduleFor(codeAndFile.map(_.relFileName).toSet, rel).map(rel -> _)
          }.toMap
      val py2Cpg =
          new Py2Cpg(
            codeAndFile.map(inputPair => () => inputPair),
            cpg,
            absTestFilePath,
            schemaValidationMode = ValidationMode.Enabled,
            moduleNames = moduleNames
          )
      py2Cpg.buildCpg()

      val context = new LayerCreatorContext(cpg)
      defaultOverlayCreators().foreach(_.run(context))
      buildResult = Some(cpg)
    end if
    buildResult.get
  end buildCpg
end Py2CpgTestContext

package io.appthreat.jssrc2cpg.passes

import better.files.File
import io.appthreat.jssrc2cpg.Config
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.utils.IOUtils

import scala.util.matching.Regex

class PrivateKeyFilePass(cpg: Cpg, config: Config) extends ConfigPass(cpg, config):

  private val PrivateKeyRegex: Regex = """.*RSA\sPRIVATE\sKEY.*""".r

  override val allExtensions: Set[String]      = Set(".key")
  override val selectedExtensions: Set[String] = Set(".key")

  override def fileContent(file: File): Seq[String] =
      Seq("Content omitted for security reasons.")

  override def generateParts(): Array[File] =
      configFiles(config, selectedExtensions).toArray.filter(p =>
          IOUtils.readLinesInFile(p.path).exists(PrivateKeyRegex.matches)
      )

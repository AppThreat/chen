package io.appthreat.php2atom.astcreation

import io.shiftleft.utils.IOUtils

import scala.io.Source

object PhpBuiltins:
  lazy val FuncNames: Set[String] =
      Source.fromResource("builtin_functions.txt").getLines().toSet

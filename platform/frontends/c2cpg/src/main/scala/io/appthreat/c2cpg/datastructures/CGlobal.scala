package io.appthreat.c2cpg.datastructures

import io.appthreat.c2cpg.astcreation.Defines
import io.appthreat.x2cpg.datastructures.Global

import scala.jdk.CollectionConverters._

object CGlobal extends Global {

  def typesSeen(): List[String] = {
    val types = usedTypes.keys().asScala.filterNot(_ == Defines.anyTypeName).toList
    usedTypes.clear()
    types
  }

}

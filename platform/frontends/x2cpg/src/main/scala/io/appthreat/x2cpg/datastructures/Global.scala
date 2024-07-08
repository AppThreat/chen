package io.appthreat.x2cpg.datastructures

import java.util.concurrent.ConcurrentHashMap

class Global:

  val usedTypes: ConcurrentHashMap[String, Boolean] = new ConcurrentHashMap()

import sbt._

object Projects {
  val frontendsRoot = file("platform/frontends")

  lazy val platform          = project.in(file("platform"))
  lazy val console           = project.in(file("console"))
  lazy val dataflowengineoss = project.in(file("dataflowengineoss"))
  lazy val macros            = project.in(file("macros"))
  lazy val semanticcpg       = project.in(file("semanticcpg"))

  lazy val c2cpg       = project.in(frontendsRoot / "c2cpg")
  lazy val x2cpg       = project.in(frontendsRoot / "x2cpg")
  lazy val pysrc2cpg   = project.in(frontendsRoot / "pysrc2cpg")
  lazy val jssrc2cpg   = project.in(frontendsRoot / "jssrc2cpg")
  lazy val javasrc2cpg = project.in(frontendsRoot / "javasrc2cpg")
  lazy val jimple2cpg  = project.in(frontendsRoot / "jimple2cpg")
  lazy val php2atom  = project.in(frontendsRoot / "php2atom")
}

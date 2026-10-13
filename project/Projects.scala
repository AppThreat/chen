import sbt.*

object Projects {
    val frontendsRoot = file("platform/frontends")

    // explicit id: the root build.sbt alias for this project cannot be named
    // `platform` (that would be ambiguous with sbt 2's Keys.platform), so the
    // id must not depend on the alias name
    lazy val platform = Project(id = "platform", base = file("platform"))
    lazy val dataflowengineoss = project.in(file("dataflowengineoss"))
    lazy val semanticcpg       = project.in(file("semanticcpg"))

    lazy val c2cpg       = project.in(frontendsRoot / "c2cpg")
    lazy val x2cpg       = project.in(frontendsRoot / "x2cpg")
    lazy val pysrc2cpg   = project.in(frontendsRoot / "pysrc2cpg")
    lazy val jssrc2cpg   = project.in(frontendsRoot / "jssrc2cpg")
    lazy val javasrc2cpg = project.in(frontendsRoot / "javasrc2cpg")
    lazy val jimple2cpg  = project.in(frontendsRoot / "jimple2cpg")
    lazy val php2atom    = project.in(frontendsRoot / "php2atom")
    lazy val ruby2atom   = project.in(frontendsRoot / "ruby2atom")
    lazy val edg2atom    = project.in(frontendsRoot / "edg2atom")
}

import sbt.*
import sbt.Keys.*

object Projects {
    val frontendsRoot = file("platform/frontends")

    // The chen#255 suites capture what a logger prints for a file the frontend lost: nothing at
    // the default level, the file and the reason at debug. slf4j-nop discards every event, and
    // being a direct dependency of the root build no exclusion rule can remove it, so the Test
    // classpath alone drops it and gets logback instead, whose loggers take appenders directly.
    // Compile, Runtime and every published artifact keep shipping nop exactly as before.
    val testLogging = Seq(
      Test / fullClasspath := Def.uncached(
        (Test / fullClasspath).value.filterNot(_.data.name.startsWith("slf4j-nop"))
      ),
      Test / dependencyClasspath := Def.uncached(
        (Test / dependencyClasspath).value.filterNot(_.data.name.startsWith("slf4j-nop"))
      ),
      libraryDependencies += "ch.qos.logback" % "logback-classic" % Versions.logback % Test
    )

    // explicit id: the root build.sbt alias for this project cannot be named
    // `platform` (that would be ambiguous with sbt 2's Keys.platform), so the
    // id must not depend on the alias name
    lazy val platform = Project(id = "platform", base = file("platform"))
    lazy val dataflowengineoss = project.in(file("dataflowengineoss"))
    lazy val semanticcpg       = project.in(file("semanticcpg"))

    lazy val c2cpg       = project.in(frontendsRoot / "c2cpg").settings(testLogging)
    lazy val x2cpg       = project.in(frontendsRoot / "x2cpg").settings(testLogging)
    lazy val pysrc2cpg   = project.in(frontendsRoot / "pysrc2cpg").settings(testLogging)
    lazy val jssrc2cpg   = project.in(frontendsRoot / "jssrc2cpg").settings(testLogging)
    lazy val javasrc2cpg = project.in(frontendsRoot / "javasrc2cpg").settings(testLogging)
    lazy val jimple2cpg  = project.in(frontendsRoot / "jimple2cpg").settings(testLogging)
    lazy val php2atom    = project.in(frontendsRoot / "php2atom").settings(testLogging)
    lazy val ruby2atom   = project.in(frontendsRoot / "ruby2atom").settings(testLogging)
    lazy val edg2atom    = project.in(frontendsRoot / "edg2atom").settings(testLogging)
}

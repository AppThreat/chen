/* reads version declarations from /build.sbt so that we can declare them in one place */
object Versions {
  val cpg = parseVersion("cpgVersion")
  val antlr         = "4.13.2"
  val scalatest     = "3.2.19"
  val cats          = "3.5.4"
  val json4s        = "4.0.7"
  val gradleTooling = "8.10.1"
  val circe         = "0.14.10"
  val requests      = "0.9.0"
  val upickle       = "3.3.1"
  val scalaReplPP   = "0.1.85"

  private def parseVersion(key: String): String = {
    val versionRegexp = s""".*val $key[ ]+=[ ]?"(.*?)"""".r
    val versions: List[String] = scala.io.Source
      .fromFile("build.sbt")
      .getLines
      .filter(_.contains(s"val $key"))
      .collect { case versionRegexp(version) => version }
      .toList
    assert(
      versions.size == 1,
      s"""unable to extract $key from build.sbt, expected exactly one line like `val $key= "0.0.0-SNAPSHOT"`."""
    )
    versions.head
  }

}

import sbt._
import sbt.Keys._

/** sbt hands Scala 3's scaladoc the classpath twice, so every project's doc task prints "Option
  * -classpath was updated" - a toolchain artefact, not a source warning. Compile warnings are
  * unaffected; this silences only the doc task, in every project.
  */
object ScaladocNoWarn extends AutoPlugin {
  override def trigger = allRequirements
  override def projectSettings: Seq[Setting[_]] = Seq(Compile / doc / scalacOptions += "-nowarn")
}

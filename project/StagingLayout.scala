import com.typesafe.sbt.packager.archetypes.JavaAppPackaging
import com.typesafe.sbt.packager.universal.UniversalPlugin
import com.typesafe.sbt.packager.universal.UniversalPlugin.autoImport.Universal
import sbt.*
import sbt.Keys.*

/** Stages every packaged project under its own `target/universal/stage`.
  *
  * sbt 2 moves each project's `target` to `target/out/jvm/scala-<version>/<project>` under the build
  * root; the frontend launch scripts (`c2cpg.sh`, `jssrc2cpg.sh`, `pysrc2cpg.sh`) and
  * `tests/querydb-test.sh` expect the staged app where sbt 1 put it.
  */
object StagingLayout extends AutoPlugin {

    override def requires: Plugins      = JavaAppPackaging
    override def trigger: PluginTrigger = allRequirements

    override def projectSettings: Seq[Setting[?]] = Seq(
      Universal / UniversalPlugin.autoImport.stagingDirectory :=
          baseDirectory.value / "target" / "universal" / "stage"
    )
}

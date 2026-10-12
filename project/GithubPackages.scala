import sbt.*
import sbt.Keys.*

/** Publishes to GitHub Packages, replacing the unmaintained
  * `com.codecommit:sbt-github-packages` plugin, which has no sbt 2.x build.
  *
  * Keeps the same `githubOwner` / `githubRepository` settings the plugin defined,
  * so per-project declarations continue to work unchanged. Credentials for
  * "GitHub Package Registry" / maven.pkg.github.com are still supplied by the
  * individual projects' build.sbt files.
  */
object GithubPackages extends AutoPlugin {

    object autoImport {
        val githubOwner      = settingKey[String]("GitHub user or organization owning the repository")
        val githubRepository = settingKey[String]("GitHub repository to publish to")
    }
    import autoImport.*

    override def trigger: PluginTrigger = allRequirements

    override def projectSettings: Seq[Setting[?]] = Seq(
      publishTo := Some(
        "GitHub Package Registry"
          .at(s"https://maven.pkg.github.com/${githubOwner.value}/${githubRepository.value}")
      )
    )
}

import sbt.*
import sbt.Keys.*

/** Publishes to and resolves from GitHub Packages, replacing the unmaintained
  * `com.codecommit:sbt-github-packages` plugin, which has no sbt 2.x build.
  *
  * Keeps the same `githubOwner` / `githubRepository` settings and the same project
  * settings the plugin applied: the publish target, the owner's package registry as a
  * resolver (io.appthreat artifacts such as cpg2 are only published there), and the POM
  * metadata. Credentials for "GitHub Package Registry" / maven.pkg.github.com are still
  * supplied by the individual projects' build.sbt files.
  */
object GithubPackages extends AutoPlugin {

    object autoImport {
        val githubOwner      = settingKey[String]("GitHub user or organization owning the repository")
        val githubRepository = settingKey[String]("GitHub repository to publish to")
    }
    import autoImport.*

    override def requires: Plugins      = plugins.JvmPlugin
    override def trigger: PluginTrigger = allRequirements

    override def projectSettings: Seq[Setting[?]] = Seq(
      publishTo := Some(
        "GitHub Package Registry"
            .at(s"https://maven.pkg.github.com/${githubOwner.value}/${githubRepository.value}")
      ),
      resolvers += s"GitHub Package Registry (${githubOwner.value})"
          .at(s"https://maven.pkg.github.com/${githubOwner.value}/_"),
      scmInfo := Some(
        ScmInfo(
          uri(s"https://github.com/${githubOwner.value}/${githubRepository.value}"),
          s"scm:git@github.com:${githubOwner.value}/${githubRepository.value}.git"
        )
      ),
      homepage             := Some(uri(s"https://github.com/${githubOwner.value}/${githubRepository.value}")),
      pomIncludeRepository := (_ => false),
      publishMavenStyle    := true
    )
}

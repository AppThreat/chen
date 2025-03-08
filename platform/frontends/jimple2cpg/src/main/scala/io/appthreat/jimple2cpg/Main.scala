package io.appthreat.jimple2cpg

import Frontend.*
import io.appthreat.x2cpg.{X2CpgConfig, X2CpgMain}
import scopt.OParser

/** Command line configuration parameters
  */
final case class Config(
  android: Option[String] = None,
  scalaSdk: Option[String] = None,
  dynamicDirs: Seq[String] = Seq.empty,
  dynamicPkgs: Seq[String] = Seq.empty,
  fullResolver: Boolean = false,
  recurse: Boolean = false,
  depth: Int = 1,
  onlyClasses: Boolean = false
) extends X2CpgConfig[Config]:
  def withAndroid(android: String): Config =
      copy(android = Some(android)).withInheritedFields(this)
  def withScalaSdk(scalaSdk: String): Config =
      copy(scalaSdk = Some(scalaSdk)).withInheritedFields(this)
  def withDynamicDirs(value: Seq[String]): Config =
      copy(dynamicDirs = value).withInheritedFields(this)
  def withDynamicPkgs(value: Seq[String]): Config =
      copy(dynamicPkgs = value).withInheritedFields(this)
  def withFullResolver(value: Boolean): Config =
      copy(fullResolver = value).withInheritedFields(this)
  def withRecurse(value: Boolean): Config =
      copy(recurse = value)
  def withDepth(value: Int): Config =
      copy(depth = value).withInheritedFields(this)
  def withOnlyClasses(value: Boolean): Config =
      copy(onlyClasses = value).withInheritedFields(this)
end Config

private object Frontend:

  implicit val defaultConfig: Config = Config()

  val cmdLineParser: OParser[Unit, Config] =
    val builder = OParser.builder[Config]
    import builder.*
    OParser.sequence(
      programName("jimple2cpg"),
      opt[String]("android")
          .text("Optional path to android.jar while processing apk file.")
          .action((android, config) => config.withAndroid(android)),
      opt[String]("scalaSdk")
          .text(
            "Optional path to scala library while processing scala-built jar file. Example: $HOME/.ivy2/cache/org.scala-lang/scala3-library_3/jars/scala3-library_3-3.6.2.jar"
          )
          .action((scalaSdk, config) => config.withScalaSdk(scalaSdk)),
      opt[Int]("depth")
          .text("maximum depth to recursively unpack jars, default value 1")
          .action((depth, config) => config.withDepth(depth)),
      opt[Unit]("onlyClasses")
          .text("only include .class files")
          .action((_, config) => config.withOnlyClasses(true)),
      opt[Unit]("full-resolver")
          .text(
            "enables full transitive resolution of all references found in all classes that are resolved"
          )
          .action((_, config) => config.withFullResolver(true)),
      opt[Unit]("recurse")
          .text("recursively unpack jars")
          .action((_, config) => config.withRecurse(true)),
      opt[Seq[String]]("dynamic-dirs")
          .valueName("<dir1>,<dir2>,...")
          .text(
            "Mark all class files in dirs as classes that may be loaded dynamically. Comma separated values for multiple directories."
          )
          .action((dynamicDirs, config) => config.withDynamicDirs(dynamicDirs)),
      opt[Seq[String]]("dynamic-pkgs")
          .valueName("<pkg1>,<pkg2>,...")
          .text(
            "Marks all class files belonging to the package pkg or any of its subpackages as classes which the application may load dynamically. Comma separated values for multiple packages."
          )
          .action((dynamicPkgs, config) => config.withDynamicPkgs(dynamicPkgs))
    )
  end cmdLineParser
end Frontend

/** Entry point for command line CPG creator
  */
object Main extends X2CpgMain(cmdLineParser, new Jimple2Cpg()):
  def run(config: Config, jimple2Cpg: Jimple2Cpg): Unit =
      jimple2Cpg.run(config)

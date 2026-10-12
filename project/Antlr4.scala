import sbt.*
import sbt.Keys.*

import java.io.File

/** Generates Java sources from ANTLR 4 grammars, replacing the unmaintained
  * `com.simplytyped:sbt-antlr4` plugin, which has no sbt 2.x build.
  *
  * Runs the ANTLR tool in-process (same approach sbt-antlr4 used) with listener-only
  * output and an explicit `-package`, so generated sources land in a directory that
  * matches their Java package.
  */
object Antlr4 {

  def generate(
      grammars: Seq[File],
      sourceManaged: File,
      packageName: Option[String],
      log: Logger
  ): Seq[File] = {
      val outDir = packageName match
          case Some(pkg) => sourceManaged / pkg.replace('.', '/')
          case None      => sourceManaged

      IO.delete(outDir)
      IO.createDirectory(outDir)

      val args =
          Seq("-o", outDir.getAbsolutePath, "-listener", "-no-visitor") ++
              packageName.toSeq.flatMap(pkg => Seq("-package", pkg)) ++
              grammars.map(_.getAbsolutePath)

      log.info(s"generating ANTLR parser sources into $outDir")
      val tool = new org.antlr.v4.Tool(args.toArray)
      tool.processGrammarsOnCommandLine()
      if tool.getNumErrors > 0 then
          sys.error(s"ANTLR generation failed with ${tool.getNumErrors} error(s)")

      (outDir ** "*").get().filter(_.isFile)
  }

  /** Grammar generation task for a project whose grammars live under
    * `src/main/antlr4`. Cached on grammar last-modified timestamps.
    */
  def sourceGenerator(packageName: String): Def.Initialize[Task[Seq[File]]] = Def.task {
      val grammars = ((Compile / sourceDirectory).value / "antlr4" ** "*.g4").get()
      val cached   = FileFunction.cached(
        streams.value.cacheDirectory / "antlr4",
        inStyle = FilesInfo.lastModified,
        outStyle = FilesInfo.exists
      ) { _ =>
          generate(
            grammars,
            (Compile / sourceManaged).value,
            Some(packageName),
            streams.value.log
          ).toSet
      }
      cached(grammars.toSet).toSeq.filter(_.getName.endsWith(".java"))
  }
}

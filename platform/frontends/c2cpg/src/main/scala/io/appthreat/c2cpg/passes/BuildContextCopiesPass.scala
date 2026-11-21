package io.appthreat.c2cpg.passes

import io.appthreat.c2cpg.Config
import io.appthreat.c2cpg.astcreation.AstCreator
import io.appthreat.c2cpg.datastructures.CGlobal
import io.appthreat.c2cpg.parser.{
    CdtLogging,
    CdtParser,
    CompileCommand,
    FileDefaults,
    ProjectSources
}
import io.appthreat.x2cpg.Defines as X2CpgDefines
import io.appthreat.x2cpg.SourceFiles
import io.appthreat.x2cpg.parse.ParseReporter
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{
    AstNodeNew,
    NewCall,
    NewMethod,
    NewMethodRef,
    NewTag
}
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.{CreateEdge, DiffGraphBuilder}
import overflowdb.DetachedNodeData

import java.nio.file.{Path, Paths}
import java.util.concurrent.{
    Callable,
    ConcurrentHashMap,
    ExecutionException,
    Executors,
    TimeUnit,
    TimeoutException
}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*

/** What a copy of a function is, and how one is named. The analyses of a file's extra build
  * contexts (see [[BuildContextCopiesPass]]) build their ASTs into diffs of their own, and the
  * copies in them are named and tagged here, before the diffs are written.
  *
  * A function whose body differs across the contexts of its file keeps one copy per context: the
  * first context's copy keeps today's full name, every other copy's full name gains `@ctx:` and the
  * first eight hex digits of its context's fingerprint, and the METHOD carries its context in a
  * `build-context` tag. The calls inside the copies reach the copy of their own context, by the
  * rewritten full name.
  */
object BuildContextCopies:

  /** The full-name suffix that names a copy kept for one build context. */
  def suffix(fingerprint: String): String = "@ctx:" + fingerprint.take(8)

  /** The labels of the nodes that hold a method's place in the graph rather than its body: the
    * decorator that runs after the AST is built adds the out parameters, so the copies of two
    * contexts compare by what both hold.
    */
  val MethodStructureLabels: Set[String] =
      Set("METHOD", "METHOD_PARAMETER_IN", "METHOD_PARAMETER_OUT", "METHOD_RETURN")

  /** A METHOD a built unit's diff holds, with what tells its copies apart across contexts: its full
    * name, its file, its place, and the body its context compiles.
    */
  case class MethodEntry(
    node: NewMethod,
    fullName: String,
    body: String,
    filename: String,
    line: Int,
    column: Int,
    /** The full names the method's calls and method references name. */
    callees: Set[String] = Set.empty
  )

  /** What one extra context's analysis of a unit built: its diff and the METHODs it holds. */
  case class ContextAnalysis(
    file: Path,
    fingerprint: String,
    diff: DiffGraphBuilder,
    methods: Seq[MethodEntry],
    usedTypes: Seq[String]
  )

  /** The METHODs of one built unit's diff, in the order the diff holds them, each with the digest
    * of its body.
    */
  def methodEntriesOf(diff: DiffGraphBuilder): Seq[MethodEntry] =
    val nodes   = diff.iterator().asScala.toIndexedSeq
    val indexOf = new java.util.IdentityHashMap[AnyRef, Integer]()
    nodes.zipWithIndex.foreach {
        case (n: DetachedNodeData, i) => indexOf.put(n, Integer.valueOf(i))
        case _                        =>
    }
    val children = mutable.HashMap.empty[Int, mutable.ArrayBuffer[Int]]
    nodes.foreach {
        case e: CreateEdge if e.label == EdgeTypes.AST =>
            val (src, dst) = (indexOf.get(e.src), indexOf.get(e.dst))
            if src != null && dst != null then
              children.getOrElseUpdate(src.intValue, mutable.ArrayBuffer.empty) += dst.intValue
        case _ =>
    }
    val entries = mutable.ArrayBuffer.empty[MethodEntry]
    nodes.foreach {
        case m: NewMethod =>
            val subtree = subtreeOf(m, indexOf, children)
            entries += MethodEntry(
              m,
              m.fullName,
              digestOf(subtree, nodes),
              m.filename,
              m.lineNumber.fold(-1)(_.intValue),
              m.columnNumber.fold(-1)(_.intValue),
              subtree.flatMap(i =>
                  nodes(i) match
                    case c: NewCall      => Some(c.methodFullName)
                    case r: NewMethodRef => Some(r.methodFullName)
                    case _               => None
              ).toSet
            )
        case _ =>
    }
    entries.toSeq
  end methodEntriesOf

  /** The diff indices of a method's AST subtree, the method's own included. */
  private def subtreeOf(
    method: NewMethod,
    indexOf: java.util.IdentityHashMap[AnyRef, Integer],
    children: mutable.HashMap[Int, mutable.ArrayBuffer[Int]]
  ): Seq[Int] =
    val seen  = mutable.LinkedHashSet.empty[Int]
    val queue = mutable.ArrayDeque.empty[Int]
    val start = indexOf.get(method)
    if start != null then queue += start.intValue
    while queue.nonEmpty do
      val i = queue.removeHead()
      if seen.add(i) then children.get(i).foreach(_.foreach(queue += _))
    seen.toSeq

  /** The labels and codes of every AST node a method's subtree holds, sorted and joined: what tells
    * the bodies two contexts compile apart, which the declaration's own code does not, since its
    * text spans the inactive branches of the conditionals too.
    */
  private def digestOf(subtree: Seq[Int], nodes: Seq[AnyRef]): String =
      subtree.map { i =>
          nodes(i) match
            case n: AstNodeNew if !MethodStructureLabels.contains(n.label) =>
                s"${n.label}\u0000${n.code}"
            case _ => ""
      }.filter(_.nonEmpty).sorted.mkString("\u0001")

  /** The digest of a method's body as the graph holds it: the same measure [[methodEntriesOf]]
    * takes from a diff, so the copies of the contexts compare equal.
    */
  def bodyDigestOf(method: io.shiftleft.codepropertygraph.generated.nodes.Method): String =
      method.ast.l
          .filterNot(n => MethodStructureLabels.contains(n.label))
          .map(n => s"${n.label}\u0000${n.code}")
          .sorted
          .mkString("\u0001")

  /** Renames the copies `mapping` names in a built unit's diff: the METHOD, the calls that reach
    * it, the method references to it, and the callee lists of dependent calls. Each renamed METHOD
    * is tagged with the build context it was analysed in.
    */
  def renameCopies(
    diff: DiffGraphBuilder,
    mapping: Map[String, String],
    fingerprint: String
  ): Unit =
      diff.iterator().asScala.toIndexedSeq.foreach {
          case m: NewMethod if mapping.contains(m.fullName) =>
              m.fullName = mapping(m.fullName)
              val tag = NewTag().name(X2CpgDefines.BuildContextTag).value(fingerprint)
              diff.addNode(tag)
              diff.addEdge(m, tag, EdgeTypes.TAGGED_BY)
          case c: NewCall =>
              mapping.get(c.methodFullName).foreach(c.methodFullName = _)
              if c.dynamicTypeHintFullName.nonEmpty then
                c.dynamicTypeHintFullName =
                    c.dynamicTypeHintFullName.map(name => mapping.getOrElse(name, name))
          case r: NewMethodRef =>
              mapping.get(r.methodFullName).foreach(r.methodFullName = _)
          case _ => ()
      }

  /** Names, tags and writes the copies the extra contexts of a project's units built.
    *
    * For each unit, the body each present context compiles is compared per function, by its file
    * and full name: where the copies sit in the file does not matter, since two arms of a
    * conditional place one function's definitions on different lines. The first present copy keeps
    * today's full name; a copy whose body differs from it is renamed for its context, and a copy
    * whose body is the same keeps the name and is removed again as a duplicate. A function whose
    * own body is the same but which calls or refers to a function renamed in its context is renamed
    * in that context too, so the calls of every context reach that context's copies. Renames are
    * decided per unit and context and apply to that unit's diff only.
    *
    * `graphFiles` names the files, relative to the input path, whose methods the first context's
    * analysis of a unit wrote into the graph: the unit itself, and the headers a front end writes
    * as part of it.
    */
  def writeCopies(
    cpg: Cpg,
    analyses: Seq[ContextAnalysis],
    graphFiles: Path => Seq[String],
    diffGraph: DiffGraphBuilder
  ): Unit =
      analyses.groupBy(_.file).toSeq.sortBy(_._1.toString).foreach { (file, group) =>
        val renamed = renamesOf(cpg, group, graphFiles(file))
        group.foreach { analysis =>
          val mapping = renamed
              .getOrElse(analysis.fingerprint, Set.empty)
              .toSeq
              .map(name => name -> s"$name${suffix(analysis.fingerprint)}")
              .toMap
          renameCopies(analysis.diff, mapping, analysis.fingerprint)
          analysis.usedTypes.foreach(t => CGlobal.usedTypes.putIfAbsent(t, true))
          diffGraph.absorb(analysis.diff)
        }
      }

  /** The full names each context of one unit renames, by the context's fingerprint. */
  private def renamesOf(
    cpg: Cpg,
    group: Seq[ContextAnalysis],
    graphFiles: Seq[String]
  ): Map[String, Set[String]] =
    type Key = (String, String)
    val present = mutable.LinkedHashMap.empty[Key, mutable.ArrayBuffer[(Option[String], String)]]
    graphFiles.foreach { relative =>
        cpg.method.filenameExact(relative).l.foreach { m =>
            present.getOrElseUpdate((m.filename, m.fullName), mutable.ArrayBuffer.empty) +=
                (None -> bodyDigestOf(m))
        }
    }
    group.foreach { analysis =>
        analysis.methods.foreach { m =>
            present.getOrElseUpdate((m.filename, m.fullName), mutable.ArrayBuffer.empty) +=
                (Some(analysis.fingerprint) -> m.body)
        }
    }
    val renamed = mutable.HashMap.empty[String, mutable.Set[String]]
    present.foreach { (key, copies) =>
      val kept = copies.head._2
      copies.drop(1).foreach {
          case (Some(fingerprint), body) if body != kept =>
              renamed.getOrElseUpdate(fingerprint, mutable.Set.empty) += key._2
          case _ =>
      }
    }
    // a caller reaches its own context's copies: a function calling a renamed one is renamed too
    group.foreach { analysis =>
      val names   = renamed.getOrElseUpdate(analysis.fingerprint, mutable.Set.empty)
      var changed = names.nonEmpty
      while changed do
        changed = false
        analysis.methods.foreach { m =>
            if !names.contains(m.fullName) && m.callees.exists(names.contains) then
              names += m.fullName
              changed = true
        }
    }
    renamed.view.mapValues(_.toSet).filter(_._2.nonEmpty).toMap
  end renamesOf
end BuildContextCopies

/** The analyses of a file's extra build contexts: with `--c-build-contexts all`, a file the
  * compilation database compiles with more than one distinct context is analysed once per context,
  * the way the first context's analysis builds it, and the copies the extra contexts build are
  * named and tagged by [[BuildContextCopies]] before they are written.
  *
  * A function whose body is the same in every context is kept once: the extra contexts' copies are
  * the same definition at the same place, and [[BuildContextDuplicatesPass]] removes them again.
  * The extra analyses run fresh on every run, on this pass's thread, one file at a time; the AST
  * cache holds the first context's fragments, keyed as it always was.
  */
class BuildContextCopiesPass(cpg: Cpg, config: Config, sources: ProjectSources)
    extends CpgPass(cpg):

  import BuildContextCopies.ContextAnalysis

  override def run(diffGraph: DiffGraphBuilder): Unit =
      if !config.buildContextsAll then ()
      else
        try
          val analyses = extraContextAnalyses()
          if analyses.nonEmpty then writeCopies(analyses, diffGraph)
        finally executor.shutdownNow()
  end run

  /** The ASTs of the extra contexts, built fresh, one file's contexts after another's. */
  private def extraContextAnalyses(): Seq[ContextAnalysis] =
    val analyses = mutable.ArrayBuffer.empty[ContextAnalysis]
    sources.files.filterNot(FileDefaults.isHeaderFile).foreach { file =>
      val contexts = sources.contextsOf(Paths.get(file).toAbsolutePath)
      if contexts.size > 1 then
        contexts.drop(1).foreach { command =>
            analyse(Paths.get(file).toAbsolutePath, command).foreach(analyses += _)
        }
    }
    analyses.toSeq

  /** The AST one extra context builds for the file, in the context's settings, under the parse
    * timeout the AST pass uses for each of its parse and AST steps. A context whose parse fails,
    * times out or throws contributes nothing and is recorded in the parse report with the context
    * it belongs to; the file's other contexts and the rest of the run go on.
    */
  private def analyse(path: Path, command: CompileCommand): Option[ContextAnalysis] =
    val relative    = SourceFiles.toRelativePath(path.toString, config.inputPath)
    val fingerprint = BuildContextPass.fingerprintOf(command.flags, root)
    val parser      = new CdtParser(config, sources.headerFileFinder, sources)
    def report(stage: String, reason: String): None.type =
      ParseReporter.record(
        ParseReporter.Frontend.C,
        relative,
        ParseReporter.Outcome.Dropped,
        stage,
        s"build context ${fingerprint.take(8)}: $reason"
      )
      None
    // the scoped command is a thread local, so the work runs inside the scope on the worker thread
    def inContext[T](block: => T): T = sources.withContextCommand(command)(block)
    try
      val translationUnit =
          try timed(inContext(parser.parse(path)))
          catch
            case e: TimeoutException =>
                parser.cancel()
                throw e
      translationUnit match
        case None => None
        case Some(tu) =>
            val settings = inContext(sources.settingsFor(path))
            val creator = new AstCreator(
              relative,
              config,
              tu,
              new ConcurrentHashMap[String, Array[Int]](),
              p => sources.textOf(p, settings.language)
            )(using config.schemaValidation)
            val diff = timed(inContext(CdtLogging.captured(creator.createAst())))
            Some(ContextAnalysis(
              path,
              fingerprint,
              diff,
              BuildContextCopies.methodEntriesOf(diff),
              creator.usedTypes
            ))
    catch
      case e: TimeoutException => report(ParseReporter.Stage.Parse, ParseReporter.describe(e))
      case e: ExecutionException =>
          report(ParseReporter.Stage.Ast, ParseReporter.describe(Option(e.getCause).getOrElse(e)))
      case e: Throwable => report(ParseReporter.Stage.Ast, ParseReporter.describe(e))
    end try
  end analyse

  private val root = Paths.get(config.inputPath).toAbsolutePath.normalize

  /** The thread the extra contexts' parse and AST steps run on, so a step past the timeout can be
    * abandoned; one at a time, like the analyses themselves.
    */
  private lazy val executor = Executors.newSingleThreadExecutor { (r: Runnable) =>
    val t = new Thread(r, "c2cpg-build-context")
    t.setDaemon(true)
    t
  }

  /** Runs `block` on the pass's thread, waiting at most the AST pass's per-step timeout. */
  private def timed[T](block: => T): T =
    val future = executor.submit(new Callable[T]:
      override def call(): T = block
    )
    try future.get(AstCreationPass.parseTimeout.toMillis, TimeUnit.MILLISECONDS)
    catch
      case e: TimeoutException =>
          future.cancel(true)
          throw e

  private def writeCopies(analyses: Seq[ContextAnalysis], diffGraph: DiffGraphBuilder): Unit =
      BuildContextCopies.writeCopies(
        cpg,
        analyses,
        file => Seq(SourceFiles.toRelativePath(file.toString, config.inputPath)),
        diffGraph
      )
end BuildContextCopiesPass

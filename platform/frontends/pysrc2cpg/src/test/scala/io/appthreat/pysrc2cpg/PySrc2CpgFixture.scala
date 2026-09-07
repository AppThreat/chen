package io.appthreat.pysrc2cpg

import io.appthreat.dataflowengineoss.layers.dataflows.{OssDataFlow, OssDataFlowOptions}
import io.appthreat.dataflowengineoss.language.Path
import io.appthreat.dataflowengineoss.queryengine.EngineContext
import io.appthreat.dataflowengineoss.DefaultSemantics
import io.appthreat.dataflowengineoss.queryengine.summaries.FlowSummaryTags
import io.appthreat.dataflowengineoss.semanticsloader.FlowSemantic
import io.appthreat.x2cpg.{PythonDepsMode, X2Cpg}
import io.appthreat.x2cpg.passes.frontend.XTypeRecoveryConfig
import io.appthreat.x2cpg.passes.base.AstLinkerPass
import io.appthreat.x2cpg.testfixtures.{Code2CpgFixture, LanguageFrontend, TestCpg}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.semanticcpg.language.{ICallResolver, NoResolve}
import io.shiftleft.semanticcpg.layers.LayerCreatorContext

import java.nio.file.{Path as JPath, Paths}

trait PythonFrontend extends LanguageFrontend:
  override val fileSuffix: String = ".py"

  /** How dependency code should be treated (`Disabled` unless the suite opts in). */
  protected def pythonDeps: PythonDepsMode = PythonDepsMode.Disabled

  /** Runs with the project directory before the frontend does: suites that exercise dependency
    * stubs create their fake `.venv` here.
    */
  protected def prepareProject(dir: java.io.File): Unit = ()

  override def execute(sourceCodePath: java.io.File): Cpg =
    prepareProject(sourceCodePath)
    new Py2CpgOnFileSystem().createCpg(sourceCodePath.getAbsolutePath)(
      using
      new Py2CpgOnFileSystemConfig()
          .withPythonDeps(pythonDeps)
    ).get

class PySrcTestCpg extends TestCpg with PythonFrontend:
  private var _withOssDataflow                    = false
  private var _extraFlows                         = List.empty[FlowSemantic]
  private var _typeRecoveryConfig                 = XTypeRecoveryConfig()
  private var _pythonDeps                         = PythonDepsMode.Disabled
  private var _venvDir: JPath                     = Paths.get(".venv")
  private var _typeshedDir: Option[JPath]         = None
  private var _ignoreVenvDir                      = true
  private var _projectSetup: java.io.File => Unit = _ => ()

  def withOssDataflow(value: Boolean = true): this.type =
    _withOssDataflow = value
    this

  def withExtraFlows(value: List[FlowSemantic] = List.empty): this.type =
    _extraFlows = value
    this

  def withTypeRecoveryConfig(value: XTypeRecoveryConfig): this.type =
    _typeRecoveryConfig = value
    this

  def withPythonDeps(value: PythonDepsMode): this.type =
    _pythonDeps = value
    this

  /** An out-of-tree venv for the dependency modes (`venv-dir` in production). */
  def withVenvDir(value: JPath): this.type =
    _venvDir = value
    this

  def withTypeshedDir(value: JPath): this.type =
    _typeshedDir = Some(value)
    this

  /** The legacy walk switch: `false` parses the venv with the project's own file walk. */
  def withIgnoreVenvDir(value: Boolean): this.type =
    _ignoreVenvDir = value
    this

  def withProjectSetup(setup: java.io.File => Unit): this.type =
    _projectSetup = setup
    this

  override protected def pythonDeps: PythonDepsMode = _pythonDeps

  override protected def prepareProject(dir: java.io.File): Unit = _projectSetup(dir)

  override def execute(sourceCodePath: java.io.File): Cpg =
    prepareProject(sourceCodePath)
    val base = new Py2CpgOnFileSystemConfig()
        .withPythonDeps(pythonDeps)
        .withVenvDir(_venvDir)
        .withIgnoreVenvDir(_ignoreVenvDir)
    val configured = _typeshedDir match
      case Some(dir) => base.withTypeshedDir(dir)
      case None      => base
    new Py2CpgOnFileSystem().createCpg(sourceCodePath.getAbsolutePath)(using configured).get

  override def applyPasses(): Unit =
    X2Cpg.applyDefaultOverlays(this)
    new ImportsPass(this).createAndApply()
    new ImportResolverPass(this).createAndApply()
    new PythonInheritanceNamePass(this).createAndApply()
    new DynamicTypeHintFullNamePass(this).createAndApply()
    new PythonAnnotationTypePass(this).createAndApply()
    new PythonTypeRecoveryPass(this, _typeRecoveryConfig).createAndApply()
    new PythonTypeHintCallLinker(this).createAndApply()
    new PythonCallSiteReturnTypePass(this).createAndApply()
    new PythonPseudoTypeSanityPass(
      this,
      removeDummyTypes = !_typeRecoveryConfig.enabledDummyTypes
    ).createAndApply()
    // The dotted full-name index is derived from the finished graph; run it after
    // every pass that creates or renames methods.

    // Some of passes above create new methods, so, we
    // need to run the ASTLinkerPass one more time
    new AstLinkerPass(this).createAndApply()

    if _withOssDataflow then
      val context = new LayerCreatorContext(this)
      // Mirrors atom's `dependencySemantics`: summaries left on ingested dependency
      // signatures become declared semantics, so a suite exercises the same wiring
      // production uses. Empty unless `python-deps=summaries` ingested something.
      val depSemantics = FlowSummaryTags.externalSemantics(
        this,
        DefaultSemantics().elements.map(_.methodFullName).toSet
      )
      val options = new OssDataFlowOptions(extraFlows = _extraFlows ++ depSemantics)
      new OssDataFlow(options).run(context)
      // Mirrors atom's enhancement order: the t-string renderer bridges run after the DDG
      // exists (task 12 D.1).
      new PythonTemplateRenderPass(this).createAndApply()
  end applyPasses
end PySrcTestCpg

/** @param typeRecoveryConfig
  *   the type-recovery configuration to build with. Defaults to the defaults of
  *   [[XTypeRecoveryConfig]], which ENABLE dummy types - so most suites here exercise the recovery
  *   with its placeholders visible. That is not the configuration atom ships for Python; pass
  *   [[PySrc2CpgFixture.shippedTypeRecoveryConfig]] to test the production shape.
  */
class PySrc2CpgFixture(
  withOssDataflow: Boolean = false,
  extraFlows: List[FlowSemantic] = List.empty,
  typeRecoveryConfig: XTypeRecoveryConfig = XTypeRecoveryConfig()
) extends Code2CpgFixture(() =>
        new PySrcTestCpg()
            .withOssDataflow(withOssDataflow)
            .withExtraFlows(extraFlows)
            .withTypeRecoveryConfig(typeRecoveryConfig)
    ):

  implicit val resolver: ICallResolver = NoResolve
  implicit val context: EngineContext  = EngineContext()

  protected def flowToResultPairs(path: Path): List[(String, Integer)] =
      path.resultPairs().collect { case (firstElement: String, secondElement: Option[Integer]) =>
          (firstElement, secondElement.getOrElse(-1))
      }

object PySrc2CpgFixture:

  /** The configuration atom builds Python graphs with: two propagation iterations and no dummy
    * types. Kept here so suites can assert against the shape that actually ships rather than
    * against the fixture default, which enables placeholders.
    */
  val shippedTypeRecoveryConfig: XTypeRecoveryConfig =
      XTypeRecoveryConfig(iterations = 2, enabledDummyTypes = false)

package io.appthreat.x2cpg.passes.taggers.python

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*
import overflowdb.BatchedUpdate.DiffGraphBuilder

/** Registry of the Python framework recognizers. Adding a framework means adding one recognizer
  * (one file) and one entry here - there is no shared match block to edit.
  */
object PythonRecognizers:

  val all: Seq[PythonFrameworkRecognizer] = Seq(
    // B1 - web/HTTP routes
    FlaskRecognizer,
    FastAPIRecognizer,
    StarletteRecognizer,
    SanicRecognizer,
    BottleRecognizer,
    AiohttpRouteRecognizer,
    TornadoRecognizer,
    FalconRecognizer,
    DjangoRecognizer,
    // B2 - models as taint carriers
    ModelTaintRecognizer,
    // B3 - request objects
    RequestObjectRecognizer,
    // B4 - RPC and MCP
    GrpcRecognizer,
    McpRecognizer,
    // B5 - AI/LLM
    AiLlmRecognizer,
    // B6 - cloud, queues, ORM
    Boto3Recognizer,
    LambdaHandlerRecognizer,
    AzureFunctionsRecognizer,
    GcpCloudFunctionRecognizer,
    TaskQueueRecognizer,
    OrmRecognizer
  )
end PythonRecognizers

/** Applies the registered [[PythonFrameworkRecognizer]]s to a Python CPG.
  *
  * Strictly Python-gated (dispatch on `metaData.language`, like EasyTagsPass), so no other
  * language's tagging is affected. Each recognizer's `applies` gate is keyed on imports or another
  * indexed lookup, so the per-recognizer cost on projects that don't use the framework stays near
  * zero.
  */
class PythonFrameworkRecognizersPass(cpg: Cpg) extends CpgPass(cpg):

  private def language: String = cpg.metaData.language.headOption.getOrElse("")

  override def run(dstGraph: DiffGraphBuilder): Unit =
      if language == Languages.PYTHON || language == Languages.PYTHONSRC then
        PythonRecognizers.all.foreach { recognizer =>
            if recognizer.applies(cpg) then recognizer.run(cpg, dstGraph)
        }

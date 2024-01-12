package io.appthreat.x2cpg.passes.taggers

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.Languages
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Creates tags on any node
  */
class EasyTagsPass(atom: Cpg) extends CpgPass(atom):

    val language: String = atom.metaData.language.head

    override def run(dstGraph: DiffGraphBuilder): Unit =
        atom.method.internal.name(".*(valid|check).*").newTagNode("validation").store()(dstGraph)
        atom.method.internal.name("is[A-Z].*").newTagNode("validation").store()(dstGraph)
        if language == Languages.PYTHON || language == Languages.PYTHONSRC then
            atom.method.internal.name("is_[a-z].*").newTagNode("validation").store()(dstGraph)
        atom.method.internal.name(".*(encode|escape|sanit).*").newTagNode("sanitization").store()(
          dstGraph
        )
        atom.method.internal.name(".*(login|authenti).*").newTagNode("authentication").store()(
          dstGraph
        )
        atom.method.internal.name(".*(authori).*").newTagNode("authorization").store()(dstGraph)
        if language == Languages.NEWC || language == Languages.C
        then
            atom.method.internal.name("main").parameter.newTagNode("cli-source").store()(dstGraph)
            atom.method.internal.name("wmain").parameter.newTagNode("cli-source").store()(dstGraph)
            atom.method.external.name("(cuda|curl_|BIO_).*").parameter.newTagNode(
              "library-call"
            ).store()(
              dstGraph
            )
            atom.method.external.name("DriverEntry").parameter.newTagNode("driver-source").store()(
              dstGraph
            )
            atom.method.external.name("WdfDriverCreate").parameter.newTagNode(
              "driver-source"
            ).store()(dstGraph)
            atom.method.external.name("OnDeviceAdd").parameter.newTagNode(
              "driver-source"
            ).store()(dstGraph)
            atom.method.external.fullName(
              "(Aws|Azure|google|cloud)(::|\\.).*"
            ).parameter.newTagNode(
              "cloud"
            ).store()(dstGraph)
            atom.method.external.fullName("(CDevice|CDriver)(::|\\.).*").parameter.newTagNode(
              "device-driver"
            ).store()(dstGraph)
            atom.method.external.fullName(
              "(Windows|WEX|WDMAudio|winrt|wilEx)(::|\\.).*"
            ).parameter.newTagNode("windows").store()(dstGraph)
            atom.method.external.fullName("(RpcServer)(::|\\.).*").parameter.newTagNode(
              "rpc"
            ).store()(
              dstGraph
            )
            atom.method.external.fullName(
              "(Pistache|Http|Rest|oatpp|HttpClient|HttpRequest|WebSocketClient|HttpResponse|drogon|chrono|httplib|web)(::|\\.).*"
            ).parameter.newTagNode(
              "http"
            ).store()(
              dstGraph
            )
            atom.method.external.name("(kore_|onion_|coro_).*").parameter.newTagNode(
              "http"
            ).store()(
              dstGraph
            )
        end if
        if language == Languages.PHP
        then
            atom.call.code("\\$_(GET|POST|FILES|REQUEST|COOKIE|SESSION|ENV).*").argument.newTagNode(
              "framework-input"
            ).store()(dstGraph)
            atom.method.name("__serialize").newTagNode("serialization").store()(dstGraph)
            atom.method.name("__unserialize").newTagNode("deserialization").store()(dstGraph)
    end run
end EasyTagsPass

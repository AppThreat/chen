package io.appthreat.x2cpg.passes.taggers

import io.circe.*
import io.circe.parser.*
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.NewNamespace
import io.shiftleft.passes.CpgPass
import io.shiftleft.semanticcpg.language.*

/** Creates tags on typeDecl and call nodes based on a cdx document
  */
class CdxPass(cpg: Cpg) extends CpgPass(cpg) {

  // Some hardcoded list of keywords to look for in the description. Hopefully this would be performed with a better category tagger in the future
  private val keywords = Seq(
    "sql",
    "http",
    "xml",
    "web",
    "security",
    "database",
    "json",
    "yaml",
    "validation",
    "sanitization",
    "cloud",
    "iam",
    "auth",
    "middleware",
    "serialization",
    "event",
    "stream",
    "rpc",
    "socket",
    "proto",
    "resource",
    "data",
    "sensitive",
    "template",
    "log",
    "service",
    "api",
    "slf4j",
    "parse",
    "emit",
    "jdbc",
    "connection",
    "pool",
    "beans",
    "transaction",
    "mysql",
    "postgres",
    "oracle",
    "mongo",
    "redis",
    "splunk",
    "stripe",
    "payment",
    "finance",
    "currency",
    "coin",
    "monero",
    "ssl",
    "traffic",
    "mvc",
    "html",
    "escape",
    "rest",
    "tomcat",
    "jackson",
    "hibernate",
    "orm",
    "aop",
    "jwt",
    "saml",
    "token",
    "tls",
    "codec",
    "cron",
    "crypto",
    "jce",
    "certificate",
    "developer",
    "tools",
    "autoconfigure",
    "test",
    "jsonpath",
    "bytecode",
    "mock",
    "injection"
  )

  override def run(dstGraph: DiffGraphBuilder): Unit = {
    cpg.configFile("bom.json").content.foreach { cdxData =>
      val cdxJson         = parse(cdxData).getOrElse(Json.Null)
      val cursor: HCursor = cdxJson.hcursor
      val components      = cursor.downField("components").focus.flatMap(_.asArray).getOrElse(Vector.empty)
      components.foreach { comp =>
        val compPurl                = comp.hcursor.downField("purl").as[String].getOrElse("")
        val compType                = comp.hcursor.downField("type").as[String].getOrElse("")
        val compDescription: String = comp.hcursor.downField("description").as[String].getOrElse("")
        val descTags                = keywords.filter(compDescription.toLowerCase().contains(_))
        val properties = comp.hcursor.downField("properties").focus.flatMap(_.asArray).getOrElse(Vector.empty)
        properties.foreach { ns =>
          val nsstr = ns.hcursor.downField("value").as[String].getOrElse("")
          nsstr.split("\n").foreach { (pkg: String) =>
            val bpkg = pkg.takeWhile(_ != '$')
            cpg.typeDecl.fullNameExact(bpkg).newTagNodePair("purl", compPurl).store()(dstGraph)
            cpg.call.typeFullNameExact(bpkg).newTagNodePair("purl", compPurl).store()(dstGraph)
            cpg.method.parameter.typeFullNameExact(bpkg).newTagNodePair("purl", compPurl).store()(dstGraph)
            if (compType != "library") {
              cpg.typeDecl.fullNameExact(bpkg).newTagNode(compType).store()(dstGraph)
              cpg.call.typeFullNameExact(bpkg).newTagNode(compType).store()(dstGraph)
              cpg.method.parameter.typeFullNameExact(bpkg).newTagNode(compType).store()(dstGraph)
            }
            descTags.foreach { t =>
              cpg.typeDecl.fullNameExact(bpkg).newTagNode(t).store()(dstGraph)
              cpg.call.typeFullNameExact(bpkg).newTagNode(t).store()(dstGraph)
              cpg.method.parameter.typeFullNameExact(bpkg).newTagNode(t).store()(dstGraph)
            }
          }
        }
      }
    }
  }

}

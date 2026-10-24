package io.appthreat.x2cpg.passes.frontend

import io.appthreat.x2cpg.AstFragment
import io.appthreat.x2cpg.passes.frontend.AstCacheStore.{CacheKey, ParsedUnit}
import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.{EdgeTypes, NodeTypes}
import io.shiftleft.codepropertygraph.generated.nodes.{NewBlock, NewLiteral, NewMethod}
import overflowdb.{BatchedUpdate, DetachedNodeGeneric}
import overflowdb.BatchedUpdate.DiffGraphBuilder
import overflowdb.util.DiffTool
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.nio.file.{Files, Paths}
import java.security.MessageDigest
import scala.jdk.CollectionConverters.*

/** End-to-end check of the fragment-codec mode of [[AstCacheStore]]: a cold run parses the part and
  * writes the on-disk fragment; a subsequent warm run reuses it WITHOUT reparsing and reconstructs
  * an identical graph and the same `usedTypes`.
  */
class AstCacheStoreFragmentTests extends AnyWordSpec with Matchers:

  private def buildUnit(): DiffGraphBuilder =
    val diff  = new DiffGraphBuilder
    val m     = NewMethod().name("foo").fullName("foo").lineNumber(7).order(1)
    val block = NewBlock().typeFullName("ANY").order(1)
    val lit   = NewLiteral().code("42").lineNumber(99).order(1)
    diff.addNode(m); diff.addNode(block); diff.addNode(lit)
    diff.addEdge(m, block, EdgeTypes.AST)
    diff.addEdge(block, lit, EdgeTypes.AST)
    diff

  private def fragmentStore(dir: String): AstCacheStore =
      new AstCacheStore(
        enableAstCacheParam = true,
        dir,
        onlyAstCache = false,
        useFragmentCache = true
      )

  private def keyBeforeRevision(key: CacheKey, fingerprint: String): String =
    val digest = MessageDigest.getInstance("SHA-256")
    digest.update(key.identity.getBytes("UTF-8"))
    digest.update(fingerprint.getBytes("UTF-8"))
    digest.update(key.content)
    digest.digest().map("%02x".format(_)).mkString

  "AstCacheStore in fragment mode" should:
    "reuse the on-disk fragment on a warm run (no reparse) and reconstruct an identical graph" in:
      val dir = Files.createTempDirectory("astfragcache").toString
      val store =
          new AstCacheStore(
            enableAstCacheParam = true,
            dir,
            onlyAstCache = false,
            useFragmentCache = true
          )
      val key       = CacheKey("file1", "content-v1".getBytes("UTF-8"))
      val usedTypes = Seq("int", "com.example.T")

      var parses = 0
      def parse(): Option[ParsedUnit] =
        parses += 1
        Some(ParsedUnit(buildUnit(), usedTypes))

      var coldTypes = Seq.empty[String]
      val cold      = new DiffGraphBuilder
      store.process(cold, "file1", Some(key), "", t => coldTypes = t.toSeq, parse())

      var warmTypes = Seq.empty[String]
      val warm      = new DiffGraphBuilder
      store.process(warm, "file1", Some(key), "", t => warmTypes = t.toSeq, parse())

      parses shouldBe 1 // only the cold run reparsed; the warm run hit the cache
      coldTypes shouldBe usedTypes
      warmTypes shouldBe usedTypes

      val gCold = Cpg.emptyCpg
      BatchedUpdate.applyDiff(gCold.graph, cold)
      val gWarm = Cpg.emptyCpg
      BatchedUpdate.applyDiff(gWarm.graph, warm)

      val diff = DiffTool.compare(gCold.graph, gWarm.graph).asScala.toList
      withClue(diff.mkString("\n")) { diff shouldBe empty }
      gWarm.graph.nodeCount() shouldBe 3

    "find, for a warm restore, the fragment a cold run wrote" in:
      val dir   = Files.createTempDirectory("astfragcache").toString
      val store = fragmentStore(dir)
      val key   = CacheKey("file1", "content-v1".getBytes("UTF-8"))

      store.process(
        new DiffGraphBuilder,
        "file1",
        Some(key),
        "fp",
        _ => (),
        Some(ParsedUnit(buildUnit()))
      )

      store.fragmentFor(Some(key), "fp") shouldBe defined

    "never serve a fragment an earlier build wrote for the same part" in:
      val dir   = Files.createTempDirectory("astfragcache").toString
      val store = fragmentStore(dir)
      val key   = CacheKey("file1", "content-v1".getBytes("UTF-8"))
      // What a native-image build wrote before this revision: the nodes, without their properties.
      val stale = new DiffGraphBuilder
      stale.addNode(new DetachedNodeGeneric(NodeTypes.METHOD))
      Files.write(
        Paths.get(dir, s"${keyBeforeRevision(key, "fp")}.frag"),
        AstFragment.encode(stale, Nil).get
      )

      store.fragmentFor(Some(key), "fp") shouldBe None

      var parses = 0
      val warm   = new DiffGraphBuilder
      store.process(
        warm,
        "file1",
        Some(key),
        "fp",
        _ => (),
        { parses += 1; Some(ParsedUnit(buildUnit())) }
      )
      val graph = Cpg.emptyCpg
      BatchedUpdate.applyDiff(graph.graph, warm)

      parses shouldBe 1
      graph.graph.nodes(NodeTypes.METHOD).asScala.map(_.property("NAME")).toList shouldBe List(
        "foo"
      )
end AstCacheStoreFragmentTests

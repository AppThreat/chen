package io.appthreat.jssrc2cpg

import better.files.File
import _root_.io.appthreat.x2cpg.passes.frontend.CacheControl
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** The jssrc2cpg per-file AST cache under Flux (CHEN3_PLAN §3/§4). With fragment caching enabled
  * and a fixed astgen output directory (so JSON paths are stable, as with CHEN_ASTGEN_OUT), a cold
  * `createCpg` parses and writes per-file `.frag` mini-graphs, and a warm `createCpg` reconstructs a
  * structurally identical CPG from the cache (skipping Babel parsing + AST creation).
  *
  * JS per-file diffs reference BINDING/LOCAL nodes only via edges; the fragment codec now treats
  * such edge-endpoint detached nodes as fragment-local (mirroring applyDiff), so these diffs are
  * self-contained and cacheable.
  */
class JsAstCacheTests extends AnyWordSpec with Matchers:

  "jssrc2cpg under --flux fragment caching" should:
    "cache per-file fragments and reconstruct an identical CPG on a warm run" in:
      val src       = File.newTemporaryDirectory("jsflux-src")
      val astgenOut = File.newTemporaryDirectory("jsflux-astgen")
      CacheControl.enableFragments()
      try
        (src / "a.js").write("function foo(x) { return bar(x); }\n")
        (src / "b.js").write("function bar(y) { return y + 1; }\n")

        def build(): Cpg =
          val out = File.newTemporaryFile("jsflux", ".atom")
          out.deleteOnExit()
          new JsSrc2Cpg().createCpg(
            Config()
              .withInputPath(src.pathAsString)
              .withOutputPath(out.pathAsString)
              .withAstGenOutDir(astgenOut.pathAsString)
          ).get

        val cold       = build()
        val coldLabels = cold.all.label.groupCount
        val coldNodes  = cold.graph.nodeCount()
        val coldEdges  = cold.graph.edgeCount()
        cold.close()

        // The cold run wrote per-file fragments (JS diffs are now self-contained).
        (src / ".chen").glob("*.frag").toList should not be empty

        val warm       = build()
        val warmLabels = warm.all.label.groupCount
        val warmNodes  = warm.graph.nodeCount()
        val warmEdges  = warm.graph.edgeCount()
        val methods    = warm.method.fullName.toList
        warm.close()

        warmNodes shouldBe coldNodes
        warmEdges shouldBe coldEdges
        warmLabels shouldBe coldLabels
        methods.exists(_.contains("foo")) shouldBe true
        methods.exists(_.contains("bar")) shouldBe true
      finally
        CacheControl.disableFragments()
        src.delete(swallowIOExceptions = true)
        astgenOut.delete(swallowIOExceptions = true)
end JsAstCacheTests

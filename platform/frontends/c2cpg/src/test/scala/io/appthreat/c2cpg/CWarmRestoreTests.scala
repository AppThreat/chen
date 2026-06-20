package io.appthreat.c2cpg

import better.files.File
import _root_.io.appthreat.x2cpg.passes.frontend.CacheControl
import _root_.io.shiftleft.codepropertygraph.Cpg
import _root_.io.shiftleft.semanticcpg.language.*
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

/** Validates the c2cpg fastest-splice warm restore (CHEN3_PLAN §3.4): with fragment caching enabled
  * (atom `--flux`), a cold `createCpg` parses the project and writes per-file `.frag` mini-graphs;
  * a second `createCpg` over the same sources reconstructs the AST layer by splicing those
  * fragments (no parsing, no diff rebuild) and yields a structurally identical graph.
  */
class CWarmRestoreTests extends AnyWordSpec with Matchers:

  "c2cpg warm restore from fragments" should:
    "reconstruct a structurally identical AST layer as a cold parse" in:
      val dir = File.newTemporaryDirectory("c2flux")
      CacheControl.enableFragments()
      try
        (dir / "a.c").write("int bar(int);\nint foo(int x) { return bar(x); }\n")
        (dir / "b.c").write("int bar(int y) { return y + 1; }\n")

        def build(): Cpg =
          val out = File.newTemporaryFile("c2flux", ".atom")
          out.deleteOnExit()
          new C2Cpg().createCpg(
            Config().withInputPath(dir.pathAsString).withOutputPath(out.pathAsString)
          ).get

        // Cold: no fragments yet -> parses and writes .frag files.
        val cold       = build()
        val coldLabels = cold.all.label.groupCount
        val coldNodes  = cold.graph.nodeCount()
        val coldEdges  = cold.graph.edgeCount()
        cold.close()

        (dir / ".chen").glob("*.frag").toList should not be empty

        // Warm: every file is cached -> reconstructed by FragmentSplicePass.
        val warm       = build()
        val warmLabels = warm.all.label.groupCount
        val warmNodes  = warm.graph.nodeCount()
        val warmEdges  = warm.graph.edgeCount()
        val methods    = warm.method.fullName.toSet
        warm.close()

        warmNodes shouldBe coldNodes
        warmEdges shouldBe coldEdges
        warmLabels shouldBe coldLabels
        (methods should contain).allOf("foo", "bar")
      finally
        CacheControl.disableFragments()
        dir.delete(swallowIOExceptions = true)
      end try
end CWarmRestoreTests

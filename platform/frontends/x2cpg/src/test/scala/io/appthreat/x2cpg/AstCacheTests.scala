package io.appthreat.x2cpg

import io.shiftleft.codepropertygraph.Cpg
import io.shiftleft.codepropertygraph.generated.EdgeTypes
import io.shiftleft.codepropertygraph.generated.nodes.{NewDependency, NewImport, NewLiteral, NewMethod}
import overflowdb.BatchedUpdate.DiffGraphBuilder
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import upickle.default.*

import scala.jdk.CollectionConverters.*

class AstCacheTests extends AnyWordSpec with Matchers {

    "AstCache value codec" should {

        "round-trip a Long larger than 2^53 without loss of precision" in {
            val big     = (1L << 60) + 12345L
            val encoded = writeBinary(AstCache.CachedValue.I64(big))
            readBinary[AstCache.CachedValue](encoded) shouldBe AstCache.CachedValue.I64(big)
        }

        "preserve the distinct numeric, char and byte types" in {
            val values: List[AstCache.CachedValue] = List(
              AstCache.CachedValue.I32(7),
              AstCache.CachedValue.I64(7L),
              AstCache.CachedValue.Chr('z'),
              AstCache.CachedValue.I8(5.toByte),
              AstCache.CachedValue.I16(9.toShort),
              AstCache.CachedValue.F32(1.5f),
              AstCache.CachedValue.F64(2.5d),
              AstCache.CachedValue.StrList(Vector("a", "b"))
            )
            values.foreach { v =>
                readBinary[AstCache.CachedValue](writeBinary(v)) shouldBe v
            }
        }
    }

    "AstCache bitcode" should {

        "be rejected when the format version is incompatible" in {
            val bitcode = AstCache.AstBitcode(AstCache.FormatTag, AstCache.FormatVersion + 1, Nil, Nil)
            AstCache.isCompatible(bitcode) shouldBe false
            val cpg       = Cpg.emptyCpg
            val diffGraph = new DiffGraphBuilder
            AstCache.storeInDiffGraph(bitcode, diffGraph) shouldBe false
            overflowdb.BatchedUpdate.applyDiff(cpg.graph, diffGraph.build())
            cpg.graph.nodeCount() shouldBe 0
        }

        "round-trip a diff graph through a save/load cycle, preserving nodes, edges and values" in {
            // method --AST--> literal; the literal carries an Integer line number and a String code
            val method  = NewMethod().name("foo").fullName("foo").lineNumber(7)
            val literal = NewLiteral().code("42").order(1).lineNumber(99)
            val source  = new DiffGraphBuilder
            source.addNode(method).addNode(literal).addEdge(method, literal, EdgeTypes.AST)

            val bitcode = AstCache.toBitcode(source).get
            bitcode.formatTag shouldBe AstCache.FormatTag
            AstCache.isCompatible(bitcode) shouldBe true

            // simulate a save/load cycle across process boundaries
            val reloaded = readBinary[AstCache.AstBitcode](writeBinary(bitcode))

            val cpg       = Cpg.emptyCpg
            val diffGraph = new DiffGraphBuilder
            AstCache.storeInDiffGraph(reloaded, diffGraph) shouldBe true
            overflowdb.BatchedUpdate.applyDiff(cpg.graph, diffGraph.build())

            val methodNode  = cpg.graph.nodes("METHOD").asScala.toList
            val literalNode = cpg.graph.nodes("LITERAL").asScala.toList
            methodNode.map(_.property("NAME")) shouldBe List("foo")
            literalNode.map(_.property("CODE")) shouldBe List("42")
            // the Integer line number survived the round-trip with its exact value and type
            literalNode.head.property("LINE_NUMBER").asInstanceOf[Integer].intValue shouldBe 99
            // the AST edge survived
            methodNode.head.out("AST").asScala.toList.map(_.label()) shouldBe List("LITERAL")
        }

        "capture non-AST edges such as IMPORTS, which an AST-only cache would miss" in {
            // mirrors how c2cpg records dependencies: an IMPORTS edge to a dependency node that is
            // not part of the AST tree
            val importNode = NewImport().code("#include <io.h>").importedEntity("io.h")
            val depNode    = NewDependency().name("io.h").version("include")
            val source     = new DiffGraphBuilder
            source.addNode(importNode).addNode(depNode).addEdge(importNode, depNode, EdgeTypes.IMPORTS)

            val reloaded = readBinary[AstCache.AstBitcode](writeBinary(AstCache.toBitcode(source).get))
            val cpg      = Cpg.emptyCpg
            val diffGraph = new DiffGraphBuilder
            AstCache.storeInDiffGraph(reloaded, diffGraph) shouldBe true
            overflowdb.BatchedUpdate.applyDiff(cpg.graph, diffGraph.build())

            cpg.graph.nodes("IMPORT").asScala.toList.head
                .out("IMPORTS").asScala.toList.map(_.label()) shouldBe List("DEPENDENCY")
        }
    }
}

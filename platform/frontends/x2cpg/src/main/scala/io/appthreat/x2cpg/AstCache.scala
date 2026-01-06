package io.appthreat.x2cpg

import io.shiftleft.codepropertygraph.generated.nodes.NewNode
import upickle.default.*

import scala.jdk.CollectionConverters.*
import scala.util.{Failure, Success, Try}

object AstCache:

  case class AstNodeBitcode(className: String, properties: Map[String, ujson.Value])
      derives ReadWriter

  case class AstEdgeBitcode(srcId: Int, dstId: Int, label: String)
      derives ReadWriter

  /** Represents the serialized "Bitcode" of an AST.
    */
  case class AstBitcode(
    rootIdx: Option[Int],
    nodes: List[AstNodeBitcode],
    edges: List[AstEdgeBitcode]
  ) derives ReadWriter

  def toBitcode(ast: Ast): AstBitcode =
    val allNodes    = ast.nodes.distinct.toVector
    val nodeToIndex = allNodes.zipWithIndex.toMap

    val cachedNodes = allNodes.map { n =>
      val propsMap = n.properties match
        case m: java.util.Map[?, ?]        => m.asScala
        case m: scala.collection.Map[?, ?] => m
        case null                          => Map.empty

      val safeProps = propsMap.map {
          case (k: String, v) => k          -> toUjson(v)
          case (k, v)         => k.toString -> toUjson(v)
      }.toMap

      AstNodeBitcode(n.getClass.getName, safeProps)
    }.toList

    def serializeEdgeList(
      edges: scala.collection.Seq[AstEdge],
      label: String
    ): List[AstEdgeBitcode] =
        edges.collect {
            case e if nodeToIndex.contains(e.src) && nodeToIndex.contains(e.dst) =>
                AstEdgeBitcode(nodeToIndex(e.src), nodeToIndex(e.dst), label)
        }.toList

    val allEdges =
        serializeEdgeList(ast.edges, "AST") ++
            serializeEdgeList(ast.refEdges, "REF") ++
            serializeEdgeList(ast.bindsEdges, "BINDS") ++
            serializeEdgeList(ast.receiverEdges, "RECEIVER") ++
            serializeEdgeList(ast.argEdges, "ARGUMENT") ++
            serializeEdgeList(ast.conditionEdges, "CONDITION") ++
            serializeEdgeList(ast.captureEdges, "CAPTURE")

    val rootIdx = ast.root.flatMap(nodeToIndex.get)

    AstBitcode(rootIdx, cachedNodes, allEdges)
  end toBitcode

  def fromBitcode(bitcode: AstBitcode)(implicit validation: ValidationMode): Ast =
    val nodesVector = bitcode.nodes.map(reconstructNode).toVector

    def getEdges(label: String): Seq[AstEdge] =
        bitcode.edges.collect {
            case ce if ce.label == label =>
                AstEdge(nodesVector(ce.srcId), nodesVector(ce.dstId))
        }

    Ast(
      nodesVector,
      getEdges("AST"),
      getEdges("CONDITION"),
      getEdges("REF"),
      getEdges("BINDS"),
      getEdges("RECEIVER"),
      getEdges("ARGUMENT"),
      getEdges("CAPTURE")
    )
  end fromBitcode

  private def toUjson(v: Any): ujson.Value = v match
    case s: String       => ujson.Str(s)
    case b: Boolean      => ujson.Bool(b)
    case i: Int          => ujson.Num(i)
    case l: Long         => ujson.Num(l.toDouble)
    case d: Double       => ujson.Num(d)
    case xs: Iterable[?] => ujson.Arr.from(xs.map(toUjson))
    case xs: Array[?]    => ujson.Arr.from(xs.map(toUjson))
    case other           => ujson.Str(other.toString)

  private def fromUjson(v: ujson.Value): Any = v match
    case ujson.Str(s)  => s
    case ujson.Bool(b) => b
    case ujson.Num(n) =>
        if n.isValidInt then n.toInt
        else if n.toLong.toDouble == n then n.toLong
        else n
    case ujson.Arr(arr) => arr.map(fromUjson).toList
    case _              => v.toString

  private def reconstructNode(cn: AstNodeBitcode): NewNode =
    if !cn.className.startsWith("io.shiftleft.codepropertygraph.generated.nodes.") then
      throw new SecurityException(s"Illegal class in cache: ${cn.className}")

    val clazz = Class.forName(cn.className)
    val node  = clazz.getDeclaredConstructor().newInstance().asInstanceOf[NewNode]

    cn.properties.foreach { case (k, v) =>
        try
          val camelName = snakeToCamel(k)
          val methods   = clazz.getMethods
          var method    = methods.find(_.getName == camelName)
          if method.isEmpty then
            method = methods.find(_.getName.equalsIgnoreCase(k.replace("_", "")))

          if method.isDefined && method.get.getParameterCount == 1 then
            val arg = fromUjson(v)
            method.get.invoke(node, arg.asInstanceOf[Object])
        catch
          case _: Exception =>
    }
    node
  end reconstructNode

  private def snakeToCamel(s: String): String =
    val tokens = s.split("_")
    if tokens.isEmpty then return s.toLowerCase
    val sb = new StringBuilder(tokens(0).toLowerCase)
    for i <- 1 until tokens.length do
      val t = tokens(i).toLowerCase
      if t.nonEmpty then
        sb.append(t.substring(0, 1).toUpperCase).append(t.substring(1))
    sb.toString

end AstCache

package io.shiftleft.semanticcpg.language

import io.shiftleft.codepropertygraph.generated.nodes.{AbstractNode, Method}
import io.shiftleft.semanticcpg.utils.Torch
import org.json4s.native.Serialization.{write, writePretty}
import org.json4s.{CustomSerializer, Extraction, Formats}
import overflowdb.traversal.help.Doc
import replpp.Colors
import replpp.Operators.*

import java.util.List as JList
import scala.collection.mutable
import scala.jdk.CollectionConverters.*
import me.shadaj.scalapy.py
import me.shadaj.scalapy.py.SeqConverters
import py.PyQuote
import me.shadaj.scalapy.interpreter.CPythonInterpreter

import java.nio.file.Files

/** Base class for our DSL These are the base steps available in all steps of the query language.
  * There are no constraints on the element types, unlike e.g. [[NodeSteps]]
  */
class Steps[A](val traversal: Iterator[A]) extends AnyVal:

  /** Execute the traversal and convert it to a mutable buffer
    */
  def toBuffer(): mutable.Buffer[A] = traversal.to(mutable.Buffer)

  /** Shorthand for `toBuffer`
    */
  def b: mutable.Buffer[A] = toBuffer()

  /** Alias for `toList`
    * @deprecated
    */
  def exec(): List[A] = traversal.toList

  /** Execute the travel and convert it to a Java stream.
    */
  def toStream(): LazyList[A] = traversal.to(LazyList)

  /** Alias for `toStream`
    */
  def s: LazyList[A] = toStream()

  /** Execute the traversal and convert it into a Java list (as opposed to the Scala list obtained
    * via `toList`)
    */
  def jl: JList[A] = b.asJava

  /** Execute this traversal and pretty print the results. This may mean that not all properties of
    * the node are displayed or that some properties have undergone transformations to improve
    * display. A good example is flow pretty-printing. This is the only three of the methods which
    * we may modify on a per-node-type basis, typically via implicits of type Show[NodeType].
    */
  @Doc(info = "execute this traversal and pretty print the results")
  def p(implicit show: Show[A] = Show.default): List[String] =
      traversal.toList.map(show.apply)

  @Doc(info = "execute this traversal and print tabular result")
  def t(implicit show: Show[A] = Show.default): Unit =
      traversal.toList.map(show.apply)

  @Doc(info = "execute this traversal and show the pretty-printed results in `less`")
  // uses scala-repl-pp's `#|^` operator which let's `less` inherit stdin and stdout
  def browse: Unit =
    given Colors = Colors.Default
    traversal #|^ "less"

  /** Execute traversal and convert the result to json. `toJson` (export) contains the exact same
    * information as `toList`, only in json format. Typically, the user will call this method upon
    * inspection of the results of `toList` in order to export the data for processing with other
    * tools.
    */
  @Doc(info = "execute traversal and convert the result to json")
  def toJson: String = toJson(pretty = false)

  /** Execute traversal and convert the result to pretty json. */
  @Doc(info = "execute traversal and convert the result to pretty json")
  def toJsonPretty: String = toJson(pretty = true)

  protected def toJson(pretty: Boolean): String =
    implicit val formats: Formats = org.json4s.DefaultFormats + Steps.nodeSerializer

    val results = traversal.toList
    if pretty then writePretty(results)
    else write(results)

  private def pyJson = py.module("json")
  @Doc(info = "execute traversal and convert the result to python object")
  def toPy: me.shadaj.scalapy.py.Dynamic = pyJson.loads(toJson(false))

  def pyg =
    val tmpDir = Files.createTempDirectory("pyg-gml-export").toFile.getAbsolutePath
    traversal match
      case methods: Iterator[Method] =>
          val exportResult = methods.gml(tmpDir)
          exportResult.files.map(Torch.to_pyg)
end Steps

object Steps:
  private lazy val nodeSerializer = new CustomSerializer[AbstractNode](implicit format =>
      (
        { case _ => ??? },
        { case node: AbstractNode with Product =>
            val elementMap = (0 until node.productArity).map { i =>
              val label   = node.productElementName(i)
              val element = node.productElement(i)
              label -> element
            }.toMap + ("_label" -> node.label)
            Extraction.decompose(elementMap)
        }
      )
  )

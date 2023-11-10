package io.shiftleft.semanticcpg.utils

import me.shadaj.scalapy.py
import me.shadaj.scalapy.py.SeqConverters
import py.PyQuote
import me.shadaj.scalapy.interpreter.CPythonInterpreter
import overflowdb.formats.ExportResult

import scala.util.{Failure, Success, Try}
import java.nio.file.Path
object Torch:

    CPythonInterpreter.execManyLines("""
      |
      |SCIENCE_PACK_AVAILABLE = True
      |try:
      |    from chenpy.graph import convert_graphml, diff_graph, to_pyg, is_similar, ged, generate_sp_model, load_sp_model
      |except ImportError:
      |    SCIENCE_PACK_AVAILABLE = False
      |""".stripMargin)

    def convert_graphml(gml_file: Path) =
        py.Dynamic.global.convert_graphml(gml_file.toAbsolutePath.toString)

    def to_pyg(gml_file: Path) = py.Dynamic.global.to_pyg(convert_graphml(gml_file))

    def diff_graph(
      first_gml_file: Path,
      second_gml_file: Path,
      include_common: Boolean = false,
      as_dict: Boolean = false
    ) =
        val first_graph = py.Dynamic.global.convert_graphml(first_gml_file.toAbsolutePath.toString)
        val second_graph =
            py.Dynamic.global.convert_graphml(second_gml_file.toAbsolutePath.toString)
        py.Dynamic.global.diff_graph(first_graph, second_graph, include_common, as_dict)

    def is_similar(
      first_gml_file: Path,
      second_gml_file: Path,
      edit_distance: Int = 10,
      upper_bound: Int = 500,
      timeout: Int = 5
    ): Boolean =
        val first_graph = py.Dynamic.global.convert_graphml(first_gml_file.toAbsolutePath.toString)
        val second_graph =
            py.Dynamic.global.convert_graphml(second_gml_file.toAbsolutePath.toString)
        py.Dynamic.global
            .is_similar(
              first_graph,
              second_graph,
              edit_distance = edit_distance,
              upper_bound = upper_bound,
              timeout = timeout
            )
            .as[Boolean]
    end is_similar

    def is_similar(
      first_result: ExportResult,
      second_result: ExportResult,
      edit_distance: Int
    ): Boolean =
        if first_result.files.nonEmpty && second_result.files.nonEmpty then
            val first_gml_file  = first_result.files.head
            val second_gml_file = second_result.files.head
            val first_graph =
                py.Dynamic.global.convert_graphml(first_gml_file.toAbsolutePath.toString)
            val second_graph =
                py.Dynamic.global.convert_graphml(second_gml_file.toAbsolutePath.toString)
            py.Dynamic.global.is_similar(
              first_graph,
              second_graph,
              edit_distance = edit_distance
            ).as[Boolean]
        else
            false

    def edit_distance(
      first_result: ExportResult,
      second_result: ExportResult,
      upper_bound: Int = 500,
      timeout: Int = 5
    ): Double =
        if first_result.files.nonEmpty && second_result.files.nonEmpty then
            val first_gml_file  = first_result.files.head
            val second_gml_file = second_result.files.head
            val first_graph =
                py.Dynamic.global.convert_graphml(first_gml_file.toAbsolutePath.toString)
            val second_graph =
                py.Dynamic.global.convert_graphml(second_gml_file.toAbsolutePath.toString)
            py.Dynamic.global.ged(
              first_graph,
              second_graph,
              upper_bound = upper_bound,
              timeout = timeout
            ).as[Double]
        else
            -1.0

    def generate_sp_model(
      filename: String,
      vocab_size: Int = 20000,
      model_type: String = "unigram",
      model_prefix: String = "m_user"
    ) = py.Dynamic.global.generate_sp_model(filename, vocab_size, model_type, model_prefix)

    def load_sp_model(filename: String) = py.Dynamic.global.load_sp_model(filename)
end Torch

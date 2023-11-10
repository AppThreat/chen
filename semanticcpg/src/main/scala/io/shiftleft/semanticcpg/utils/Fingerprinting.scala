package io.shiftleft.semanticcpg.utils

import me.shadaj.scalapy.py
import me.shadaj.scalapy.py.SeqConverters
import py.PyQuote
import me.shadaj.scalapy.interpreter.CPythonInterpreter

import scala.util.{Failure, Success, Try}

object Fingerprinting:

    CPythonInterpreter.execManyLines("""
      |from hashlib import blake2b
      |
      |def calculate_hash(content, digest_size = 16):
      |  h = blake2b(digest_size = digest_size)
      |  if content and isinstance(content, str):
      |    content = content.replace("\n", "").replace("\t", "").replace(" ", "")
      |    h.update(content.encode())
      |    return h.hexdigest()
      |  return None
      |""".stripMargin)

    def calculate_hash(content: String, digest_size: Int = 16): Option[String] =
        Option(py.Dynamic.global.calculate_hash(content, digest_size).as[String])

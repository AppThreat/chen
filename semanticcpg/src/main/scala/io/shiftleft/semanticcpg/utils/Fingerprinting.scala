package io.shiftleft.semanticcpg.utils

import me.shadaj.scalapy.interpreter.CPythonInterpreter
import me.shadaj.scalapy.py

import java.security.MessageDigest

object Fingerprinting:

    def calculate_hash(content: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(content.getBytes("UTF-8"))
            .map("%02x".format(_)).mkString

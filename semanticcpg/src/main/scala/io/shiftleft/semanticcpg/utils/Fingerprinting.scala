package io.shiftleft.semanticcpg.utils

import java.security.MessageDigest

object Fingerprinting:

  def calculate_hash(content: String): String =
      MessageDigest.getInstance("SHA-256")
          .digest(content.getBytes("UTF-8"))
          .map("%02x".format(_)).mkString

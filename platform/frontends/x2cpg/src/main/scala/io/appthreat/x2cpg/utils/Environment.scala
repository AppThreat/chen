package io.appthreat.x2cpg.utils

import java.nio.file.Paths

object Environment:

  object OperatingSystemType extends Enumeration:
    type OperatingSystemType = Value

    val Windows, Linux, Mac, Unknown = Value

  object ArchitectureType extends Enumeration:
    type ArchitectureType = Value

    val X86, ARMv8 = Value

  lazy val operatingSystem: OperatingSystemType.OperatingSystemType =
      if scala.util.Properties.isMac then OperatingSystemType.Mac
      else if scala.util.Properties.isLinux then OperatingSystemType.Linux
      else if scala.util.Properties.isWin then OperatingSystemType.Windows
      else OperatingSystemType.Unknown

  lazy val architecture: ArchitectureType.ArchitectureType =
      if scala.util.Properties.propOrNone("os.arch").contains("aarch64") then ArchitectureType.ARMv8
      // We do not distinguish between x86 and x64. E.g, a 64 bit Windows will always lie about
      // this and will report x86 anyway for backwards compatibility with 32 bit software.
      else ArchitectureType.X86

  def pathExists(path: String): Boolean =
      if !Paths.get(path).toFile.exists() then
        false
      else
        true
end Environment

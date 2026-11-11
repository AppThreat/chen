package io.appthreat.javasrc2cpg.typesolvers

import better.files.File
import JmodClassPath.*
import javassist.ClassPath

import scala.jdk.CollectionConverters.*
import scala.util.Try
import java.io.InputStream
import java.net.URL
import java.util.jar.{JarEntry, JarFile}

class JmodClassPath(jmodPath: String) extends ClassPath:
  private val jarfile = new JarFile(jmodPath)
  private val entries = getEntriesMap(jarfile)
  // javassist calls `find` only to learn whether the class exists, so any URL will do. A file: URL
  // works in a native image, which has no handler for jmod: URLs.
  private val jmodUrl = Try(File(jmodPath).url).toOption

  private def entryToClassName(entry: JarEntry): String =
      entry.getName.stripPrefix(JmodClassesPrefix).stripSuffix(".class").replace('/', '.')

  private def getEntriesMap(jarfile: JarFile): Map[String, JarEntry] =
      jarfile
          .entries()
          .asScala
          .filter(_.getName.startsWith(JmodClassesPrefix))
          .filter(_.getName.endsWith(".class"))
          .map { entry => entryToClassName(entry) -> entry }
          .toMap

  override def find(classname: String): URL =
      if entries.contains(classname) then jmodUrl.orNull else null

  override def openClassfile(classname: String): InputStream =
      entries.get(classname) match
        case None => null

        case Some(entry) => jarfile.getInputStream(entry)
end JmodClassPath

object JmodClassPath:
  val JmodClassesPrefix: String = "classes/"

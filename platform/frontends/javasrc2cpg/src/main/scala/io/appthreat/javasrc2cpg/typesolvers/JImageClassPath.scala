package io.appthreat.javasrc2cpg.typesolvers

import io.appthreat.x2cpg.utils.JImage
import javassist.ClassPath

import java.io.{ByteArrayInputStream, InputStream}
import java.net.URL
import scala.util.Try

/** Serves the classes of a JDK's `lib/modules` image to javassist. Every JDK 9 or later has the
  * image, also one built without jmods (JEP 493), and it can be read inside a native image.
  */
class JImageClassPath(image: JImage) extends ClassPath:

  // javassist calls `find` only to learn whether the class exists, so any URL will do. A file: URL
  // works in a native image, where no handler for jrt: or jmod: URLs exists.
  private val imageUrl: Option[URL] = Try(image.path.toUri.toURL).toOption

  private def internalName(classname: String): String = classname.replace('.', '/')

  override def find(classname: String): URL =
      if image.containsClass(internalName(classname)) then imageUrl.orNull else null

  override def openClassfile(classname: String): InputStream =
      image.readClass(internalName(classname)).map(new ByteArrayInputStream(_)).orNull

  override def toString: String = image.path.toString

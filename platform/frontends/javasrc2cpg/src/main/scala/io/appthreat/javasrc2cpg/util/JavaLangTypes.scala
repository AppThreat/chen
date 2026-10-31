package io.appthreat.javasrc2cpg.util

import scala.io.Source
import scala.util.{Try, Using}

/** The simple names of the JDK's `java.lang` types, read once from the committed resource.
  *
  * `java.lang` is the one package every compilation unit imports on demand, so a name the package
  * declares resolves there even when the file also carries a wildcard import whose package does not
  * declare it (`@Override` under `import javax.servlet.annotation.*`). The resource is the
  * top-level `java/lang/*.class` entries of the JDK's module image, one simple name per line:
  *
  * {{{
  * jimage list "$JAVA_HOME/lib/modules" | sed 's/^ *//' \
  *   | grep -E '^java/lang/[A-Z][A-Za-z0-9$]*\.class$' \
  *   | sed 's|^java/lang/||; s|\.class$||' | grep -v '\$' | sort -u
  * }}}
  */
object JavaLangTypes:

  private val names: Set[String] =
      Try(Using.resource(Source.fromResource("java-lang-types.txt")) { source =>
          source.getLines().map(_.trim).filter(_.nonEmpty).toSet
      }).getOrElse(Set.empty)

  def contains(simpleName: String): Boolean = names.contains(simpleName)

  /** The fully qualified name when `simpleName` is a `java.lang` type, else `None`. */
  def fullName(simpleName: String): Option[String] =
      Option.when(names.contains(simpleName))(s"java.lang.$simpleName")

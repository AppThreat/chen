package io.appthreat.c2cpg.parser

import org.eclipse.cdt.core.CCorePlugin
import org.eclipse.core.runtime.Plugin
import org.osgi.framework.connect.FrameworkUtilHelper
import org.osgi.framework.{Bundle, BundleContext, ServiceReference, Version}
import org.slf4j.LoggerFactory

import java.io.{ByteArrayOutputStream, File, InputStream, OutputStream, PrintStream}
import java.net.URL
import java.nio.charset.Charset
import java.security.cert.X509Certificate
import java.util
import java.util.Optional
import scala.util.Try

/** Lets Eclipse CDT log outside an OSGi runtime.
  *
  * CDT reports internal conditions through its plugin object (`CCorePlugin.log`), often from code
  * that recovers from the condition it reports: an ambiguity it resolves another way, a binding it
  * cannot store. The plugin object only exists inside an OSGi runtime, and c2cpg runs CDT without
  * one, so each such call threw a `NullPointerException` that ended the parse, or the AST walk, and
  * lost the whole file.
  *
  * [[install]] creates the plugin object and gives it a bundle (see [[CdtBundleLocator]]), so a log
  * call goes through. Outside OSGi, Eclipse's log then prints each message and its stack trace to
  * standard output; [[captured]] sends what a thread prints while it parses or walks a CDT AST to
  * the debug log instead.
  */
object CdtLogging:

  private val logger = LoggerFactory.getLogger(getClass)

  // set once; not a lazy val, which a native image would need reflection metadata for
  @volatile private var state: Option[Boolean] = None

  /** Whether CDT can log: true once its plugin object exists and has a bundle. */
  def installed: Boolean = state.getOrElse(synchronized {
      state.getOrElse {
          val ready = setUp()
          state = Some(ready)
          ready
      }
  })

  private def setUp(): Boolean =
    val plugin     = Option(CCorePlugin.getDefault).orElse(Try(new CCorePlugin()).toOption)
    val ready      = plugin.exists(p => Try(p.getBundle).toOption.flatMap(Option(_)).nonEmpty)
    val withBundle = ready || plugin.exists(attachBundle)
    if withBundle then CapturedOut.install()
    else logger.debug("CDT's log is not available; a CDT log call will fail its file")
    withBundle

  /** Makes CDT able to log. Safe to call any number of times, from any thread; a call after
    * standard output was replaced captures from the new stream.
    */
  def install(): Unit = if installed then CapturedOut.install()

  /** Runs `body`, sending what this thread prints to standard output meanwhile (which, while CDT
    * runs, is CDT's log) to the debug log. Nested calls are fine.
    */
  def captured[T](body: => T): T =
      if !installed then body
      else
        val depth = CapturedOut.depth.get
        CapturedOut.depth.set(depth + 1)
        try body
        finally
          CapturedOut.depth.set(depth)
          if depth == 0 then CapturedOut.drain()

  /** Gives the plugin its bundle when the bundle lookup found none: `Plugin.getBundle` reads a
    * private field before it asks the OSGi framework. Fails quietly where reflection is not
    * available.
    */
  private def attachBundle(plugin: CCorePlugin): Boolean =
      Try {
          val field = classOf[Plugin].getDeclaredField("bundle")
          field.setAccessible(true)
          field.set(plugin, CdtCoreBundle)
          plugin.getBundle ne null
      }.getOrElse(false)

  /** Standard output, except on a thread inside [[captured]]: there, complete lines go to the debug
    * log.
    */
  private object CapturedOut:
    val depth: ThreadLocal[Int] = ThreadLocal.withInitial(() => 0)
    private val pending         = ThreadLocal.withInitial(() => new ByteArrayOutputStream())
    @volatile private var charset: Charset = Charset.defaultCharset()

    def install(): Unit = synchronized {
        System.out match
          case _: Capturing => ()
          case out =>
              charset = out.charset()
              System.setOut(new Capturing(out))
    }

    private final class Capturing(out: PrintStream)
        extends PrintStream(new Router(out), true, out.charset())

    private final class Router(out: PrintStream) extends OutputStream:
      override def write(b: Int): Unit =
          if depth.get > 0 then
            pending.get.write(b)
            if b == '\n' then drain()
          else out.write(b)
      override def write(b: Array[Byte], off: Int, len: Int): Unit =
          if depth.get > 0 then
            pending.get.write(b, off, len)
            if (off until off + len).exists(i => b(i) == '\n') then drain()
          else out.write(b, off, len)
      override def flush(): Unit = if depth.get == 0 then out.flush()

    /** Logs this thread's pending output. Whatever the logger itself prints is not captured again.
      */
    def drain(): Unit =
      val buffer = pending.get
      if buffer.size > 0 then
        val text = buffer.toString(charset).stripTrailing()
        buffer.reset()
        val saved = depth.get
        depth.set(0)
        try if text.nonEmpty then logger.debug(s"CDT: $text")
        finally depth.set(saved)
  end CapturedOut
end CdtLogging

/** Answers the OSGi framework's bundle lookup for CDT's plugin class outside an OSGi runtime
  * (registered as a `FrameworkUtilHelper` service), so `CCorePlugin.getBundle` is not null.
  */
final class CdtBundleLocator extends FrameworkUtilHelper:
  override def getBundle(classFromBundle: Class[?]): Optional[Bundle] =
      if classOf[CCorePlugin].isAssignableFrom(classFromBundle) then Optional.of(CdtCoreBundle)
      else Optional.empty()

/** The bundle CDT's plugin reports outside an OSGi runtime: resolved, with no context, entries or
  * services. Nothing in c2cpg's use of CDT reads more than its name and state.
  */
object CdtCoreBundle extends Bundle:
  override def getState: Int                                               = Bundle.RESOLVED
  override def start(options: Int): Unit                                   = ()
  override def start(): Unit                                               = ()
  override def stop(options: Int): Unit                                    = ()
  override def stop(): Unit                                                = ()
  override def update(input: InputStream): Unit                            = ()
  override def update(): Unit                                              = ()
  override def uninstall(): Unit                                           = ()
  override def getHeaders: util.Dictionary[String, String]                 = new util.Hashtable()
  override def getBundleId: Long                                           = -1L
  override def getLocation: String                                         = CCorePlugin.PLUGIN_ID
  override def getRegisteredServices: Array[ServiceReference[?]]           = Array.empty
  override def getServicesInUse: Array[ServiceReference[?]]                = Array.empty
  override def hasPermission(permission: AnyRef): Boolean                  = true
  override def getResource(name: String): URL                              = null
  override def getHeaders(locale: String): util.Dictionary[String, String] = new util.Hashtable()
  override def getSymbolicName: String                                     = CCorePlugin.PLUGIN_ID
  override def loadClass(name: String): Class[?]                           = Class.forName(name)
  override def getResources(name: String): util.Enumeration[URL] =
      util.Collections.emptyEnumeration()
  override def getEntryPaths(path: String): util.Enumeration[String] =
      util.Collections.emptyEnumeration()
  override def getEntry(path: String): URL = null
  override def getLastModified: Long       = 0L
  override def findEntries(
    path: String,
    filePattern: String,
    recurse: Boolean
  ): util.Enumeration[URL] = util.Collections.emptyEnumeration()
  override def getBundleContext: BundleContext = null
  override def getSignerCertificates(signersType: Int)
    : util.Map[X509Certificate, util.List[X509Certificate]] = util.Collections.emptyMap()
  override def getVersion: Version                 = Version.emptyVersion
  override def adapt[A](`type`: Class[A]): A       = null.asInstanceOf[A]
  override def getDataFile(filename: String): File = null
  override def compareTo(other: Bundle): Int =
      java.lang.Long.compare(getBundleId, other.getBundleId)
end CdtCoreBundle

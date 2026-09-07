package io.appthreat.x2cpg.perf

import java.lang.management.ManagementFactory
import java.nio.file.{Files, Paths, StandardOpenOption}
import scala.util.Try
import scala.util.control.NonFatal

/** Opt-in per-stage performance reporting (Task P.4).
  *
  * Enabled by pointing it at an output file, either with the JVM system property `chen.perf.report`
  * (what atom's `--perf-report` sets during option parsing) or the `CHEN_PERF_REPORT` environment
  * variable. When neither is set, [[stage]] is a pass-through that resolves the property once and
  * runs the body - no clock read, no allocation, nothing per node - so the instrument is genuinely
  * zero-cost for every run that did not ask for it.
  *
  * Output is NDJSON, one line per stage completion, appended as stages finish so a hung or crashed
  * run still leaves the completed stages behind for diagnosis. Each line:
  *
  *   - `stage` fully qualified driver-side name, e.g. `python.PythonTypeRecoveryPass`
  *   - `phase` `analysis` (atom build, passes, dataflow), `slicing` (reachables/usage extraction -
  *     the product) or `verification` (export, graphml round-trip, persist - scaffolding). The
  *     harness gates analysis and verification separately so a scaffolding improvement cannot mask
  *     an analysis regression.
  *   - `wallMs` wall-clock span of the stage
  *   - `cpuMs` CPU time of the APPLYING thread during the stage
  *   - `allocMB` bytes allocated by the APPLYING thread during the stage
  *
  * What is measured, stated here because a reader will otherwise assume otherwise: `wallMs` is the
  * wall-clock span of the stage as applied by the driver. Drivers apply stages sequentially, so
  * spans do not overlap and sum to the run. `cpuMs`/`allocMB` are the applying thread only - a
  * stage that farms work out to internal parallelism shows it in `wallMs` but not in
  * `cpuMs`/`allocMB`. That is why both are reported rather than one.
  */
object PerfReporter:

  private val PropKey = "chen.perf.report"
  private val EnvKey  = "CHEN_PERF_REPORT"

  private val lock = new Object

  /** The environment cannot change during a run, so it is read once; the system property is read
    * live because atom sets it while parsing options and the tests toggle it. Resolved per stage
    * call, never per node - and a disabled run costs exactly one `System.getProperty`, not a
    * rebuild of the whole environment map (`sys.env` is a `def`).
    */
  private lazy val envPath: Option[String] = sys.env.get(EnvKey).filter(_.nonEmpty)

  private def outputPath: Option[String] =
      Option(System.getProperty(PropKey)).filter(_.nonEmpty).orElse(envPath)

  def isEnabled: Boolean = outputPath.isDefined

  /** Run `body` as a named stage. When the reporter is disabled this is `body` itself. */
  def stage[T](name: String, phase: String)(body: => T): T =
    val path = outputPath
    if path.isEmpty then return body

    val threadId   = Thread.currentThread.threadId()
    val startWall  = System.nanoTime()
    val startCpu   = Try(threadBean.getThreadCpuTime(threadId)).getOrElse(0L)
    val startAlloc = Try(threadBean.getThreadAllocatedBytes(threadId)).getOrElse(-1L)
    val startEpoch = System.currentTimeMillis()
    val outcome = Try {
        body
    }
    val endWall  = System.nanoTime()
    val endCpu   = Try(threadBean.getThreadCpuTime(threadId)).getOrElse(0L)
    val endAlloc = Try(threadBean.getThreadAllocatedBytes(threadId)).getOrElse(-1L)

    append(
      path.get,
      s"""{"stage":"$name","phase":"$phase","wallMs":${ms(endWall - startWall)},""" +
          s""""cpuMs":${ms(endCpu - startCpu)},"allocMB":${mb(startAlloc, endAlloc)},""" +
          s""""startEpochMs":$startEpoch,"ok":${outcome.isSuccess}}"""
    )
    outcome.get
  end stage

  /** `Locale.ROOT`, not the default: this output is parsed as JSON, and a comma-decimal default
    * locale would emit `12,3` and make every line unreadable on exactly the machines it is hardest
    * to debug on.
    */
  private def fixed(value: Double): String = String.format(java.util.Locale.ROOT, "%.1f", value)

  private def ms(nanos: Long): String = fixed(nanos / 1000000.0)

  /** `-1` means "not measured", and it has to survive the subtraction. Reporting `end - start` when
    * both readings failed would print `0.0` - a stage that allocated nothing, which is a
    * measurement claim rather than the absence of one, and precisely the failure this whole task
    * exists to stop making.
    */
  private def mb(startBytes: Long, endBytes: Long): String =
      if startBytes < 0 || endBytes < 0 || endBytes < startBytes then "-1"
      else fixed((endBytes - startBytes) / 1048576.0)

  private lazy val threadBean =
      ManagementFactory.getThreadMXBean.asInstanceOf[com.sun.management.ThreadMXBean]

  private def append(path: String, line: String): Unit =
      lock.synchronized {
          Try {
              val p = Paths.get(path)
              Option(p.getParent).foreach(Files.createDirectories(_))
              if !Files.exists(p) then
                Files.writeString(
                  p,
                  metaLine() + "\n",
                  StandardOpenOption.CREATE,
                  StandardOpenOption.WRITE,
                  StandardOpenOption.TRUNCATE_EXISTING
                )
              Files.writeString(
                p,
                line + "\n",
                StandardOpenOption.CREATE,
                StandardOpenOption.APPEND
              )
          }.recover { case NonFatal(e) =>
              System.err.println(s"perf-report: failed to write $path: ${e.getMessage}")
          }
      }

  private def metaLine(): String =
    val runtime = ManagementFactory.getRuntimeMXBean
    val jvm     = System.getProperty("java.vm.name", "?")
    val version = System.getProperty("java.version", "?")
    s"""{"stage":"__meta__","phase":"meta","jvm":"$jvm $version","pid":${runtime.getPid},""" +
        s""""maxHeapMB":${Runtime.getRuntime.maxMemory / 1048576},"host":"${hostLabel()}"}"""

  private def hostLabel(): String =
      Try(java.net.InetAddress.getLocalHost.getHostName).getOrElse("unknown")
end PerfReporter

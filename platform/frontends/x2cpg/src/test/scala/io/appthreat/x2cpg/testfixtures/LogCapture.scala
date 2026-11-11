package io.appthreat.x2cpg.testfixtures

import org.apache.logging.log4j.Level
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.core.LogEvent
import org.apache.logging.log4j.core.Logger
import org.apache.logging.log4j.core.appender.AbstractAppender
import org.apache.logging.log4j.core.config.Property

import java.util.concurrent.ConcurrentLinkedQueue
import scala.jdk.CollectionConverters.*

/** Collects what one named logger logs while the body runs, at a level the body chooses.
  *
  * The suites use this for the chen#255 gates: with the level at what a default run uses, nothing
  * may be logged for a file the frontend lost, and with the level at DEBUG the file and the reason
  * must be there.
  */
final class RecordingAppender(name: String)
    extends AbstractAppender(name, null, null, true, Property.EMPTY_ARRAY):

  private val logged = new ConcurrentLinkedQueue[LogEvent]()

  override def append(event: LogEvent): Unit =
      logged.add(event.toImmutable())

  /** The logged messages at exactly `level`, in order. */
  def messagesAt(level: Level): List[String] =
      logged.asScala.filter(_.getLevel == level).map(_.getMessage.getFormattedMessage).toList

  /** Everything logged at `level` or above, in order. */
  def messagesAtOrAbove(level: Level): List[String] =
      logged.asScala
          .filter(event => event.getLevel.isMoreSpecificThan(level))
          .map(event => s"${event.getLevel}: ${event.getMessage.getFormattedMessage}")
          .toList

object LogCapture:

  /** Attach an appender to `loggerName`, set it to `level` for the duration of `body`, and hand the
    * appender to the body. The logger's previous level is restored afterwards.
    */
  def withCapture[T](loggerName: String, level: Level)(body: RecordingAppender => T): T =
      LogManager.getLogger(loggerName) match
        case coreLogger: Logger =>
            val appender = new RecordingAppender(s"recording-$loggerName")
            val before   = coreLogger.getLevel
            appender.start()
            coreLogger.setLevel(level)
            coreLogger.addAppender(appender)
            try body(appender)
            finally
              coreLogger.removeAppender(appender)
              coreLogger.setLevel(before)
              appender.stop()
        case other =>
            throw new IllegalStateException(
              s"The test logging backend for '$loggerName' is ${other.getClass.getName}, " +
                  "not log4j2, so the quiet-by-default gates cannot capture it"
            )
end LogCapture

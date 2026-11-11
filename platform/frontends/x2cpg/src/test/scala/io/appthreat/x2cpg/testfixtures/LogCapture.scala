package io.appthreat.x2cpg.testfixtures

import ch.qos.logback.classic.Level
import ch.qos.logback.classic.Logger
import ch.qos.logback.classic.spi.ILoggingEvent
import ch.qos.logback.core.read.ListAppender
import org.slf4j.LoggerFactory

import scala.jdk.CollectionConverters.*

/** Collects what one named logger logs while the body runs, at a level the body chooses.
  *
  * The suites use this for the chen#255 gates: with the level at what a default run uses, nothing
  * may be logged for a file the frontend lost, and with the level at DEBUG the file and the reason
  * must be there. The tests run on logback (see project/Projects.scala) precisely because its
  * loggers take appenders directly, so a capture sees exactly the events the code emitted.
  */
object LogCapture:

  /** Attach a ListAppender to `loggerName`, set it to `level` for the duration of `body`, and hand
    * the appender to the body. The logger's previous level is restored afterwards.
    */
  def withCapture[T](loggerName: String, level: Level)(body: ListAppender[ILoggingEvent] => T): T =
      LoggerFactory.getLogger(loggerName) match
        case logger: Logger =>
            val appender = new ListAppender[ILoggingEvent]()
            val before   = logger.getLevel
            appender.start()
            logger.setLevel(level)
            logger.addAppender(appender)
            logger.setAdditive(false)
            try body(appender)
            finally
              logger.detachAppender(appender)
              logger.setAdditive(true)
              logger.setLevel(before)
              appender.stop()
        case other =>
            throw new IllegalStateException(
              s"The test logging backend for '$loggerName' is ${other.getClass.getName}, " +
                  "not logback, so the quiet-by-default gates cannot capture it"
            )

  /** The logged messages at exactly `level`, in order. */
  def messagesAt(appender: ListAppender[ILoggingEvent], level: Level): List[String] =
      appender.list.asScala.filter(_.getLevel == level).map(_.getFormattedMessage).toList

  /** Everything logged at `level` or above, in order. */
  def messagesAtOrAbove(appender: ListAppender[ILoggingEvent], level: Level): List[String] =
      appender.list.asScala
          .filter(_.getLevel.isGreaterOrEqual(level))
          .map(event => s"${event.getLevel}: ${event.getFormattedMessage}")
          .toList
end LogCapture

package io.appthreat.jimple2cpg.util

import better.files.File
import org.benf.cfr.reader.api.OutputSinkFactory.{Sink, SinkClass, SinkType}
import org.benf.cfr.reader.api.SinkReturns.Decompiled
import org.benf.cfr.reader.api.{CfrDriver, OutputSinkFactory}

import java.util
import java.util.{Collection, Collections}
import scala.collection.mutable
import scala.jdk.CollectionConverters.*

class Decompiler(classFile: List[File]):

  private val classToDecompiledSource: mutable.HashMap[String, String] = mutable.HashMap.empty;

  /** Decompiles the class files and returns a map of the method name to its source code contents.
    */
  def decompile(): mutable.HashMap[String, String] =
    val driver = new CfrDriver.Builder().withOutputSink(outputSink).build()
    driver.analyse(SeqHasAsJava(classFile.map(_.pathAsString)).asJava)
    classToDecompiledSource

  private val outputSink: OutputSinkFactory = new OutputSinkFactory():

    override def getSupportedSinks(
      sinkType: SinkType,
      collection: util.Collection[SinkClass]
    ): util.List[SinkClass] =
        if sinkType == SinkType.JAVA && collection.contains(SinkClass.DECOMPILED) then
          util.Arrays.asList(SinkClass.DECOMPILED)
        else
          Collections.singletonList(SinkClass.STRING)

    override def getSink[T](sinkType: SinkType, sinkClass: SinkClass): OutputSinkFactory.Sink[T] =
        new Sink[T]():
          override def write(s: T): Unit =
              sinkType match
                case OutputSinkFactory.SinkType.JAVA =>
                    s match
                      case x: Decompiled =>
                          val className   = x.getClassName
                          val packageName = x.getPackageName
                          val classFullName =
                              Seq(packageName, className).filterNot(_.isBlank).mkString(".")
                          classToDecompiledSource.put(classFullName, x.getJava)
                      case _ =>
                case OutputSinkFactory.SinkType.PROGRESS =>
                    s.toString.split(" ").last
                case OutputSinkFactory.SinkType.EXCEPTION =>
                case _                                    => // ignore
end Decompiler
